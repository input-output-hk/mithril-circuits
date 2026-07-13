# mithril-circuits — Design

This document describes the architecture and cryptographic design of `mithril-circuits`.

---

## 1. Goal and high-level idea

Mithril lets a set of stake-weighted signers on Cardano jointly certify a message (e.g. a
snapshot digest) for an epoch. A valid **certificate** is a set of individual signatures large
enough — under a stake-weighted lottery — to constitute a quorum. Certificates chain across
epochs: each epoch's certificate authorizes the signer set (the _aggregate verification key_)
and protocol parameters of the next epoch, rooted in a one-time genesis certificate.

This repository proposes a **SNARK-friendly redesign** of that structure so that it becomes
**succinctly verifiable**. Two things make the standard protocol impractical to prove directly:
its primitives (BLS multi-signatures, SHA-256 / Blake2b hashing, floating-point lottery
arithmetic) are extremely expensive in a SNARK, and a full certificate chain grows _linearly in
the number of epochs_ — linking the latest certificate back to genesis requires at least one
certificate from every intervening epoch. The redesign swaps those primitives for
proof-system-native equivalents (Jubjub unique signatures, Poseidon Merkle registration, a
registration-time lottery target committed in the Merkle tree) and recasts the epoch chain as a
recursive computation:

1. **Inner layer — the certificate circuit.** A single SNARK proves that a quorum of signers
   validly signed a message under Mithril's rules (Merkle membership + unique signature +
   lottery eligibility). This replaces "verify N signatures" with "verify one proof".

2. **Recursive layer — the IVC circuit.** _Incrementally Verifiable Computation_ folds an
   unbounded chain of certificates into a **constant-size** artifact: each step verifies the
   previous IVC proof _and_ the next certificate proof _inside the circuit_, deferring the
   expensive elliptic-curve pairing work into a KZG **accumulator**. A verifier checks the
   final IVC proof plus the folded accumulator and thereby transitively trusts the whole chain
   back to genesis.

The result: verifying "the entire history of Mithril certificates from genesis to epoch _n_"
costs one SNARK verification plus one accumulator decider check, independent of _n_.

---

## 2. Cryptographic foundation

Everything is built on the [**midnight-zk**](https://github.com/midnightntwrk/midnight-zk) stack
(`midnight-circuits`, `midnight-proofs`, `midnight-curves`, `midnight-zk-stdlib`) — a halo2/KZG
proving system over **BLS12-381**.

| Concept                 | Type / value                                            | Notes                                                          |
| ----------------------- | ------------------------------------------------------- | -------------------------------------------------------------- |
| Proving system          | halo2 PLONK + KZG (`midnight-proofs`)                   | Commitments over BLS12-381 `G1`.                               |
| Native circuit field    | `JubjubBase = BlsScalar` (`Fq`)                         | Rows are constrained over this field.                          |
| Signature curve         | `Jubjub` (twisted Edwards over `JubjubBase`)            | `sk ∈ JubjubScalar`, keys/points over `JubjubBase`.            |
| Recursion pairing curve | BLS12-381, via `BlstrsEmulation`                        | The IVC circuit does _foreign_ EC / pairing arithmetic.        |
| In-circuit hash         | Poseidon (`PoseidonChip`)                               | Cheap over the native field; used for MT, signatures, lottery. |
| Protocol-message hash   | SHA-256 (`Sha256Chip`)                                  | Mithril hashes the `ProtocolMessage` preimage with SHA-256.    |
| Transcript hash         | `PoseidonState` (intermediate) / `blake2b_simd` (final) | See §6.4.                                                      |

The choice of `JubjubBase` as the native field is what makes the certificate circuit cheap:
Jubjub is defined _over_ `JubjubBase`, so signature/point arithmetic is native, and Poseidon
is native too. The IVC circuit pays the cost of BLS12-381 arithmetic because it must verify
KZG proofs, but it does so through emulation and defers the pairing to the accumulator.

### 2.1 The `lib.rs` re-export facade

`src/lib.rs` flattens most of the midnight-zk API into the crate root via `pub use`. Internal
modules import from `crate::{...}` rather than from `midnight_circuits`/`midnight_proofs`
directly. **When you pull in a new chip or type from the underlying stack, re-export it from
`lib.rs` first, then import it via `crate::`.** This keeps a single seam between this crate and
the (fast-moving) upstream stack.

`lib.rs` also defines the domain-separation tags (`DST_*`) and asserts they are unique in a
test. Reuse an existing tag; never invent an ad-hoc one.

---

## 3. Mapping Mithril concepts to this codebase

| Mithril concept                    | This crate                                              | File                                    |
| ---------------------------------- | ------------------------------------------------------- | --------------------------------------- |
| Signer registration (VK ↦ stake)   | `MTLeaf(vk, target)` in a Poseidon Merkle tree          | `merkle_tree.rs`                        |
| Aggregate verification key (AVK)   | Merkle root (+ `nr_leaves`, `total_stake`)              | `merkle_tree.rs`, `protocol_message.rs` |
| Individual signature               | VRF-style **unique signature** `σ = H₁(msg)^sk`         | `signatures/unique_signature.rs`        |
| Stake-weighted lottery eligibility | `target(phi_f, stake, total)`, then check `ev ≤ target` | `lottery.rs`                            |
| Quorum `k`, lotteries `m`          | `Certificate { quorum, num_lotteries, .. }`             | `circuits/certificate.rs`               |
| Signed message                     | `ProtocolMessage` → SHA-256 → field element             | `protocol_message.rs`                   |
| Genesis / authority certificate    | Schnorr signature over the genesis message              | `signatures/schnorr_signature.rs`       |
| Cross-epoch chaining               | `State` transition inside the IVC circuit               | `circuits/ivc_one/`                     |

---

## 4. CPU-side primitives (`src/`)

These are the _native_ (non-circuit) implementations. Each in-circuit gadget mirrors one of
these exactly — the CPU version is the specification the circuit must reproduce, and the tests
generate witnesses with these types.

### 4.1 Unique signature (`signatures/unique_signature.rs`)

A VRF-style **unique** signature — this crate's SNARK-friendly replacement for Mithril's core signer primitive.

- `σ = H₁(msg)^sk` where `H₁ = hash_to_curve` onto Jubjub. `σ` is _deterministic_ per
  `(sk, msg)`, so it is a canonical per-message tag — this is what makes the lottery
  per-signer rather than per-nonce.
- Proof of correctness is a **Chaum–Pedersen** equality-of-discrete-log: prove
  `log_g(vk) = log_{H₁(msg)}(σ)` without revealing `sk`. Concretely the signature is
  `(σ, s, c)` where
  - `R₁ = H₁(msg)^r`, `R₂ = g^r` for random `r`,
  - `c = Poseidon(DST_UNIQUE_SIGNATURE, H₁, vk, σ, R₁, R₂)`,
  - `s = r − sk·c`.
- Verification recomputes `R₁' = H₁^s · σ^c`, `R₂' = g^s · vk^c`, and checks
  `c == Poseidon(…, R₁', R₂')`.
- `LongSignature` carries `R₁, R₂` explicitly (vs. recomputing) — useful for batching /
  alternative flows. `to_short_signature` converts back.

### 4.2 Merkle tree (`merkle_tree.rs`)

A Poseidon Merkle tree over signer registrations.

- Leaf: `MTLeaf(vk, target)`, hashed as `Poseidon(vk_x, vk_y, target)` (arity 3).
- Internal node: `Poseidon(left, right)` (arity 2). Padding uses `Poseidon(0)` (arity 1).
- Arity-based domain separation only — leaf/node/empty are distinguished by input count, not
  by an explicit DST. The `DST_MERKLE_*` constants exist but are currently unused, which is a
  footgun for future readers.
- Binding `target` into the leaf is the security crux: `target` is a free witness in the
  circuit, but it must hash into the public root, so a prover cannot inflate their own lottery
  target. Correctness rests on **registration** producing honest targets.
- `MerkleTreeCommitment` = `root (32B) + nr_leaves (4B)`; the AVK adds `total_stake (8B)` →
  44 bytes total. These byte layouts matter — the IVC circuit slices them out of the SHA-256
  preimage (§6.3).

### 4.3 Lottery (`lottery.rs`)

- `target(phi_f, stake, total_stake)` — high-precision (`rug`) conversion of stake share to a
  field-element threshold: `target = ⌊(1 − (1−phi_f)^(stake/total)) · modulus⌋`. `phi_f = 1`
  maps to the maximum target (`modulus − 1`, i.e. always eligible).
- Eligibility for lottery `index`: `ev = Poseidon(prefix, σ_x, σ_y, index)` and the signer
  wins iff `ev ≤ target`. `prefix = Poseidon(DST_LOTTERY, merkle_root, msg)`.
- A high-stake signer can win many of the `m = num_lotteries` indices; each win is a separate
  quorum slot. This is _not_ double-counting because `σ` is deterministic per signer.

### 4.4 Protocol message (`protocol_message.rs`)

Mirrors Mithril's `ProtocolMessage` / `ProtocolMessagePartKey`.

- A `BTreeMap<PartKey, Vec<u8>>`; the **preimage** is the concatenation, in `BTreeMap` key
  order, of each `key_string_bytes || value_bytes`.
- `compute_hash()` = SHA-256 of the preimage. This digest, reduced to a `JubjubBase` element,
  is the message the certificate signers actually sign.
- **The exact byte layout is load-bearing.** The IVC circuit extracts `next_merkle_root`,
  `next_protocol_params`, and `current_epoch` by _hard-coded byte offsets_ into this preimage
  (§6.3). Any change to which parts are present, their order (`BTreeMap` ordering of the enum),
  or their sizes silently breaks extraction. The 10 possible part keys and their string
  lengths are enumerated in the module's tests.

### 4.5 Schnorr signature (`signatures/schnorr_signature.rs`)

Standard Schnorr over Jubjub, used only for the **genesis** (authority) certificate that roots
the IVC chain: `c = Poseidon(DST_SCHNORR_SIGNATURE, vk, R, msg)`, `s = r − sk·c`.

### 4.6 Utilities (`utils.rs`)

Field/bigint conversions (`fe_to_big`, `big_to_fe`, `split`, `decompose`), curve coordinate
extraction, on-curve checks, and `JubjubBase ↔ JubjubScalar` reinterpretation. `split` is the
CPU counterpart to the in-circuit `decompose_unsafe` (§5.3).

---

## 5. The circuit layer (`src/circuits/`)

### 5.1 The `Relation` trait

Every production circuit implements midnight-zk's **`Relation`**:

- `Instance` — public inputs; `format_instance` flattens them to `Vec<F>`.
- `Witness` — private inputs.
- `circuit(std_lib, layouter, instance, witness)` — synthesizes the constraints via the
  `ZkStdLib` chip bundle.
- `used_chips() -> ZkStdLibArch` — toggles which sub-chips (Poseidon, Jubjub, SHA-256, …) are
  laid out. Only enable what the circuit uses; unused chips still cost columns.
- `write_relation` / `read_relation` — (de)serialize the circuit's _parameters_ (not witness),
  so a verifier can reconstruct the exact relation.

The IVC circuit does **not** use `Relation`; it implements the lower-level halo2 `Circuit`
trait directly, because it needs custom column layout and multi-instance-column public inputs
(§6).

### 5.2 The certificate relation (`certificate.rs`)

**Parameters:** `(quorum k, num_lotteries m, merkle_tree_depth)`. **Public instance:**
`(merkle_root, msg)`. **Witness:** `quorum`-many tuples
`(MTLeaf, MerklePath, Signature, LotteryIndex)`.

For each of the `k` signers, the circuit enforces:

1. **Merkle membership** — `verify_merkle_path`: the leaf `Poseidon(vk_x, vk_y, target)` hashes
   up to the public `merkle_root`.
2. **Valid unique signature** — `verify_unique_signature` over `H₁(merkle_root, msg)`.
3. **Lottery win** — `verify_lottery`: `ev = Poseidon(prefix, σ, index) ≤ target`.

Plus two aggregation-level constraints:

4. **Strictly increasing indices** — `lower_than(pre_index, index, 16)` for `i > 0`. This
   prevents a prover from re-using the same lottery slot to pad the quorum.
5. **`index < num_lotteries`** — the final `lower_than(pre_index, m, 16)`.

`assert!(quorum < num_lotteries)` is a construction-time invariant. Sizing: `test_certificate_small`
uses `k=13, quorum=6`; medium `k=16, quorum=32`; large `k=21, quorum=1024` — the `k`
(log₂ rows) grows with the quorum because each signer replays the full MT + signature + lottery
gadget set.

### 5.3 Shared in-circuit gadgets (`circuits/mod.rs`)

Reused across relations:

- `verify_merkle_path`, `verify_unique_signature`, `verify_lottery` — the in-circuit mirrors of
  §4.1–4.3.
- **255-bit native comparison** — `lower_than_native` / `decompose_unsafe`. The `ZkStdLib`
  `lower_than` works on bounded widths; a full-field (255-bit) comparison is built by
  splitting each operand into a 127-bit low limb and a 128-bit high limb, range-checking each
  limb via `lower_than(·, ·, 127/128)`, and comparing high-then-low. `decompose_unsafe` is
  "unsafe" because it does _not_ itself range-check the split — it relies on (a) the later
  `lower_than` bounding the limbs and (b) a **least-significant-bit parity** check
  (`assert_equal_parity`) that, _because the field modulus is odd_, forces the decomposition to
  be unique. **Do not "simplify" this** — the parity trick is what closes the soundness gap.
  It assumes `lower_than` range-checks _both_ of its operands to the given bit width.
- `div_rem_native`, `is_divisible_by_base` — native division/divisibility used by ALBA.

### 5.4 Alternative / experimental circuits

- `certificate_alba.rs` — ALBA-based aggregation, an alternative certificate relation.
- `ivc.rs`, `ivc_sd.rs`, `ivc_with_inner.rs`, `wrapper_tx.rs` — earlier IVC experiments.
  **`ivc_one` is the current, canonical IVC.**
- `alba.rs` — Approximate Lower Bound Arguments (telescope) sampling, an alternative to a fixed
  quorum.

---

## 6. The IVC circuit (`circuits/ivc_one/`)

This is the recursive layer and the most intricate part of the crate. Each IVC step proves a
single **state transition** (adding one certificate to the chain) while folding proof
verification into an accumulator.

Module split:

| File         | Responsibility                                                                                                                                         |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `state.rs`   | `State` (the transition being proven), `Global` (per-chain constants), `Witness`; their assigned counterparts; `trivial_acc`, `fixed_bases_and_names`. |
| `io.rs`      | Serialization of accumulators / IVC artifacts.                                                                                                         |
| `config.rs`  | `configure_ivc_circuit` — column layout shared by all sub-chips.                                                                                       |
| `gadget.rs`  | `IvcGadget` — the actual constraint logic (genesis, transition, verify+fold).                                                                          |
| `circuit.rs` | `IvcCircuit` — assembles the above into a halo2 `Circuit`.                                                                                             |
| `mod.rs`     | Type aliases, `PREIMAGE_SIZE = 190`, `K = 19`, and the end-to-end `test_ivc_one`.                                                                      |

### 6.1 `State`, `Global`, `Witness`

- **`Global`** — constants fixed for the whole chain and passed as public input every step:
  `genesis_msg`, `genesis_vk` (Schnorr), and the _transcript reprs_ (hashes) of the certificate
  VK (`cert_vk_repr`) and the IVC VK itself (`self_vk_repr`). The self-VK hash is what makes the
  recursion well-defined: the circuit verifies proofs against _its own_ verifying key.
- **`State`** — the transition data: `counter`, `msg`, `merkle_root`, `next_merkle_root`,
  `protocol_params`, `next_protocol_params`, `current_epoch`. `State::genesis()` is all-zero;
  `counter == 0` **is** the genesis marker.
- **`Witness`** — the next certificate to fold: `genesis_sig` (Schnorr, only meaningful at
  genesis), `cert_msg`, `cert_merkle_root`, and the SHA-256 `msg_preimage` (`[u8; 190]`).

Public inputs of each IVC step are `[global, next_state, next_acc]` (see `test_ivc_one`).

### 6.2 Per-step logic (`circuit.rs` → `gadget.rs`)

`IvcCircuit::synthesize` runs, in order:

1. `assign_global_as_public_input` — assign `Global`, including the two child VKs.
2. `assign_state`, `assign_witness`.
3. `is_genesis = is_zero(counter)`.
4. `assert_genesis` — if genesis, verify the Schnorr genesis signature; otherwise skip
   (gated by `or(is_genesis_sig_valid, is_not_genesis)`).
5. `transition` — compute and constrain `next_state` (§6.3).
6. `verify_prepare` — verify the cert proof and previous IVC proof, fold into `next_acc` (§6.4).
7. Constrain `next_state` and `next_acc` as public inputs; load the decomposition and SHA-256
   chips.

### 6.3 State transition semantics (`gadget.rs::transition`)

This is where Mithril's epoch/chaining rules become constraints. Given the previous `state` and
the new certificate `witness`:

- `counter' = counter + 1`.
- `msg` = `genesis_msg` if genesis else `cert_msg`.
- **Preimage binding:** `sha256(msg_preimage) == msg`. Because the signers signed `cert_msg`,
  this ties the preimage to the signed message; substituting a different preimage would require
  a SHA-256 collision.
- **Field extraction by fixed offset** — from `msg_preimage`:
  - `next_merkle_root  = preimage[69..101]`
  - `next_protocol_params = preimage[137..169]`
  - `current_epoch     = preimage[182..190]`

  These offsets assume the message contains exactly `{Digest, NextAggregateVerificationKey,
NextProtocolParameters, CurrentEpoch}` with the exact key-string and value lengths.

- **Epoch rules:**
  - `is_same_epoch` / `is_next_epoch` restrict `current_epoch ∈ {state.epoch, state.epoch+1}`.
  - At `counter == 1` (first cert after genesis), `is_next_epoch` is _forced_ — the first
    post-genesis certificate must be in `genesis_epoch + 1`.
  - Merkle-root link: `merkle_root` must equal `state.merkle_root` (same epoch) or
    `state.next_merkle_root` (next epoch) — i.e. an epoch's certificate is signed under the AVK
    that the _previous_ epoch's certificate announced.
  - Within an epoch, `next_merkle_root` and `next_protocol_params` are immutable.
- `next_state` bundles the results.

### 6.4 Verification and accumulation (`gadget.rs::verify_prepare`)

This implements the recursion via midnight-zk's `VerifierGadget` + `Accumulator` machinery
(`SelfEmulation = BlstrsEmulation`). Per step:

1. **Prepare the certificate proof** — `verifier_gadget.prepare(cert_vk, …, cert_proof)`
   produces a `dual_msm` → `cert_proof_acc` (an `AssignedAccumulator`). Its public inputs are
   `[cert_merkle_root, cert_msg]` — the certificate relation's instance.
2. **Prepare the previous IVC proof** — `prepare(self_vk, …, self_proof)` against the previous
   step's public inputs `[global, state, acc]`, chaining state _and_ accumulator.
3. **Genesis gating** — `scale_by_bit(is_not_genesis, …)` zeroes out the (nonexistent) child
   proofs at genesis, letting the prover inject a trivial accumulator that satisfies the
   invariant.
4. **Fold** — `AssignedAccumulator::accumulate([acc, cert_proof_acc, self_proof_acc])` →
   `next_acc`, then `collapse()`.

Each accumulator's `fixed_bases` are keyed by name (`CERT_VK_NAME = "cert_vk"`,
`IVC_ONE_NAME = "ivc_one_vk"`, plus `"com_instance"`) — see `fixed_bases_and_names`. **Preserve
this naming and the per-step accumulate/collapse ordering**; the `check(...)` assertions in
`test_ivc_one` are the correctness oracle.

**Transcript types and per-epoch proof generation.** The transcript hash chosen when producing an
IVC proof determines how cheaply that proof can later be re-verified: `PoseidonState<F>` is cheap
to verify _inside_ the circuit (so it is used for a proof that the next IVC step will recursively
aggregate), whereas `blake2b_simd::State` is the standard choice for a standalone proof verified
_outside_ the circuit. The transcript type must match between `prove` and `prepare`/`verify`.

Because the chain only needs to fold **one certificate per epoch** to link back to genesis, proofs
are generated as follows:

- **First certificate of an epoch** — _two_ IVC proofs are produced: one with a **Poseidon**
  transcript, consumed by the next IVC step to continue the aggregation, and one with a **Blake2b**
  transcript, the externally-verifiable, standalone constant-size proof of the whole chain up to
  this certificate.
- **Any other certificate in the epoch** — a single IVC proof with a **Blake2b** transcript. It is
  verified externally but is not folded further into the chain.

### 6.5 The mandatory decider check

The accumulation scheme is sound **only if the final verifier runs both**:

- `dual_msm.check(srs.verifier_params())` on the last IVC proof, **and**
- `acc.check(srs.s_g2(), fixed_bases)` on the folded accumulator.

Verifying the SNARK but skipping the accumulator decider check leaves every folded cert/IVC
proof effectively unverified. `test_ivc_one` does both; any integration must too.

### 6.6 Circuit configuration (`config.rs`)

`configure_ivc_circuit` allocates a single pool of advice/fixed columns sized to the _maximum_
demand across all sub-chips (native, Poseidon, SHA-256, foreign BLS12-381 ECC), plus **two
instance columns** (`committed_instance` + `instance`) for the accumulator's committed-instance
public-input scheme. The IVC circuit's `K = 19` is fixed and assumes the
`truncated-challenges` feature.

---

## 7. Feature flags, parameters, and testing

- **`default = ["truncated-challenges"]`** — propagated to `midnight-circuits` and
  `midnight-proofs`. It changes verifier-key hashes and proof layout, so all cached VKs and `k`
  sizings assume it is on. Keep it on; the IVC's fixed `K = 19` depends on it.
- **KZG params are a prerequisite.** Circuit tests read
  `examples/assets/params_kzg_unsafe_<k>` (empty on fresh checkout). `src/main.rs` takes `k` as a
  command-line argument, so generate with `cargo run --release -- <k>` (e.g.
  `cargo run --release -- 13`). Some tests use `filecoin_srs(k)` instead and need no local file.
  `<k>` is the log₂ circuit size; each test declares its own `K` and needs the matching file.
- **Always test with `--release`** — debug proving is extremely slow.

---

## 8. Recursion model — summary diagram

```
 genesis                 epoch e+1                 epoch e+2
 ┌──────────┐   cert₁    ┌───────────┐   cert₂     ┌───────────┐
 │ Schnorr  │──────────▶ │certificate│──────────▶  │certificate│  ...
 │  sig     │            │  proof π₁ │             │  proof π₂ │
 └────┬─────┘            └─────┬─────┘             └─────┬─────┘
      │                        │                        │
      ▼                        ▼                        ▼
   IVC step 0 ───────────▶ IVC step 1 ───────────▶ IVC step 2 ───▶ ...
   proof Π₀                proof Π₁                 proof Π₂
   acc  A₀                 acc  A₁ = fold(A₀,π₁,Π₀) acc A₂ = fold(A₁,π₂,Π₁)

 Each IVC step i proves:
   • state transition Sᵢ → Sᵢ₊₁ (epoch/root/params chaining rules)
   • prepare(cert_vk, πᵢ)     — the new certificate is valid
   • prepare(self_vk, Πᵢ₋₁)   — the previous IVC proof is valid
   • Aᵢ₊₁ = accumulate(Aᵢ, cert_accᵢ, self_accᵢ)

 Final verification (constant cost, any i):
   • dual_msm(Πₙ).check(srs)          ← the last IVC proof
   • Aₙ.check(srs, fixed_bases)       ← the folded accumulator  (MANDATORY)
```
