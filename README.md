# mithril-circuits

### Mithril snarkification — a SNARK-friendly variant of the Mithril multi-signature protocol

> ### ⚠️ Important Disclaimer & Acceptance of Risk
>
> **This repository contains prototype implementations.** This code is provided "as is" for research and educational purposes
> only. It has not been thoroughly tested and audited and is not intended for production use. By using this code, you
> acknowledge and accept all associated risks, and our company disclaims any liability for damages or losses.

## Overview

This repository proposes and implements a **SNARK-friendly variant of
the Mithril stake-based multi-signature protocol** (Cardano), together with a full recursive
proof system for it.

The existing Mithril implementation is built from primitives that are extremely expensive to prove inside a SNARK: **BLS multi-signatures** (pairing-heavy), **SHA-256** and
**Blake2b** hashing (bit-oriented, thousands of constraints per call), and **floating-point
arithmetic** in the stake-weighted lottery (not natively expressible over a prime field at all).
Naively wrapping that implementation in a proof would be prohibitively costly. Worse, a full
certificate chain grows **linearly in the number of epochs**: linking the latest certificate back
to the genesis certificate requires including at least one certificate from every intervening
epoch, so both the chain's size and its verification cost scale with the chain's length.

Instead, this repository _redesigns_ Mithril's primitives — signatures, registration, lottery,
and cross-epoch chaining — around proof-system-native building blocks, so that the entire protocol
and an unbounded chain of certificates across epochs can be verified succinctly with a single
SNARK proof plus an accumulator. Its contributions are:

- **A SNARK-friendly signer primitive** — a VRF-style _unique_ signature with a Chaum–Pedersen
  equal-discrete-log proof over the Jubjub curve, replacing BLS multi-signatures. Signing and
  verification are native to the circuit field and need no pairings, and hashing uses Poseidon in
  place of SHA-256 / Blake2b.
- **A registration-time lottery** — the floating-point lottery is removed entirely: each signer's
  stake-weighted eligibility _target_ is precomputed off-circuit at registration and committed into
  the signer's Merkle-tree leaf. In-circuit, the lottery collapses to a single field comparison
  (`ev ≤ target`) against a value already bound by the Merkle root — no floating-point or
  high-precision arithmetic is ever needed.
- **The certificate relation** — a PLONKish circuit that proves an entire Mithril quorum
  (Merkle membership, valid unique signatures, and stake-weighted lottery wins, with distinct-index
  enforcement) and produces a single succinct SNARK proof. A verifier checks that one proof
  rather than re-checking each signer's signature individually.
- **A SNARK-friendly genesis certificate** — the genesis (authority) certificate that roots the
  chain is redesigned as a Schnorr signature on the Jubjub curve with Poseidon hashing, replacing
  Mithril's original genesis signature scheme so it can be verified cheaply inside the IVC circuit.
- **A unified protocol-message format** — all certificate types (genesis and regular) share one
  canonical, fixed-length `ProtocolMessage` byte layout, so the IVC circuit can recompute its
  SHA-256 digest in-circuit and extract the fields that drive the epoch transition (next AVK root,
  next protocol parameters, current epoch) at known byte offsets — binding the signed message to
  the state transition.
- **An IVC / accumulation design for Mithril's epoch chain** — a recursive circuit that folds an
  unbounded sequence of certificate proofs into a constant-size artifact, encoding Mithril's
  epoch-transition semantics (AVK hand-off, protocol-parameter roll-over, genesis rooting) as
  in-circuit constraints. Each step links its certificate all the way back to the genesis
  certificate, so every IVC proof is a **standalone proof of the entire certificate chain** — of
  **constant size, independent of the number of certificates or epochs**.

More details can be found in sections of [`DESIGN.md`](./DESIGN.md), which documents the architecture and cryptographic design in full.

This repository is the **research prototype**: it is where the SNARK-friendly Mithril design was first
worked out. The **production** implementation, which builds on the design prototyped here, lives
in the main Mithril repository under
[`mithril-stm/src/circuits`](https://github.com/input-output-hk/mithril/tree/main/mithril-stm/src/circuits).

## How it works, in one picture

```
 genesis          epoch e+1          epoch e+2
 Schnorr   cert₁  certificate  cert₂ certificate
  sig    ───────▶  proof π₁  ───────▶ proof π₂  ...
   │                  │                  │
   ▼                  ▼                  ▼
 IVC step 0 ──────▶ IVC step 1 ──────▶ IVC step 2 ──▶ ...
 proof Π₀           proof Π₁           proof Π₂
 acc  A₀            A₁=fold(A₀,π₁,Π₀)  A₂=fold(A₁,π₂,Π₁)
```

- **Certificate circuit** (inner) — one SNARK proves a Mithril quorum is reached for a single certificate.
- **IVC circuit** (recursive) — folds the unbounded certificate chain into a **constant-size**
  proof plus an accumulator. To trust every certificate from genesis up to the current epoch, a
  verifier checks only the latest IVC proof plus one accumulator decider check — a cost
  independent of how many epochs the chain spans.

## Repository layout

```
src/
  lib.rs                      re-export facade + domain-separation tags (DST_*)
  signatures/
    unique_signature.rs       VRF-style unique signature (SNARK-friendly signer primitive)
    schnorr_signature.rs      Schnorr signature (genesis / authority certificate)
  merkle_tree.rs              Poseidon Merkle tree over signer registrations
  lottery.rs                  stake → target conversion + eligibility check
  protocol_message.rs         Mithril ProtocolMessage → SHA-256 digest → field element
  alba.rs                     ALBA (telescope) sampling — alternative aggregation
  utils.rs                    field / bigint / curve helpers
  circuits/
    mod.rs                    shared in-circuit gadgets (merkle path, signature, lottery, cmp)
    certificate.rs            the certificate relation (inner circuit)
    ivc_one/                  the current IVC (recursive) circuit
  main.rs                     generate KZG parameters (`cargo run --release -- <k>`)
benches/                      criterion benchmarks (signature, bls)
```

## Getting started

### KZG parameters (prerequisite for most tests)

Circuit tests read a structured reference string (SRS) from
`examples/assets/params_kzg_unsafe_<k>`, where `<k>` is the log₂ circuit size (rows = 2^k). This
directory is empty on a fresh checkout, so generate the params first. `src/main.rs` takes `k` as
a command-line argument:

```bash
cargo run --release -- <k>            # e.g. `cargo run --release -- 13`
```

Each test declares its own `K` (e.g. 13 for `test_certificate_small`, 16 for medium, 21 for
large, 19 for IVC) and needs the matching params file — generate one per `k` you intend to test.
Some tests instead call `filecoin_srs(k)` and need no local file.

Always build and test in `--release`; debug proving is extremely slow.

```bash
cargo build --release
cargo test  --release <substring> -- --nocapture     # e.g. certificate_small, test_ivc_one
```

## Further reading

- [`DESIGN.md`](./DESIGN.md) — full architecture and cryptographic design.

## Citation

If you use this repository or the design it proposes, please cite it. GitHub renders a
**"Cite this repository"** button from [`CITATION.cff`](./CITATION.cff) (with ready-to-copy
BibTeX and APA). A BibTeX entry:

```bibtex
@misc{mithril_circuits,
  title        = {Mithril snarkification: a SNARK-friendly variant of the Mithril multi-signature protocol},
  author       = {Jia Liu and Raphael Toledo},
  howpublished = {\url{https://github.com/input-output-hk/mithril-circuits}},
  year         = {2025}
}
```
