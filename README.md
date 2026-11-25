# snark_stms

Native cryptographic primitives and SNARK circuits for stake-weighted
certificates, built with `midnight-circuits`, `midnight-proofs`, and
`midnight-zk-stdlib`. The prototype uses compact Schnorr signatures over Jubjub,
Poseidon hashing, Merkle membership proofs, and KZG-backed proofs over BLS12-381.

Registration is responsible for validating the registry and deriving lottery
targets from signer stakes and the total stake. It commits verification keys
and targets in a Merkle tree. Certificate proofs authenticate those entries
against the public registry root and check signatures and lottery eligibility.

Run the commands below from this directory, which contains `Cargo.toml`.

## Circuit variants

| Module | Public inputs | Signed messages per witness entry |
| --- | --- | --- |
| [`certificate_topiconly`](src/circuits/certificate_topiconly.rs) | `(root, topic)` | One signature on `[root, topic]` |
| [`certificate_topicbody`](src/circuits/certificate_topicbody.rs) | `(root, topic, body)` | A topic signature on `[root, topic]` and a full-message signature on `[root, topic, body]` |

Topics and bodies are represented by field elements. Callers choose how
application data is encoded into those elements.

Both circuits take a vector of exactly `quorum` witness entries. Each entry
contains a registered `(verification_key, target)` leaf, its Merkle path,
the signature or signatures, and a lottery index. Indices must be strictly
increasing and lie in `0..num_lotteries`. The quorum counts winning indices;
one signer can contribute several different indices.

Each relation is configured with `Certificate::new(quorum, num_lotteries,
merkle_tree_depth)`. Use a positive quorum satisfying
`quorum < num_lotteries < 2^16`, and provide paths containing exactly
`merkle_tree_depth` siblings. The constructor stores these parameters without
validating them. For a tree with `n` leaves, the path depth is
`ceil(log2(n))`; a singleton tree has depth zero.

The deterministic tag of the topic signature supplies the lottery projection.
The native and circuit checks accept an evaluation when `ev <= target`.
Targets are computed outside the circuit by [`lottery::target`](src/lottery.rs).

## Build

Use Rust 1.90 or newer (edition 2024). This checkout has been tested
with Rust 1.93.1. The `rug` dependency builds native arithmetic libraries, so
a C build environment is also required.

```bash
cargo build
```

The four direct Midnight dependencies are pinned to upstream revision `c3e8432`. Keep
`Cargo.lock` to reproduce the resolved dependency graph. This revision always
truncates challenges; `truncated-challenges` remains a compatibility alias,
and `--no-default-features` does not change the challenge format.

## SRS setup

Certificate benchmarks use unsafe KZG parameters cached in
`examples/assets/params_kzg_unsafe_<k>`, sized for each circuit. Missing files
are generated automatically by the setup binary in a separate process, then
reused on subsequent runs. This excludes SRS generation from the benchmark's
timings and process peak RAM; loading the SRS still contributes to peak RAM.
The generator checks serialization before publishing the completed cache file.
Generated cache files are ignored by Git. These parameters are for tests and
benchmarks only, never production.

To prepare a size manually (for example, `k = 22`):

```bash
cargo run --release -- 22
```

Alternatively, set `K` in [`examples/setup.rs`](examples/setup.rs), create the
output directory, and run the example:

```bash
mkdir -p examples/assets
cargo run --release --example setup
```

Both setup commands replace an existing file for that size. For certificate
tests, proof examples, and certificate benchmarks, set `SRS_FILE` to use an
explicit parameter file in Midnight's `RawBytesUnchecked` format instead of
the cache. The file must already exist and cover every enabled case; larger
parameters are downsized in memory. A missing or undersized explicit file
causes an error instead of falling back to the cache. The override file is
never generated or overwritten. No Filecoin download is required.

## Proof examples

Each example generates and verifies one proof, printing setup (VK and PK),
proof generation, and verification times, plus the proof size. Change
`NUM_SIGNERS`, `QUORUM`, and `NUM_LOTTERIES` in the example to select the
workload. SRS loading and generation, along with certificate construction, are
excluded from the timings. Missing unsafe SRS files are generated and cached
automatically. The examples use maximum lottery targets so every index is eligible.

```bash
cargo run --release --example certificate_topiconly
cargo run --release --example certificate_topicbody
```

## Tests

Run all tests in release mode:

```bash
cargo test --release
```

With `SRS_FILE` unset, certificate tests require
`examples/assets/params_kzg_unsafe_<k>` for `k = 13, 14, 16, 17, 21, 22`.
Before running the full suite, generate the missing sizes using one of the
setup commands above. Alternatively, use one existing file with `k >= 22`
for the full suite:

```bash
SRS_FILE=examples/assets/params_kzg_unsafe_22 cargo test --release
```

Filtered runs can use a smaller file if it covers every selected test.
The larger proof tests require substantially more time and memory.

## Benchmarks

### Certificate circuits

Certificate benchmarks report sequential setup and proving times, Criterion
verification timings, proof sizes, and process-wide peak RAM on Linux. Adjust
parameters and run counts in [`benches/certificates.rs`](benches/certificates.rs).

```bash
cargo bench --bench certificates
```

Filter verification cases or list them. All configured cases still perform
setup and proving, including when listing:

```bash
cargo bench --bench certificates -- certificate_topiconly
cargo bench --bench certificates -- certificate_topicbody
cargo bench --bench certificates -- --list
```

### Signatures

Native Schnorr and BLS benchmarks:

```bash
cargo bench --bench schnorr
cargo bench --bench bls
```

## API documentation

```bash
cargo doc --no-deps --open
```

The generated documentation starts at `target/doc/snark_stms/index.html`
and includes a native signing example.

## Source layout

| Path | Purpose |
| --- | --- |
| [`src/circuits/`](src/circuits/) | Certificate relations and shared verification gadgets |
| [`src/schnorr_signature.rs`](src/schnorr_signature.rs) | Compact Schnorr signatures with deterministic lottery tags |
| [`src/lottery.rs`](src/lottery.rs) | Registration-time targets and native lottery checks |
| [`src/merkle_tree.rs`](src/merkle_tree.rs) | Registry leaves, Poseidon Merkle trees, and membership paths |
| [`src/utils.rs`](src/utils.rs) | Field conversions and witness-calculation helpers |
| [`src/main.rs`](src/main.rs) | KZG parameter generation with a command-line `k` |
| [`examples/setup.rs`](examples/setup.rs) | KZG parameter generation with a source-level `K` |
| [`benches/`](benches/) | Native primitives and certificate circuit Criterion benchmarks |
