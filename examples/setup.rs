//! Generates and reloads local KZG parameters using the `K` selected in `main`.
//!
//! From the crate directory, run `mkdir -p examples/assets`, then
//! `cargo run --release --example setup`. The generated file replaces any
//! existing file for that `K`; `unsafe_setup` is used for tests and benchmarks.

use std::fs::File;
use std::io::{self, BufReader, BufWriter, Write};

use midnight_proofs::{poly::kzg::params::ParamsKZG, utils::SerdeFormat};
use snark_stms::Bls12;
use rand::rngs::OsRng;

/// Generates parameters for a `2^k`-point domain in unchecked raw encoding.
/// Flushes the output before reporting success and propagates any I/O error.
fn create(k: u32, path: &str) -> io::Result<()> {
    let params: ParamsKZG<Bls12> = ParamsKZG::unsafe_setup(k, OsRng);

    let file = File::create(path)?;
    let mut writer = BufWriter::new(file);
    params.write_custom(&mut writer, SerdeFormat::RawBytesUnchecked)?;
    writer.flush()?;

    println!("ParamsKZG written to {}", path);
    Ok(())
}

/// Reloads the parameter file to exercise the corresponding decoding path.
fn open(path: &str) -> io::Result<ParamsKZG<Bls12>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    ParamsKZG::read_custom(&mut reader, SerdeFormat::RawBytesUnchecked)
}

fn main() -> io::Result<()> {
    // const K: u32 = 13;
    // const K: u32 = 16;
    const K: u32 = 22;
    // Create the output directory with `mkdir -p examples/assets` before running this example.
    let path = format!("examples/assets/params_kzg_unsafe_{}", K);

    create(K, &path)?;
    open(&path)?;

    Ok(())
}
