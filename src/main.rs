//! Generates local KZG parameters and reads them back to check serialization.
//!
//! Run `cargo run --release -- <k>` from the crate directory. Output goes to
//! `examples/assets/params_kzg_unsafe_<k>`; the directory is created as needed.
//! An existing file is replaced after the new parameters have been flushed and
//! reloaded successfully. Parameters use `unsafe_setup` for tests and benchmarks.

use rand::rngs::OsRng;
use std::env;
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Write};

use midnight_proofs::poly::kzg::params::ParamsKZG;
use midnight_proofs::utils::SerdeFormat;
use snark_stms::Bls12;

/// Generates parameters for a `2^k`-point domain in unchecked raw encoding.
/// Flushes the output before reporting success and propagates any I/O error.
fn create(k: u32, path: &str) -> io::Result<()> {
    let params: ParamsKZG<Bls12> = ParamsKZG::unsafe_setup(k, OsRng);

    let file = File::create(path)?;
    let mut writer = BufWriter::new(file);
    params.write_custom(&mut writer, SerdeFormat::RawBytesUnchecked)?;
    writer.flush()?;

    Ok(())
}

/// Reloads a locally generated parameter file in the matching raw encoding.
fn open(path: &str) -> io::Result<ParamsKZG<Bls12>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    ParamsKZG::read_custom(&mut reader, SerdeFormat::RawBytesUnchecked)
}

fn main() -> io::Result<()> {
    // Create unsafe params for tests
    // Usage: cargo run --release -- <k>

    // Retrieve command-line arguments
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <k>", args[0]);
        std::process::exit(1);
    }

    // Parse the first argument as a u32
    let k: u32 = args[1]
        .parse()
        .expect("Invalid value for k: expected an unsigned integer");

    fs::create_dir_all("examples/assets")?;
    let path = format!("examples/assets/params_kzg_unsafe_{k}");
    let temporary = format!("{path}.tmp-{}", std::process::id());
    create(k, &temporary)?;
    open(&temporary)?;
    fs::rename(&temporary, &path)?;
    println!("ParamsKZG written to {path}");
    Ok(())
}
