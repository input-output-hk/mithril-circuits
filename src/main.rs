use rand::rngs::OsRng;
use std::env;
use std::fs::File;
use std::io::{BufReader, BufWriter};

use midnight_proofs::poly::kzg::params::ParamsKZG;
use midnight_proofs::utils::SerdeFormat;
use mithril_circuits::Bls12;

fn create(k: u32) {
    let path = format!("examples/assets/params_kzg_unsafe_{}", k);
    // Step 1: Create an instance of ParamsKZG
    let params: ParamsKZG<Bls12> = ParamsKZG::unsafe_setup(k, OsRng);

    // Step 2: Open a file for writing
    let file = File::create(&path).unwrap();
    let mut writer = BufWriter::new(file);

    // Step 3: Write the ParamsKZG to the file
    params
        .write_custom(&mut writer, SerdeFormat::RawBytesUnchecked)
        .unwrap();

    println!("ParamsKZG written to {}", path);
}

fn open(k: u32) -> ParamsKZG<Bls12> {
    let path = format!("examples/assets/params_kzg_unsafe_{}", k);
    let file = File::open(path).unwrap();
    let mut reader = BufReader::new(file);
    let params: ParamsKZG<Bls12> =
        ParamsKZG::read_custom(&mut reader, SerdeFormat::RawBytesUnchecked).unwrap();

    params
}

fn main() {
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
        .expect("Invalid value for k, must be an integer");

    create(k);
    open(k);
}
