//! Examples on how to perform ECC operations using the ECC Chip inside of
//! ZkStdLib.

use rand::rngs::OsRng;
use std::fs::File;
use std::io::{BufReader, BufWriter};

use blstrs::Bls12;
use midnight_proofs::poly::kzg::params::ParamsKZG;
use midnight_proofs::utils::SerdeFormat;

// create unsafe params for tests
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
    create(20);
    open(20);
}
