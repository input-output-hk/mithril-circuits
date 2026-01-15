use std::fs::File;
use std::io::{self, BufReader, BufWriter};

use mithril_circuits::Bls12;
use midnight_proofs::{poly::kzg::params::ParamsKZG, utils::SerdeFormat};
use rand::rngs::OsRng;

fn create(k: u32, path: &str) {
    // Step 1: Create an instance of ParamsKZG
    let params: ParamsKZG<Bls12> = ParamsKZG::unsafe_setup(k, OsRng);

    // Step 2: Open a file for writing
    let file = File::create(&path).unwrap();
    let mut writer = BufWriter::new(file);

    // Step 3: Write the ParamsKZG to the file
    params.write_custom(&mut writer, SerdeFormat::RawBytesUnchecked).unwrap();

    println!("ParamsKZG written to {}", path);
}

fn open(path: &str) -> ParamsKZG<Bls12>{
    let file = File::open(path).unwrap();
    let mut reader = BufReader::new(file);
    let params: ParamsKZG<Bls12> = ParamsKZG::read_custom(&mut reader, SerdeFormat::RawBytesUnchecked).unwrap();

    params
}

fn main() -> io::Result<()> {
    // const K: u32 = 13;
    // const K: u32 = 16;
    const K: u32 = 21;
    let path = format!("examples/assets/params_kzg_unsafe_{}", K);

    create(K, &path);
    let srs = open(&path);

    Ok(())
}