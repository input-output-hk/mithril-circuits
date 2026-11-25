//! Shared SRS loading and peak RAM reporting for certificate benchmarks.

use std::{env, fs, fs::File, io::BufReader, path::PathBuf, process::Command};

use midnight_proofs::{poly::kzg::params::ParamsKZG, utils::SerdeFormat};
use snark_stms::Bls12;

pub(super) fn load_srs(k: u32) -> ParamsKZG<Bls12> {
    let path = env::var_os("SRS_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join(format!("examples/assets/params_kzg_unsafe_{k}"));
            if !path.try_exists().expect("Could not inspect the SRS cache") {
                eprintln!("Generating unsafe benchmark SRS for k={k} in a separate process");
                // Cargo builds this binary alongside the benchmark. Invoke it
                // directly to avoid nested Cargo builds and keep generation RAM
                // out of this benchmark process's high-water mark.
                let status = Command::new(env!("CARGO_BIN_EXE_snark_stms"))
                    .arg(k.to_string())
                    .current_dir(env!("CARGO_MANIFEST_DIR"))
                    .status()
                    .expect("Could not launch the SRS generator");
                assert!(
                    status.success(),
                    "SRS generation failed for k={k}: {status}"
                );
            }
            path
        });
    eprintln!("Loading SRS from {}", path.display());
    let file = File::open(&path)
        .unwrap_or_else(|error| panic!("Could not open SRS {}: {error}", path.display()));
    let mut srs =
        ParamsKZG::<Bls12>::read_custom(&mut BufReader::new(file), SerdeFormat::RawBytesUnchecked)
            .expect("Could not read SRS in Midnight's RawBytesUnchecked format");
    assert!(
        srs.max_k() >= k,
        "SRS is too small: need k={k}, found k={}",
        srs.max_k()
    );
    srs.downsize(k);
    srs
}

pub(super) fn report_peak_ram() {
    // VmHWM is Linux's reported lifetime peak RSS in KiB. Reading it at the
    // end also includes memory released during setup/proving and prior cases.
    let peak_kib = fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status.lines().find_map(|line| {
                line.strip_prefix("VmHWM:")?
                    .split_whitespace()
                    .next()?
                    .parse::<u64>()
                    .ok()
            })
        });
    match peak_kib {
        Some(kib) => println!(
            "Peak process RAM: {} bytes ({:.2} MiB)",
            kib * 1024,
            kib as f64 / 1024.0
        ),
        None => println!("Peak process RAM: unavailable (requires Linux /proc)"),
    }
}
