//! Shared loading of existing KZG parameters for certificate proof tests.

use std::{
    env,
    fs::File,
    io::{self, BufReader},
    path::{Path, PathBuf},
};

use midnight_proofs::{poly::kzg::params::ParamsKZG, utils::SerdeFormat};

use crate::Bls12;

/// Uses an explicit SRS_FILE when set, otherwise the cache for the requested k.
/// Larger files are downsized in memory; no parameter files are generated or written.
pub(super) fn load_srs(k: u32) -> ParamsKZG<Bls12> {
    let path = env::var_os("SRS_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join(format!("examples/assets/params_kzg_unsafe_{k}"))
        });

    eprintln!("Loading SRS from {}", path.display());
    read_srs(&path, k).unwrap_or_else(|error| panic!("{error}"))
}

fn read_srs(path: &Path, k: u32) -> io::Result<ParamsKZG<Bls12>> {
    let file = File::open(path).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("Could not open SRS {}: {error}", path.display()),
        )
    })?;
    let mut srs = ParamsKZG::read_custom(&mut BufReader::new(file), SerdeFormat::RawBytesUnchecked)
        .map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "Could not read SRS {} in Midnight's RawBytesUnchecked format: {error}",
                    path.display()
                ),
            )
        })?;

    if srs.max_k() < k {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "SRS {} is too small: need k={k}, found k={}",
                path.display(),
                srs.max_k()
            ),
        ));
    }

    srs.downsize(k);
    Ok(srs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::{OsRng, RngCore};

    struct SrsFile(PathBuf);

    impl SrsFile {
        fn create() -> Self {
            let path = env::temp_dir().join(format!(
                "snark-stms-test-srs-{}-{:016x}",
                std::process::id(),
                OsRng.next_u64()
            ));
            File::options()
                .write(true)
                .create_new(true)
                .open(&path)
                .unwrap();
            Self(path)
        }

        fn with_params(k: u32) -> Self {
            let file = Self::create();
            let srs = ParamsKZG::<Bls12>::unsafe_setup(k, OsRng);
            srs.write_custom(
                &mut File::create(&file.0).unwrap(),
                SerdeFormat::RawBytesUnchecked,
            )
            .unwrap();
            file
        }
    }

    impl Drop for SrsFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    #[test]
    fn accepts_exact_size_and_downsizes_without_changing_file() {
        let file = SrsFile::with_params(3);
        let original = std::fs::read(&file.0).unwrap();

        assert_eq!(read_srs(&file.0, 3).unwrap().max_k(), 3);
        assert_eq!(read_srs(&file.0, 2).unwrap().max_k(), 2);
        assert_eq!(std::fs::read(&file.0).unwrap(), original);
    }

    #[test]
    fn rejects_undersized_srs_with_path_and_sizes() {
        let file = SrsFile::with_params(3);
        let error = read_srs(&file.0, 4).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains(file.0.to_str().unwrap()));
        assert!(error.to_string().contains("need k=4, found k=3"));
    }

    #[test]
    fn reports_missing_file_without_creating_it() {
        let file = SrsFile::create();
        std::fs::remove_file(&file.0).unwrap();
        let error = read_srs(&file.0, 3).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert!(error.to_string().contains(file.0.to_str().unwrap()));
        assert!(!file.0.exists());
    }

    #[test]
    fn reports_unreadable_srs_format_with_path() {
        let file = SrsFile::create();
        let error = read_srs(&file.0, 3).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        assert!(error.to_string().contains(file.0.to_str().unwrap()));
        assert!(error.to_string().contains("RawBytesUnchecked"));
    }
}
