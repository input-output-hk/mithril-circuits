//! Registry construction and cached unsafe SRS loading for the proof examples.

use std::{
    env,
    fs::{self, File},
    io::{self, BufReader, BufWriter, Write},
    path::{Path, PathBuf},
};

use ff::Field;
use midnight_proofs::{poly::kzg::params::ParamsKZG, utils::SerdeFormat};
use rand_core::OsRng;
use snark_stms::{
    Bls12, JubjubBase as F,
    merkle_tree::{MTLeaf, MerkleTree},
    schnorr_signature::{SigningKey, VerificationKey},
};

pub(super) fn create_registry(num_signers: usize) -> (Vec<SigningKey>, Vec<MTLeaf>, MerkleTree) {
    assert!(num_signers > 0, "num_signers must be positive");
    let keys: Vec<_> = (0..num_signers)
        .map(|_| SigningKey::generate(&mut OsRng))
        .collect();
    // Maximum targets make every lottery index eligible in these examples.
    // Applications should derive targets from stakes using lottery::target.
    let leaves: Vec<_> = keys
        .iter()
        .map(|key| MTLeaf(VerificationKey::from(key), -F::ONE))
        .collect();
    let tree = MerkleTree::create(&leaves);
    (keys, leaves, tree)
}

fn read_srs(path: &Path) -> io::Result<ParamsKZG<Bls12>> {
    let file = File::open(path).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("Could not open SRS {}: {error}", path.display()),
        )
    })?;
    ParamsKZG::read_custom(&mut BufReader::new(file), SerdeFormat::RawBytesUnchecked)
}

pub(super) fn load_srs(k: u32) -> io::Result<ParamsKZG<Bls12>> {
    let override_path = env::var_os("SRS_FILE");
    let path = override_path
        .as_ref()
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join(format!("examples/assets/params_kzg_unsafe_{k}"))
        });

    let mut srs = if override_path.is_none() && !path.try_exists()? {
        println!("Generating unsafe SRS for k={k} (outside setup timing)...");
        fs::create_dir_all(path.parent().expect("SRS cache has a parent directory"))?;
        let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
        {
            let srs = ParamsKZG::<Bls12>::unsafe_setup(k, OsRng);
            let mut writer = BufWriter::new(File::create(&temporary)?);
            srs.write_custom(&mut writer, SerdeFormat::RawBytesUnchecked)?;
            writer.flush()?;
        }
        // Read back successfully before publishing the cache file.
        let srs = read_srs(&temporary)?;
        fs::rename(&temporary, &path)?;
        srs
    } else {
        println!("Loading SRS from {}", path.display());
        read_srs(&path)?
    };

    if srs.max_k() < k {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("SRS is too small: need k={k}, found k={}", srs.max_k()),
        ));
    }
    srs.downsize(k);
    Ok(srs)
}
