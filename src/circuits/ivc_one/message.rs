//! Fixed-length protocol-message encoding inherited from the main branch.
//!
//! Topic-only certificates sign its hash as their topic. Topic/body certificates
//! sign it as their body and may keep their lottery topic stable across bodies.

use crate::{HashCPU, utils::jubjub_base_from_le_bytes};
use midnight_circuits::hash::sha256::Sha256Chip;

use super::{F, PREIMAGE_SIZE};

/// Fixed key strings and their positions in the original message layout.
pub(crate) const KEYS: [(usize, &[u8]); 4] = [
    (0, b"digest"),
    (38, b"next_aggregate_verification_key"),
    (113, b"next_protocol_parameters"),
    (169, b"current_epoch"),
];

/// Fields whose serialization is opened by the recursive state transition.
#[derive(Clone, Debug)]
pub struct ProtocolMessage {
    pub digest: [u8; 32],
    pub next_merkle_root: F,
    pub next_registry_size: u32,
    pub total_stake: u64,
    pub next_protocol_params: F,
    pub current_epoch: u64,
}

impl ProtocolMessage {
    /// Encodes the original digest/AVK/protocol-parameters/epoch layout.
    pub fn preimage(&self) -> [u8; PREIMAGE_SIZE] {
        let mut bytes = Vec::with_capacity(PREIMAGE_SIZE);
        bytes.extend_from_slice(b"digest");
        bytes.extend_from_slice(&self.digest);
        bytes.extend_from_slice(b"next_aggregate_verification_key");
        bytes.extend_from_slice(&self.next_merkle_root.to_bytes_le());
        bytes.extend_from_slice(&self.next_registry_size.to_le_bytes());
        bytes.extend_from_slice(&self.total_stake.to_le_bytes());
        bytes.extend_from_slice(b"next_protocol_parameters");
        bytes.extend_from_slice(&self.next_protocol_params.to_bytes_le());
        bytes.extend_from_slice(b"current_epoch");
        bytes.extend_from_slice(&self.current_epoch.to_le_bytes());
        bytes
            .try_into()
            .expect("protocol message has a fixed layout")
    }

    /// Reduces the SHA-256 digest's little-endian integer into the circuit field.
    pub fn hash(&self) -> F {
        jubjub_base_from_le_bytes(&Sha256Chip::<F>::hash(&self.preimage()))
    }

    /// Parses the fixed layout, rejecting altered keys and noncanonical field encodings.
    pub fn from_preimage(bytes: &[u8; PREIMAGE_SIZE]) -> Result<Self, crate::Error> {
        let invalid = || crate::Error::Synthesis("invalid IVC protocol-message encoding".into());
        for (offset, key) in KEYS {
            if &bytes[offset..offset + key.len()] != key {
                return Err(invalid());
            }
        }
        let next_merkle_root =
            Option::<F>::from(F::from_bytes_le(bytes[69..101].try_into().unwrap()))
                .ok_or_else(invalid)?;
        let next_protocol_params =
            Option::<F>::from(F::from_bytes_le(bytes[137..169].try_into().unwrap()))
                .ok_or_else(invalid)?;
        Ok(Self {
            digest: bytes[6..38].try_into().unwrap(),
            next_merkle_root,
            next_registry_size: u32::from_le_bytes(bytes[101..105].try_into().unwrap()),
            total_stake: u64::from_le_bytes(bytes[105..113].try_into().unwrap()),
            next_protocol_params,
            current_epoch: u64::from_le_bytes(bytes[182..190].try_into().unwrap()),
        })
    }
}
