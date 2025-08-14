//! Utility functions for the SP1 Groth16 Solana verifier.
//!
//! This module contains functions for decompressing G1 and G2 points, as well as
//! for loading proofs into a form appropriate for verification. This is necessary to coerce
//! SP1 Groth16 proofs into the form expected by the `groth16_solana` crate.

use ark_bn254::{Fq, G1Affine};
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("G1 compression error")]
    G1CompressionError,
    #[error("G2 compression error")]
    G2CompressionError,
    #[error("Verification error")]
    VerificationError,
    #[error("Invalid public input")]
    InvalidPublicInput,
    #[error("Serialization error")]
    SerializationError,
    #[error("Deserialization error")]
    DeserializationError,
    #[error("Invalid instruction data")]
    InvalidInstructionData,
    #[error("Arithmetic error")]
    ArithmeticError,
    #[error("Pairing error")]
    PairingError,
    #[error("Invalid input")]
    InvalidInput,
    #[error("Borsh serialization error")]
    BorshSerializeError,
    #[error("Borsh deserialization error")]
    BorshDeserializeError,
    #[error("IO error")]
    IoError,
    #[error("Groth16 vkey hash mismatch")]
    Groth16VkeyHashMismatch,
    #[error("Invalid program vkey hash")]
    InvalidProgramVkeyHash,
}

const SCALAR_LEN: usize = 32;
const G1_LEN: usize = 64;
const G2_LEN: usize = 128;

/// Everything needed to verify a Groth16 proof.
#[allow(dead_code)]
pub struct Verifier<'a, const N_PUBLIC: usize> {
    /// The proof to verify.
    proof: &'a Proof,
    /// The public inputs to the proof.
    public: &'a PublicInputs<N_PUBLIC>,
    /// The verification key.
    vk: &'a VerificationKey,
}

/// A Groth16 proof.
///
/// All Group elements are represented in uncompressed form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    pub pi_a: [u8; 64],
    pub pi_b: [u8; 128],
    pub pi_c: [u8; 64],
}

/// A generic Groth16 verification key over BN254.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationKey {
    pub nr_pubinputs: u32,
    pub vk_alpha_g1: [u8; G1_LEN],
    pub vk_beta_g2: [u8; G2_LEN],
    pub vk_gamma_g2: [u8; G2_LEN],
    pub vk_delta_g2: [u8; G2_LEN],
    pub vk_ic: Vec<[u8; G1_LEN]>,
}

/// The public inputs for a Groth16 proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicInputs<const N: usize> {
    pub inputs: [[u8; SCALAR_LEN]; N],
}

/// Convert the endianness of a byte array, chunk by chunk.
///
/// Taken from https://github.com/anza-xyz/agave/blob/c54d840/curves/bn254/src/compression.rs#L176-L189
fn convert_endianness<const CHUNK_SIZE: usize, const ARRAY_SIZE: usize>(
    bytes: &[u8; ARRAY_SIZE],
) -> [u8; ARRAY_SIZE] {
    let reversed: [_; ARRAY_SIZE] = bytes
        .chunks_exact(CHUNK_SIZE)
        .flat_map(|chunk| chunk.iter().rev().copied())
        .enumerate()
        .fold([0u8; ARRAY_SIZE], |mut acc, (i, v)| {
            acc[i] = v;
            acc
        });
    reversed
}

fn decompress_g1(g1_bytes: &[u8; 32]) -> Result<[u8; 64], Error> {
    let g1_bytes = gnark_compressed_x_to_ark_compressed_x(g1_bytes)?;
    let g1_bytes = convert_endianness::<32, 32>(&g1_bytes.as_slice().try_into().unwrap());
    groth16_solana::decompression::decompress_g1(&g1_bytes).map_err(|_| Error::G1CompressionError)
}

fn decompress_g2(g2_bytes: &[u8; 64]) -> Result<[u8; 128], Error> {
    let g2_bytes = gnark_compressed_x_to_ark_compressed_x(g2_bytes)?;
    let g2_bytes = convert_endianness::<64, 64>(&g2_bytes.as_slice().try_into().unwrap());
    groth16_solana::decompression::decompress_g2(&g2_bytes).map_err(|_| Error::G2CompressionError)
}

const GNARK_MASK: u8 = 0b11 << 6;
const GNARK_COMPRESSED_POSITIVE: u8 = 0b10 << 6;
const GNARK_COMPRESSED_NEGATIVE: u8 = 0b11 << 6;
const GNARK_COMPRESSED_INFINITY: u8 = 0b01 << 6;

const ARK_MASK: u8 = 0b11 << 6;
const ARK_COMPRESSED_POSITIVE: u8 = 0b00 << 6;
const ARK_COMPRESSED_NEGATIVE: u8 = 0b10 << 6;
const ARK_COMPRESSED_INFINITY: u8 = 0b01 << 6;

fn gnark_flag_to_ark_flag(msb: u8) -> Result<u8, Error> {
    let gnark_flag = msb & GNARK_MASK;

    let ark_flag = match gnark_flag {
        GNARK_COMPRESSED_POSITIVE => ARK_COMPRESSED_POSITIVE,
        GNARK_COMPRESSED_NEGATIVE => ARK_COMPRESSED_NEGATIVE,
        GNARK_COMPRESSED_INFINITY => ARK_COMPRESSED_INFINITY,
        _ => {
            return Err(Error::InvalidInput);
        }
    };

    Ok(msb & !ARK_MASK | ark_flag)
}

fn gnark_compressed_x_to_ark_compressed_x(x: &[u8]) -> Result<Vec<u8>, Error> {
    if x.len() != 32 && x.len() != 64 {
        return Err(Error::InvalidInput);
    }
    let mut x_copy = x.to_owned();

    let msb = gnark_flag_to_ark_flag(x_copy[0])?;
    x_copy[0] = msb;

    x_copy.reverse();
    Ok(x_copy)
}

fn uncompressed_bytes_to_g1_point(buf: &[u8]) -> Result<G1Affine, Error> {
    if buf.len() != 64 {
        return Err(Error::InvalidInput);
    };

    let (x_bytes, y_bytes) = buf.split_at(32);

    let x = Fq::from_be_bytes_mod_order(x_bytes);
    let y = Fq::from_be_bytes_mod_order(y_bytes);

    Ok(G1Affine::new_unchecked(x, y))
}

fn negate_g1(g1_bytes: &[u8; 64]) -> Result<[u8; 64], Error> {
    let g1 = -uncompressed_bytes_to_g1_point(g1_bytes)?;
    let mut g1_bytes = [0u8; 64];
    g1.serialize_uncompressed(&mut g1_bytes[..])
        .map_err(|_| Error::G1CompressionError)?;
    Ok(convert_endianness::<32, 64>(
        &g1_bytes.as_slice().try_into().unwrap(),
    ))
}

pub(crate) fn load_proof_from_bytes(buffer: &[u8]) -> Result<Proof, Error> {
    Ok(Proof {
        pi_a: negate_g1(
            &buffer[..64]
                .try_into()
                .map_err(|_| Error::G1CompressionError)?,
        )?,
        pi_b: buffer[64..192]
            .try_into()
            .map_err(|_| Error::G2CompressionError)?,
        pi_c: buffer[192..256]
            .try_into()
            .map_err(|_| Error::G1CompressionError)?,
    })
}
pub(crate) fn load_groth16_verifying_key_from_bytes(
    buffer: &[u8],
) -> Result<VerificationKey, Error> {
    // Note that g1_beta and g1_delta are not used in the verification process.
    let g1_alpha = decompress_g1(buffer[..32].try_into().unwrap())?;
    let g2_beta = decompress_g2(buffer[64..128].try_into().unwrap())?;
    let g2_gamma = decompress_g2(buffer[128..192].try_into().unwrap())?;
    let g2_delta = decompress_g2(buffer[224..288].try_into().unwrap())?;

    let num_k = u32::from_be_bytes([buffer[288], buffer[289], buffer[290], buffer[291]]);
    let mut k = Vec::new();
    let mut offset = 292;
    for _ in 0..num_k {
        let point = decompress_g1(&buffer[offset..offset + 32].try_into().unwrap())?;
        k.push(point);
        offset += 32;
    }

    let num_of_array_of_public_and_commitment_committed = u32::from_be_bytes([
        buffer[offset],
        buffer[offset + 1],
        buffer[offset + 2],
        buffer[offset + 3],
    ]);
    offset += 4;
    for _ in 0..num_of_array_of_public_and_commitment_committed {
        let num = u32::from_be_bytes([
            buffer[offset],
            buffer[offset + 1],
            buffer[offset + 2],
            buffer[offset + 3],
        ]);
        offset += 4;
        for _ in 0..num {
            offset += 4;
        }
    }

    Ok(VerificationKey {
        vk_alpha_g1: g1_alpha,
        vk_beta_g2: g2_beta,
        vk_gamma_g2: g2_gamma,
        vk_delta_g2: g2_delta,
        vk_ic: k.clone(),
        nr_pubinputs: num_of_array_of_public_and_commitment_committed,
    })
}

pub(crate) fn load_public_inputs_from_bytes(buffer: &[u8]) -> Result<PublicInputs<2>, Error> {
    let mut bytes = [0u8; 64];
    bytes[1..].copy_from_slice(buffer); // vkey_hash is 31 bytes

    Ok(PublicInputs::<2> {
        inputs: [
            bytes[..32].try_into().map_err(|_| Error::InvalidInput)?, // vkey_hash
            bytes[32..].try_into().map_err(|_| Error::InvalidInput)?, // committed_values_digest
        ],
    })
}

/// Hashes the public inputs in the same format as the Groth16 verifier.
pub fn hash_public_inputs(public_inputs: &[u8]) -> [u8; 32] {
    let mut result = Sha256::digest(public_inputs);

    // The Groth16 verifier operates over a 254 bit field (BN254), so we need to zero
    // out the first 3 bits. The same logic happens in the SP1 Ethereum verifier contract.
    result[0] &= 0x1F;

    result.into()
}

/// Formats the sp1 vkey hash and public inputs for use in the Groth16 verifier.
pub fn groth16_public_values(sp1_vkey_hash: &[u8; 32], sp1_public_inputs: &[u8]) -> Vec<u8> {
    let committed_values_digest = hash_public_inputs(sp1_public_inputs);
    [
        sp1_vkey_hash[1..].to_vec(),
        committed_values_digest.to_vec(),
    ]
    .concat()
}

/// Decodes the sp1 vkey hash from the string from bytes32.
pub fn decode_sp1_vkey_hash(sp1_vkey_hash: &str) -> Result<[u8; 32], Error> {
    let bytes = hex::decode(&sp1_vkey_hash[2..]).map_err(|_| Error::InvalidProgramVkeyHash)?;
    bytes.try_into().map_err(|_| Error::InvalidProgramVkeyHash)
}
