use std::{
    fs::File,
    io::{BufReader, BufWriter},
    path::Path,
};

use ark_bn254::{Fq, G1Affine};
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use borsh::{BorshDeserialize, BorshSerialize};
use groth16_solana::groth16::Groth16Verifyingkey;
use num_bigint::BigUint;
use sha2::{Digest, Sha256};
use thiserror::Error;

#[cfg(feature = "sp1-serialize")]
use num_traits::Num;
#[cfg(feature = "sp1-serialize")]
use sp1_sdk::SP1ProofWithPublicValues;

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

pub const GROTH16_VK_BYTES: &[u8] = include_bytes!("../vk/groth16_vk.bin");

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
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize)]
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

/// The necessary information for a solana program to verify an SP1 Groth16 proof.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct SP1ProofFixture {
    /// The proof is 256 bytes.
    pub proof: [u8; 256],
    /// The public inputs are 63 bytes.
    pub public_inputs: [u8; 63],
    /// The first 4 bytes of the Groth16 vkey hash.
    pub groth16_vkey_hash: [u8; 4],
}

impl SP1ProofFixture {
    /// Load a SP1ProofFixture from a file.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, Error> {
        let path = path.as_ref();
        let file = File::open(path).map_err(|_| Error::IoError)?;
        let mut reader = BufReader::new(file);
        let fixture = borsh::from_reader(&mut reader).map_err(|_| Error::BorshDeserializeError)?;
        Ok(fixture)
    }

    /// Save a SP1ProofFixture to a file.
    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), Error> {
        let path = path.as_ref();
        let file = File::create(path).map_err(|_| Error::IoError)?;
        let mut writer = BufWriter::new(file);
        BorshSerialize::serialize(&self, &mut writer).map_err(|_| Error::BorshSerializeError)?;
        Ok(())
    }

    /// Retrieves the SP1 commited values digest from the public inputs.
    pub fn commited_values_digest(&self) -> Result<String, Error> {
        // The committed values digest is the second half of the public inputs
        let digest_bytes = &self.public_inputs[31..63];

        // Convert the digest bytes to a BigUint
        let digest_biguint = BigUint::from_bytes_be(digest_bytes);

        // Convert the BigUint to a decimal string
        let digest_string = digest_biguint.to_str_radix(10);

        Ok(digest_string)
    }

    /// Retrieves the SP1 vkey hash from the public inputs.
    ///
    /// This is the vkey hash of the underlying SP1 program, not the Groth16 vkey hash.
    pub fn vkey_hash(&self) -> Result<String, Error> {
        let vkey_hash_bytes = &self.public_inputs[0..31];

        // Convert the vkey hash bytes to a BigUint
        let vkey_hash_biguint = BigUint::from_bytes_be(vkey_hash_bytes);

        // Convert the BigUint to a decimal string
        let vkey_hash_string = vkey_hash_biguint.to_str_radix(10);

        Ok(vkey_hash_string)
    }
}

/// Convert a SP1ProofWithPublicValues to a SP1ProofFixture.
#[cfg(feature = "sp1-serialize")]
impl From<SP1ProofWithPublicValues> for SP1ProofFixture {
    fn from(sp1_proof_with_public_values: SP1ProofWithPublicValues) -> Self {
        let proof = sp1_proof_with_public_values
            .proof
            .try_as_groth_16()
            .expect("Failed to convert proof to Groth16 proof");

        let raw_proof = hex::decode(proof.raw_proof).unwrap();

        // Convert public inputs to byte representations.
        let vkey_hash = BigUint::from_str_radix(&proof.public_inputs[0], 10)
            .unwrap()
            .to_bytes_be();
        let committed_values_digest = BigUint::from_str_radix(&proof.public_inputs[1], 10)
            .unwrap()
            .to_bytes_be();

        let public_inputs = [vkey_hash.to_vec(), committed_values_digest.to_vec()].concat();

        SP1ProofFixture {
            proof: raw_proof[..256].try_into().unwrap(),
            public_inputs: public_inputs.try_into().unwrap(),
            groth16_vkey_hash: proof.groth16_vkey_hash[..4].try_into().unwrap(),
        }
    }
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
const GNARK_COMPRESSED_POSTIVE: u8 = 0b10 << 6;
const GNARK_COMPRESSED_NEGATIVE: u8 = 0b11 << 6;
const GNARK_COMPRESSED_INFINITY: u8 = 0b01 << 6;

const ARK_MASK: u8 = 0b11 << 6;
const ARK_COMPRESSED_POSTIVE: u8 = 0b00 << 6;
const ARK_COMPRESSED_NEGATIVE: u8 = 0b10 << 6;
const ARK_COMPRESSED_INFINITY: u8 = 0b01 << 6;

fn gnark_flag_to_ark_flag(msb: u8) -> Result<u8, Error> {
    let gnark_flag = msb & GNARK_MASK;

    let ark_flag = match gnark_flag {
        GNARK_COMPRESSED_POSTIVE => ARK_COMPRESSED_POSTIVE,
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

fn load_proof_from_bytes(buffer: &[u8]) -> Result<Proof, Error> {
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

fn load_groth16_verifying_key_from_bytes(buffer: &[u8]) -> Result<VerificationKey, Error> {
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

fn load_public_inputs_from_bytes(buffer: &[u8]) -> Result<PublicInputs<2>, Error> {
    let mut bytes = [0u8; 64];
    bytes[1..].copy_from_slice(buffer); // vkey_hash is 31 bytes

    Ok(PublicInputs::<2> {
        inputs: [
            bytes[..32].try_into().map_err(|_| Error::InvalidInput)?, // vkey_hash
            bytes[32..].try_into().map_err(|_| Error::InvalidInput)?, // committed_values_digest
        ],
    })
}

/// Verify a proof using raw bytes.
///
/// The public inputs are the vkey hash and the commited values digest, concatenated.
/// The proof is a decompressed G1 element, followed by a decompressed G2 element, followed by a
/// decompressed G1 element.
fn verify_proof_raw(proof: &[u8], public_inputs: &[u8], vk: &[u8]) -> Result<(), Error> {
    let proof = load_proof_from_bytes(proof)?;
    let vk = load_groth16_verifying_key_from_bytes(vk)?;
    let public_inputs = load_public_inputs_from_bytes(public_inputs)?;

    let vk = Groth16Verifyingkey {
        nr_pubinputs: vk.nr_pubinputs as usize,
        vk_alpha_g1: vk.vk_alpha_g1,
        vk_beta_g2: vk.vk_beta_g2,
        vk_gamme_g2: vk.vk_gamma_g2,
        vk_delta_g2: vk.vk_delta_g2,
        vk_ic: vk.vk_ic.as_slice(),
    };

    let mut verifier = groth16_solana::groth16::Groth16Verifier::new(
        &proof.pi_a,
        &proof.pi_b,
        &proof.pi_c,
        &public_inputs.inputs,
        &vk,
    )
    .map_err(|_| Error::VerificationError)?;

    if verifier.verify().map_err(|_| Error::VerificationError)? {
        println!("Verification successful.");
        Ok(())
    } else {
        println!("Verification failed.");
        Err(Error::VerificationError)
    }
}

/// Verify a proof using a [`SP1ProofFixture`].
///
/// Checks the Groth16 vkey hash in the fixture against the provided vk.
#[inline]
pub fn verify_proof_fixture(fixture: &SP1ProofFixture, vk: &[u8]) -> Result<(), Error> {
    // Hash the vk and get the first 4 bytes.
    let groth16_vk_hash: [u8; 4] = Sha256::digest(vk)[..4].try_into().unwrap();

    // Compare against the fixture's groth16 vkey hash.
    if groth16_vk_hash != fixture.groth16_vkey_hash {
        return Err(Error::Groth16VkeyHashMismatch);
    }

    // Verify the proof.
    verify_proof_raw(&fixture.proof, &fixture.public_inputs, vk)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_programs() {
        // Read the serialized fixture from the file.
        let fixture_file = "../proof-fixtures/fibonacci_fixture.bin";
        let fixture = SP1ProofFixture::load(&fixture_file).unwrap();

        // Verify the proof.
        let result = verify_proof_fixture(&fixture, GROTH16_VK_BYTES);
        assert!(result.is_ok(), "Proof verification failed for fibonacci");
    }

    #[test]
    fn test_serialize_fixture_roundtrip() {
        // Read the serialized fixture from the file.
        let fixture_file = "../proof-fixtures/fibonacci_fixture.bin";
        let fixture = SP1ProofFixture::load(&fixture_file).unwrap();

        // Serialize the fixture to a new file.
        let serialized_fixture_file = "test_serialized_fixture.bin";
        fixture.save(&serialized_fixture_file).unwrap();

        // Deserialize the fixture from the new file.
        let deserialized_fixture = SP1ProofFixture::load(&serialized_fixture_file).unwrap();

        // Verify the deserialized fixture is equal to the original fixture.
        assert_eq!(
            fixture, deserialized_fixture,
            "Serialized fixture does not match original"
        );
    }

    #[cfg(feature = "sp1-serialize")]
    #[test]
    fn test_public_inputs() {
        // Read the serialized SP1ProofWithPublicValues from the file.
        let sp1_proof_with_public_values_file = "../proofs/fibonacci_proof.bin";
        let sp1_proof_with_public_values =
            SP1ProofWithPublicValues::load(&sp1_proof_with_public_values_file).unwrap();

        let groth16_proof = sp1_proof_with_public_values
            .clone()
            .proof
            .try_as_groth_16()
            .unwrap();

        let vkey_hash = &groth16_proof.public_inputs[0];
        let commited_values_digest = &groth16_proof.public_inputs[1];

        // Convert the SP1ProofWithPublicValues to a SP1ProofFixture.
        let fixture = SP1ProofFixture::from(sp1_proof_with_public_values);

        // Verify the public inputs.
        assert_eq!(
            fixture.commited_values_digest().unwrap(),
            commited_values_digest.to_string()
        );
        assert_eq!(fixture.vkey_hash().unwrap(), vkey_hash.to_string());
    }
}
