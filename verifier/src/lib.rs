use ark_bn254::{Fq, Fq2, G1Affine, G2Affine};
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use borsh::{BorshDeserialize, BorshSerialize};
use groth16_solana::groth16::Groth16Verifyingkey;
use thiserror::Error;

#[cfg(feature = "sp1-serialize")]
use num_bigint::BigUint;
#[cfg(feature = "sp1-serialize")]
use num_traits::Num;
#[cfg(feature = "sp1-serialize")]
use sp1_sdk::SP1ProofWithPublicValues;

pub fn convert_endianness<const CHUNK_SIZE: usize, const ARRAY_SIZE: usize>(
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
}

const SCALAR_LEN: usize = 32;
const G1_LEN: usize = 64;
const G2_LEN: usize = 128;

#[allow(dead_code)]
pub struct Verifier<'a, const N_PUBLIC: usize> {
    proof: &'a Proof,
    public: &'a PublicInputs<N_PUBLIC>,
    vk: &'a VerificationKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    pub pi_a: [u8; 64],
    pub pi_b: [u8; 128],
    pub pi_c: [u8; 64],
}

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
#[derive(BorshSerialize, BorshDeserialize)]
pub struct SP1ProofFixture {
    pub proof: Vec<u8>,
    pub public_inputs: Vec<u8>,
}

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
            proof: raw_proof,
            public_inputs,
        }
    }
}

pub fn decompress_g1(g1_bytes: &[u8; 32]) -> Result<[u8; 64], Error> {
    let g1_bytes = gnark_compressed_x_to_ark_compressed_x(g1_bytes)?;
    let g1_bytes = convert_endianness::<32, 32>(&g1_bytes.as_slice().try_into().unwrap());
    groth16_solana::decompression::decompress_g1(&g1_bytes).map_err(|_| Error::G1CompressionError)
}

pub fn decompress_g2(g2_bytes: &[u8; 64]) -> Result<[u8; 128], Error> {
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

pub fn gnark_uncompressed_bytes_to_g2_point(buf: &[u8]) -> Result<G2Affine, Error> {
    if buf.len() != 128 {
        return Err(Error::InvalidInput);
    };

    let (x_bytes, y_bytes) = buf.split_at(64);
    let (x0_bytes, x1_bytes) = x_bytes.split_at(32);
    let (y0_bytes, y1_bytes) = y_bytes.split_at(32);

    let x0 = Fq::from_be_bytes_mod_order(x0_bytes);
    let x1 = Fq::from_be_bytes_mod_order(x1_bytes);
    let y0 = Fq::from_be_bytes_mod_order(y0_bytes);
    let y1 = Fq::from_be_bytes_mod_order(y1_bytes);

    Ok(G2Affine::new_unchecked(Fq2::new(x0, x1), Fq2::new(y0, y1)))
}

pub(crate) fn uncompressed_bytes_to_g1_point(buf: &[u8]) -> Result<G1Affine, Error> {
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

fn load_public_inputs_from_bytes(buffer: &[u8]) -> Result<PublicInputs<2>, Error> {
    let mut bytes = [0u8; 64];
    bytes[1..].copy_from_slice(buffer); // vkey_hash is 31 bytes

    Ok(PublicInputs::<2> {
        inputs: [
            bytes[..32].try_into().map_err(|_| Error::InvalidInput)?, // vkey_hash
            bytes[32..].try_into().map_err(|_| Error::InvalidInput)?, //  committed_values_digest
        ],
    })
}

/// Verify a proof using raw bytes.
pub fn verify_proof_raw(proof: &[u8], public_inputs: &[u8], vk: &[u8]) -> Result<(), Error> {
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

/// Verify a proof using a SP1ProofFixture.
#[inline]
pub fn verify_proof_fixture(fixture: &SP1ProofFixture, vk: &[u8]) -> Result<(), Error> {
    verify_proof_raw(&fixture.proof, &fixture.public_inputs, vk)
}
