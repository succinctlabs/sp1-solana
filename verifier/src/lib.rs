use ark_bn254::{Fq, Fq2, G2Affine};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use borsh::BorshSerialize;
use solana_bn254::compression::prelude::{
    alt_bn128_g1_decompress, alt_bn128_g2_decompress, convert_endianness,
};
use solana_bn254::prelude::{alt_bn128_addition, alt_bn128_multiplication, alt_bn128_pairing};
use solana_program::entrypoint::ProgramResult;
use solana_program::program_error::ProgramError;
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
}

const SCALAR_LEN: usize = 32;
const G1_LEN: usize = 64;
const G2_LEN: usize = 128;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicInputs<const N: usize> {
    pub inputs: [[u8; SCALAR_LEN]; N],
}

pub fn decompress_g1(g1_bytes: &[u8; 32]) -> Result<[u8; 64], Error> {
    println!("g1 bytes: {:?}", g1_bytes);
    let g1_bytes = gnark_commpressed_x_to_ark_commpressed_x(&g1_bytes.to_vec())?;
    let g1_bytes = convert_endianness::<32, 32>(&g1_bytes.as_slice().try_into().unwrap());
    alt_bn128_g1_decompress(&g1_bytes).map_err(|_| Error::G1CompressionError)
}

pub fn decompress_g2(g2_bytes: &[u8; 64]) -> Result<[u8; 128], Error> {
    let g2_bytes = gnark_commpressed_x_to_ark_commpressed_x(&g2_bytes.to_vec())?;
    let g2_bytes = convert_endianness::<64, 64>(&g2_bytes.as_slice().try_into().unwrap());
    alt_bn128_g2_decompress(&g2_bytes).map_err(|_| Error::G2CompressionError)
}

impl From<Error> for ProgramError {
    fn from(error: Error) -> Self {
        ProgramError::Custom(error as u32)
    }
}

impl<'a, const N_PUBLIC: usize> Verifier<'a, N_PUBLIC> {
    pub fn new(
        proof: &'a Proof,
        public: &'a PublicInputs<N_PUBLIC>,
        vk: &'a VerificationKey,
    ) -> Self {
        Self { proof, public, vk }
    }

    pub fn verify(&self) -> ProgramResult {
        println!("prepared public inputs");
        let prepared_public = self.prepare_public_inputs()?;
        println!("prepared public inputs: {:?}", prepared_public);
        self.perform_pairing(&prepared_public)
    }

    fn prepare_public_inputs(&self) -> Result<[u8; 64], Error> {
        let mut prepared = self.vk.vk_ic[0];
        for (i, input) in self.public.inputs.iter().enumerate() {
            let mul_res =
                alt_bn128_multiplication(&[&self.vk.vk_ic[i + 1][..], &input[..]].concat())
                    .map_err(|_| Error::ArithmeticError)?;
            prepared = alt_bn128_addition(&[&mul_res[..], &prepared[..]].concat())
                .unwrap()
                .try_into()
                .map_err(|_| Error::ArithmeticError)?;
        }
        Ok(prepared)
    }

    fn perform_pairing(&self, prepared_public: &[u8; 64]) -> ProgramResult {
        let pairing_input = [
            self.proof.pi_a.as_slice(),
            self.proof.pi_b.as_slice(),
            prepared_public.as_slice(),
            self.vk.vk_gamma_g2.as_slice(),
            self.proof.pi_c.as_slice(),
            self.vk.vk_delta_g2.as_slice(),
            self.vk.vk_alpha_g1.as_slice(),
            self.vk.vk_beta_g2.as_slice(),
        ]
        .concat();

        let pairing_res = alt_bn128_pairing(&pairing_input).map_err(|_| Error::PairingError)?;

        if pairing_res[31] != 1 {
            return Err(Error::VerificationError.into());
        }

        Ok(())
    }
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

fn gnark_commpressed_x_to_ark_commpressed_x(x: &Vec<u8>) -> Result<Vec<u8>, Error> {
    if x.len() != 32 && x.len() != 64 {
        return Err(Error::InvalidInput);
    }
    let mut x_copy = x.clone();

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

    let x0 = Fq::from_be_bytes_mod_order(&x0_bytes.to_vec());
    let x1 = Fq::from_be_bytes_mod_order(&x1_bytes.to_vec());
    let y0 = Fq::from_be_bytes_mod_order(&y0_bytes.to_vec());
    let y1 = Fq::from_be_bytes_mod_order(&y1_bytes.to_vec());

    Ok(G2Affine::new_unchecked(Fq2::new(x0, x1), Fq2::new(y0, y1)))
}

fn negate_g2(g2_bytes: &[u8; 128]) -> Result<[u8; 128], Error> {
    let mut bytes = [0u8; 128];
    println!("g2 bytes: {:?}", g2_bytes);
    // let g2 = ark_bn254::G2Affine::deserialize_uncompressed_unchecked(&g2_bytes[..]).unwrap();
    let g2 = gnark_uncompressed_bytes_to_g2_point(g2_bytes)?;
    let negated_g2 = -g2;
    negated_g2
        .serialize_uncompressed(&mut bytes[..])
        .map_err(|_| Error::G2CompressionError)?;

    Ok(bytes)
}

pub(crate) fn load_proof_from_bytes(buffer: &[u8]) -> Result<Proof, Error> {
    Ok(Proof {
        pi_a: buffer[..64]
            .try_into()
            .map_err(|_| Error::G1CompressionError)?,
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
    println!("Decompressing g1_alpha from buffer slice...");
    let g1_alpha = decompress_g1(buffer[..32].try_into().unwrap())?;
    println!("Decompressing g2_beta from buffer slice...");
    let g2_beta = decompress_g2(buffer[64..128].try_into().unwrap())?;
    println!("Decompressing g2_gamma from buffer slice...");
    let g2_gamma = decompress_g2(buffer[128..192].try_into().unwrap())?;
    println!("Decompressing g2_delta from buffer slice...");
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
        vk_beta_g2: negate_g2(&g2_beta)?,
        vk_gamma_g2: g2_gamma,
        vk_delta_g2: g2_delta,
        vk_ic: k.clone(),
        nr_pubinputs: num_of_array_of_public_and_commitment_committed,
    })
}

fn load_public_inputs_from_bytes(buffer: &[u8]) -> Result<PublicInputs<2>, Error> {
    let mut bytes = [0u8; 64];
    bytes[1..].copy_from_slice(&buffer); // vkey_hash is 31 bytes
    Ok(PublicInputs::<2> {
        inputs: [
            bytes[..32].try_into().map_err(|_| Error::InvalidInput)?, // vkey_hash
            bytes[32..].try_into().map_err(|_| Error::InvalidInput)?, //  committed_values_digest
        ],
    })
}

pub fn verify_proof(proof: &[u8], public_inputs: &[u8], vk: &[u8]) -> Result<(), ProgramError> {
    println!("public_inputs length: {:?}", public_inputs.len());
    println!("Loading proof from bytes...");
    let proof = load_proof_from_bytes(proof)?;
    println!("Loading verifying key from bytes...");
    let vk = load_groth16_verifying_key_from_bytes(vk)?;
    println!("Loading public inputs from bytes...");
    let public_inputs = load_public_inputs_from_bytes(public_inputs)?;

    println!("Creating verifier...");
    let verifier = Verifier::new(&proof, &public_inputs, &vk);
    println!("Verifying proof...");
    verifier.verify()
}
