use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use borsh::BorshSerialize;
use solana_bn254::compression::prelude::{alt_bn128_g1_decompress, alt_bn128_g2_decompress};
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
    alt_bn128_g1_decompress(g1_bytes).map_err(|_| Error::G1CompressionError)
}

pub fn decompress_g2(g2_bytes: &[u8; 64]) -> Result<[u8; 128], Error> {
    alt_bn128_g2_decompress(g2_bytes).map_err(|_| Error::G2CompressionError)
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
        let prepared_public = self.prepare_public_inputs()?;
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

fn negate_g2(g2_bytes: &[u8; 128]) -> Result<[u8; 128], Error> {
    let mut bytes = [0u8; 128];
    let g2 = ark_bn254::G2Affine::deserialize_uncompressed(&g2_bytes[..]).unwrap();
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
        vk_beta_g2: negate_g2(&g2_beta)?,
        vk_gamma_g2: g2_gamma,
        vk_delta_g2: g2_delta,
        vk_ic: k.clone(),
        nr_pubinputs: num_of_array_of_public_and_commitment_committed,
    })
}

fn load_public_inputs_from_bytes(buffer: &[u8]) -> Result<PublicInputs<2>, Error> {
    Ok(PublicInputs::<2> {
        inputs: [
            buffer[..32].try_into().map_err(|_| Error::InvalidInput)?, // vkey_hash
            buffer[32..64].try_into().map_err(|_| Error::InvalidInput)?, //  committed_values_digest
        ],
    })
}

pub fn verify_proof(proof: &[u8], public_inputs: &[u8], vk: &[u8]) -> Result<(), ProgramError> {
    let proof = load_proof_from_bytes(proof)?;
    let vk = load_groth16_verifying_key_from_bytes(vk)?;
    let public_inputs = load_public_inputs_from_bytes(public_inputs)?;

    let verifier = Verifier::new(&proof, &public_inputs, &vk);
    verifier.verify()
}
