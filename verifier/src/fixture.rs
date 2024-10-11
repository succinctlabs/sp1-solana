use std::{
    fs::File,
    io::{BufReader, BufWriter},
    path::Path,
};

use crate::{verify_proof_raw, Error};
use borsh::{BorshDeserialize, BorshSerialize};
use sha2::{Digest, Sha256};

/// The necessary information for a solana program to verify an SP1 Groth16 proof.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct SP1ProofFixture {
    /// The proof is 256 bytes.
    pub proof: [u8; 256],
    /// The first 4 bytes of the Groth16 vkey hash.
    pub groth16_vkey_hash: [u8; 4],
    /// The public inputs of the underlying SP1 program.
    pub sp1_public_inputs: Vec<u8>,
    /// The vkey hash of the underlying SP1 program.
    pub sp1_vkey_hash: [u8; 32],
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
    pub fn commited_values_digest(&self) -> [u8; 32] {
        hash_public_inputs(&self.sp1_public_inputs)
    }

    /// Formats public values for the Groth16 verifier.
    pub fn groth16_public_values(&self) -> Vec<u8> {
        let committed_values_digest = self.commited_values_digest();
        [
            self.sp1_vkey_hash[1..].to_vec(),
            committed_values_digest.to_vec(),
        ]
        .concat()
    }
}

/// Hashes the public inputs in the same format as the Groth16 verifier.
pub fn hash_public_inputs(public_inputs: &[u8]) -> [u8; 32] {
    let mut result = Sha256::digest(public_inputs);

    // Zero out the first 3 bits.
    result[0] = result[0] & 0x1F;

    result.into()
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
    verify_proof_raw(&fixture.proof, &fixture.groth16_public_values(), vk)
}

#[cfg(feature = "sp1-serialize")]
mod sp1_serialize {
    use num_bigint::BigUint;
    use num_traits::Num;
    use sp1_sdk::SP1ProofWithPublicValues;

    use super::SP1ProofFixture;
    /// Convert a SP1ProofWithPublicValues to a SP1ProofFixture.
    impl From<SP1ProofWithPublicValues> for SP1ProofFixture {
        fn from(sp1_proof_with_public_values: SP1ProofWithPublicValues) -> Self {
            let proof = sp1_proof_with_public_values
                .proof
                .try_as_groth_16()
                .expect("Failed to convert proof to Groth16 proof");

            let raw_proof = hex::decode(proof.raw_proof).unwrap();

            // Convert public inputs and vkey hash to bytes.
            let vkey_hash = BigUint::from_str_radix(&proof.public_inputs[0], 10)
                .unwrap()
                .to_bytes_be();

            // To match the standard format, the 31 byte vkey hash is left padded with a 0 byte.
            let mut padded_vkey_hash = vec![0];
            padded_vkey_hash.extend_from_slice(&vkey_hash);
            let vkey_hash = padded_vkey_hash;

            SP1ProofFixture {
                proof: raw_proof[..256].try_into().unwrap(),
                groth16_vkey_hash: proof.groth16_vkey_hash[..4].try_into().unwrap(),
                sp1_public_inputs: sp1_proof_with_public_values.public_values.to_vec(),
                sp1_vkey_hash: vkey_hash.try_into().unwrap(),
            }
        }
    }

    #[cfg(feature = "sp1-serialize")]
    #[test]
    fn test_verify_from_sp1() {
        use crate::{verify_proof_fixture, GROTH16_VK_BYTES};

        // Read the serialized SP1ProofWithPublicValues from the file.
        let sp1_proof_with_public_values_file = "../proofs/fibonacci_proof.bin";
        let sp1_proof_with_public_values =
            SP1ProofWithPublicValues::load(&sp1_proof_with_public_values_file).unwrap();

        let fixture = SP1ProofFixture::from(sp1_proof_with_public_values);

        assert!(verify_proof_fixture(&fixture, &GROTH16_VK_BYTES).is_ok());
    }

    #[cfg(feature = "sp1-serialize")]
    #[test]
    fn test_hash_public_inputs_() {
        use crate::hash_public_inputs;

        // Read the serialized SP1ProofWithPublicValues from the file.
        let sp1_proof_with_public_values_file = "../proofs/fibonacci_proof.bin";
        let sp1_proof_with_public_values =
            SP1ProofWithPublicValues::load(&sp1_proof_with_public_values_file).unwrap();

        let proof = sp1_proof_with_public_values
            .proof
            .try_as_groth_16()
            .expect("Failed to convert proof to Groth16 proof");

        let committed_values_digest = BigUint::from_str_radix(&proof.public_inputs[1], 10)
            .unwrap()
            .to_bytes_be();

        assert_eq!(
            committed_values_digest,
            hash_public_inputs(&sp1_proof_with_public_values.public_values.to_vec())
        );
    }
}
