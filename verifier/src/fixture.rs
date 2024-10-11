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
    /// The public inputs are 63 bytes.
    pub public_inputs: [u8; 63],
    /// The first 4 bytes of the Groth16 vkey hash.
    pub groth16_vkey_hash: [u8; 4],
    /// The public inputs of the underlying SP1 program.
    pub sp1_public_inputs: Option<Vec<u8>>,
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
        self.public_inputs[31..63].try_into().unwrap()
    }

    /// Retrieves the SP1 vkey hash from the public inputs.
    ///
    /// This is the vkey hash of the underlying SP1 program, not the Groth16 vkey hash.
    pub fn vkey_hash(&self) -> String {
        // Prepend a 0 to the first 31 bytes of the public inputs.
        let mut padded_vkey_hash_bytes = vec![0];
        padded_vkey_hash_bytes.extend_from_slice(&self.public_inputs[0..31]);
        let vkey_hash_bytes = padded_vkey_hash_bytes.as_slice();

        // Convert the vkey hash bytes to a hex string
        hex::encode(vkey_hash_bytes)
    }
}

/// Hashes the public inputs in order to match the groth16 verifier's format
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
    verify_proof_raw(&fixture.proof, &fixture.public_inputs, vk)
}

#[cfg(feature = "sp1-serialize")]
mod sp1_serialize {
    use num_bigint::BigUint;
    use num_traits::Num;
    use sp1_sdk::SP1ProofWithPublicValues;

    use super::SP1ProofFixture;
    /// Convert a SP1ProofWithPublicValues to a SP1ProofFixture.
    impl SP1ProofFixture {
        pub fn from_sp1(
            sp1_proof_with_public_values: SP1ProofWithPublicValues,
            use_public_values: bool,
        ) -> Self {
            let proof = sp1_proof_with_public_values
                .proof
                .try_as_groth_16()
                .expect("Failed to convert proof to Groth16 proof");

            let raw_proof = hex::decode(proof.raw_proof).unwrap();

            // Convert public inputs and vkey hash to bytes.
            let vkey_hash = BigUint::from_str_radix(&proof.public_inputs[0], 10)
                .unwrap()
                .to_bytes_be();

            let committed_values_digest = BigUint::from_str_radix(&proof.public_inputs[1], 10)
                .unwrap()
                .to_bytes_be();

            let public_inputs = [vkey_hash.to_vec(), committed_values_digest.to_vec()].concat();

            let raw_public_values = if use_public_values {
                Some(sp1_proof_with_public_values.public_values.to_vec()) // TODO: get rid of this clone
            } else {
                None
            };

            SP1ProofFixture {
                proof: raw_proof[..256].try_into().unwrap(),
                public_inputs: public_inputs.try_into().unwrap(),
                groth16_vkey_hash: proof.groth16_vkey_hash[..4].try_into().unwrap(),
                sp1_public_inputs: raw_public_values,
            }
        }
    }

    #[cfg(feature = "sp1-serialize")]
    #[test]
    fn test_public_inputs() {
        use crate::hash_public_inputs;
        use std::str::FromStr;

        // Read the serialized SP1ProofWithPublicValues from the file.
        let sp1_proof_with_public_values_file = "../proofs/fibonacci_proof.bin";
        let sp1_proof_with_public_values =
            SP1ProofWithPublicValues::load(&sp1_proof_with_public_values_file).unwrap();

        let groth16_proof = sp1_proof_with_public_values
            .clone()
            .proof
            .try_as_groth_16()
            .unwrap();

        // Convert vkey_hash from base 10 to hex using the hex crate.
        let vkey_hash = &groth16_proof.public_inputs[0];
        let vkey_hash_biguint = BigUint::from_str(vkey_hash).unwrap();
        let mut vkey_hash_bytes = vec![0];
        vkey_hash_bytes.extend_from_slice(&vkey_hash_biguint.to_bytes_be());
        let vkey_hash_hex = hex::encode(vkey_hash_bytes);

        // let commited_values_digest: &String = &groth16_proof.public_inputs[1];

        // Convert the SP1ProofWithPublicValues to a SP1ProofFixture.
        let fixture = SP1ProofFixture::from_sp1(sp1_proof_with_public_values, false);

        // Verify the public inputs.
        assert_eq!(
            &fixture.commited_values_digest(),
            &hash_public_inputs(fixture.sp1_public_inputs.as_ref().unwrap())
        );

        // Verify the vkey hash.
        assert_eq!(fixture.vkey_hash(), vkey_hash_hex);
    }
}
