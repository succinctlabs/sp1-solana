use std::{
    fs::File,
    io::{BufReader, BufWriter},
    path::Path,
};

use crate::{verify_proof_raw, Error};
use borsh::{BorshDeserialize, BorshSerialize};
use num_bigint::BigUint;
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
    pub fn commited_values_digest(&self) -> String {
        // The committed values digest is the second half of the public inputs
        let digest_bytes = &self.public_inputs[31..63];

        // Convert the digest bytes to a BigUint
        let digest_biguint = BigUint::from_bytes_be(digest_bytes);

        // Convert the BigUint to a decimal string
        let digest_string = digest_biguint.to_str_radix(10);

        digest_string
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

    #[cfg(feature = "sp1-serialize")]
    #[test]
    fn test_public_inputs() {
        // Read the serialized SP1ProofWithPublicValues from the file.

        use std::str::FromStr;
        let sp1_proof_with_public_values_file = "../proofs/fibonacci_proof.bin";
        let sp1_proof_with_public_values =
            SP1ProofWithPublicValues::load(&sp1_proof_with_public_values_file).unwrap();

        let groth16_proof = sp1_proof_with_public_values
            .clone()
            .proof
            .try_as_groth_16()
            .unwrap();

        let vkey_hash = &groth16_proof.public_inputs[0];
        // Convert vkey_hash from base 10 to hex using the hex crate
        let vkey_hash_biguint = BigUint::from_str(vkey_hash).unwrap();
        let mut vkey_hash_bytes = vec![0];
        vkey_hash_bytes.extend_from_slice(&vkey_hash_biguint.to_bytes_be());
        let vkey_hash_hex = hex::encode(vkey_hash_bytes);

        let commited_values_digest = &groth16_proof.public_inputs[1];

        // Convert the SP1ProofWithPublicValues to a SP1ProofFixture.
        let fixture = SP1ProofFixture::from(sp1_proof_with_public_values);

        // Verify the public inputs.
        assert_eq!(
            fixture.commited_values_digest(),
            commited_values_digest.to_string()
        );
        assert_eq!(fixture.vkey_hash(), vkey_hash_hex);
    }
}
