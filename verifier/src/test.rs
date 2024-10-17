use num_bigint::BigUint;
use num_traits::Num;
use sp1_sdk::SP1ProofWithPublicValues;

#[test]
fn test_verify_from_sp1() {
    use crate::{verify_proof, GROTH16_VK_2_0_0_BYTES};

    // Read the serialized SP1ProofWithPublicValues from the file.
    let sp1_proof_with_public_values_file = "../proofs/fibonacci_proof.bin";
    let sp1_proof_with_public_values =
        SP1ProofWithPublicValues::load(&sp1_proof_with_public_values_file).unwrap();

    let proof_bytes = sp1_proof_with_public_values.bytes();
    let sp1_public_inputs = sp1_proof_with_public_values.public_values.to_vec();

    let proof = sp1_proof_with_public_values
        .proof
        .try_as_groth_16()
        .expect("Failed to convert proof to Groth16 proof");

    // Convert vkey hash to bytes.
    let vkey_hash = BigUint::from_str_radix(&proof.public_inputs[0], 10)
        .unwrap()
        .to_bytes_be();

    // To match the standard format, the 31 byte vkey hash is left padded with a 0 byte.
    let mut padded_vkey_hash = vec![0];
    padded_vkey_hash.extend_from_slice(&vkey_hash);
    let vkey_hash = padded_vkey_hash;

    let sp1_vkey_hash = format!("0x{}", hex::encode(vkey_hash));

    assert!(verify_proof(
        &proof_bytes,
        &sp1_public_inputs,
        &sp1_vkey_hash,
        &GROTH16_VK_2_0_0_BYTES
    )
    .is_ok());
}

#[test]
fn test_hash_public_inputs_() {
    use crate::utils::hash_public_inputs;

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

#[test]
fn test_decode_sp1_vkey_hash() {
    use crate::utils::decode_sp1_vkey_hash;

    let sp1_vkey_hash = "0x0054c0e58911dd8b993c6d8f249aa50a2e523114ec4b7ef9dd355c5f6bfbf3ce";
    let decoded_sp1_vkey_hash = decode_sp1_vkey_hash(sp1_vkey_hash).unwrap();
    assert_eq!(
        decoded_sp1_vkey_hash,
        hex_literal::hex!("0054c0e58911dd8b993c6d8f249aa50a2e523114ec4b7ef9dd355c5f6bfbf3ce")
    );
}
