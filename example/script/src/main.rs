use clap::Parser;
use groth16_solana::{verify_proof_fixture, SP1ProofFixture, GROTH16_VK_BYTES};
use sp1_sdk::{utils, ProverClient, SP1ProofWithPublicValues, SP1Stdin};
use std::str::FromStr;
use strum_macros::{Display, EnumIter, EnumString};

fn main() {
    // Setup logging for the application.
    utils::setup_logger();

    // Parse command line arguments.
    let args = Cli::parse();

    // Where to save / load the proof from.
    let proof_file = "../proofs/fibonacci_proof.bin";

    // Load the proof from the file, and convert it to a fixture.
    let sp1_proof_with_public_values = SP1ProofWithPublicValues::load(&proof_file).unwrap();
    let fixture = SP1ProofFixture::from(sp1_proof_with_public_values);
    let fixture_file = "../proof-fixtures/fibonacci_fixture.bin";
    fixture.save(&fixture_file).unwrap();

    // Verify the proof.
    verify_proof_fixture(&fixture, GROTH16_VK_BYTES).expect("Proof verification failed");
    println!("Successfully verified proof for the program!")
}

#[cfg(test)]
mod tests {
    use super::*;
    use strum::IntoEnumIterator;

    #[test]
    fn test_programs() {
        Elf::iter().for_each(|program| {
            // Read the serialized fixture from the file.
            let fixture_file = format!("../proof-fixtures/{}_fixture.bin", program.to_string());
            let fixture = SP1ProofFixture::load(&fixture_file).unwrap();

            // Verify the proof.
            let result = verify_proof_fixture(&fixture, GROTH16_VK_BYTES);
            assert!(result.is_ok(), "Proof verification failed for {}", program);
        });
    }
}
