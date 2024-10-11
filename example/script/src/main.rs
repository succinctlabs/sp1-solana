use clap::Parser;
use solana_program_test::{processor, ProgramTest};
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signer::Signer,
    transaction::Transaction,
};
use sp1_sdk::{utils, ProverClient, SP1ProofWithPublicValues, SP1Stdin};
use sp1_solana::SP1ProofFixture;

#[derive(clap::Parser)]
#[command(name = "zkVM Proof Generator")]
struct Cli {
    #[arg(
        long,
        value_name = "prove",
        default_value = "false",
        help = "Specifies whether to generate a proof for the program."
    )]
    prove: bool,
}

const ELF: &[u8] = include_bytes!("../../sp1-program/elf/riscv32im-succinct-zkvm-elf");

async fn run_example_instruction(fixture: SP1ProofFixture) {
    let program_id = Pubkey::new_unique();

    // Create program test environment
    let (banks_client, payer, recent_blockhash) = ProgramTest::new(
        "example-solana-contract",
        program_id,
        processor!(example_solana_contract::process_instruction),
    )
    .start()
    .await;

    let instruction = Instruction::new_with_borsh(
        program_id,
        &fixture,
        vec![AccountMeta::new(payer.pubkey(), false)],
    );

    // Create and send transaction
    let mut transaction = Transaction::new_with_payer(&[instruction], Some(&payer.pubkey()));
    transaction.sign(&[&payer], recent_blockhash);
    banks_client.process_transaction(transaction).await.unwrap();
}

#[tokio::main]
async fn main() {
    // Setup logging for the application.
    utils::setup_logger();

    // Where to save / load the proof from.
    let proof_file = "../../proofs/fibonacci_proof.bin";

    // Parse command line arguments.
    let args = Cli::parse();

    // Only generate a proof if the prove flag is set.
    if args.prove {
        // Initialize the prover client
        let client = ProverClient::new();
        let (pk, _) = client.setup(ELF);

        // Compute the 20th fibonacci number.
        let mut stdin = SP1Stdin::new();
        stdin.write(&20u32);

        // Generate a proof for the fibonacci program.
        let proof = client
            .prove(&pk, stdin)
            .groth16()
            .run()
            .expect("Groth16 proof generation failed");

        // Save the generated proof to `proof_file`.
        proof.save(&proof_file).unwrap();
    }

    // Load the proof from the file, and convert it to a fixture.
    let sp1_proof_with_public_values = SP1ProofWithPublicValues::load(&proof_file).unwrap();
    let fixture = SP1ProofFixture::from(sp1_proof_with_public_values);
    let fixture_file = "../../proof-fixtures/fibonacci_fixture.bin";
    fixture.save(&fixture_file).unwrap();

    run_example_instruction(fixture).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_honest_proof_succeeds() {
        let fixture_file = "../../proof-fixtures/fibonacci_fixture.bin";
        let fixture = SP1ProofFixture::load(&fixture_file).unwrap();

        run_example_instruction(fixture).await;
    }

    #[tokio::test]
    #[should_panic]
    async fn test_malicious_proof_fails() {
        let fixture_file = "../../proof-fixtures/fibonacci_fixture_bad.bin";
        let fixture = SP1ProofFixture::load(&fixture_file).unwrap();

        run_example_instruction(fixture).await;
    }
}
