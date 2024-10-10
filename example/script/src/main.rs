use groth16_solana::{verify_proof_fixture, SP1ProofFixture, GROTH16_VK_BYTES};
use solana_sdk::{pubkey::Pubkey, transaction::Transaction};
use sp1_sdk::{utils, SP1ProofWithPublicValues};

#[tokio::main]
async fn main() {
    // Setup logging for the application.
    utils::setup_logger();

    // Where to save / load the proof from.
    let proof_file = "../../proofs/fibonacci_proof.bin";

    // Load the proof from the file, and convert it to a fixture.
    let sp1_proof_with_public_values = SP1ProofWithPublicValues::load(&proof_file).unwrap();
    let fixture = SP1ProofFixture::from(sp1_proof_with_public_values);
    let fixture_file = "../../proof-fixtures/fibonacci_fixture.bin";
    fixture.save(&fixture_file).unwrap();

    // Verify the proof.
    verify_proof_fixture(&fixture, GROTH16_VK_BYTES).expect("Proof verification failed");

    // Create program test environment
    let program_id = Pubkey::new_unique();
    let (mut banks_client, payer, recent_blockhash) = ProgramTest::new(
        "example-solana-contract",
        program_id,
        processor!(example_solana_contract::process_instruction),
    )
    .start()
    .await;

    // Create and send transaction to create account
    let mut transaction = Transaction::new_with_payer(&[], Some(&payer.pubkey()));
    transaction.sign(&[&payer], recent_blockhash);
    banks_client.process_transaction(transaction).await.unwrap();
}
