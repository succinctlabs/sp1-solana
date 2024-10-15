use clap::Parser;
use fibonacci_verifier_contract::SP1Groth16Proof;
use solana_program_test::{processor, ProgramTest};
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signer::Signer,
    transaction::Transaction,
};
use sp1_sdk::{utils, ProverClient, SP1ProofWithPublicValues, SP1Stdin};

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

async fn run_verify_instruction(groth16_proof: SP1Groth16Proof) {
    let program_id = Pubkey::new_unique();

    // Create program test environment
    let (banks_client, payer, recent_blockhash) = ProgramTest::new(
        "fibonacci-verifier-contract",
        program_id,
        processor!(fibonacci_verifier_contract::process_instruction),
    )
    .start()
    .await;

    let instruction = Instruction::new_with_borsh(
        program_id,
        &groth16_proof,
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
        let (pk, _vk) = client.setup(ELF);

        // In our SP1 program, compute the 20th fibonacci number.
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

    // Load the proof from the file, and extract the proof, public inputs, and program vkey hash.
    let sp1_proof_with_public_values = SP1ProofWithPublicValues::load(&proof_file).unwrap();

    let groth16_proof = SP1Groth16Proof {
        proof: sp1_proof_with_public_values.bytes(),
        sp1_public_inputs: sp1_proof_with_public_values.public_values.to_vec(),
    };

    // Run the example instruction in a test environment
    run_verify_instruction(groth16_proof).await;
}
