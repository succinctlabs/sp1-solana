use clap::Parser;
use fibonacci_verifier_contract::SP1Groth16Proof;
use solana_program_test::{processor, ProgramTest};
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signer::Signer,
    transaction::Transaction,
};
use sp1_sdk::{include_elf, utils, ProverClient, SP1ProofWithPublicValues, SP1Stdin};

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

/// The ELF binary of the SP1 program.
const ELF: &[u8] = include_elf!("fibonacci-program");

/// Invokes the solana program using Solana Program Test.
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

    // Where to save / load the sp1 proof from.
    let proof_file = "../../proofs/fibonacci_proof.bin";

    // Parse command line arguments.
    let args = Cli::parse();

    // Only generate a proof if the prove flag is set.
    if args.prove {
        // Initialize the prover client
        let client = ProverClient::from_env();
        let (pk, vk) = client.setup(ELF);

        println!(
            "Program Verification Key Bytes {:?}",
            sp1_sdk::HashableKey::bytes32(&vk)
        );

        // In our SP1 program, compute the 20th fibonacci number.
        let mut stdin = SP1Stdin::new();
        stdin.write(&20u32);

        // Generate a proof for the fibonacci program.
        let proof = client
            .prove(&pk, &stdin)
            .groth16()
            .run()
            .expect("Groth16 proof generation failed");

        // Save the generated proof to `proof_file`.
        proof.save(proof_file).unwrap();
    }

    // Load the proof from the file, and convert it to a Borsh-serializable `SP1Groth16Proof`.
    let sp1_proof_with_public_values = SP1ProofWithPublicValues::load(proof_file).unwrap();
    let groth16_proof = SP1Groth16Proof {
        proof: sp1_proof_with_public_values.bytes(),
        sp1_public_inputs: sp1_proof_with_public_values.public_values.to_vec(),
    };

    // Send the proof to the contract, and verify it on `solana-program-test`.
    run_verify_instruction(groth16_proof).await;
}
