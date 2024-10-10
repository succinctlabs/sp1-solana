use clap::Parser;
use sp1_sdk::{utils, HashableKey, ProverClient, SP1ProofWithPublicValues, SP1Stdin};
use sp1_solana::{verify_proof_fixture, SP1ProofFixture, GROTH16_VK_BYTES};

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

fn main() {
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
        let (pk, vk) = client.setup(ELF);

        println!("vkey hash: {:?}", vk.bytes32());

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

    // Verify the proof.
    verify_proof_fixture(&fixture, GROTH16_VK_BYTES).expect("Proof verification failed");
    println!("Successfully verified proof for the program!")
}
