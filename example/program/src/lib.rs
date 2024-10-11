use borsh::BorshDeserialize;
use solana_program::{account_info::AccountInfo, entrypoint::ProgramResult, pubkey::Pubkey};
use sp1_solana::{hash_public_inputs, verify_proof_fixture, SP1ProofFixture};

#[cfg(not(feature = "no-entrypoint"))]
use solana_program::entrypoint;

#[cfg(not(feature = "no-entrypoint"))]
entrypoint!(process_instruction);

// Derived by running `cargo prove vkey --elf ../../sp1-program/elf/riscv32im-succinct-zkvm-elf`
// TODO:
const FIBONACCI_VKEY_HASH: &str =
    "0083e8e370d7f0d1c463337f76c9a60b62ad7cc54c89329107c92c1e62097872";

pub fn process_instruction(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    // Deserialize the fixture from the instruction data.
    let fixture = SP1ProofFixture::try_from_slice(instruction_data).unwrap();

    // Get the SP1 Groth16 verification key from the `groth16-solana` crate.
    let vk = sp1_solana::GROTH16_VK_BYTES;

    // Verify the proof.
    let result = verify_proof_fixture(&fixture, &vk);
    assert!(result.is_ok());

    // Make sure that we're verifying a fibonacci program.
    assert_eq!(&fixture.vkey_hash(), FIBONACCI_VKEY_HASH);

    if let Some(sp1_public_inputs) = &fixture.sp1_public_inputs {
        let digest = hash_public_inputs(sp1_public_inputs);
        assert_eq!(digest, fixture.commited_values_digest());
    }

    Ok(())
}
