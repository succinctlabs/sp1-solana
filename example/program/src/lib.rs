use borsh::BorshDeserialize;
use solana_program::{account_info::AccountInfo, entrypoint::ProgramResult, msg, pubkey::Pubkey};
use sp1_solana::{verify_proof_fixture, SP1ProofFixture};

#[cfg(not(feature = "no-entrypoint"))]
use solana_program::entrypoint;

#[cfg(not(feature = "no-entrypoint"))]
entrypoint!(process_instruction);

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
    msg!("Result: {:?}", result);
    assert!(result.is_ok());
    Ok(())
}
