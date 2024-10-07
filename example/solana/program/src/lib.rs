use borsh::BorshDeserialize;
use groth16_solana::{verify_proof_fixture, SP1ProofFixture};
use solana_program::{
    account_info::AccountInfo, declare_id, entrypoint::ProgramResult, msg, pubkey::Pubkey,
};

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

#[cfg(not(feature = "no-entrypoint"))]
use solana_program::entrypoint;

#[cfg(not(feature = "no-entrypoint"))]
entrypoint!(process_instruction);

pub fn process_instruction(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let fixture = SP1ProofFixture::try_from_slice(instruction_data).unwrap();
    let vk = groth16_solana::GROTH16_VK_BYTES;
    let result = verify_proof_fixture(&fixture, &vk);
    msg!("Result: {:?}", result);
    Ok(())
}
