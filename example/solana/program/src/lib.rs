use borsh::BorshDeserialize;
use groth16_solana::{verify_proof, SP1ProofFixture};
use solana_program::{
    account_info::AccountInfo, declare_id, entrypoint::ProgramResult, msg, pubkey::Pubkey,
};

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

#[cfg(not(feature = "no-entrypoint"))]
use solana_program::entrypoint;

#[cfg(not(feature = "no-entrypoint"))]
entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Pubkey,
    _accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    msg!("Program ID: {}", program_id);
    let fixture = SP1ProofFixture::try_from_slice(instruction_data).unwrap();
    let vk = groth16_solana::GROTH16_VK_BYTES;
    verify_proof(&fixture.proof, &fixture.public_inputs, &vk).unwrap();
    Ok(())
}
