import { describe, test } from 'node:test';
import { PublicKey, Transaction, TransactionInstruction } from '@solana/web3.js';
import { start } from 'solana-bankrun';
import chai from 'chai';
import chaiAsPromised from 'chai-as-promised';
chai.use(chaiAsPromised);

const expect = chai.expect;
const PROGRAM_ID = PublicKey.unique();

// Helper function to read the proof fixture from the provided path
function createVerifyInstruction(pubkey: PublicKey, proof_path: string): TransactionInstruction {
  const fs = require('fs');
  const data = fs.readFileSync(proof_path);
  return new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [{ pubkey: pubkey, isSigner: true, isWritable: true }],
    data: data,
  });
}

describe('Verify Groth16 Solana', async () => {
  const context = await start([{ name: 'example_solana_contract', programId: PROGRAM_ID }], []);
  const client = context.banksClient;
  const payer = context.payer;

  // Tests that a valid proof will verify successfully.
  test('Test Verify Honest Proof Success', async () => {
    // Initialize transaction. 
    const tx = new Transaction()

    // Import ComputeBudgetProgram.
    const { ComputeBudgetProgram } = require('@solana/web3.js');

    // Request a higher compute budget. 
    const setComputeUnitLimitIx = ComputeBudgetProgram.setComputeUnitLimit({
      units: 1_000_000,
    });

    // Add the compute budget instructions to the transaction before the main instruction.
    tx.add(setComputeUnitLimitIx);

    // Set up and add the verify instruction to the transaction.
    const verifyIx: TransactionInstruction = createVerifyInstruction(payer.publicKey, '../../proof-fixtures/fibonacci_fixture.bin');
    tx.add(verifyIx);

    // Set the blockhash. 
    const blockhash = context.lastBlockhash;
    tx.recentBlockhash = blockhash;

    // Sign the transaction with the payer's keypair.
    tx.sign(payer);

    // Send transaction to bankrun.
    await client.processTransaction(tx);
  });

  // Tests that an invalid proof will fail to verify.
  test('Test Verify Malicious Proof Failure', async () => {
    // Initialize transaction. 
    const tx = new Transaction()

    // Import ComputeBudgetProgram.
    const { ComputeBudgetProgram } = require('@solana/web3.js');

    // Request a higher compute budget. 
    const setComputeUnitLimitIx = ComputeBudgetProgram.setComputeUnitLimit({
      units: 1_000_000,
    });

    // Add the compute budget instructions to the transaction before the main instruction.
    tx.add(setComputeUnitLimitIx);

    // Set up and add the verify instruction to the transaction.
    const verifyIx: TransactionInstruction = createVerifyInstruction(payer.publicKey, '../../proof-fixtures/fibonacci_fixture_bad.bin');
    tx.add(verifyIx);

    // Set the blockhash. 
    const blockhash = context.lastBlockhash;
    tx.recentBlockhash = blockhash;

    // Sign the transaction with the payer's keypair.
    tx.sign(payer);

    // Send transaction to bankrun.
    await expect(client.processTransaction(tx)).to.be.rejected;
  });
});
