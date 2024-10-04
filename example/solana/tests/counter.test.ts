import { describe, test } from 'node:test';
// import { Transaction, type TransactionInstruction } from '@solana/web3.js';
import { PublicKey, Transaction, TransactionInstruction } from '@solana/web3.js';

import { assert } from 'chai';
import { start } from 'solana-bankrun';
import { PROGRAM_ID, createVerifyInstruction} from '../ts';

describe('Verify Groth16 Solana Native', async () => {
  // Randomly generate the program keypair and load the program to solana-bankrun
  const context = await start([{ name: 'example_solana_contract', programId: PROGRAM_ID }], []);
  const client = context.banksClient;
  // Get the payer keypair from the context, this will be used to sign transactions with enough lamports
  const payer = context.payer;

  test('Test verify tx', async () => {
    const verifyIx: TransactionInstruction = createVerifyInstruction(payer.publicKey, '../binaries/fibonacci_fixture.bin');
    const tx = new Transaction()
    const blockhash = context.lastBlockhash;
    // Import ComputeBudgetProgram
    const { ComputeBudgetProgram } = require('@solana/web3.js');

    // Request a higher compute budget (e.g., 1,000,000 units)
    const setComputeUnitLimitIx = ComputeBudgetProgram.setComputeUnitLimit({
      units: 1_000_000,
    });

    // Add the compute budget instructions to the transaction before the main instruction
    tx.add(setComputeUnitLimitIx);
    tx.add(verifyIx);
    tx.recentBlockhash = blockhash;

    // Sign the transaction with the payer's keypair
    tx.sign(payer);

    // Send transaction to bankrun
    await client.processTransaction(tx);
  });
});
