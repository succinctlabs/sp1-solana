import { type PublicKey, TransactionInstruction } from '@solana/web3.js';
import { PROGRAM_ID } from '../';

export function createVerifyInstruction(pubkey: PublicKey, proof_path: string): TransactionInstruction {
  const fs = require('fs');
  const data = fs.readFileSync(proof_path);
  return new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [{ pubkey: pubkey, isSigner: true, isWritable: true }],
    data: data,
  });

}
