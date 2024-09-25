# Solana Verifier

A Groth16 verifier implementation for Solana using BN254 precompiles. This crate verifies Groth16 proofs generated with SP1, leveraging Solana's BN254 precompiles for efficient cryptographic operations.

## Features

- **Groth16 Proof Verification**: Implements the Groth16 protocol for zero-knowledge proof verification.
- **Solana BN254 Precompiles**: Leverages Solana's native BN254 precompiles for optimized performance.
- **Easy Integration**: Seamlessly integrates with existing Solana programs and infrastructure.
- **Extensible**: Built with modularity in mind, allowing for future enhancements and integrations.

## Installation

Add `solana-verifier` to your `Cargo.toml`:

```toml
[dependencies]
solana-verifier = { git = "https://github.com/0xWOLAND/groth16-verifier" }
```

