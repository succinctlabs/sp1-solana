# `sp1-solana`

This crate verifies Groth16 proofs generated with SP1, leveraging Solana's BN254 precompiles for efficient cryptographic operations.

> [!CAUTION]
>
> This repository is under active development and is not yet ready for production use.

## Repository Overview

The `sp1-solana` library itself is in the [`verifier`](verifier) directory. `example/program` contains an example Solana program that uses this library to verify SP1 proofs, and `example/script` contains an example Solana script that invokes this program. See the [example README](example/README.md) for more information.

## Features

- **Groth16 Proof Verification**: Implements the Groth16 protocol for zero-knowledge proof verification.
- **Solana BN254 Precompiles**: Leverages Solana's native BN254 precompiles for optimized performance.
- **Easy Integration**: Seamlessly integrates with existing Solana programs and infrastructure.
- **Extensible**: Built with modularity in mind, allowing for future enhancements and integrations.

## Installation

Add `sp1-solana` to your `Cargo.toml`:

```toml
[dependencies]
sp1-solana = { git = "https://github.com/succinctlabs/groth16-solana" }
```

## Acknowledgements
This crate uses the [`groth16-solana`](https://github.com/Lightprotocol/groth16-solana/) crate from Light Protocol Labs for the Groth16 proof verification, and the [`ark-bn254`](https://github.com/arkworks-rs/algebra) crate for the elliptic curve operations.