#!/bin/bash

# Set Solana configuration
solana config set -ul

# Build the Solana program
cargo build-sbf --manifest-path=./program/Cargo.toml --sbf-out-dir=./program/target/so

# Deploy the Solana program
solana program deploy ./program/target/so/example_solana_contract.so

echo "Solana program build and deployment completed."