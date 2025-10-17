# Bitcoin ZK Proof System

A zero-knowledge proof system for Bitcoin block processing that enables Core Lane to verify Bitcoin block data without downloading full blocks.

## 🎯 What This Does

This system generates zero-knowledge proofs that prove:

1. **Block Hash Verification**: The block hash was computed correctly
2. **Merkle Root Verification**: The merkle root was computed correctly
3. **Transaction Filtering**: Only Core Lane relevant transactions (burns, fills, DA posting) were extracted
4. **Merkle Proofs**: Each matching transaction has a valid merkle proof of inclusion

## 🚀 Quick Start

### Prerequisites

- Rust 1.88.0+ (installed via `rzup`)
- Risc0 toolchain (installed via `rzup`)

### Build

```bash
cargo build
```

### Generate a ZK Proof

```bash
# Generate proof for a specific block
cargo run --bin host -- prove --height 100000 --output proof.json

# Generate proof for a recent block (will take longer)
cargo run --bin host -- prove --height 840000 --output recent_proof.json
```

### Verify a Proof

```bash
cargo run --bin host -- verify --proof-file proof.json
```

### Run as Daemon

```bash
# Continuously process new blocks
cargo run --bin host -- daemon --start-height 840000 --output-dir ./proofs
```

## 📊 Performance

- **Small blocks (100k height)**: ~30 seconds
- **Large blocks (840k height)**: ~5-10 minutes
- **Data reduction**: 99%+ (from 1-4MB blocks to ~1-10KB proofs)

## 🏗️ Architecture

### Guest Program (`methods/guest/`)

- Runs inside Risc0 zkVM
- Processes raw Bitcoin blocks
- Filters for Core Lane transactions
- Generates merkle proofs
- Commits results to journal

### Host Program (`host/`)

- Fetches Bitcoin blocks from Blockstream API
- Generates ZK proofs using the guest program
- Verifies proofs
- Saves proofs to files
- Can run as a daemon

## 🔍 Core Lane Transaction Detection

The system detects three types of Core Lane transactions:

### 1. Burn Transactions

- **Pattern**: OP_RETURN with "BRN1" prefix
- **Format**: BRN1 + chain_id(4) + eth_address(20)
- **Purpose**: Burn BTC to mint laneBTC

### 2. Fill Transactions

- **Pattern**: Core Lane fill intents
- **Purpose**: Bitcoin withdrawal requests

### 3. DA Posting Transactions

- **Pattern**: OP_RETURN with "CORE" prefix
- **Purpose**: Data availability posting

## 📁 Output Format

```json
{
  "block_hash": "000000000003ba27aa200b1cecaad478d2b00432346c3f1f3986da1afd33e506",
  "block_height": 100000,
  "merkle_root": "6657a9252aacd5c0b2940996ecff952228c3067cc38d4885efb5a4ac4247e9f3",
  "matching_transactions": [
    {
      "txid": "abc123...",
      "transaction_index": 1,
      "merkle_proof": {
        "path": [...],
        "leaf_index": 1
      },
      "transaction_type": "Burn",
      "data": {
        "amount": 100000,
        "chain_id": 1,
        "eth_address": "0x..."
      }
    }
  ],
  "total_transactions": 4,
  "matching_count": 1
}
```

## 🔧 Integration with Core Lane

This system enables Core Lane to:

1. **Fast Sync**: Download ZK proofs instead of full blocks
2. **Trustless Verification**: Verify block data without trusting a third party
3. **Reduced Bandwidth**: 99%+ reduction in data transfer
4. **Scalable**: Process thousands of blocks efficiently

## 🚧 Current Status

✅ **Completed**:

- ZK proof generation for Bitcoin blocks
- Transaction filtering for Core Lane patterns
- Merkle proof generation
- Proof verification
- CLI interface
- Daemon mode

🔄 **In Progress**:

- Integration with Core Lane bitcoin-cache
- Boundless marketplace integration
- Performance optimization

📋 **TODO**:

- CBOR output format
- Hardware acceleration
- Batch processing
- Error handling improvements

## 🧪 Testing

```bash
# Test with a small block
cargo run --bin host -- prove --height 100000

# Test with a larger block
cargo run --bin host -- prove --height 500000

# Test verification
cargo run --bin host -- verify --proof-file test_proof.json
```

## 📈 Next Steps

1. **Integrate with Core Lane**: Modify bitcoin-cache to fetch ZK proofs
2. **Boundless Integration**: Use Boundless for distributed proof generation
3. **Performance Optimization**: Hardware acceleration and batch processing
4. **Production Deployment**: Scale to handle mainnet Bitcoin blocks

## 🤝 Contributing

This is part of the Core Lane project. See the main Core Lane repository for contribution guidelines.

## 📄 License

All rights reserved for now.
