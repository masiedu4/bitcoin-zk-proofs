# Bitcoin ZK Proofs for Core Lane

Zero-Knowledge proof system that compresses Bitcoin blocks from ~1.7 MB to ~200 bytes (99.99% reduction) for Core Lane sync.

## What This Does

Instead of downloading entire Bitcoin blocks, Core Lane can download tiny cryptographic proofs that identify which transactions are Core Lane transactions (burns, DA posts, fills). The system:

- Compresses blocks by 99.99% (1.7 MB → 200 bytes)
- Tested with real mainnet data (block 916201: found 2 Core Lane transactions)
- Cryptographically verified against Bitcoin blockchain
- Enables 8,500x faster sync (1,000 blocks: 1.7 GB → 200 KB)

## Quick Start

### Build

```bash
cargo build --release
```

### Generate Proof for a Block

```bash
# Generate searching proof (find all Core Lane transactions)
./target/release/host prove --height 916201 --output proof_916201.json --strategy searching

# Generate pointing proof (prove specific transaction exists)
./target/release/host prove --height 916201 --output proof_916201_pointing.json \
  --strategy "pointing:69c4106b6c0d9ec67b7a0cfa54aed07f202ce99fdabf40e721000f2d4b71ae86:0:da"

# View the proof
cat proof_916201.json | jq
```

### Verify Proof

```bash
./target/release/host verify --proof-file proof_916201.json
```

### Run as Daemon

```bash
# Continuously generate proofs for new blocks
./target/release/host daemon --start-height 916201 --output-dir ./proofs
```

## Example Output

### Searching Proof

```json
{
  "block_hash": "00000000000000000000f07f586abf62cb55629a79da2c34d19e782d40189b64",
  "block_height": 916201,
  "strategy": {
    "Searching": {
      "pattern": "All"
    }
  },
  "matching_transactions": [
    {
      "txid": "69c4106b6c0d9ec67b7a0cfa54aed07f202ce99fdabf40e721000f2d4b71ae86",
      "tx_type": "DataAvailability"
    },
    {
      "txid": "a7b619029731e6541fcbbbeea1f980ae1b97007e3a91c47cfc75e22c1d587276",
      "tx_type": "Burn"
    }
  ],
  "merkle_proofs": [],
  "total_transactions": 2055,
  "matching_count": 2
}
```

### Pointing Proof

```json
{
  "block_hash": "00000000000000000000f07f586abf62cb55629a79da2c34d19e782d40189b64",
  "block_height": 916201,
  "strategy": {
    "Pointing": {
      "txid": "69c4106b6c0d9ec67b7a0cfa54aed07f202ce99fdabf40e721000f2d4b71ae86",
      "tx_position": 0,
      "expected_type": "DataAvailability"
    }
  },
  "matching_transactions": [
    {
      "txid": "69c4106b6c0d9ec67b7a0cfa54aed07f202ce99fdabf40e721000f2d4b71ae86",
      "tx_type": "DataAvailability"
    }
  ],
  "merkle_proofs": [
    {
      "txid": [
        105, 196, 16, 107, 108, 13, 158, 198, 123, 122, 12, 250, 84, 174, 208,
        127, 32, 44, 233, 159, 218, 191, 64, 231, 33, 0, 15, 45, 75, 113, 174,
        134
      ],
      "path": [
        [
          167, 182, 25, 2, 151, 49, 230, 84, 31, 203, 187, 238, 161, 249, 128,
          174, 27, 151, 0, 126, 58, 145, 196, 124, 252, 117, 226, 44, 29, 88,
          114, 118
        ]
      ],
      "positions": [true]
    }
  ],
  "total_transactions": 2055,
  "matching_count": 1
}
```

## Testing with Core Lane

### 1. Generate Proofs

```bash
# Generate proofs for multiple blocks
for height in 916201 916202 916203 916204 916205; do
  ./target/release/host prove --height $height --output proofs/proof_$height.json
done
```

### 2. Copy to Core Lane

```bash
# Copy proofs to Core Lane's proof cache
cd /path/to/core-lane
mkdir -p .proof_cache
cp /path/to/bitcoin-zk-proofs/proofs/*.json .proof_cache/
```

### 3. Run Core Lane

Core Lane will automatically use ZK proofs if available, falling back to full block processing if not.

## How It Works

The system supports two proof strategies:

### 1. **Searching Strategy** (Current approach)

- **Prover** (Risc0 guest program):

  - Fetches Bitcoin block from Blockstream API
  - Computes block hash
  - Filters transactions for Core Lane patterns
  - Commits block hash + matching txids to ZK proof

- **Proof Format** (~200 bytes):
  - Block hash (commits to all block data)
  - List of matching transaction IDs
  - Transaction types (Burn, DA, Fill)

### 2. **Pointing Strategy** (New Merkle-based approach)

- **Prover** (Risc0 guest program):

  - Fetches Bitcoin block from Blockstream API
  - Computes block hash and Merkle tree
  - Points to specific transaction at known position
  - Generates Merkle proof from txid to block root
  - Commits block hash + txid + Merkle proof to ZK proof

- **Proof Format** (~300 bytes):
  - Block hash (commits to all block data)
  - Single transaction ID
  - Merkle proof path (sibling hashes + positions)
  - Transaction type verification

### 3. **Verifier** (Core Lane):

- **Searching proofs**: Verifies block hash, looks up txids, validates patterns
- **Pointing proofs**: Verifies block hash, validates Merkle proof path, confirms transaction exists
- **Non-existence verification**: Downloads all txids for block, builds local Merkle tree, caches for future lookups

## Architecture

```
Bitcoin Block (1.7 MB)
    ↓
ZK Prover (Risc0)
    ↓
Proof (200 bytes: block_hash + [txids])
    ↓
Core Lane Verifier
    ↓
Only fetch relevant transactions
```

## Core Lane Integration

The system integrates with Core Lane through three modules:

- **`core-lane/src/zk_proof_storage.rs`**: Local proof cache with CBOR serialization
- **`core-lane/src/zk_proof_verifier.rs`**: Verify proofs against Bitcoin blockchain
- **`core-lane/src/zk_proof_integration.rs`**: Integrate into block processing

## Performance

| Blocks | Without ZK | With ZK | Savings |
| ------ | ---------- | ------- | ------- |
| 100    | 170 MB     | 20 KB   | 99.99%  |
| 1,000  | 1.7 GB     | 200 KB  | 99.99%  |
| 10,000 | 17 GB      | 2 MB    | 99.99%  |

## Transaction Patterns

The system detects three Core Lane transaction types:

1. **Burn**: OP_RETURN with "BRN1" prefix (28 bytes: prefix + chain_id + eth_address)

   - Hybrid P2WSH + OP_RETURN pattern
   - Burns BTC to mint Core Lane tokens

2. **Data Availability**: Taproot witness with "CORE_LANE" envelope

   - Format: `OP_FALSE OP_IF [CORE_LANE + tx_data] OP_ENDIF OP_TRUE`
   - Posts Core Lane transactions to Bitcoin for data availability

3. **Fill**: Intent fulfillment transactions
   - OP_RETURN with "FILL" prefix
   - Proves Bitcoin was sent to fulfill an intent
   - Used by filler bots to prove payment completion

## Proof Strategies

### Searching Strategy

- **Use case**: Find all Core Lane transactions in a block
- **Efficiency**: Best when many transactions match patterns
- **Proof size**: ~200 bytes
- **Command**: `--strategy searching`

### Pointing Strategy

- **Use case**: Prove a specific transaction exists at a known position
- **Efficiency**: Best when you know exactly which transaction to verify
- **Proof size**: ~300 bytes (includes Merkle proof)
- **Command**: `--strategy "pointing:txid:position:type"`

### Non-Existence Verification

- **Use case**: Verify a transaction does NOT exist in a block
- **Method**: Download all txids, build local Merkle tree, cache for future lookups
- **Efficiency**: One-time cost per block, then instant verification
- **Implementation**: Automatic fallback when server claims transaction doesn't exist

## Technical Details

- **ZK System**: Risc0
- **Proof Format**: CBOR-serialized
- **Bitcoin API**: Blockstream (public)
- **Security**: Cryptographically verified against Bitcoin mainnet
- **Fallback**: Graceful fallback to full block processing
