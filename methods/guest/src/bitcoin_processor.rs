use bitcoin::{hashes::Hash, Block, Transaction, Txid};
use sha2::{Digest, Sha256};

use crate::types::{
    BitcoinBlockInput, BitcoinBlockProof, CoreLanePatterns, MatchingTransaction, MerkleProof,
    MerkleProofNode, TransactionData, TransactionType,
};

/// Processes a Bitcoin block and extracts Core Lane relevant transactions
pub fn process_bitcoin_block(input: &BitcoinBlockInput) -> Result<BitcoinBlockProof, String> {
    // Parse the raw block
    let block: Block = bitcoin::consensus::deserialize(&input.raw_block)
        .map_err(|e| format!("Failed to parse Bitcoin block: {}", e))?;

    // Compute block hash
    let block_hash = block.block_hash().to_string();

    // Compute merkle root
    let merkle_root = compute_merkle_root(&block.txdata)?;

    // Extract transaction IDs for merkle tree construction
    let txids: Vec<Txid> = block.txdata.iter().map(|tx| tx.compute_txid()).collect();

    // Build merkle tree for proof generation
    let merkle_tree = build_merkle_tree(&txids)?;

    // Filter transactions for Core Lane patterns
    let patterns = CoreLanePatterns::default();
    let mut matching_transactions = Vec::new();

    for (index, tx) in block.txdata.iter().enumerate() {
        if let Some(matching_tx) = analyze_transaction(tx, index as u32, &patterns, &merkle_tree)? {
            matching_transactions.push(matching_tx);
        }
    }

    let matching_count = matching_transactions.len() as u32;

    Ok(BitcoinBlockProof {
        block_hash,
        block_height: input.block_height,
        merkle_root,
        matching_transactions,
        total_transactions: block.txdata.len() as u32,
        matching_count,
    })
}

/// Computes the merkle root of a block's transactions
fn compute_merkle_root(transactions: &[Transaction]) -> Result<String, String> {
    if transactions.is_empty() {
        return Ok("0000000000000000000000000000000000000000000000000000000000000000".to_string());
    }

    if transactions.len() == 1 {
        let txid = transactions[0].compute_txid();
        return Ok(hex::encode(txid.as_byte_array()));
    }

    // Convert TXIDs to byte vectors
    let mut current_level: Vec<Vec<u8>> = transactions
        .iter()
        .map(|tx| tx.compute_txid().as_byte_array().to_vec())
        .collect();

    // Build merkle tree level by level
    while current_level.len() > 1 {
        let mut next_level = Vec::new();

        for i in (0..current_level.len()).step_by(2) {
            let left = &current_level[i];
            let right = if i + 1 < current_level.len() {
                &current_level[i + 1]
            } else {
                &current_level[i] // Duplicate last hash if odd number
            };

            // Concatenate and apply double SHA-256
            let mut combined = Vec::new();
            combined.extend_from_slice(left);
            combined.extend_from_slice(right);

            let hash = double_sha256(&combined);
            next_level.push(hash);
        }

        current_level = next_level;
    }

    Ok(hex::encode(&current_level[0]))
}

/// Builds a merkle tree structure for proof generation
fn build_merkle_tree(txids: &[Txid]) -> Result<MerkleTree, String> {
    if txids.is_empty() {
        return Ok(MerkleTree::new());
    }

    let mut levels: Vec<Vec<Vec<u8>>> = vec![txids
        .iter()
        .map(|txid| txid.as_byte_array().to_vec())
        .collect()];

    while levels.last().unwrap().len() > 1 {
        let current_level = levels.last().unwrap();
        let mut next_level = Vec::new();

        for i in (0..current_level.len()).step_by(2) {
            let left = &current_level[i];
            let right = if i + 1 < current_level.len() {
                &current_level[i + 1]
            } else {
                &current_level[i]
            };

            let mut combined = Vec::new();
            combined.extend_from_slice(left);
            combined.extend_from_slice(right);

            let hash = double_sha256(&combined);
            next_level.push(hash);
        }

        levels.push(next_level);
    }

    Ok(MerkleTree { levels })
}

/// Analyzes a transaction to see if it matches Core Lane patterns
fn analyze_transaction(
    tx: &Transaction,
    index: u32,
    patterns: &CoreLanePatterns,
    merkle_tree: &MerkleTree,
) -> Result<Option<MatchingTransaction>, String> {
    let txid = tx.compute_txid().to_string();

    // Check for burn transactions (OP_RETURN with BRN1 prefix)
    if let Some(burn_data) = extract_burn_transaction(tx, patterns) {
        let merkle_proof = generate_merkle_proof(index, merkle_tree)?;
        return Ok(Some(MatchingTransaction {
            txid,
            transaction_index: index,
            merkle_proof,
            transaction_type: TransactionType::Burn,
            data: burn_data,
        }));
    }

    // Check for Core Lane DA transactions
    if let Some(da_data) = extract_da_transaction(tx, patterns) {
        let merkle_proof = generate_merkle_proof(index, merkle_tree)?;
        return Ok(Some(MatchingTransaction {
            txid,
            transaction_index: index,
            merkle_proof,
            transaction_type: TransactionType::DAPosting,
            data: da_data,
        }));
    }

    // Check for fill transactions (placeholder - implement based on Core Lane spec)
    if let Some(fill_data) = extract_fill_transaction(tx) {
        let merkle_proof = generate_merkle_proof(index, merkle_tree)?;
        return Ok(Some(MatchingTransaction {
            txid,
            transaction_index: index,
            merkle_proof,
            transaction_type: TransactionType::Fill,
            data: fill_data,
        }));
    }

    Ok(None)
}

/// Extracts burn transaction data from OP_RETURN outputs
fn extract_burn_transaction(
    tx: &Transaction,
    patterns: &CoreLanePatterns,
) -> Option<TransactionData> {
    for output in &tx.output {
        if output.script_pubkey.is_op_return() {
            if let Some(payload) = extract_op_return_data(&output.script_pubkey) {
                if payload.len() >= 28 && payload.starts_with(&patterns.burn_prefix) {
                    // Parse BRN1 format: BRN1 + chain_id(4) + eth_address(20)
                    let chain_id =
                        u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
                    let eth_address_bytes = &payload[8..28];
                    let eth_address = alloy_primitives::Address::from_slice(eth_address_bytes);

                    // Calculate burn amount from input value
                    let burn_amount = calculate_burn_amount(tx);

                    return Some(TransactionData::Burn {
                        amount: burn_amount,
                        chain_id,
                        eth_address,
                    });
                }
            }
        }
    }
    None
}

/// Extracts Core Lane DA transaction data
fn extract_da_transaction(
    tx: &Transaction,
    patterns: &CoreLanePatterns,
) -> Option<TransactionData> {
    for output in &tx.output {
        if output.script_pubkey.is_op_return() {
            if let Some(payload) = extract_op_return_data(&output.script_pubkey) {
                if payload.starts_with(&patterns.da_prefix) {
                    return Some(TransactionData::DAPosting { raw_data: payload });
                }
            }
        }
    }
    None
}

/// Extracts fill transaction data (placeholder implementation)
fn extract_fill_transaction(_tx: &Transaction) -> Option<TransactionData> {
    // TODO: Implement based on Core Lane fill transaction specification
    None
}

/// Extracts data from OP_RETURN script
fn extract_op_return_data(script: &bitcoin::Script) -> Option<Vec<u8>> {
    let instructions = script.instructions();
    for instruction in instructions {
        if let Ok(bitcoin::script::Instruction::PushBytes(bytes)) = instruction {
            return Some(bytes.as_bytes().to_vec());
        }
    }
    None
}

/// Calculates the burn amount from transaction inputs
fn calculate_burn_amount(tx: &Transaction) -> u64 {
    // For now, return the total input value
    // In a real implementation, you'd need to look up the previous outputs
    // This is a simplified version for the ZK proof
    tx.input.len() as u64 * 100000 // Placeholder: assume 0.001 BTC per input
}

/// Generates a merkle proof for a transaction at the given index
fn generate_merkle_proof(index: u32, merkle_tree: &MerkleTree) -> Result<MerkleProof, String> {
    if merkle_tree.levels.is_empty() {
        return Err("Empty merkle tree".to_string());
    }

    let mut path = Vec::new();
    let mut current_index = index as usize;

    for level in &merkle_tree.levels[..merkle_tree.levels.len() - 1] {
        let is_left = current_index % 2 == 0;
        let sibling_index = if is_left {
            current_index + 1
        } else {
            current_index - 1
        };

        if sibling_index < level.len() {
            path.push(MerkleProofNode {
                hash: hex::encode(&level[sibling_index]),
                is_left,
            });
        }

        current_index /= 2;
    }

    Ok(MerkleProof {
        path,
        leaf_index: index,
    })
}

/// Applies double SHA-256 to data
fn double_sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let first_hash = hasher.finalize();

    let mut hasher = Sha256::new();
    hasher.update(&first_hash);
    let second_hash = hasher.finalize();

    second_hash.to_vec()
}

/// Merkle tree structure for proof generation
#[derive(Debug)]
struct MerkleTree {
    levels: Vec<Vec<Vec<u8>>>,
}

impl MerkleTree {
    fn new() -> Self {
        Self { levels: Vec::new() }
    }
}
