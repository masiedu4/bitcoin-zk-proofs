use bitcoin::{Block, Transaction};
use risc0_zkvm::guest::env;

use crate::types::{
    BitcoinBlockInput, BitcoinBlockProof, CoreLanePatterns, MatchingTransaction, TransactionData,
    TransactionType,
};

/// Processes a Bitcoin block and extracts Core Lane relevant transactions
pub fn process_bitcoin_block(input: &BitcoinBlockInput) -> Result<BitcoinBlockProof, String> {
    env::log("Starting Bitcoin block processing...");
    env::log(&format!(
        "Input block size: {} bytes",
        input.raw_block.len()
    ));
    // Parse the raw block
    env::log("Parsing raw block...");
    let block: Block = bitcoin::consensus::deserialize(&input.raw_block)
        .map_err(|e| format!("Failed to parse Bitcoin block: {}", e))?;
    env::log(&format!(
        "Block parsed successfully. Transaction count: {}",
        block.txdata.len()
    ));

    // Compute block hash
    env::log("Computing block hash...");
    let block_hash = block.block_hash().to_string();
    env::log(&format!("Block hash computed: {}", block_hash));

    // Filter transactions for Core Lane patterns (no merkle tree needed!)
    env::log("Filtering transactions for Core Lane patterns...");
    let patterns = CoreLanePatterns::default();
    let mut matching_transactions = Vec::new();

    for (index, tx) in block.txdata.iter().enumerate() {
        if let Some(matching_tx) = analyze_transaction_simple(tx, index as u32, &patterns)? {
            matching_transactions.push(matching_tx);
        }
    }

    let matching_count = matching_transactions.len() as u32;
    env::log(&format!(
        "Found {} matching transactions out of {}",
        matching_count,
        block.txdata.len()
    ));

    Ok(BitcoinBlockProof {
        block_hash,
        block_height: input.block_height,
        matching_transactions,
        total_transactions: block.txdata.len() as u32,
        matching_count,
    })
}

/// Analyzes a transaction to see if it matches Core Lane patterns (simplified without merkle proofs)
fn analyze_transaction_simple(
    tx: &Transaction,
    index: u32,
    patterns: &CoreLanePatterns,
) -> Result<Option<MatchingTransaction>, String> {
    let txid = tx.compute_txid().to_string();

    // Check for burn transactions (OP_RETURN with BRN1 prefix)
    if let Some(burn_data) = extract_burn_transaction(tx, patterns) {
        return Ok(Some(MatchingTransaction {
            txid,
            transaction_index: index,
            transaction_type: TransactionType::Burn,
            data: burn_data,
        }));
    }

    // Check for Core Lane DA transactions
    if let Some(da_data) = extract_da_transaction(tx, patterns) {
        return Ok(Some(MatchingTransaction {
            txid,
            transaction_index: index,
            transaction_type: TransactionType::DAPosting,
            data: da_data,
        }));
    }

    // Check for fill transactions (placeholder - implement based on Core Lane spec)
    if let Some(fill_data) = extract_fill_transaction(tx) {
        return Ok(Some(MatchingTransaction {
            txid,
            transaction_index: index,
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
