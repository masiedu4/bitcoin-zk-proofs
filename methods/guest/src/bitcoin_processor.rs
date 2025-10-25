use bitcoin::hashes::Hash;
use bitcoin::{Block, Transaction};
use risc0_zkvm::guest::env;

use crate::merkle_simple::{MerkleProof, MerkleTree};
use crate::types::{
    BitcoinBlockInput, BitcoinBlockProof, CoreLanePatterns, MatchingTransaction, PointingProof,
    ProofStrategy, SearchingProof, TransactionPattern, TransactionType,
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

    // Compute block hash (this commits to the entire block including merkle root)
    env::log("Computing block hash...");
    let block_hash = block.block_hash().to_string();
    env::log(&format!("Block hash computed: {}", block_hash));

    // Process based on strategy
    match &input.strategy {
        ProofStrategy::Searching(searching_proof) => {
            process_searching_strategy(&block, searching_proof, &block_hash, input.block_height)
        }
        ProofStrategy::Pointing(pointing_proof) => {
            process_pointing_strategy(&block, pointing_proof, &block_hash, input.block_height)
        }
    }
}

/// Process using searching strategy - find transactions by pattern
fn process_searching_strategy(
    block: &Block,
    searching_proof: &SearchingProof,
    block_hash: &str,
    block_height: u64,
) -> Result<BitcoinBlockProof, String> {
    env::log("Using searching strategy...");

    let patterns = CoreLanePatterns::default();
    let mut matching_transactions = Vec::new();

    for (index, tx) in block.txdata.iter().enumerate() {
        if let Some((tx_type, txid)) =
            check_transaction_patterns(tx, index as u32, &patterns, &searching_proof.pattern)?
        {
            env::log(&format!(
                "Found matching transaction: {} (type: {:?})",
                txid, tx_type
            ));

            let matching_tx = MatchingTransaction {
                txid: txid.clone(),
                tx_type,
            };

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
        block_hash: block_hash.to_string(),
        block_height,
        strategy: ProofStrategy::Searching(searching_proof.clone()),
        matching_transactions,
        merkle_proofs: Vec::new(), // No Merkle proofs for searching
        total_transactions: block.txdata.len() as u32,
        matching_count,
    })
}

/// Process using pointing strategy - prove specific transaction exists
fn process_pointing_strategy(
    block: &Block,
    pointing_proof: &PointingProof,
    block_hash: &str,
    block_height: u64,
) -> Result<BitcoinBlockProof, String> {
    env::log("Using pointing strategy...");
    env::log(&format!(
        "Looking for transaction {} at position {}",
        pointing_proof.txid, pointing_proof.tx_position
    ));

    // Find the transaction by ID (ignore the provided position for now)
    let mut found_position = None;
    for (index, tx) in block.txdata.iter().enumerate() {
        let actual_txid = tx.compute_txid().to_string();
        if actual_txid == pointing_proof.txid {
            found_position = Some(index);
            break;
        }
    }

    let tx_position = found_position
        .ok_or_else(|| format!("Transaction {} not found in block", pointing_proof.txid))?
        as u32;

    let tx = &block.txdata[tx_position as usize];
    env::log(&format!("Found transaction at position {}", tx_position));

    // Verify the transaction matches the expected type
    let patterns = CoreLanePatterns::default();
    let (actual_type, _) = check_transaction_patterns(
        tx,
        pointing_proof.tx_position,
        &patterns,
        &TransactionPattern::All,
    )?
    .ok_or_else(|| {
        format!(
            "Transaction {} does not match any Core Lane pattern",
            pointing_proof.txid
        )
    })?;

    if actual_type != pointing_proof.expected_type {
        return Err(format!(
            "Transaction type mismatch: expected {:?}, got {:?}",
            pointing_proof.expected_type, actual_type
        ));
    }

    // Build Merkle tree and generate proof
    env::log("Building Merkle tree...");
    let txids: Vec<[u8; 32]> = block
        .txdata
        .iter()
        .map(|tx| tx.compute_txid().to_byte_array())
        .collect();

    let merkle_tree = MerkleTree::build_merkle_tree(&txids)?;
    let merkle_proof = merkle_tree.generate_proof(tx_position)?;

    // Verify the proof
    if !merkle_proof.verify_proof(&merkle_tree.merkle_root)? {
        return Err("Generated Merkle proof failed verification".to_string());
    }

    env::log("Merkle proof generated and verified successfully");

    let matching_tx = MatchingTransaction {
        txid: pointing_proof.txid.clone(),
        tx_type: actual_type,
    };

    Ok(BitcoinBlockProof {
        block_hash: block_hash.to_string(),
        block_height,
        strategy: ProofStrategy::Pointing(pointing_proof.clone()),
        matching_transactions: vec![matching_tx],
        merkle_proofs: vec![merkle_proof],
        total_transactions: block.txdata.len() as u32,
        matching_count: 1,
    })
}

/// Checks if a transaction matches Core Lane patterns and returns the type and txid if it does
fn check_transaction_patterns(
    tx: &Transaction,
    _index: u32,
    patterns: &CoreLanePatterns,
    search_pattern: &TransactionPattern,
) -> Result<Option<(TransactionType, String)>, String> {
    let txid = tx.compute_txid().to_string();

    // Check for burn transactions (OP_RETURN with BRN1 prefix)
    if extract_burn_transaction(tx, patterns) {
        if matches!(
            search_pattern,
            TransactionPattern::Burns | TransactionPattern::All
        ) {
            return Ok(Some((TransactionType::Burn, txid)));
        }
    }

    // Check for Core Lane DA transactions
    if extract_da_transaction(tx, patterns) {
        if matches!(
            search_pattern,
            TransactionPattern::DataAvailability | TransactionPattern::All
        ) {
            return Ok(Some((TransactionType::DataAvailability, txid)));
        }
    }

    // Check for fill transactions
    if extract_fill_transaction(tx, patterns) {
        if matches!(
            search_pattern,
            TransactionPattern::Fills | TransactionPattern::All
        ) {
            return Ok(Some((TransactionType::Fill, txid)));
        }
    }

    Ok(None)
}

/// Checks if transaction is a burn transaction (OP_RETURN with BRN1 prefix)
fn extract_burn_transaction(tx: &Transaction, patterns: &CoreLanePatterns) -> bool {
    for output in &tx.output {
        if output.script_pubkey.is_op_return() {
            if let Some(payload) = extract_op_return_data(&output.script_pubkey) {
                if payload.len() >= 28 && payload.starts_with(&patterns.burn_prefix) {
                    return true;
                }
            }
        }
    }
    false
}

/// Checks if transaction is a Core Lane DA transaction
fn extract_da_transaction(tx: &Transaction, patterns: &CoreLanePatterns) -> bool {
    for output in &tx.output {
        if output.script_pubkey.is_op_return() {
            if let Some(payload) = extract_op_return_data(&output.script_pubkey) {
                if payload.starts_with(&patterns.da_prefix) {
                    return true;
                }
            }
        }
    }
    false
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

/// Checks if transaction is a fill transaction (intent fulfillment)
fn extract_fill_transaction(tx: &Transaction, _patterns: &CoreLanePatterns) -> bool {
    // Fill transactions are identified by:
    // 1. They send Bitcoin to a specific address (from intent)
    // 2. They have a specific amount (from intent)
    // 3. They may have OP_RETURN data indicating it's a fill

    // For now, we'll identify fills by looking for OP_RETURN with "FILL" prefix
    // In practice, fills would be identified by the filler bot pointing to them
    for output in &tx.output {
        if output.script_pubkey.is_op_return() {
            if let Some(payload) = extract_op_return_data(&output.script_pubkey) {
                if payload.len() >= 4 && payload.starts_with(b"FILL") {
                    return true;
                }
            }
        }
    }

    false
}

/// Calculates the burn amount from transaction inputs
fn calculate_burn_amount(tx: &Transaction) -> u64 {
    // For now, return the total input value
    // In a real implementation, you'd need to look up the previous outputs
    // This is a simplified version for the ZK proof
    tx.input.len() as u64 * 100000 // Placeholder: assume 0.001 BTC per input
}
