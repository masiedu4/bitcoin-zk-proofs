use alloy_primitives::{Address, U256};
use serde::{Deserialize, Serialize};

/// Input data for the ZK proof - raw Bitcoin block
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcoinBlockInput {
    pub raw_block: Vec<u8>,
    pub block_height: u64,
}

/// Output data from the ZK proof - filtered transactions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcoinBlockProof {
    pub block_hash: String,
    pub block_height: u64,
    pub matching_transactions: Vec<MatchingTransaction>,
    pub total_transactions: u32,
    pub matching_count: u32,
}

/// A transaction that matches Core Lane criteria (burns, fills, DA posting)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchingTransaction {
    pub txid: String,
    pub transaction_index: u32,
    pub transaction_type: TransactionType,
    pub data: TransactionData,
}

/// Type of Core Lane transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransactionType {
    Burn,
    Fill,
    DAPosting,
}

/// Specific data for each transaction type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransactionData {
    Burn {
        amount: u64, // satoshis
        chain_id: u32,
        eth_address: Address,
    },
    Fill {
        bitcoin_address: Vec<u8>,
        amount: U256,
        max_fee: U256,
        expire_by: u64,
    },
    DAPosting {
        raw_data: Vec<u8>,
    },
}

/// Core Lane transaction patterns to match
#[derive(Debug, Clone)]
pub struct CoreLanePatterns {
    pub burn_prefix: Vec<u8>, // "BRN1" for burns
    pub da_prefix: Vec<u8>,   // Core Lane DA transaction prefix
}

impl Default for CoreLanePatterns {
    fn default() -> Self {
        Self {
            burn_prefix: b"BRN1".to_vec(),
            da_prefix: b"CORE".to_vec(), // Placeholder - adjust based on actual Core Lane format
        }
    }
}
