use serde::{Deserialize, Serialize};

/// Proof strategy for processing Bitcoin blocks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProofStrategy {
    /// Search for transactions matching patterns (burns, DA)
    Searching(SearchingProof),
    /// Point to a specific transaction with Merkle proof
    Pointing(PointingProof),
}

/// Input for searching strategy - find transactions by pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchingProof {
    /// Pattern to search for (burns, DA, fills)
    pub pattern: TransactionPattern,
}

/// Input for pointing strategy - prove specific transaction exists
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PointingProof {
    /// Transaction ID to prove
    pub txid: String,
    /// Expected position in block
    pub tx_position: u32,
    /// Expected transaction type
    pub expected_type: TransactionType,
}

/// Transaction patterns to match during searching
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransactionPattern {
    /// Find all burn transactions (BRN1 prefix)
    Burns,
    /// Find all DA transactions (CORE_LANE prefix)
    DataAvailability,
    /// Find all fill transactions
    Fills,
    /// Find all Core Lane transactions (burns + DA + fills)
    All,
}

/// Input data for the ZK proof - raw Bitcoin block
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcoinBlockInput {
    pub raw_block: Vec<u8>,
    pub block_height: u64,
    pub strategy: ProofStrategy,
}

/// Transaction type classification for Core Lane
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TransactionType {
    Burn,
    DataAvailability,
    Fill,
}

/// A matching transaction identified by the ZK proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchingTransaction {
    /// Transaction ID (committed in the ZK proof)
    pub txid: String,
    /// Transaction type classification
    pub tx_type: TransactionType,
}

/// A Merkle proof path from a transaction to the root
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    /// The transaction ID being proven
    pub txid: [u8; 32],
    /// Path from leaf to root - each element is a sibling hash
    pub path: Vec<[u8; 32]>,
    /// Position indicators: true = right sibling, false = left sibling
    pub positions: Vec<bool>,
}

/// Output data from the ZK proof
///
/// The proof commits to:
/// 1. The block hash (which was computed)
/// 2. Each matching transaction's txid (which was found by filtering or pointing)
/// 3. Merkle proofs for pointed transactions (if using pointing strategy)
///
/// This is sufficient because:
/// - The block hash commits to all block data (including merkle root)
/// - The txids identify specific transactions in that block
/// - Merkle proofs cryptographically prove transaction inclusion
/// - A verifier can fetch the block by hash and look up the txids
/// - The actual transaction data can be content-addressed by txid
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcoinBlockProof {
    /// Bitcoin block hash (committed in ZK proof)
    pub block_hash: String,
    /// Bitcoin block height
    pub block_height: u64,
    /// Strategy used to generate this proof
    pub strategy: ProofStrategy,
    /// Matching transaction IDs (each committed in ZK proof)
    pub matching_transactions: Vec<MatchingTransaction>,
    /// Merkle proofs for pointed transactions (only for pointing strategy)
    pub merkle_proofs: Vec<MerkleProof>,
    /// Total number of transactions in the block
    pub total_transactions: u32,
    /// Number of matching transactions
    pub matching_count: u32,
}

impl BitcoinBlockProof {
    /// Serialize to CBOR format for efficient storage
    pub fn to_cbor(&self) -> Result<Vec<u8>, String> {
        let mut buffer = Vec::new();
        ciborium::into_writer(self, &mut buffer)
            .map_err(|e| format!("CBOR serialization failed: {}", e))?;
        Ok(buffer)
    }

    /// Deserialize from CBOR format
    pub fn from_cbor(data: &[u8]) -> Result<Self, String> {
        ciborium::from_reader(data).map_err(|e| format!("CBOR deserialization failed: {}", e))
    }
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
