use bitcoin::hashes::{sha256, Hash, HashEngine};
use risc0_zkvm::guest::env;
use serde::{Deserialize, Serialize};

/// A single node in the Merkle tree
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleNode {
    pub hash: [u8; 32],
    pub left: Option<Box<MerkleNode>>,
    pub right: Option<Box<MerkleNode>>,
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

/// A complete Merkle tree for a Bitcoin block
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleTree {
    pub root: MerkleNode,
    pub txids: Vec<[u8; 32]>,
    pub merkle_root: [u8; 32],
}

impl MerkleTree {
    /// Build a Merkle tree from a list of transaction IDs
    pub fn build_merkle_tree(txids: &[[u8; 32]]) -> Result<Self, String> {
        env::log(&format!(
            "Building Merkle tree for {} transactions",
            txids.len()
        ));

        if txids.is_empty() {
            return Err("Cannot build Merkle tree with no transactions".to_string());
        }

        // Convert txids to leaf nodes
        let mut nodes: Vec<MerkleNode> = txids
            .iter()
            .map(|txid| MerkleNode {
                hash: *txid,
                left: None,
                right: None,
            })
            .collect();

        // Build tree bottom-up
        while nodes.len() > 1 {
            let mut next_level = Vec::new();

            // Process pairs of nodes
            for i in (0..nodes.len()).step_by(2) {
                let left = nodes[i].clone();
                let right = if i + 1 < nodes.len() {
                    nodes[i + 1].clone()
                } else {
                    // Bitcoin rule: if odd number of nodes, duplicate the last one
                    nodes[i].clone()
                };

                // Compute parent hash using double SHA-256
                let parent_hash = Self::compute_parent_hash(&left.hash, &right.hash);

                let parent = MerkleNode {
                    hash: parent_hash,
                    left: Some(Box::new(left)),
                    right: Some(Box::new(right)),
                };

                next_level.push(parent);
            }

            nodes = next_level;
        }

        let root = nodes.into_iter().next().unwrap();
        let merkle_root = root.hash;

        env::log(&format!(
            "Merkle tree built successfully. Root: {}",
            hex::encode(merkle_root)
        ));

        Ok(MerkleTree {
            root,
            txids: txids.to_vec(),
            merkle_root,
        })
    }

    /// Generate a Merkle proof for a transaction at the given index
    pub fn generate_proof(&self, tx_index: u32) -> Result<MerkleProof, String> {
        if tx_index as usize >= self.txids.len() {
            return Err(format!(
                "Transaction index {} out of range (max: {})",
                tx_index,
                self.txids.len() - 1
            ));
        }

        let txid = self.txids[tx_index as usize];
        let mut path = Vec::new();
        let mut positions = Vec::new();

        // Traverse from leaf to root, collecting sibling hashes
        self.collect_proof_path(&self.root, tx_index, &mut path, &mut positions)?;

        env::log(&format!(
            "Generated Merkle proof for tx {} at index {}",
            hex::encode(txid),
            tx_index
        ));

        Ok(MerkleProof {
            txid,
            path,
            positions,
        })
    }

    /// Recursively collect the proof path from leaf to root
    fn collect_proof_path(
        &self,
        node: &MerkleNode,
        target_index: u32,
        path: &mut Vec<[u8; 32]>,
        positions: &mut Vec<bool>,
    ) -> Result<(), String> {
        // If this is a leaf node, we're done
        if node.left.is_none() && node.right.is_none() {
            return Ok(());
        }

        let left = node.left.as_ref().ok_or("Invalid tree structure")?;
        let right = node.right.as_ref().ok_or("Invalid tree structure")?;

        // Determine which subtree contains our target
        let left_subtree_size = self.count_leaves(left);
        let is_in_left = target_index < left_subtree_size;

        if is_in_left {
            // Target is in left subtree, add right sibling to path
            path.push(right.hash);
            positions.push(true); // right sibling
            self.collect_proof_path(left, target_index, path, positions)?;
        } else {
            // Target is in right subtree, add left sibling to path
            path.push(left.hash);
            positions.push(false); // left sibling
            self.collect_proof_path(right, target_index - left_subtree_size, path, positions)?;
        }

        Ok(())
    }

    /// Count the number of leaf nodes in a subtree
    fn count_leaves(&self, node: &MerkleNode) -> u32 {
        if node.left.is_none() && node.right.is_none() {
            1
        } else {
            let left_count = node
                .left
                .as_ref()
                .map(|l| self.count_leaves(l))
                .unwrap_or(0);
            let right_count = node
                .right
                .as_ref()
                .map(|r| self.count_leaves(r))
                .unwrap_or(0);
            left_count + right_count
        }
    }

    /// Compute the parent hash using Bitcoin's double SHA-256
    fn compute_parent_hash(left_hash: &[u8; 32], right_hash: &[u8; 32]) -> [u8; 32] {
        let mut engine = sha256::HashEngine::default();
        engine.input(left_hash);
        engine.input(right_hash);
        let first_hash = sha256::Hash::from_engine(engine);

        // Second SHA-256
        let mut engine = sha256::HashEngine::default();
        engine.input(&first_hash[..]);
        sha256::Hash::from_engine(engine).to_byte_array()
    }
}

impl MerkleProof {
    /// Verify a Merkle proof against a given Merkle root
    pub fn verify_proof(&self, merkle_root: &[u8; 32]) -> Result<bool, String> {
        env::log(&format!(
            "Verifying Merkle proof for tx {}",
            hex::encode(self.txid)
        ));

        if self.path.len() != self.positions.len() {
            return Err("Proof path and positions length mismatch".to_string());
        }

        let mut current_hash = self.txid;

        // Walk up the tree using the proof path
        for (i, (sibling_hash, is_right)) in self.path.iter().zip(self.positions.iter()).enumerate()
        {
            env::log(&format!(
                "Proof step {}: current={}, sibling={}, is_right={}",
                i,
                hex::encode(current_hash),
                hex::encode(*sibling_hash),
                is_right
            ));

            current_hash = if *is_right {
                // Current is left child, sibling is right child
                MerkleTree::compute_parent_hash(&current_hash, sibling_hash)
            } else {
                // Sibling is left child, current is right child
                MerkleTree::compute_parent_hash(sibling_hash, &current_hash)
            };
        }

        let is_valid = current_hash == *merkle_root;
        env::log(&format!(
            "Merkle proof verification: {} (computed: {}, expected: {})",
            if is_valid { "VALID" } else { "INVALID" },
            hex::encode(current_hash),
            hex::encode(*merkle_root)
        ));

        Ok(is_valid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_tree_single_tx() {
        let txids = vec![[1u8; 32]];
        let tree = MerkleTree::build_merkle_tree(&txids).unwrap();
        assert_eq!(tree.merkle_root, [1u8; 32]);
    }

    #[test]
    fn test_merkle_tree_two_txs() {
        let txids = vec![[1u8; 32], [2u8; 32]];
        let tree = MerkleTree::build_merkle_tree(&txids).unwrap();

        // Verify we can generate proofs
        let proof0 = tree.generate_proof(0).unwrap();
        assert!(proof0.verify_proof(&tree.merkle_root).unwrap());

        let proof1 = tree.generate_proof(1).unwrap();
        assert!(proof1.verify_proof(&tree.merkle_root).unwrap());
    }

    #[test]
    fn test_merkle_tree_odd_txs() {
        let txids = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        let tree = MerkleTree::build_merkle_tree(&txids).unwrap();

        // All proofs should be valid
        for i in 0..3 {
            let proof = tree.generate_proof(i).unwrap();
            assert!(proof.verify_proof(&tree.merkle_root).unwrap());
        }
    }
}
