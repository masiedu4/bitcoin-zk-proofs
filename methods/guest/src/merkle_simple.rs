use bitcoin::hashes::{sha256, Hash, HashEngine};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MerkleProof {
    pub txid: [u8; 32],
    pub path: Vec<[u8; 32]>,
    pub positions: Vec<bool>, // true for right child, false for left child
}

#[derive(Debug, Clone)]
pub struct MerkleTree {
    pub leaves: Vec<[u8; 32]>,
    pub merkle_root: [u8; 32],
    pub tree: Vec<Vec<[u8; 32]>>, // Stores all levels of the tree
}

impl MerkleTree {
    pub fn build_merkle_tree(txids: &[[u8; 32]]) -> Result<Self, String> {
        if txids.is_empty() {
            return Err("Cannot build Merkle tree from empty transaction list".to_string());
        }

        let mut leaves = txids.to_vec();
        if leaves.len() % 2 != 0 {
            leaves.push(*leaves.last().unwrap()); // Duplicate last leaf if odd number
        }

        let mut tree = Vec::new();
        tree.push(leaves.clone());

        let mut current_level = leaves;

        while current_level.len() > 1 {
            let mut next_level = Vec::new();
            for i in (0..current_level.len()).step_by(2) {
                let left = current_level[i];
                let right = if i + 1 < current_level.len() {
                    current_level[i + 1]
                } else {
                    current_level[i] // Should not happen with initial padding
                };

                let mut engine = sha256::HashEngine::default();
                engine.input(&left);
                engine.input(&right);
                let hash = sha256::Hash::from_engine(engine).to_byte_array();
                next_level.push(hash);
            }
            current_level = next_level;
            tree.push(current_level.clone());
        }

        let merkle_root = *current_level.first().unwrap();

        Ok(Self {
            leaves: txids.to_vec(), // Store original leaves
            merkle_root,
            tree,
        })
    }

    pub fn generate_proof(&self, tx_index: u32) -> Result<MerkleProof, String> {
        if tx_index as usize >= self.leaves.len() {
            return Err("Transaction index out of bounds".to_string());
        }

        let original_txid = self.leaves[tx_index as usize];
        let mut current_hash = original_txid;
        let mut path = Vec::new();
        let mut positions = Vec::new();

        let mut current_level_index = 0;
        let mut current_tx_index = tx_index as usize;

        while current_level_index < self.tree.len() - 1 {
            let level = &self.tree[current_level_index];
            let sibling_index;
            let is_right_sibling;

            if current_tx_index % 2 == 0 {
                // Current hash is a left child
                sibling_index = current_tx_index + 1;
                is_right_sibling = true;
            } else {
                // Current hash is a right child
                sibling_index = current_tx_index - 1;
                is_right_sibling = false;
            }

            let sibling_hash = if sibling_index < level.len() {
                level[sibling_index]
            } else {
                // This case should only happen if the last element was duplicated
                // and we are processing the duplicated element.
                // In a canonical Merkle tree, this means the sibling is itself.
                level[current_tx_index]
            };

            path.push(sibling_hash);
            positions.push(is_right_sibling);

            // Compute parent hash
            let mut engine = sha256::HashEngine::default();
            if is_right_sibling {
                engine.input(&current_hash);
                engine.input(&sibling_hash);
            } else {
                engine.input(&sibling_hash);
                engine.input(&current_hash);
            }
            current_hash = sha256::Hash::from_engine(engine).to_byte_array();

            current_level_index += 1;
            current_tx_index /= 2;
        }

        if current_hash != self.merkle_root {
            return Err(
                "Merkle proof generation failed: final hash does not match root".to_string(),
            );
        }

        Ok(MerkleProof {
            txid: original_txid,
            path,
            positions,
        })
    }
}

impl MerkleProof {
    pub fn verify_proof(&self, merkle_root: &[u8; 32]) -> Result<bool, String> {
        let mut current_hash = self.txid;

        for (i, sibling_hash) in self.path.iter().enumerate() {
            let is_right_sibling = self.positions[i];
            let mut engine = sha256::HashEngine::default();

            if is_right_sibling {
                engine.input(&current_hash);
                engine.input(sibling_hash);
            } else {
                engine.input(sibling_hash);
                engine.input(&current_hash);
            }
            current_hash = sha256::Hash::from_engine(engine).to_byte_array();
        }

        Ok(&current_hash == merkle_root)
    }
}
