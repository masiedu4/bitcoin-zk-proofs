use bitcoin::absolute::LockTime;
use bitcoin::blockdata::script::ScriptBuf;
use bitcoin::blockdata::transaction::Version;
use bitcoin::consensus::serialize;
use bitcoin::hashes::Hash;
use bitcoin::{
    Block, BlockHeader, OutPoint, Script, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};

fn create_mock_block_with_core_lane_tx() -> Block {
    // Create a mock transaction with BRN1 pattern
    let mut script = ScriptBuf::new();
    script.push_opcode(bitcoin::opcodes::all::OP_RETURN);
    script.push_slice(b"BRN1");
    script.push_slice(&[0x00, 0x00, 0x00, 0x01]); // chain_id = 1
    script.push_slice(&[0x42; 20]); // eth_address

    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: 100000, // 0.001 BTC
            script_pubkey: script,
        }],
    };

    // Create block header
    let header = BlockHeader {
        version: bitcoin::blockdata::block::Version::TWO,
        prev_blockhash: bitcoin::BlockHash::all_zeros(),
        merkle_root: tx.compute_txid().into(),
        time: 1231006505, // Genesis timestamp
        bits: 0x1d00ffff,
        nonce: 2083236893,
    };

    Block {
        header,
        txdata: vec![tx],
    }
}

fn main() {
    let block = create_mock_block_with_core_lane_tx();
    let serialized = serialize(&block);

    println!("Mock block size: {} bytes", serialized.len());
    println!("Block hash: {}", block.block_hash());
    println!("Transaction count: {}", block.txdata.len());

    for (i, tx) in block.txdata.iter().enumerate() {
        println!("Tx {}: {}", i, tx.compute_txid());
    }
}
