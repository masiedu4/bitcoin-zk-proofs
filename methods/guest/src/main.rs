use risc0_zkvm::guest::env;

mod bitcoin_processor;
mod merkle_simple;
mod types;

use bitcoin_processor::process_bitcoin_block;
use types::BitcoinBlockInput;

fn main() {
    // Read the Bitcoin block input
    let input: BitcoinBlockInput = env::read();

    // Process the Bitcoin block and extract Core Lane transactions
    let proof = process_bitcoin_block(&input).expect("Failed to process Bitcoin block");

    // Commit the proof to the journal
    env::commit(&proof);
}
