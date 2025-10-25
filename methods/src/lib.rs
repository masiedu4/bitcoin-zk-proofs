include!(concat!(env!("OUT_DIR"), "/methods.rs"));

// Re-export types module
// This allows the host and core-lane to import these types
pub mod types;
