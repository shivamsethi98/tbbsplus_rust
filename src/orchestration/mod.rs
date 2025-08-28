pub mod types;
pub mod mesh;
pub mod helpers;
#[cfg(feature = "mpc")]
pub mod mpc;
pub mod threshold_phases;

// Phase 0 scaffolding: new modular boundaries (no behavior changes yet)
pub mod config;
pub mod persistence;
pub mod onchain;
pub mod chain;
pub mod crypto;
// vb_accum was removed; use vb_accumulator crate directly in binaries

