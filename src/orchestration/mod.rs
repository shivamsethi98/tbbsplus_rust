pub mod mesh;
#[cfg(feature = "mpc")]
pub mod threshold_phases;

// Phase 0 scaffolding: new modular boundaries (no behavior changes yet)
pub mod persistence;
pub mod onchain;
pub mod chain;
pub mod crypto;
pub mod batching;
