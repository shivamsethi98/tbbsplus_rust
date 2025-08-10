#![cfg(feature = "mpc")]

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MpcMsg {
    Round1Commitment { sid: u64, from: u16, blob: Vec<u8> },
    Round1Shares { sid: u64, from: u16, to: u16, blob: Vec<u8> },
    Round2Msg1 { sid: u64, from: u16, to: u16, blob: Vec<u8> },
    Round2Msg2 { sid: u64, from: u16, to: u16, blob: Vec<u8> },
}

pub struct MpcDriver {
    pub sid: u64,
    pub idx: u16,
}

impl MpcDriver {
    pub fn new(sid: u64, idx: u16) -> Self { Self { sid, idx } }
}
