use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stage1Config {
    pub threshold: u16,
    pub total: u16,
    pub message_count: u32,
    pub ttp_addr: SocketAddr,
    pub issuer_bind: SocketAddr,
    pub user_addr: SocketAddr,
}

impl Default for Stage1Config {
    fn default() -> Self {
        Self {
            threshold: std::env::var("THRESHOLD").ok().and_then(|v| v.parse().ok()).unwrap_or(3),
            total: std::env::var("TOTAL").ok().and_then(|v| v.parse().ok()).unwrap_or(5),
            message_count: std::env::var("MESSAGE_COUNT").ok().and_then(|v| v.parse().ok()).unwrap_or(5),
            ttp_addr: std::env::var("TTP_ADDR").ok().and_then(|v| v.parse().ok()).unwrap_or("127.0.0.1:9000".parse().unwrap()),
            issuer_bind: std::env::var("ISSUER_BIND").ok().and_then(|v| v.parse().ok()).unwrap_or("127.0.0.1:0".parse().unwrap()),
            user_addr: std::env::var("USER_ADDR").ok().and_then(|v| v.parse().ok()).unwrap_or("127.0.0.1:9100".parse().unwrap()),
        }
    }
}
