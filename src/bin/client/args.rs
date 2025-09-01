use clap::{Parser, Subcommand};

#[derive(Debug, Clone, Subcommand)]
pub enum Sub {
    /// Request a credential for a session id
    Request { sid: u64, #[arg(short, long)] wait: bool },
    /// Verify (fetch and persist artifacts) then enter actions
    Verify { sid: u64 },
    /// Enter actions for an existing sid
    Present { sid: u64 },
}

#[derive(Debug, Clone, Parser)]
#[command(name = "client", about = "BBS+ client", version, disable_help_flag = true)]
pub struct Args {
    /// Show help
    #[arg(short='h', long, action=clap::ArgAction::Help)]
    pub help: Option<bool>,
    #[command(subcommand)]
    pub cmd: Option<Sub>,
}

#[derive(Debug, Clone)]
pub enum Mode {
    Request { sid: u64, wait_and_verify: bool },
    Verify { sid: u64 },
    Present { sid: u64 },
    Interactive,
}

pub fn parse_mode() -> Mode {
    let a = Args::parse();
    match a.cmd {
        Some(Sub::Request { sid, wait }) => Mode::Request { sid, wait_and_verify: wait },
        Some(Sub::Verify { sid }) => Mode::Verify { sid },
        Some(Sub::Present { sid }) => Mode::Present { sid },
        None => Mode::Interactive,
    }
}
