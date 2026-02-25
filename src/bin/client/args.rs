use clap::{Parser, Subcommand};

#[derive(Debug, Clone, Subcommand)]
pub enum Sub {
    /// Request a credential
    Request { #[arg(short, long)] wait: bool },
    /// Verify (fetch and persist artifacts) then enter actions
    Verify,
    /// Enter actions for an existing credential
    Present,
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
    Request { wait_and_verify: bool },
    Verify,
    Present,
    Interactive,
}

pub fn parse_mode() -> Mode {
    let a = Args::parse();
    match a.cmd {
        Some(Sub::Request { wait }) => Mode::Request { wait_and_verify: wait },
        Some(Sub::Verify) => Mode::Verify,
        Some(Sub::Present) => Mode::Present,
        None => Mode::Interactive,
    }
}
