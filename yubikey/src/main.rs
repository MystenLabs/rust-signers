mod cli;
mod error;
mod types;
mod yubikey_handler;
use crate::cli::Cli;
use crate::yubikey_handler::device::RealSmartCard;
use clap::Parser;

fn main() -> anyhow::Result<()> {
    let device = Box::new(RealSmartCard::new()?);
    let cli = Cli::parse();
    cli::execute(cli, device)
}
