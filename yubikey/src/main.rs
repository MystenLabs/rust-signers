mod cli;
mod error;
mod types;
mod yubikey_handler;
use crate::cli::Cli;
use crate::yubikey_handler::device::RealSmartCard;
use anyhow::Context;
use clap::Parser;

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let device = Box::new(RealSmartCard::new().context("failed to open YubiKey device")?);
    cli::execute(cli, device)
}
