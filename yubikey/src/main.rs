mod error;
mod jsonrpc;
mod yubikey_handler;
mod yubikey_signer;
use crate::yubikey_handler::device::RealSmartCard;
use crate::yubikey_signer::Cli;
use anyhow::Context;
use clap::Parser;

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let device = Box::new(RealSmartCard::new().context("failed to open YubiKey device")?);
    yubikey_signer::execute(cli, device)
}
