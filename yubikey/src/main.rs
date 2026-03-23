mod error;
mod jsonrpc;
mod yubikey_handler;
mod yubikey_signer;
use crate::error::{AppError, SignerError};
use crate::yubikey_handler::device::RealSmartCard;
use crate::yubikey_handler::SmartCard;
use crate::yubikey_signer::{Cli, Commands};
use clap::Parser;

fn main() {
    let cli = Cli::parse();
    let is_jsonrpc_call = matches!(&cli.command, Commands::Call);

    if let Err(error) = run(cli) {
        if !is_jsonrpc_call {
            eprintln!("{error:#}");
            std::process::exit(exit_code(error.exit_kind()));
        }
    }
}

fn run(cli: Cli) -> Result<(), AppError> {
    let device = build_device()?;
    yubikey_signer::execute(cli, device)
}

fn build_device() -> Result<Box<dyn SmartCard>, AppError> {
    Ok(Box::new(RealSmartCard::new()?))
}

fn exit_code(kind: ExitKind) -> i32 {
    match kind {
        ExitKind::Generic => 1,
        ExitKind::Usage => 64,
        ExitKind::Unavailable => 69,
        ExitKind::Permission => 77,
        ExitKind::Software => 70,
    }
}

impl AppError {
    fn exit_kind(&self) -> ExitKind {
        match self {
            AppError::Signer(SignerError::InvalidSlotNumber) => ExitKind::Usage,
            AppError::Signer(SignerError::KeyAlreadyExists) => ExitKind::Usage,
            AppError::Signer(SignerError::AuthenticationFailed) => ExitKind::Permission,
            AppError::Signer(SignerError::YubiKey(_)) => ExitKind::Unavailable,
            AppError::Signer(_) => ExitKind::Software,
            _ => ExitKind::Generic,
        }
    }
}

enum ExitKind {
    Generic,
    Usage,
    Unavailable,
    Permission,
    Software,
}
