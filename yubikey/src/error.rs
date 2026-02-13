#[derive(thiserror::Error, Debug, PartialEq)]
pub enum Error {
    #[error("Invalid slot number")]
    InvalidSlotNumber,

    #[error("Failed to authenticate")]
    AuthenticationFailed,

    #[error("Failed to generate key")]
    KeyGenerationFailed,

    #[error("Key already exists in the specified slot. Use --force to overwrite.")]
    KeyAlreadyExists,

    #[error("No public key found")]
    NoPublicKey,

    #[error("Public key malformed")]
    PublicKeyMalformed,

    #[error("Failed to sign data")]
    SignatureFailed,

    #[error("Failed to import key")]
    KeyImportFailed,

    #[error("Yubikey error: {0}")]
    YubikeyError(#[from] yubikey::Error),
}
