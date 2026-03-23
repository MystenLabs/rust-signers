#[derive(thiserror::Error, Debug)]
pub enum AppError {
    #[error(transparent)]
    Signer(#[from] SignerError),

    #[error("Invalid pin policy. Allowed: always, once, never")]
    InvalidPinPolicy,

    #[error("Invalid touch policy. Allowed: always, cached, never")]
    InvalidTouchPolicy,

    #[error("JSON-RPC call requires method")]
    JsonRpcMethodRequired,

    #[error("JSON-RPC invalid method")]
    JsonRpcInvalidMethod,

    #[error("Serde Error: {0}")]
    SerdeError(#[from] serde_json::Error),

    #[error("failed to deserialize {target}")]
    Deserialize {
        target: &'static str,
        #[source]
        source: serde_json::Error,
    },
}

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum SignerError {
    #[error("Invalid slot number")]
    InvalidSlotNumber,

    #[error("No available slots")]
    NoAvailableSlots,

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

    #[error("Unexpected key type derived")]
    UnexpectedKeyType,

    #[error("Bad management key")]
    BadManagementKey,

    #[error("Invalid signature scheme, YubiKey only supports secp256r1")]
    InvalidSignatureScheme,

    #[error("Invalid derivation path {0}")]
    InvalidDerivationPath(String),

    #[error("Invalid mnemonic")]
    InvalidMnemonic,

    #[error("Failed to derive keypair")]
    KeyDerivationFailed,

    #[error(transparent)]
    YubiKey(#[from] yubikey::Error),
}
