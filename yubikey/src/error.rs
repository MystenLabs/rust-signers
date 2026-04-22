use signer_types::JsonRpcErrorObject;

pub(crate) const PROVISION_MODE_NOT_SUPPORTED_ERROR_CODE: i64 = -32012;

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

    #[error("Provision mode is not supported by yubikey-signer")]
    ProvisionModeNotSupported,

    #[error("Recoverable mode requires revealing the recovery phrase")]
    RecoveryPhraseRevealRequired,

    #[error("Recovery phrase reveal is only supported for recoverable mode")]
    PhraseRevealRequiresRecoverable,

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

impl From<&AppError> for JsonRpcErrorObject {
    fn from(error: &AppError) -> JsonRpcErrorObject {
        match error {
            AppError::Signer(signer_error) => signer_error.into(),
            AppError::InvalidPinPolicy | AppError::InvalidTouchPolicy => JsonRpcErrorObject {
                code: -32602,
                message: error.to_string(),
            },
            AppError::JsonRpcMethodRequired => JsonRpcErrorObject {
                code: -32600,
                message: error.to_string(),
            },
            AppError::JsonRpcInvalidMethod => JsonRpcErrorObject {
                code: -32601,
                message: error.to_string(),
            },
            AppError::ProvisionModeNotSupported => JsonRpcErrorObject {
                code: PROVISION_MODE_NOT_SUPPORTED_ERROR_CODE,
                message: error.to_string(),
            },
            AppError::RecoveryPhraseRevealRequired
            | AppError::PhraseRevealRequiresRecoverable => JsonRpcErrorObject {
                code: -32602,
                message: error.to_string(),
            },
            AppError::SerdeError(e) => JsonRpcErrorObject {
                code: -32603,
                message: format!("Serde error: {}", e),
            },
            AppError::Deserialize { target, source } => JsonRpcErrorObject {
                code: -32602,
                message: format!("Failed to deserialize {}: {}", target, source),
            },
        }
    }
}

impl From<&SignerError> for JsonRpcErrorObject {
    fn from(error: &SignerError) -> JsonRpcErrorObject {
        let code = match error {
            SignerError::InvalidSlotNumber => -32602,
            SignerError::NoAvailableSlots => -32001,
            SignerError::AuthenticationFailed => -32002,
            SignerError::KeyGenerationFailed => -32003,
            SignerError::KeyAlreadyExists => -32004,
            SignerError::NoPublicKey => -32005,
            SignerError::PublicKeyMalformed => -32006,
            SignerError::SignatureFailed => -32007,
            SignerError::KeyImportFailed => -32008,
            SignerError::UnexpectedKeyType => -32009,
            SignerError::BadManagementKey => -32010,
            SignerError::InvalidSignatureScheme => -32602,
            SignerError::InvalidDerivationPath(_) => -32602,
            SignerError::InvalidMnemonic => -32602,
            SignerError::KeyDerivationFailed => -32011,
            SignerError::YubiKey(_) => -32603,
        };

        JsonRpcErrorObject {
            code,
            message: error.to_string(),
        }
    }
}
