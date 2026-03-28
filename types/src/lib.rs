use bip39::Mnemonic;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Serialize, Deserialize, Debug)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub method: String,
    pub params: Value,
    pub id: u64,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum JsonRpcResponse {
    Success(JsonRpcSuccess),
    Error(JsonRpcFailure),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct JsonRpcSuccess {
    pub jsonrpc: String,
    pub result: serde_json::Value,
    pub id: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct JsonRpcFailure {
    pub jsonrpc: String,
    pub error: JsonRpcErrorObject,
    pub id: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct JsonRpcErrorObject {
    pub code: i64,
    pub message: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SignParams {
    pub key_id: String,
    pub msg: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PublicKeyParams {
    pub key_id: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Default)]
/// Provision modes for key creation. `Recoverable` mode allows for key recovery using a backup, while `Device` mode creates a key that is tied to the device and cannot be recovered if lost.
pub enum ProvisionMode {
    /// Creates a recoverable key without revealing a recovery phrase in this flow,
    /// because backup is assumed to be handled by the signer at setup time or key creation time.
    /// Signers should error if this is not a valid assumption.
    #[default]
    RecoverableAssumed,
    /// Creates a recoverable key and reveals the recovery phrase in this flow, allowing the user to back up the key immediately.
    MnemonicBacked,
    /// User has explicitly asked to generate a key on a device with no backup
    NonRecoverable,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct CreateKeyParams {
    pub mode: ProvisionMode,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KeysResponse {
    pub keys: Vec<PublicKeyResponse>,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum PublicKey {
    Ed25519(String),
    Secp256r1(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PublicKeyResponse {
    pub key_id: String,
    pub public_key: PublicKey,
    pub sui_address: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateKeyResponse {
    pub key_id: String,
    pub public_key: PublicKey,
    pub sui_address: String,
    pub mnemonic: Option<String>,
}

impl CreateKeyResponse {
    pub fn from_public_key_response(
        response: PublicKeyResponse,
        mnemonic: Option<Mnemonic>,
    ) -> Self {
        Self {
            key_id: response.key_id,
            public_key: response.public_key,
            sui_address: response.sui_address,
            mnemonic: mnemonic.map(|m| m.phrase().to_string()),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignatureResponse {
    pub signature: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum JsonRpcResult {
    KeysResponse(KeysResponse),
    PublicKeyResponse(PublicKeyResponse),
    CreateKeyResponse(CreateKeyResponse),
    SignatureResponse(SignatureResponse),
}

impl From<KeysResponse> for JsonRpcResult {
    fn from(value: KeysResponse) -> Self {
        JsonRpcResult::KeysResponse(value)
    }
}

impl From<PublicKeyResponse> for JsonRpcResult {
    fn from(value: PublicKeyResponse) -> Self {
        JsonRpcResult::PublicKeyResponse(value)
    }
}

impl From<CreateKeyResponse> for JsonRpcResult {
    fn from(value: CreateKeyResponse) -> Self {
        JsonRpcResult::CreateKeyResponse(value)
    }
}

impl From<SignatureResponse> for JsonRpcResult {
    fn from(value: SignatureResponse) -> Self {
        JsonRpcResult::SignatureResponse(value)
    }
}

macro_rules! impl_json_display {
  ($($ty:ty),+ $(,)?) => {
      $(
          impl std::fmt::Display for $ty {
              fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                  let json = serde_json::to_string(self).map_err(|_| std::fmt::Error)?;
                  f.write_str(&json)
              }
          }
      )+
  };
}
impl_json_display!(
    JsonRpcRequest,
    JsonRpcSuccess,
    JsonRpcFailure,
    JsonRpcResponse
);
