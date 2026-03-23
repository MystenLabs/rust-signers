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
pub struct SignatureResponse {
    pub signature: String,
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
impl_json_display!(JsonRpcRequest, JsonRpcSuccess, JsonRpcFailure, JsonRpcResponse);
