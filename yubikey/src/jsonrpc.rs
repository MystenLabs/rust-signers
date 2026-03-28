use crate::error::{AppError, SignerError};
use crate::yubikey_handler::{from_slot_input, parse_slot, resolve_pin, YubiKeyHandler};
use crate::yubikey_signer::secp256r1_key_bytes;
use bip39::{Language, Mnemonic, MnemonicType, Seed};
use serde_json::{to_value, Value};
use signer_types::*;
use std::io::BufRead;
use sui_keys::key_derive::derive_key_pair_from_path;
use sui_types::crypto::SignatureScheme;
use yubikey::piv::SlotId;
use yubikey::{PinPolicy, TouchPolicy};

pub(crate) fn process_call_command<R: BufRead>(
    handler: &mut YubiKeyHandler,
    buf_reader: R,
) -> Result<(), AppError> {
    let JsonRpcRequest {
        jsonrpc: _,
        method,
        params,
        id,
    } = read_json_line(buf_reader).map_err(|e| AppError::Deserialize {
        target: "JsonRpcRequest",
        source: e,
    })?;

    if method.is_empty() {
        let error = AppError::JsonRpcMethodRequired;
        return_error((&error).into(), id);
        return Err(error);
    }

    match handle_request(handler, &method, params) {
        Ok(result) => {
            let response = JsonRpcSuccess {
                jsonrpc: "2.0".to_string(),
                result: to_value(result)?,
                id,
            };
            println!("{}", serde_json::to_string(&response).unwrap());
            Ok(())
        }
        Err(error) => {
            return_error((&error).into(), id);
            Err(error)
        }
    }
}

pub(crate) fn handle_request(
    handler: &mut YubiKeyHandler,
    method: &str,
    params: Value,
) -> Result<JsonRpcResult, AppError> {
    match method {
        "sign" => {
            let args: SignParams =
                serde_json::from_value(params).map_err(|e| AppError::Deserialize {
                    target: "SignParams",
                    source: e,
                })?;
            let slot = parse_slot(&args.key_id)?;

            let pin = resolve_pin(None)?;
            let signature = handler.sign_transaction(slot, &args.msg, &pin)?;

            Ok(SignatureResponse { signature }.into())
        }
        "keys" => {
            let mut keys = vec![];
            for i in 1..=20 {
                if let Ok(slot_id) = from_slot_input(i) {
                    let slot = SlotId::Retired(slot_id);
                    if let Ok(resp) = handler.get_public_key(slot) {
                        keys.push(resp);
                    }
                }
            }
            Ok(KeysResponse { keys }.into())
        }
        "public_key" => {
            let args: PublicKeyParams =
                serde_json::from_value(params).map_err(|e| AppError::Deserialize {
                    target: "PublicKeyParams",
                    source: e,
                })?;
            let slot = parse_slot(&args.key_id)?;
            Ok(handler.get_public_key(slot)?.into())
        }
        "create_key" => {
            let args = match params {
                Value::Null => CreateKeyParams::default(),
                value => serde_json::from_value::<CreateKeyParams>(value).map_err(|e| {
                    AppError::Deserialize {
                        target: "CreateKeyParams",
                        source: e,
                    }
                })?,
            };

            // YubiKeys cannot be exported, nor does a yubikey automatically back up your PIV slot key, therefore they are non-recoverable
            if matches!(args.mode, ProvisionMode::RecoverableAssumed) {
                return Err(AppError::ProvisionModeNotSupported);
            }

            for i in 1..=20 {
                if let Ok(slot_id) = from_slot_input(i) {
                    let slot = SlotId::Retired(slot_id);
                    if handler.get_public_key(slot).is_err() {
                        return Ok(match args.mode {
                            ProvisionMode::MnemonicBacked => {
                                let mnemonic =
                                    Mnemonic::new(MnemonicType::Words12, Language::English);
                                let seed = Seed::new(&mnemonic, "");
                                let (_address, kp) = derive_key_pair_from_path(
                                    seed.as_bytes(),
                                    None,
                                    &SignatureScheme::Secp256r1,
                                )
                                .map_err(|_| SignerError::KeyDerivationFailed)?;
                                handler.import_key(
                                    slot,
                                    &secp256r1_key_bytes(kp)?,
                                    PinPolicy::Once,
                                    TouchPolicy::Always,
                                    false,
                                )?;
                                CreateKeyResponse::from_public_key_response(
                                    handler.get_public_key(slot)?,
                                    Some(mnemonic),
                                )
                            }
                            ProvisionMode::NonRecoverable => {
                                handler.generate_key(slot, None, false)?;
                                CreateKeyResponse::from_public_key_response(
                                    handler.get_public_key(slot)?,
                                    None,
                                )
                            }
                            ProvisionMode::RecoverableAssumed => unreachable!(),
                        }
                        .into());
                    }
                }
            }
            Err(SignerError::NoAvailableSlots.into())
        }
        _ => Err(AppError::JsonRpcInvalidMethod),
    }
}

fn read_json_line<R: BufRead>(mut buf_reader: R) -> Result<JsonRpcRequest, serde_json::Error> {
    let mut input = String::new();
    buf_reader
        .read_line(&mut input)
        .expect("Failed to read line");
    serde_json::from_str(&input)
}

fn return_error(error: JsonRpcErrorObject, id: u64) {
    println!(
        "{}",
        JsonRpcFailure {
            jsonrpc: "2.0".to_string(),
            error,
            id,
        }
    );
}
