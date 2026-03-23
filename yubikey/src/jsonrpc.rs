use crate::yubikey_handler::{from_slot_input, parse_slot, resolve_pin, YubiKeyHandler};
use anyhow::{anyhow, Context};
use serde_json::{json, Value};
use signer_types::*;
use std::io::BufRead;
use yubikey::piv::SlotId;

pub fn process_call_command<R: BufRead>(
    handler: &mut YubiKeyHandler,
    buf_reader: R,
) -> anyhow::Result<()> {
    let JsonRpcRequest {
        jsonrpc: _,
        method,
        params,
        id,
    } = read_json_line(buf_reader).expect("Unable to deserialize request");

    if method.is_empty() {
        let error = anyhow!("Method is required");
        return_error(&error.to_string(), id);
        return Err(error);
    }

    match handle_request(handler, &method, params) {
        Ok(result) => {
            let response = JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                result,
                id,
            };
            println!("{}", serde_json::to_string(&response).unwrap());
            Ok(())
        }
        Err(error) => {
            return_error(&error.to_string(), id);
            Err(error)
        }
    }
}

pub(crate) fn handle_request(
    handler: &mut YubiKeyHandler,
    method: &str,
    params: Value,
) -> Result<Value, anyhow::Error> {
    match method {
        "sign" => {
            let args: SignParams =
                serde_json::from_value(params).context("Failed to deserialize sign params")?;
            let slot = parse_slot(&args.key_id)?;

            let pin = resolve_pin(None)?;
            let signature = handler.sign_transaction(slot, &args.msg, &pin)?;

            Ok(serde_json::to_value(SignatureResponse { signature })?)
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
            Ok(serde_json::to_value(KeysResponse { keys })?)
        }
        "public_key" => {
            let args: PublicKeyParams = serde_json::from_value(params)
                .context("Failed to deserialize public_key params")?;
            let slot = parse_slot(&args.key_id)?;
            Ok(serde_json::to_value(handler.get_public_key(slot)?)?)
        }
        "create_key" => {
            for i in 1..=20 {
                if let Ok(slot_id) = from_slot_input(i) {
                    let slot = SlotId::Retired(slot_id);
                    if handler.get_public_key(slot).is_err() {
                        handler.generate_key(slot, None, false)?;
                        return Ok(serde_json::to_value(handler.get_public_key(slot)?)?);
                    }
                }
            }
            Err(anyhow!("No available slots found"))
        }
        _ => Err(anyhow!("Invalid method: {}", method)),
    }
}

fn read_json_line<R: BufRead>(mut buf_reader: R) -> Result<JsonRpcRequest, serde_json::Error> {
    let mut input = String::new();
    buf_reader.read_line(&mut input).unwrap();
    serde_json::from_str(&input)
}

fn return_error(message: &str, id: u64) {
    println!(
        "{}",
        json!({
            "jsonrpc": "2.0",
            "error": {
                "code": 1,
                "message": message,
            },
            "id": id,
        })
    );
}
