use crate::error;
use crate::types::*;
use crate::yubikey_handler::{from_slot_input, resolve_pin, SmartCard, YubiKeyHandler};
use anyhow::{anyhow, Context};
use clap::{Args, Parser, Subcommand};
use serde_json::{json, Value};
use std::io::{self, BufRead};

use sui_types::crypto::{KeypairTraits as KeyPair, ToFromBytes};
use yubikey::piv::SlotId;
use yubikey::{MgmKey, PinPolicy, TouchPolicy};
use zeroize::ZeroizeOnDrop;

// Generates Secp256r1 key on Retired Slot 1(Default) - TouchPolicy cached
// Prints our corresponding address
// Sign whatever base64 serialized tx data blindly
// Prints out Sui Signature
// Requires Yubikey firmware > 5.3
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Generate Key. Defaults to Retired Slot 1. Use --slot to choose a specific Retired Slot (1-20).
    GenerateKey(GenKeyArgs),
    /// Import key from mnemonic
    Import(ImportArgs),
    /// Sign a transaction digest
    Sign(SignArgs),
    /// JSON-RPC mode for integration with Sui CLI (reads from stdin)
    Call,
    /// Prints the Sui Address for the key in the given slot (default R1)
    Address(AddressArgs),
    /// Prints slot information
    Slot(SlotArgs),
}

#[derive(Args, Clone, ZeroizeOnDrop)]
pub struct SignArgs {
    #[clap(long, short = 'd')]
    // The base64 encoded BCS TransactionData to be passed for signing
    pub data: String,
    #[clap(long, short = 'p')]
    // Pin of your yubikey, uses pinentry or default if not provided
    pub pin: Option<String>,
    #[clap(long, short = 's')]
    pub slot: String,
}

#[derive(Args, Clone, ZeroizeOnDrop)]
pub struct AddressArgs {
    #[clap(long, short = 's')]
    pub slot: String,
}

#[derive(Args, Clone, ZeroizeOnDrop)]
pub struct SlotArgs {
    #[clap(long, short = 's')]
    pub slot: String,
}

#[derive(Args, Clone, ZeroizeOnDrop)]
pub struct ImportArgs {
    /// The mnemonic phrase (12-24 words)
    #[clap(long, short = 'w')]
    pub words: String,

    /// The slot to import the key into (default: 1)
    #[clap(long, short = 's')]
    pub slot: String,

    /// Force overwrite required if slot is occupied
    #[clap(long, short = 'f')]
    pub force: bool,

    /// The PIN policy (default: once)
    /// Possible values: never, once, always
    #[clap(long)]
    pub pin_policy: Option<String>,

    /// The touch policy (default: always)
    /// Possible values: never, always, cached
    #[clap(long)]
    pub touch_policy: Option<String>,

    /// The key scheme (default: secp256r1)
    /// Possible values: ed25519, secp256k1, secp256r1
    #[clap(long, default_value = "secp256r1")]
    pub key_scheme: String,

    /// The derivation path (default depends on scheme)
    #[clap(long)]
    pub derivation_path: Option<String>,

    /// The word length (default: word12)
    /// Possible values: word12, word15, word18, word21, word24
    #[clap(long, default_value = "word12")]
    pub word_length: String,
}

#[derive(Args, Clone, ZeroizeOnDrop)]
pub struct GenKeyArgs {
    #[clap(long, short = 's')]
    pub slot: String,
    #[clap(long, short = 'm')]
    pub mgmt_key: Option<String>,
    #[clap(long, short = 'f')]
    pub force: bool,
}

pub fn execute(cli: Cli, device: Box<dyn SmartCard>) -> anyhow::Result<()> {
    // Determine verbosity based on command
    let verbose = !matches!(&cli.command, Commands::Call);

    let mut handler = YubiKeyHandler::new_with_device(device, verbose);

    match &cli.command {
        Commands::GenerateKey(gen_key_args) => {
            let slot = parse_slot(&gen_key_args.slot)?;

            let m_key = match &gen_key_args.mgmt_key {
                Some(m) => MgmKey::from_bytes(m.as_str()),
                None => Ok(MgmKey::default()),
            }?;

            handler.generate_key(slot, Some(m_key), gen_key_args.force)?;
            Ok(())
        }
        Commands::Import(import_args) => {
            let slot = parse_slot(&import_args.slot)?;

            let key_scheme = import_args.key_scheme
                .parse::<sui_types::crypto::SignatureScheme>()
                .map_err(|_| anyhow!("Unsupported key scheme. YubiKey only supports [secp256r1, ed25519, secp256k1] (though import might fail on device for non-r1)"))?;

            if key_scheme != sui_types::crypto::SignatureScheme::Secp256r1 {
                return Err(anyhow!("YubiKey only supports secp256r1 key scheme"));
            }

            let derivation_path = import_args
                .derivation_path
                .as_deref()
                .map(|s| {
                    s.parse()
                        .map_err(|e| anyhow!("Invalid derivation path: {:?}", e))
                })
                .transpose()?;

            let mnemonic =
                bip39::Mnemonic::from_phrase(&import_args.words, bip39::Language::English)
                    .map_err(|e| anyhow!("Invalid mnemonic: {}", e))?;
            let seed = bip39::Seed::new(&mnemonic, "");

            // Path handling
            let path = derivation_path;

            let (_address, kp) =
                sui_keys::key_derive::derive_key_pair_from_path(seed.as_bytes(), path, &key_scheme)
                    .map_err(|e| anyhow!("Failed to derive key pair: {}", e))?;

            let key = match kp {
                sui_types::crypto::SuiKeyPair::Secp256r1(k) => {
                    k.copy().private().as_bytes().to_vec()
                }
                _ => return Err(anyhow!("Unexpected key type derived")),
            };

            let pin_policy = match &import_args.pin_policy {
                Some(p) => match p.to_lowercase().as_str() {
                    "always" => PinPolicy::Always,
                    "once" => PinPolicy::Once,
                    "never" => PinPolicy::Never,
                    _ => return Err(anyhow!("Invalid pin policy. Allowed: always, once, never")),
                },
                None => PinPolicy::Once,
            };

            let touch_policy = match &import_args.touch_policy {
                Some(p) => match p.to_lowercase().as_str() {
                    "always" => TouchPolicy::Always,
                    "cached" => TouchPolicy::Cached,
                    "never" => TouchPolicy::Never,
                    _ => {
                        return Err(anyhow!(
                            "Invalid touch policy. Allowed: always, cached, never"
                        ))
                    }
                },
                None => TouchPolicy::Always,
            };

            handler.import_key(slot, &key, pin_policy, touch_policy, import_args.force)?;
            Ok(())
        }
        Commands::Sign(sign_args) => {
            let data = &sign_args.data;
            let slot = parse_slot(&sign_args.slot)?;
            let pin = resolve_pin(sign_args.pin.clone())?;
            let _ = handler.sign_transaction(slot, data, &pin);
            Ok(())
        }
        Commands::Call => {
            let reader = io::stdin();
            let buf_reader = io::BufReader::new(reader);
            process_call_command(&mut handler, buf_reader)
        }
        Commands::Slot(slot_args) => {
            let slot = parse_slot(&slot_args.slot)?;
            let response = handler
                .get_public_key(slot)
                .map_err(|e| anyhow!("Failed to get slot info: {}", e))?;
            println!("Public Key Information:");
            println!("  Sui Address: {}", response.sui_address);
            match response.public_key {
                crate::types::PublicKey::Secp256r1(key) => {
                    println!("  Public Key (Base64): {}", key);
                    println!("  Key Scheme: Secp256r1");
                }
                crate::types::PublicKey::Ed25519(key) => {
                    println!("  Public Key (Base64): {}", key);
                    println!("  Key Scheme: Ed25519");
                }
            }
            Ok(())
        }
        Commands::Address(address_args) => {
            let slot = parse_slot(&address_args.slot)?;
            let response = handler.get_public_key(slot)?;
            println!("{}", response.sui_address);
            Ok(())
        }
    }
}

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
        let e = anyhow::anyhow!("Method is required");
        return_error(&e.to_string(), id);
        return Err(e.into());
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
        Err(e) => {
            return_error(&e.to_string(), id);
            Err(e.into())
        }
    }
}

pub fn read_json_line<R: BufRead>(mut buf_reader: R) -> Result<JsonRpcRequest, serde_json::Error> {
    let mut input = String::new();
    buf_reader.read_line(&mut input).unwrap();
    serde_json::from_str(&input)
}

fn handle_request(
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

pub fn return_error(message: &str, id: u64) {
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

pub fn parse_slot(slot: &String) -> Result<SlotId, error::Error> {
    let slot_id = from_slot_input(slot.parse().map_err(|_| error::Error::InvalidSlotNumber)?)?;
    Ok(SlotId::Retired(slot_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;
    use crate::yubikey_handler::{DeviceMetadata, GeneratedKeyInfo, MockSmartCard};

    use mockall::predicate::*;
    use yubikey::piv::{AlgorithmId, RetiredSlotId, SlotId};
    use yubikey::{PinPolicy, TouchPolicy};

    use fastcrypto::encoding::{Base64, Encoding};
    use sui_types::base_types::{ObjectDigest, ObjectID, SequenceNumber, SuiAddress};
    use sui_types::transaction::{ProgrammableTransaction, TransactionData};

    // Valid P-256 public key (uncompressed)
    const VALID_PUBKEY: &[u8] = &[
        0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4,
        0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8,
        0x98, 0xc2, 0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a,
        0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40,
        0x68, 0x37, 0xbf, 0x51, 0xf5,
    ];

    #[test]
    fn test_execute_generate_key() {
        let mut mock_device = MockSmartCard::new();

        mock_device
            .expect_authenticate()
            .with(always())
            .times(1)
            .returning(|_| Ok(()));

        mock_device
            .expect_generate()
            .with(
                eq(SlotId::Retired(RetiredSlotId::R1)),
                eq(AlgorithmId::EccP256),
                eq(PinPolicy::Once),
                eq(TouchPolicy::Always),
            )
            .times(1)
            .returning(|_, _, _, _| {
                Ok(GeneratedKeyInfo {
                    public_key: VALID_PUBKEY.to_vec(),
                })
            });

        mock_device.expect_metadata().returning(|_| {
            Ok(DeviceMetadata {
                public_key: VALID_PUBKEY.to_vec(),
            })
        }); // Used for existence check or logging

        let cli = Cli {
            command: Commands::GenerateKey(GenKeyArgs {
                slot: "1".to_string(),
                mgmt_key: None,
                force: true,
            }),
        };

        execute(cli, Box::new(mock_device)).unwrap();
    }

    #[test]
    fn test_execute_sign() {
        let mut mock_device = MockSmartCard::new();

        // Mock verification
        mock_device
            .expect_verify_pin()
            .with(eq("123456".as_bytes()))
            .times(1)
            .returning(|_| Ok(()));

        mock_device.expect_metadata().returning(|_| {
            Ok(DeviceMetadata {
                public_key: VALID_PUBKEY.to_vec(),
            })
        });

        // Construct valid TransactionData
        let pt = ProgrammableTransaction {
            inputs: vec![],
            commands: vec![],
        };
        let sender = SuiAddress::ZERO;
        let gas_payment = vec![(
            ObjectID::ZERO,
            SequenceNumber::from_u64(1),
            ObjectDigest::new([0; 32]),
        )];

        let tx_data = TransactionData::new_programmable(sender, gas_payment, pt, 1000, 1);
        let tx_bytes = bcs::to_bytes(&tx_data).unwrap();
        let tx_base64 = Base64::encode(&tx_bytes);

        mock_device
            .expect_sign_data()
            .with(
                function(|digest: &[u8]| digest.len() == 32),
                eq(AlgorithmId::EccP256),
                eq(SlotId::Retired(RetiredSlotId::R1)),
            )
            .times(1)
            .returning(|_, _, _| {
                Ok(vec![
                    // Valid ASN.1 signature (dummy)
                    0x30, 0x44, 0x02, 0x20, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x02, 0x20, 0x01,
                    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                    0x01, 0x01, 0x01, 0x01, 0x01,
                ])
            });

        let cli = Cli {
            command: Commands::Sign(SignArgs {
                data: tx_base64,
                pin: Some("123456".to_string()),
                slot: "1".to_string(),
            }),
        };

        execute(cli, Box::new(mock_device)).unwrap();
    }

    #[test]
    fn test_handle_request_public_key() {
        let mut mock_device = MockSmartCard::new();
        mock_device
            .expect_metadata()
            .with(eq(SlotId::Retired(RetiredSlotId::R1)))
            .returning(|_| {
                Ok(DeviceMetadata {
                    public_key: VALID_PUBKEY.to_vec(),
                })
            });

        let mut handler = YubiKeyHandler::new_with_device(Box::new(mock_device), false);

        let params = json!({
            "key_id": "1"
        });

        let result = handle_request(&mut handler, "public_key", params).unwrap();
        let resp: PublicKeyResponse = serde_json::from_value(result).unwrap();
        assert_eq!(resp.key_id, "1");
        assert!(resp.sui_address.starts_with("0x"));
    }

    #[test]
    fn test_handle_request_keys() {
        let mut mock_device = MockSmartCard::new();
        // Since it iterates 1..20, and likely some fail or some succeed.
        // We'll mock returning a key for R1 and error (or empty) for others.
        // Or we can just mock R1 specifically and let others default if the mock allows fallback or we need expectations for all.
        // Mockall strictness might require expectations for ALL calls unless we use `returning` with a catch-all or partial.
        // Best approach: Mock R1 always returning Ok, R1 Ok. Others Err.
        // Actually, logic is: if let Ok(resp) = handler.get_public_key(slot).
        // get_public_key calls metadata.

        mock_device
            .expect_metadata()
            .with(eq(SlotId::Retired(RetiredSlotId::R1)))
            .returning(|_| {
                Ok(DeviceMetadata {
                    public_key: VALID_PUBKEY.to_vec(),
                })
            });

        mock_device
            .expect_metadata()
            .with(eq(SlotId::Retired(RetiredSlotId::R2)))
            .returning(|_| {
                Ok(DeviceMetadata {
                    public_key: VALID_PUBKEY.to_vec(),
                })
            });

        // For all other slots, return Error. matching anything else?
        // Mockall doesn't support "anything else" easily with `with`.
        // We can use a single expect_metadata with a closure that checks slot.
        mock_device.expect_metadata().returning(|slot| {
            if slot == SlotId::Retired(RetiredSlotId::R1)
                || slot == SlotId::Retired(RetiredSlotId::R2)
            {
                Ok(DeviceMetadata {
                    public_key: VALID_PUBKEY.to_vec(),
                })
            } else {
                Err(Error::SignatureFailed)
            }
        });

        let mut handler = YubiKeyHandler::new_with_device(Box::new(mock_device), false);
        let params = json!({});

        let result = handle_request(&mut handler, "keys", params).unwrap();
        let resp: KeysResponse = serde_json::from_value(result).unwrap();
        assert_eq!(resp.keys.len(), 2);
    }

    #[test]
    fn test_handle_request_sign() {
        // Similar to test_execute_sign but via RPC params
        let mut mock_device = MockSmartCard::new();
        mock_device.expect_verify_pin().returning(|_| Ok(()));
        mock_device.expect_metadata().returning(|_| {
            Ok(DeviceMetadata {
                public_key: VALID_PUBKEY.to_vec(),
            })
        });

        // Valid dummy TransactionData
        let pt = ProgrammableTransaction {
            inputs: vec![],
            commands: vec![],
        };
        let sender = SuiAddress::ZERO;
        let gas_payment = vec![(
            ObjectID::ZERO,
            SequenceNumber::from_u64(1),
            ObjectDigest::new([0; 32]),
        )];
        let tx_data = TransactionData::new_programmable(sender, gas_payment, pt, 1000, 1);
        let tx_base64 = Base64::encode(&bcs::to_bytes(&tx_data).unwrap());

        mock_device.expect_sign_data().returning(|_, _, _| {
            Ok(vec![
                0x30, 0x44, 0x02, 0x20, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x02, 0x20, 0x01, 0x01, 0x01, 0x01,
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x01, 0x01,
            ])
        });

        let mut handler = YubiKeyHandler::new_with_device(Box::new(mock_device), false);
        let params = json!({
            "key_id": "1",
            "msg": tx_base64
        });

        let result = handle_request(&mut handler, "sign", params).unwrap();
        let resp: SignatureResponse = serde_json::from_value(result).unwrap();
        assert!(!resp.signature.is_empty());
    }

    #[test]
    fn test_execute_invalid_slot() {
        let mock_device = MockSmartCard::new();
        // Slot "99" is invalid
        let cli = Cli {
            command: Commands::GenerateKey(GenKeyArgs {
                slot: "99".to_string(),
                mgmt_key: None,
                force: true,
            }),
        };
        let result = execute(cli, Box::new(mock_device));
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "Invalid slot number");

        let mock_device2 = MockSmartCard::new();
        let cli_sign = Cli {
            command: Commands::Sign(SignArgs {
                data: "dummy".to_string(),
                pin: None,
                slot: "99".to_string(),
            }),
        };
        // We need a fresh mock for sign because execute consumes the box.
        let result_sign = execute(cli_sign, Box::new(mock_device2));
        assert!(result_sign.is_err());
        assert_eq!(result_sign.unwrap_err().to_string(), "Invalid slot number");
    }

    #[test]
    fn test_process_call_command() {
        let mut mock_device = MockSmartCard::new();
        mock_device
            .expect_metadata()
            .with(eq(SlotId::Retired(RetiredSlotId::R1)))
            .returning(|_| {
                Ok(DeviceMetadata {
                    public_key: VALID_PUBKEY.to_vec(),
                })
            });

        let mut handler = YubiKeyHandler::new_with_device(Box::new(mock_device), false);

        // Prepare input: a valid JSON-RPC request for "public_key"
        let input_json = json!({
            "jsonrpc": "2.0",
            "method": "public_key",
            "params": {
                "key_id": "1"
            },
            "id": 1
        })
        .to_string();

        // Add newline because read_json_line uses read_line
        let input = format!("{}\n", input_json);
        let cursor = std::io::Cursor::new(input);

        // We can capture stdout if we really want to check the output, but for now we check it returns Ok
        let result = process_call_command(&mut handler, cursor);
        assert!(result.is_ok());
    }
    #[test]
    fn test_execute_address() {
        let mut mock_device = MockSmartCard::new();
        mock_device
            .expect_metadata()
            .with(eq(SlotId::Retired(RetiredSlotId::R1)))
            .returning(|_| {
                Ok(DeviceMetadata {
                    public_key: VALID_PUBKEY.to_vec(),
                })
            });

        let cli = Cli {
            command: Commands::Address(AddressArgs {
                slot: "1".to_string(),
            }),
        };

        execute(cli, Box::new(mock_device)).unwrap();
    }
    #[test]
    fn test_handle_request_create() {
        let mut mock_device = MockSmartCard::new();

        let should_succeed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let s = should_succeed.clone();

        // R1 is used
        mock_device
            .expect_metadata()
            .with(eq(SlotId::Retired(RetiredSlotId::R1)))
            .returning(|_| {
                Ok(DeviceMetadata {
                    public_key: VALID_PUBKEY.to_vec(),
                })
            });

        // R2 is initially unused (returns Err), then used (returns Ok)
        mock_device
            .expect_metadata()
            .with(eq(SlotId::Retired(RetiredSlotId::R2)))
            .returning(move |_| {
                if s.load(std::sync::atomic::Ordering::SeqCst) {
                    Ok(DeviceMetadata {
                        public_key: VALID_PUBKEY.to_vec(),
                    })
                } else {
                    Err(Error::SignatureFailed)
                }
            });

        mock_device.expect_authenticate().returning(|_| Ok(()));

        let s2 = should_succeed.clone();
        mock_device
            .expect_generate()
            .with(
                eq(SlotId::Retired(RetiredSlotId::R2)),
                always(),
                always(),
                always(),
            )
            .times(1)
            .returning(move |_, _, _, _| {
                s2.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(GeneratedKeyInfo {
                    public_key: VALID_PUBKEY.to_vec(),
                })
            });

        let mut handler = YubiKeyHandler::new_with_device(Box::new(mock_device), false);
        let params = json!({});

        let result = handle_request(&mut handler, "create_key", params).unwrap();
        let resp: PublicKeyResponse = serde_json::from_value(result).unwrap();
        assert_eq!(resp.key_id, "2");
    }

    #[test]
    fn test_execute_import() {
        let mut mock_device = MockSmartCard::new();

        mock_device
            .expect_authenticate()
            .with(always())
            .times(1)
            .returning(|_| Ok(()));

        mock_device.expect_metadata().returning(|_| {
            Ok(DeviceMetadata {
                public_key: VALID_PUBKEY.to_vec(),
            })
        });

        mock_device
            .expect_import_key()
            .with(
                eq(SlotId::Retired(RetiredSlotId::R1)), // Default slot
                function(|key: &[u8]| key.len() == 32), // Check it's a valid private key length
                eq(PinPolicy::Once),                    // Default
                eq(TouchPolicy::Always),                // Default
            )
            .times(1)
            .returning(|_, _, _, _| {
                Ok(GeneratedKeyInfo {
                    public_key: VALID_PUBKEY.to_vec(),
                })
            });

        // Valid 12-word mnemonic for testing
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        let cli = Cli {
            command: Commands::Import(ImportArgs {
                words: mnemonic.to_string(),
                slot: "1".to_string(),
                force: true,
                pin_policy: None,
                touch_policy: None,
                key_scheme: "secp256r1".to_string(),
                derivation_path: None,
                word_length: "word12".to_string(),
            }),
        };

        execute(cli, Box::new(mock_device)).unwrap();
    }
}
