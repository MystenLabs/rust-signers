use super::{DeviceMetadata, GeneratedKeyInfo, SmartCard};

use crate::error::Error;
use crate::types::*;
use fastcrypto::encoding::{Base64, Encoding, Hex};
use fastcrypto::hash::{Blake2b256, HashFunction, Sha256};
use fastcrypto::secp256r1::Secp256r1PublicKey;
use fastcrypto::traits::ToFromBytes;
use shared_crypto::intent::{Intent, IntentMessage};
use sui_types::crypto::SignatureScheme;
use sui_types::transaction::TransactionData;
use tracing::info;
use yubikey::piv::{generate, sign_data, AlgorithmId, SlotId};
use yubikey::{MgmKey, PinPolicy, TouchPolicy, YubiKey};

pub struct RealSmartCard {
    device: YubiKey,
}

impl RealSmartCard {
    pub fn new() -> Result<Self, Error> {
        Ok(Self {
            device: YubiKey::open()?,
        })
    }
}

impl SmartCard for RealSmartCard {
    fn authenticate(&mut self, key: MgmKey) -> Result<(), Error> {
        self.device
            .authenticate(key)
            .map_err(|_| Error::AuthenticationFailed)
    }

    fn metadata(&mut self, slot: SlotId) -> Result<DeviceMetadata, Error> {
        let meta = yubikey::piv::metadata(&mut self.device, slot)?;
        let public_key = meta
            .public
            .ok_or(Error::NoPublicKey)?
            .subject_public_key
            .as_bytes()
            .ok_or(Error::PublicKeyMalformed)?
            .to_vec();
        Ok(DeviceMetadata { public_key })
    }

    fn generate(
        &mut self,
        slot: SlotId,
        alg: AlgorithmId,
        pin_policy: PinPolicy,
        touch_policy: TouchPolicy,
    ) -> Result<GeneratedKeyInfo, Error> {
        let key = generate(&mut self.device, slot, alg, pin_policy, touch_policy)
            .map_err(|_| Error::KeyGenerationFailed)?;
        let public_key = key
            .subject_public_key
            .as_bytes()
            .ok_or(Error::PublicKeyMalformed)?
            .to_vec();
        Ok(GeneratedKeyInfo { public_key })
    }

    fn sign_data(
        &mut self,
        digest: &[u8],
        alg: AlgorithmId,
        slot: SlotId,
    ) -> Result<Vec<u8>, Error> {
        let sig =
            sign_data(&mut self.device, digest, alg, slot).map_err(|_| Error::SignatureFailed)?;
        Ok(sig.to_vec())
    }

    fn verify_pin(&mut self, pin: &[u8]) -> Result<(), Error> {
        self.device
            .verify_pin(pin)
            .map_err(|_| Error::AuthenticationFailed)
    }

    fn import_key(
        &mut self,
        slot: SlotId,
        key_data: &[u8],
        pin_policy: PinPolicy,
        touch_policy: TouchPolicy,
    ) -> Result<GeneratedKeyInfo, Error> {
        // 1. Import the private key
        // Using `yubikey::piv::import_key` which is available with "untested" feature or standard in 0.8.0?
        // If "untested" feature enabled, it should work.

        yubikey::piv::import_ecc_key(
            &mut self.device,
            slot,
            AlgorithmId::EccP256,
            key_data,
            touch_policy,
            pin_policy,
        )?;

        // 2. Derive public key to return
        use p256::elliptic_curve::sec1::ToEncodedPoint;

        let secret_key =
            p256::SecretKey::from_slice(key_data).map_err(|_| Error::KeyImportFailed)?;
        let public_key_obj = secret_key.public_key();
        let public_key_bytes = public_key_obj.to_encoded_point(false).as_bytes().to_vec();

        Ok(GeneratedKeyInfo {
            public_key: public_key_bytes,
        })
    }
}

pub struct YubiKeyHandler {
    device: Box<dyn SmartCard>,
    verbose: bool,
}

impl YubiKeyHandler {
    pub fn new_with_device(device: Box<dyn SmartCard>, verbose: bool) -> Self {
        Self { device, verbose }
    }
    pub fn import_key(
        &mut self,
        slot: SlotId,
        key_data: &[u8],
        pin_policy: PinPolicy,
        touch_policy: TouchPolicy,
        force: bool,
    ) -> Result<(), Error> {
        self.device.authenticate(MgmKey::default())?;

        // metadata check
        let existing = self.device.metadata(slot).is_ok();

        if existing && !force {
            return Err(Error::KeyAlreadyExists);
        }

        if self.verbose {
            println!("Importing Key on {:?}", slot);
        }

        let key_info = self
            .device
            .import_key(slot, key_data, pin_policy, touch_policy)?;

        if self.verbose {
            println!("Key imported successfully");
            info!("Public key info: {:?}", key_info);
        }

        // Perform the same post-import logging as generate_key?
        // Let's print the address immediately to be helpful.

        let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&key_info.public_key)
            .expect("ecdsa key expected");
        let binding = vk.to_encoded_point(true);
        let pk_bytes = binding.as_bytes();
        if self.verbose {
            info!("Public key bytes: {:?}", pk_bytes);
        }

        let secp_pk = Secp256r1PublicKey::from_bytes(pk_bytes).unwrap();
        let mut sui_pk = vec![SignatureScheme::Secp256r1.flag()];
        sui_pk.extend(secp_pk.as_ref());

        let mut suiaddress_hash = Blake2b256::new();
        suiaddress_hash.update(sui_pk);
        let sui_address = suiaddress_hash.finalize().digest;

        if self.verbose {
            println!("Sui Address: 0x{}", Hex::encode(sui_address));
        }

        Ok(())
    }

    pub fn generate_key(
        &mut self,
        slot: SlotId,
        mgmt_key: Option<MgmKey>,
        force: bool,
    ) -> Result<(), Error> {
        let algorithm = AlgorithmId::EccP256;

        self.device.authenticate(mgmt_key.unwrap_or_default())?;
        let existing_data = self.device.metadata(slot).ok();
        if existing_data.is_some() && !force {
            return Err(Error::KeyAlreadyExists);
        }
        if self.verbose {
            println!("Generating Key on {:?}", slot);
        }

        let key_info =
            self.device
                .generate(slot, algorithm, PinPolicy::Once, TouchPolicy::Always)?;
        if self.verbose {
            println!("Key generated successfully");
            info!("Public key info: {:?}", key_info);
        }

        let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&key_info.public_key)
            .expect("ecdsa key expected");
        let binding = vk.to_encoded_point(true);
        let pk_bytes = binding.as_bytes();
        if self.verbose {
            info!("Public key bytes: {:?}", pk_bytes);
        }

        let secp_pk = Secp256r1PublicKey::from_bytes(pk_bytes).unwrap();
        let mut sui_pk = vec![SignatureScheme::Secp256r1.flag()];
        sui_pk.extend(secp_pk.as_ref());

        let mut suiaddress_hash = Blake2b256::new();
        suiaddress_hash.update(sui_pk);
        let sui_address = suiaddress_hash.finalize().digest;

        if self.verbose {
            println!("Sui Address: 0x{}", Hex::encode(sui_address));
        }
        Ok(())
    }

    #[allow(dead_code)]
    pub fn metadata(&mut self, slot: SlotId) -> Result<DeviceMetadata, Error> {
        self.device.metadata(slot)
    }

    pub fn get_public_key(&mut self, slot: SlotId) -> Result<PublicKeyResponse, Error> {
        let metadata = self.device.metadata(slot)?;
        // Metadata now directly contains public key bytes (DeviceMetadata)

        let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&metadata.public_key)
            .expect("ecdsa key expected");
        let binding = vk.to_encoded_point(true);
        let pk_bytes = binding.as_bytes();

        let secp_pk = Secp256r1PublicKey::from_bytes(pk_bytes).unwrap();
        let mut sui_pk = vec![SignatureScheme::Secp256r1.flag()];
        sui_pk.extend(secp_pk.as_ref());

        let mut suiaddress_hash = Blake2b256::new();
        suiaddress_hash.update(sui_pk);
        let sui_address = suiaddress_hash.finalize().digest;

        let key_id = format!("{:?}", slot)
            .replace("Retired(R", "")
            .replace(")", "");

        let public_key_b64 = Base64::encode(pk_bytes);

        Ok(PublicKeyResponse {
            key_id,
            public_key: PublicKey::Secp256r1(public_key_b64),
            sui_address: format!("0x{}", Hex::encode(sui_address)),
        })
    }

    pub fn sign_transaction(
        &mut self,
        slot: SlotId,
        data: &str,
        pin: &str,
    ) -> Result<String, Error> {
        let algorithm = AlgorithmId::EccP256;

        // Check if key exists (implicitly by getting metadata)
        let metadata = self.device.metadata(slot)?;

        let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&metadata.public_key)
            .expect("ecdsa key expected");
        let binding = vk.to_encoded_point(true);
        let pk_bytes = binding.as_bytes();

        let msg: TransactionData =
            bcs::from_bytes(&Base64::decode(data).map_err(|_| Error::SignatureFailed)?)
                .map_err(|_| Error::SignatureFailed)?;
        let intent_msg = IntentMessage::new(Intent::sui_transaction(), msg);
        let mut hasher = Blake2b256::new();
        hasher.update(bcs::to_bytes(&intent_msg).map_err(|_| Error::SignatureFailed)?);
        let digest = hasher.finalize().digest;

        let mut hasher2 = Sha256::default();
        hasher2.update(digest);
        let sha_digest = hasher2.finalize().digest;

        self.device.verify_pin(pin.as_bytes())?;

        if self.verbose {
            eprintln!("[*] Please touch your yubikey....");
        }

        let sig_bytes = self.device.sign_data(&sha_digest, algorithm, slot).unwrap();

        let mut output = Vec::new();
        if sig_bytes[3] == 33 {
            if sig_bytes[4] != 0 {
                panic!("Invalid form");
            }
            output.extend(&sig_bytes[5..(5 + 32)]);
        } else if sig_bytes[3] == 32 {
            output.extend(&sig_bytes[4..(4 + 32)]);
        } else {
            panic!("Invalid form");
        }
        output.extend(&sig_bytes[&sig_bytes.len() - 32..]);

        let sig = p256::ecdsa::Signature::from_slice(&output).unwrap();
        let normalized_sig = sig.normalize_s().unwrap_or(sig);

        let mut flag = vec![SignatureScheme::Secp256r1.flag()];
        flag.extend(normalized_sig.to_bytes());
        flag.extend(pk_bytes);

        let serialized_sig = Base64::encode(&flag);
        if self.verbose {
            println!(
                "Serialized signature (`flag || sig || pk` in Base64): {:?}",
                serialized_sig
            );
        }
        Ok(serialized_sig)
    }
}
