//! API response types for Ledger Signer
pub use signer_types::*;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub device_name: String,
    pub device_version: String,
    pub sui_app_version: String,
    pub sui_app_major: u8,
    pub sui_app_minor: u8,
    pub sui_app_patch: u8,
    pub hardware_model: String,
    pub connection_type: String,
    pub usb_vendor_id: Option<u16>,
    pub usb_product_id: Option<u16>,
    pub usb_path: Option<String>,
}
