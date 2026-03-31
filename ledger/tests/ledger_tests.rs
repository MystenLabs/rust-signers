/*
Warning these tests require a running emulator or ledger device.
*/
use base64::{Engine as _, engine::general_purpose};
use ledger_signer::{
    ledger::{get_public_key, get_tcp_connection, sign_transaction},
    path::get_derivation_path,
};

mod ledger_manager;
use ledger_manager::LedgerManager;
use anyhow::{anyhow, Result};
use ledger_signer::errors::AppError;

#[tokio::test]
async fn test_get_test_connection() {
    let _mgr = LedgerManager::acquire().await;

    // This test is for demonstration purposes only
    // In practice, you would use a mock or a real Ledger device
    let result = get_tcp_connection(9999).await;
    assert!(
        result.is_ok(),
        "Failed to get test connection: {:?}",
        result.err()
    );
}

#[tokio::test]
async fn test_get_public_key() {
    let _mgr = LedgerManager::acquire().await;

    let mut connection = get_tcp_connection(9999).await.unwrap();
    let derivation_path = get_derivation_path(0);
    let public_key = get_public_key(&derivation_path, &mut connection.0).await;
    assert!(
        public_key.is_ok(),
        "Failed to get public key: {:?}",
        public_key.err()
    );
}

#[tokio::test]
async fn test_sign_transaction() -> Result<()> {
    let mut mgr = LedgerManager::acquire().await;

    mgr.set_blind_signing(true).await.unwrap();

    let mut connection = get_tcp_connection(9999).await.unwrap();
    let derivation_path = get_derivation_path(0);

    let message = "message";
    let message = general_purpose::STANDARD.encode(message);

    let (signature_result, ledger_mgr_result) = tokio::join!(
        sign_transaction(derivation_path, &message, &mut connection),
        async {
            tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
            mgr.accept_transaction().await
        }
    );
    ledger_mgr_result?;
    let signature = signature_result?
        .signature;
    assert!(!signature.is_empty(), "Signature should not be empty");
    Ok(())
}


#[tokio::test]
async fn test_blind_sign_disabled() -> Result<()> {
    let mut mgr = LedgerManager::acquire().await;
    mgr.set_blind_signing(false).await?;

    let mut connection = get_tcp_connection(9999).await.unwrap();
    let derivation_path = get_derivation_path(0);

    let message = "message";
    let message = general_purpose::STANDARD.encode(message);

    let (signature_result, _ledger_mgr_result) = tokio::join!(
        sign_transaction(derivation_path, &message, &mut connection),
        async {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            mgr.send_keys(ledger_manager::SendKey::Right).await.unwrap();
            mgr.send_keys(ledger_manager::SendKey::Right).await.unwrap();
        }
    );

    match signature_result {
        Ok(_) => Err(anyhow!("Expected an error")),
        Err(e) => match e {
            AppError::BlindSigningNotEnabled => Ok(()),
            _ => Err(anyhow!("Expected BlindSigningNotEnabled error, got: {e:?}"))
        }
    }
}

#[tokio::test]
async fn test_set_blind_signing() -> Result<()>{
    let mut mgr = LedgerManager::acquire().await;
    // initial state
    mgr.set_blind_signing(true).await?;
    // true to true
    mgr.set_blind_signing(true).await?;
    // true to false
    mgr.set_blind_signing(false).await?;
    // false to false
    mgr.set_blind_signing(false).await?;
    // false to true
    mgr.set_blind_signing(true).await
}

#[tokio::test]
async fn test_go_home() -> Result<()> {
    let mgr = LedgerManager::acquire().await;
    mgr.go_home().await
}
