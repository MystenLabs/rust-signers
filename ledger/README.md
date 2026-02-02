# Ledger Rust Signer

## Install the Signer

Add this repo to your local `PATH` and cargo install or optionally install from releases.

```bash
git clone git@github.com:MystenLabs/rust-signer.git
cd rust-signers
cargo install --path ledger # installs `ledger-signer` binary
```

## Add  A Key

First connect, unlock and open the sui app on your ledger device. Ensure your ledger firmware and Sui app are up to date.

Then run:

```bash

sui external-keys list-keys ledger-signer
# ╭────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
# │ ╭───────────┬────────────────────────────────────────────────────────────────────────────────────────────╮ │
# │ │ keyId     │  **m/44'/784'/0'/0'/0'**                                                                       │ │
# │ │ isIndexed │  false                                                                                     │ │
# │ │ key       │ ╭─────────────────┬──────────────────────────────────────────────────────────────────────╮ │ │
# │ │           │ │ alias           │                                                                      │ │ │
# │ │           │ │ suiAddress      │  **0x9776b3322d1df8ff5ff573b8f8389cea550e16a6a8e3ce6c9ed9950a81a40b0e**  │ │ │
# ...
sui external-keys add-existing "m/44'/784'/0'/0'/0'" ledger-signer
# OR
sui external-keys generate ledger-signer
```

With the ledger signer you can use any valid derivation path with add-existing, not all paths will be present in the list-keys
output.

## Use the Key

Set your new key as active, then perform a sign operation:

```bash
sui client switch --address [sui-address]
sui client transfer --object-id [object-id] --to [to address]
# confirm on your ledger
```
