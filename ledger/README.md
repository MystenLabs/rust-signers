# Ledger Rust Signer

Ledger external signer support requires Sui CLI version 1.66.2 or newer.

## Install the Signer

You can install `ledger-signer` with `suiup`, from the GitHub Releases page, or build it from source.

### Install with `suiup`

```bash
suiup install ledger-signer
```

### Install from releases

Download the latest `ledger-signer` binary from the [releases page](https://github.com/MystenLabs/rust-signers/releases) and ensure it is available on your `PATH`.

### Build from source

Make sure you have Rust installed on your system, which you can do using [rustup](https://rustup.rs/).

```bash
git clone git@github.com:MystenLabs/rust-signers.git
cd rust-signers
cargo install --path ledger # installs `ledger-signer` binary
```

## Add A Key

First connect, unlock, and open the Sui app on your Ledger device. Ensure your Ledger firmware and Sui app are up to date.

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
