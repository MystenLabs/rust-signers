# Yubikey Signer

## Install the Signer

Add this repo to your local `PATH` and cargo install or optionally install from releases.

```bash
git clone git@github.com:MystenLabs/rust-signer.git
cd rust-signers
cargo install --path yubikey
```

## Yubikey CLI Commands

```
Usage: yubikey-signer <COMMAND>

Commands:
  generate-key  Generate Key by default on RetiredSlot13, use --slot-id to choose retired slot 1-20
  sign          Sign a transaction digest
  call          JSON-RPC mode for integration with Sui CLI (reads from stdin)
  address       Prints the Sui Address for the key in the given slot (default R13)
  help          Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

`cargo run sign --data "<Base64 TX Bytes"` -> Must Generate key before on R13 Slot

## Add A Key to Sui CLI

First ensure your YubiKey is connected, and you have generated a key on it using the `generate-key` command.

Then run:

```bash
sui external-keys list-keys yubikey-signer
# ╭────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
# │ keyId     │ ...                                                                                          │
# │ suiAddress│ 0x...                                                                                        │
# ...

sui external-keys add-existing "key-id-or-path" yubikey-signer
# OR
# This will attempt to use the first available retired slot, however it is not always possible to detect which slots are in use.
sui external-keys generate yubikey-signer
```

## Use the Key

Set your new key as active, then perform a sign operation:

```bash
sui client switch --address [sui-address]
sui client transfer --object-id [object-id] --to [to address]
```
