# Yubikey Signer

EXPERIMENTAL: This is an experimental implementation of a Yubikey signer for Sui. It is not yet ready for production use. Not recommended for use in production.

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
  generate-key  Generate Key by default on RetiredSlot1, use --slot-id to choose retired slot 1-20
  import        Import a key from a mnemonic phrase
  sign          Sign a transaction digest
  call          JSON-RPC mode for integration with Sui CLI (reads from stdin)
  address       Prints the Sui Address for the key in the given slot (default R1)
  help          Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

`cargo run sign --data "<Base64 TX Bytes"` -> Must Generate key before on R1 Slot

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
# Touch your YubiKey to confirm
```

## Import a Key

You can import a key from a standard 12 or 24 word mnemonic phrase. This supports standard BIP-32 derivation paths.

**Basic Import (Defaults to Retired Slot 1):**

```bash
yubikey-signer import --words "word1 word2 ... word12"
```

**Advanced Import:**

You can specify the specific slot, force overwrite, and set security policies.

```bash
yubikey-signer import \
  --words "word1 word2 ..." \
  --slot 2 \
  --force \
  --pin-policy once \
  --touch-policy cached \
  --derivation-path "m/44'/784'/0'/0/0"
```

## Using a non-default pin

By default, the signer will attempt to use pinentry to prompt for the pin, then fallback to the default pin for YubiKeys, which is "123456". Optionally, you can also set the `YUBIKEY_PIN` environment variable to the pin you have set on your YubiKey.

```bash
YUBIKEY_PIN="your-pin-here" [sui command]
```
