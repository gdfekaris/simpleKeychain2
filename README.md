# simpleKeychain2 (sk2)

A lightweight, local-only CLI password manager. No servers, no sync, no network. Your credentials stay on your machine, encrypted with your master password.

## How It Works

- Your master password is run through **Argon2id** to derive a 256-bit encryption key.
- Each credential (username + password) is encrypted with **XChaCha20-Poly1305** using a unique random nonce.
- Everything is stored in a local **SQLite** database (`vault.db`).

## Installation

Requires [Rust](https://www.rust-lang.org/tools/install) (1.85+).

```bash
git clone <repo-url>
cd sk2-dev
cargo build --release
```

The binary will be at `target/release/simpleKeychain2`. You can copy it somewhere on your `$PATH`:

```bash
cp target/release/simpleKeychain2 ~/.local/bin/sk2
```

## Usage

### Initialize the vault

Run this once to set your master password:

```bash
sk2 init
```

You'll be asked to enter and confirm your master password.

### Add a credential

```bash
sk2 add github
```

Prompts for username and password. If the service already exists, it will be overwritten.

### Retrieve a credential

```bash
sk2 get github
```

Prints the service name and username. The password is copied to your clipboard.

### Delete a credential

```bash
sk2 delete github
```

### List all services

```bash
sk2 list
```

All commands require your master password.

## Platform Support

Works on **Linux**, **macOS**, and **Windows**. Clipboard support is provided by [arboard](https://github.com/1Password/arboard) (maintained by 1Password).
