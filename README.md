# safe-txt

A small encrypted text vault. Files use the [age](https://age-encryption.org/) format (X25519 + ChaCha20-Poly1305). Encrypt with a **public** key; open only with the matching **private** identity.

## Build

```bash
# CLI (Windows / Linux)
cargo build --release

# CLI + GUI
cargo build --release --features gui
```

Binaries:

- `safe-txt` — command line
- `safe-txt-gui` — simple editor (needs `--features gui`)

## Quick start (CLI)

```bash
# 1. Create your private identity (prints your public key)
safe-txt keygen -o identity.txt

# Optional: passphrase-protect the identity file
safe-txt keygen -o identity.txt --passphrase

# 2. Create / edit a vault (opens $EDITOR / $VISUAL; notepad on Windows, vi on Linux)
safe-txt edit secrets.age

# 3. Print decrypted contents
safe-txt cat secrets.age

# Show your public key again
safe-txt pubkey -i identity.txt
```

Default identity path is `identity.txt` in the current directory (override with `-i` / `--identity`).

### Encrypt / decrypt utilities

```bash
# Encrypt stdin (or -f FILE) to yourself (recipient from identity)
echo "db_password=..." | safe-txt encrypt -o secrets.age

# Encrypt to someone else's public key
safe-txt encrypt -f note.txt -o note.age -r age1...

# Decrypt to a file
safe-txt decrypt -f secrets.age -o plain.txt
```

## Model

| Key | Can |
|-----|-----|
| Public (`age1...`) | Encrypt content *for* that identity |
| Private (`identity.txt`) | Decrypt / read vaults encrypted to you |

Personal vault: you encrypt to yourself. Someone with only your public key can create files you can open, but cannot read your existing vaults.

Files are interoperable with [`age`](https://github.com/FiloSottile/age) / [`rage`](https://github.com/str4d/rage).

## GUI

```bash
cargo run --features gui --bin safe-txt-gui
```

Set the identity path, use **New key** / **Open…** / **Save**. Same crypto modules as the CLI.

## Tips

- Keep `identity.txt` private and backed up. Losing it means losing access to your vaults.
- Prefer `--passphrase` on machines you share.
- Set `EDITOR` (or `VISUAL`) for a better CLI edit experience.
