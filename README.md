# safe-txt

A small encrypted text vault. Files use the [age](https://age-encryption.org/) format under the hood (X25519 + ChaCha20-Poly1305). Encrypt with a **public** key; open only with the matching **private** identity.

| Extension | What it is |
|-----------|------------|
| `.safelock` | Your private identity (key) |
| `.safetxt` | Encrypted vault text |

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
# 1. Create your private identity (prints your public key; also writes `identity.safelock.pub`)
safe-txt keygen -o identity.safelock

# Optional: passphrase-protect the identity file
safe-txt keygen -o identity.safelock --passphrase
# → creates identity.safelock (encrypted) + identity.safelock.pub (public key, safe to keep)

# 2. Create / edit a vault (opens $EDITOR / $VISUAL; notepad on Windows, vi on Linux)
safe-txt edit secrets.safetxt

# 3. Print decrypted contents
safe-txt cat secrets.safetxt

# Show your public key again
safe-txt pubkey -i identity.safelock
```

Default identity path is `identity.safelock` in the current directory (override with `-i` / `--identity`).

### Encrypt / decrypt utilities

```bash
# Encrypt stdin (or -f FILE) to yourself (recipient from identity)
echo "db_password=..." | safe-txt encrypt -o secrets.safetxt

# Encrypt to someone else's public key
safe-txt encrypt -f note.txt -o note.safetxt -r age1...

# Decrypt to a file
safe-txt decrypt -f secrets.safetxt -o plain.txt
```

## Model

| Key | Can |
|-----|-----|
| Public (`age1...`) | Encrypt content *for* that identity |
| Private (`.safelock`) | Decrypt / read vaults encrypted to you |

Personal vault: you encrypt to yourself. Someone with only your public key can create files you can open, but cannot read your existing vaults.

Content is still age-compatible (interop with [`age`](https://github.com/FiloSottile/age) / [`rage`](https://github.com/str4d/rage) if you pass the file explicitly).

## GUI

```bash
cargo run --features gui --bin safe-txt-gui
```

Set the identity path (`.safelock`), use **New key** / **Open…** / **Save** (`.safetxt`).

## Tips

- Keep `identity.safelock` private and backed up. Losing it means losing access to your vaults.
- Prefer `--passphrase` on machines you share.
- Set `EDITOR` (or `VISUAL`) for a better CLI edit experience.
