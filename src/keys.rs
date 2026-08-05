use std::fs;
use std::io::{Write, stdout};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use age::cli_common::{StdinGuard, UiCallbacks, read_identities};
use age::secrecy::{ExposeSecret, SecretString};
use age::x25519::{Identity, Recipient};
use anyhow::{Context, Result, anyhow, bail};

/// Generate a new identity and write it to `path`.
///
/// When `passphrase` is true, prompts for a passphrase and writes an age-encrypted
/// identity file (compatible with `IdentityFile` / `read_identities`).
pub fn keygen(path: &Path, passphrase: bool) -> Result<Recipient> {
    if path.exists() {
        bail!("refusing to overwrite existing identity: {}", path.display());
    }

    let identity = Identity::generate();
    let recipient = identity.to_public();
    let created = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let plaintext = format!(
        "# created: {created}\n# public key: {recipient}\n{secret}\n",
        recipient = recipient,
        secret = identity.to_string().expose_secret()
    );

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create directory {}", parent.display()))?;
        }
    }

    if passphrase {
        let pass = prompt_new_passphrase()?;
        let encrypted = age::encrypt(&age::scrypt::Recipient::new(pass), plaintext.as_bytes())
            .context("encrypt identity with passphrase")?;
        fs::write(path, encrypted)
            .with_context(|| format!("write identity {}", path.display()))?;
    } else {
        let mut file = fs::File::create(path)
            .with_context(|| format!("create identity {}", path.display()))?;
        file.write_all(plaintext.as_bytes())
            .with_context(|| format!("write identity {}", path.display()))?;
    }

    Ok(recipient)
}

/// Load identities from a file (supports passphrase-protected identity files).
pub fn load_identities(path: &Path) -> Result<Vec<Box<dyn age::Identity>>> {
    let mut guard = StdinGuard::new(true);
    read_identities(vec![path.display().to_string()], None, &mut guard)
        .with_context(|| format!("read identity {}", path.display()))
}

/// Parse one or more recipient strings (`age1...`).
pub fn parse_recipients(values: &[String]) -> Result<Vec<Recipient>> {
    let mut out = Vec::with_capacity(values.len());
    for value in values {
        let recipient: Recipient = value
            .parse()
            .map_err(|e| anyhow!("invalid recipient `{value}`: {e}"))?;
        out.push(recipient);
    }
    Ok(out)
}

/// Derive recipients from an identity file (uses the corresponding public keys).
pub fn recipients_from_identity(path: &Path) -> Result<Vec<Box<dyn age::Recipient + Send>>> {
    let file = age::IdentityFile::from_file(path.display().to_string())
        .with_context(|| format!("parse identity {}", path.display()))?
        .with_callbacks(UiCallbacks);
    file.to_recipients()
        .context("derive recipients from identity")
}

/// Print the public recipient(s) for an identity file.
pub fn public_keys(path: &Path) -> Result<Vec<String>> {
    // Fast path: plaintext identity with comment or AGE-SECRET-KEY lines.
    if let Ok(text) = fs::read_to_string(path) {
        let mut keys = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("# public key:") {
                let key = rest.trim().to_string();
                if !keys.contains(&key) {
                    keys.push(key);
                }
            } else if line.starts_with("AGE-SECRET-KEY-") {
                if let Ok(id) = line.parse::<Identity>() {
                    let key = id.to_public().to_string();
                    if !keys.contains(&key) {
                        keys.push(key);
                    }
                }
            }
        }
        if !keys.is_empty() {
            return Ok(keys);
        }
    }

    // Encrypted or unusual identity: convert via IdentityFile (may prompt passphrase).
    let file = age::IdentityFile::from_file(path.display().to_string())
        .with_context(|| format!("parse identity {}", path.display()))?
        .with_callbacks(UiCallbacks);
    let mut buf = Vec::new();
    file.write_recipients_file(&mut buf)
        .context("convert identity to recipients")?;
    let text = String::from_utf8(buf).context("recipients file utf-8")?;
    let keys: Vec<String> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect();
    if keys.is_empty() {
        bail!("could not derive public keys from {}", path.display());
    }
    Ok(keys)
}

fn prompt_new_passphrase() -> Result<SecretString> {
    eprint!("Passphrase: ");
    let _ = stdout().flush();
    let first = rpassword::read_password().context("read passphrase")?;
    eprint!("Confirm passphrase: ");
    let _ = stdout().flush();
    let second = rpassword::read_password().context("read passphrase confirmation")?;
    if first.is_empty() {
        bail!("passphrase must not be empty");
    }
    if first != second {
        bail!("passphrases do not match");
    }
    Ok(SecretString::from(first))
}
