use std::fs;
use std::io::{BufReader, Write, stdout};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use age::armor::ArmoredReader;
use age::cli_common::{StdinGuard, UiCallbacks, read_identities};
use age::secrecy::{ExposeSecret, SecretString};
use age::x25519::{Identity, Recipient};
use anyhow::{Context, Result, anyhow, bail};

/// Sidecar public-key file for an identity path (`foo.safelock` → `foo.safelock.pub`).
pub fn pubkey_path(identity: &Path) -> PathBuf {
    let mut s = identity.as_os_str().to_os_string();
    s.push(".pub");
    PathBuf::from(s)
}

/// Generate a new identity and write it to `path`.
///
/// Always writes a plaintext sidecar `{path}.pub` with the recipient (`age1...`).
/// When `passphrase` is true, the identity itself is ASCII-armored and passphrase-encrypted.
pub fn keygen(path: &Path, passphrase: bool) -> Result<Recipient> {
    if path.exists() {
        bail!("refusing to overwrite existing identity: {}", path.display());
    }

    let pass = if passphrase {
        Some(prompt_new_passphrase()?)
    } else {
        None
    };
    keygen_with_optional_passphrase(path, pass)
}

/// Same as [`keygen`], but with an explicit passphrase (for tests / non-interactive use).
pub fn keygen_with_optional_passphrase(
    path: &Path,
    passphrase: Option<SecretString>,
) -> Result<Recipient> {
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

    if let Some(pass) = passphrase {
        // Canonical passphrase identity: scrypt + ASCII armor (what age/rage expect).
        let encrypted =
            age::encrypt_and_armor(&age::scrypt::Recipient::new(pass), plaintext.as_bytes())
                .context("encrypt identity with passphrase")?;
        fs::write(path, encrypted.as_bytes())
            .with_context(|| format!("write identity {}", path.display()))?;
    } else {
        let mut file = fs::File::create(path)
            .with_context(|| format!("create identity {}", path.display()))?;
        file.write_all(plaintext.as_bytes())
            .with_context(|| format!("write identity {}", path.display()))?;
    }

    write_pubkey_sidecar(path, &recipient)?;
    Ok(recipient)
}

fn write_pubkey_sidecar(identity: &Path, recipient: &Recipient) -> Result<()> {
    let path = pubkey_path(identity);
    fs::write(&path, format!("{recipient}\n"))
        .with_context(|| format!("write public key {}", path.display()))?;
    Ok(())
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
            .trim()
            .parse()
            .map_err(|e| anyhow!("invalid recipient `{value}`: {e}"))?;
        out.push(recipient);
    }
    Ok(out)
}

/// Derive recipients from an identity file (prefer `.pub` sidecar; never parse armor as secret lines).
pub fn recipients_from_identity(path: &Path) -> Result<Vec<Box<dyn age::Recipient + Send>>> {
    if let Some(keys) = read_pubkey_sidecar(path)? {
        return Ok(keys
            .into_iter()
            .map(|r| Box::new(r) as Box<dyn age::Recipient + Send>)
            .collect());
    }

    // Plaintext identity: parse secret keys / comments.
    if let Ok(text) = fs::read_to_string(path) {
        if !text.trim_start().starts_with("-----BEGIN AGE ENCRYPTED FILE-----") {
            let mut keys = Vec::new();
            for line in text.lines() {
                let line = line.trim();
                if let Some(rest) = line.strip_prefix("# public key:") {
                    if let Ok(r) = rest.trim().parse::<Recipient>() {
                        keys.push(Box::new(r) as Box<dyn age::Recipient + Send>);
                    }
                } else if line.starts_with("AGE-SECRET-KEY-") {
                    if let Ok(id) = line.parse::<Identity>() {
                        keys.push(Box::new(id.to_public()) as Box<dyn age::Recipient + Send>);
                    }
                }
            }
            if !keys.is_empty() {
                return Ok(keys);
            }
        }
    }

    // Passphrase-protected identity without sidecar: decrypt via callbacks.
    let file = fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let reader = BufReader::new(file);
    let maybe = age::encrypted::Identity::from_buffer(
        ArmoredReader::new(reader),
        Some(path.display().to_string()),
        UiCallbacks,
        None,
    )
    .context("parse encrypted identity")?;

    match maybe {
        Some(enc) => enc.recipients().context("derive recipients (passphrase needed)"),
        None => bail!(
            "identity {} is not a valid age identity (missing {}.pub?)",
            path.display(),
            pubkey_path(path).display()
        ),
    }
}

fn read_pubkey_sidecar(identity: &Path) -> Result<Option<Vec<Recipient>>> {
    let path = pubkey_path(identity);
    if !path.exists() {
        return Ok(None);
    }
    let text = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    let mut keys = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        keys.push(
            line.parse::<Recipient>()
                .map_err(|e| anyhow!("invalid recipient in {}: {e}", path.display()))?,
        );
    }
    if keys.is_empty() {
        bail!("no recipients in {}", path.display());
    }
    Ok(Some(keys))
}

/// Print the public recipient(s) for an identity file.
pub fn public_keys(path: &Path) -> Result<Vec<String>> {
    if let Some(keys) = read_pubkey_sidecar(path)? {
        return Ok(keys.into_iter().map(|k| k.to_string()).collect());
    }

    if let Ok(text) = fs::read_to_string(path) {
        if text.trim_start().starts_with("-----BEGIN AGE ENCRYPTED FILE-----") {
            bail!(
                "passphrase-protected identity needs {} (re-run keygen, or create it with your age1... key)",
                pubkey_path(path).display()
            );
        }
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

    bail!("could not derive public keys from {}", path.display());
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{decrypt_file, encrypt_to_file, resolve_recipients};
    use age::Callbacks;
    use tempfile::tempdir;

    #[derive(Clone)]
    struct FixedPassphrase(SecretString);

    impl Callbacks for FixedPassphrase {
        fn display_message(&self, _: &str) {}
        fn confirm(&self, _: &str, _: &str, _: Option<&str>) -> Option<bool> {
            None
        }
        fn request_public_string(&self, _: &str) -> Option<String> {
            None
        }
        fn request_passphrase(&self, _: &str) -> Option<SecretString> {
            Some(self.0.clone())
        }
    }

    fn load_passphrase_identities(
        path: &Path,
        pass: SecretString,
    ) -> Result<Vec<Box<dyn age::Identity>>> {
        let file = fs::File::open(path)?;
        let identity = age::encrypted::Identity::from_buffer(
            ArmoredReader::new(BufReader::new(file)),
            Some(path.display().to_string()),
            FixedPassphrase(pass),
            None,
        )?
        .context("expected passphrase-encrypted identity")?;
        Ok(vec![Box::new(identity)])
    }

    #[test]
    fn passphrase_keygen_roundtrip_vault() {
        let dir = tempdir().unwrap();
        let identity = dir.path().join("identity.safelock");
        let vault = dir.path().join("secrets.safetxt");
        let pass = SecretString::from("test-passphrase-not-for-prod".to_owned());

        let recipient =
            keygen_with_optional_passphrase(&identity, Some(pass.clone())).unwrap();
        assert!(identity.exists());
        assert!(pubkey_path(&identity).exists());
        assert_eq!(
            public_keys(&identity).unwrap(),
            vec![recipient.to_string()]
        );

        // Armor header must be present (readable UTF-8).
        let text = fs::read_to_string(&identity).unwrap();
        assert!(
            text.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"),
            "got: {}",
            &text[..text.len().min(40)]
        );

        // Recipients must come from .pub without decrypting the lock.
        let recipients = resolve_recipients(&[], &identity).unwrap();
        assert_eq!(recipients.len(), 1);

        let plaintext = b"hello from vault";
        encrypt_to_file(plaintext, &recipients, &vault).unwrap();

        let identities = load_passphrase_identities(&identity, pass).unwrap();
        let out = decrypt_file(&vault, &identities).unwrap();
        assert_eq!(out, plaintext);
    }

    #[test]
    fn plaintext_keygen_roundtrip_vault() {
        let dir = tempdir().unwrap();
        let identity = dir.path().join("identity.safelock");
        let vault = dir.path().join("secrets.safetxt");

        keygen_with_optional_passphrase(&identity, None).unwrap();
        let recipients = resolve_recipients(&[], &identity).unwrap();
        encrypt_to_file(b"secret", &recipients, &vault).unwrap();

        let identities = load_identities(&identity).unwrap();
        let out = decrypt_file(&vault, &identities).unwrap();
        assert_eq!(out, b"secret");
    }
}
