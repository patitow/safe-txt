//! End-to-end: passphrase lock + real CLI encrypt + decrypt (edit's crypto path).

use std::fs;
use std::io::{BufReader, Write};
use std::process::{Command, Stdio};

use age::armor::ArmoredReader;
use age::secrecy::SecretString;
use age::Callbacks;
use anyhow::{Context, Result, bail};
use tempfile::tempdir;

use safe_txt::crypto::{decrypt_file, encrypt_to_file, resolve_recipients};
use safe_txt::keys::{keygen_with_optional_passphrase, pubkey_path};

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

fn safe_txt_bin() -> Result<std::path::PathBuf> {
    for key in ["CARGO_BIN_EXE_safe_txt", "CARGO_BIN_EXE_safe-txt"] {
        if let Ok(p) = std::env::var(key) {
            return Ok(p.into());
        }
    }
    let target = std::env::var_os("CARGO_TARGET_DIR")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            let mut path = std::env::current_exe().ok()?;
            // .../target/<profile>/deps/<test> -> .../target
            path.pop();
            path.pop();
            path.pop();
            Some(path)
        })
        .context("locate target dir")?;
    for profile in ["release", "debug"] {
        for name in ["safe-txt.exe", "safe-txt"] {
            let candidate = target.join(profile).join(name);
            if candidate.exists() {
                return Ok(candidate);
            }
        }
    }
    bail!("safe-txt binary not found under {}", target.display())
}

fn decrypt_with_pass(lock: &std::path::Path, vault: &std::path::Path, pass: &str) -> Result<Vec<u8>> {
    let file = fs::File::open(lock)?;
    let identity = age::encrypted::Identity::from_buffer(
        ArmoredReader::new(BufReader::new(file)),
        Some(lock.display().to_string()),
        FixedPassphrase(SecretString::from(pass.to_owned())),
        None,
    )?
    .context("expected encrypted identity")?;
    decrypt_file(vault, &[Box::new(identity)])
}

#[test]
fn passphrase_lock_cli_encrypt_edit_save_path() -> Result<()> {
    let bin = safe_txt_bin()?;
    let dir = tempdir()?;
    let pass = "e2e-cli-passphrase-ok";
    let lock = dir.path().join("identity.safelock");
    let vault = dir.path().join("secrets.safetxt");

    // Same code path as `safe-txt keygen --passphrase` after the prompt.
    keygen_with_optional_passphrase(&lock, Some(SecretString::from(pass.to_owned())))?;
    assert!(lock.exists());
    assert!(pubkey_path(&lock).exists());
    let lock_text = fs::read_to_string(&lock)?;
    assert!(
        lock_text.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"),
        "lock must be ASCII-armored"
    );

    // Real CLI encrypt — this was failing with "non-identity data on line 1".
    let mut child = Command::new(&bin)
        .args(["encrypt", "-o", "secrets.safetxt"])
        .current_dir(dir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawn encrypt")?;
    {
        let stdin = child.stdin.as_mut().context("encrypt stdin")?;
        write!(stdin, "payload-from-cli-e2e")?;
    }
    let out = child.wait_with_output().context("wait encrypt")?;
    assert!(
        out.status.success(),
        "encrypt failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(vault.exists());

    // Same recipient resolution used by `edit` / `encrypt`.
    let recipients = resolve_recipients(&[], &lock).context("resolve_recipients")?;
    assert_eq!(recipients.len(), 1);

    let plaintext = decrypt_with_pass(&lock, &vault, pass)?;
    assert_eq!(plaintext, b"payload-from-cli-e2e");

    // Re-encrypt like `edit` save.
    let vault2 = dir.path().join("secrets2.safetxt");
    encrypt_to_file(b"edited-payload", &recipients, &vault2)?;
    let plaintext = decrypt_with_pass(&lock, &vault2, pass)?;
    assert_eq!(plaintext, b"edited-payload");

    Ok(())
}
