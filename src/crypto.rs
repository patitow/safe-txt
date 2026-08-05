use std::fs;
use std::io::{Read, Write};
use std::path::Path;

use anyhow::{Context, Result, bail};

/// Encrypt `plaintext` to one or more recipients and write ciphertext to `output`.
pub fn encrypt_to_file(
    plaintext: &[u8],
    recipients: &[Box<dyn age::Recipient + Send>],
    output: &Path,
) -> Result<()> {
    if recipients.is_empty() {
        bail!("at least one recipient is required");
    }

    let encryptor = age::Encryptor::with_recipients(
        recipients.iter().map(|r| r.as_ref() as &dyn age::Recipient),
    )
    .expect("recipients non-empty");

    let mut encrypted = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut encrypted)
        .context("start encryption")?;
    writer.write_all(plaintext).context("write plaintext")?;
    writer.finish().context("finish encryption")?;

    if let Some(parent) = output.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create directory {}", parent.display()))?;
        }
    }
    fs::write(output, encrypted).with_context(|| format!("write {}", output.display()))?;
    Ok(())
}

/// Decrypt an age file using the given identities.
pub fn decrypt_file(input: &Path, identities: &[Box<dyn age::Identity>]) -> Result<Vec<u8>> {
    if identities.is_empty() {
        bail!("at least one identity is required");
    }

    let encrypted = fs::read(input).with_context(|| format!("read {}", input.display()))?;
    let decryptor = age::Decryptor::new(&encrypted[..]).context("parse age header")?;
    let mut reader = decryptor
        .decrypt(identities.iter().map(|i| i.as_ref()))
        .context("decrypt (wrong identity or corrupted file)?")?;

    let mut plaintext = Vec::new();
    reader
        .read_to_end(&mut plaintext)
        .context("read decrypted payload")?;
    Ok(plaintext)
}

/// Resolve recipients: explicit `--recipient` values, otherwise derive from identity.
pub fn resolve_recipients(
    recipient_args: &[String],
    identity: &Path,
) -> Result<Vec<Box<dyn age::Recipient + Send>>> {
    if !recipient_args.is_empty() {
        let parsed = crate::keys::parse_recipients(recipient_args)?;
        return Ok(parsed
            .into_iter()
            .map(|r| Box::new(r) as Box<dyn age::Recipient + Send>)
            .collect());
    }

    crate::keys::recipients_from_identity(identity)
}
