use std::env;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};
use tempfile::{Builder, NamedTempFile};
use zeroize::Zeroize;

use crate::crypto::{decrypt_file, encrypt_to_file, resolve_recipients};
use crate::keys::load_identities;

/// Decrypt (or create empty), open in `$EDITOR`, then re-encrypt.
pub fn edit_encrypted_file(
    path: &Path,
    identity: &Path,
    recipient_args: &[String],
) -> Result<()> {
    let identities = load_identities(identity)?;
    let recipients = resolve_recipients(recipient_args, identity)?;

    let mut plaintext = if path.exists() {
        decrypt_file(path, &identities)?
    } else {
        Vec::new()
    };

    let editor = resolve_editor()?;

    // Close the file handle before launching the editor (required on Windows).
    let temp = Builder::new()
        .prefix("safe-txt-")
        .suffix(".txt")
        .tempfile()
        .context("create temp file")?;
    {
        let mut file = temp.as_file();
        file.write_all(&plaintext)
            .context("write plaintext to temp")?;
        file.flush().context("flush temp")?;
    }
    plaintext.zeroize();
    let temp_path = temp.into_temp_path();

    let status = Command::new(&editor)
        .arg(&temp_path)
        .status()
        .with_context(|| format!("launch editor `{editor}`"))?;

    if !status.success() {
        let _ = secure_wipe_path(&temp_path);
        let _ = temp_path.close();
        bail!("editor exited with {status}");
    }

    let mut updated = fs::read(&temp_path).context("read edited temp file")?;
    let _ = secure_wipe_path(&temp_path);
    let _ = temp_path.close();

    // Atomic-ish replace: write ciphertext to sibling temp then rename.
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let out_temp = NamedTempFile::new_in(parent).context("create output temp near target")?;
    encrypt_to_file(&updated, &recipients, out_temp.path())?;
    updated.zeroize();

    out_temp
        .persist(path)
        .map_err(|e| e.error)
        .with_context(|| format!("replace {}", path.display()))?;
    Ok(())
}

fn resolve_editor() -> Result<String> {
    if let Ok(editor) = env::var("VISUAL") {
        if !editor.trim().is_empty() {
            return Ok(editor);
        }
    }
    if let Ok(editor) = env::var("EDITOR") {
        if !editor.trim().is_empty() {
            return Ok(editor);
        }
    }
    if cfg!(windows) {
        Ok("notepad".to_string())
    } else {
        Ok("vi".to_string())
    }
}

fn secure_wipe_path(path: &Path) -> Result<()> {
    if let Ok(meta) = fs::metadata(path) {
        let len = meta.len() as usize;
        let mut zeros = vec![0u8; len.min(4 * 1024 * 1024)];
        if let Ok(mut file) = fs::OpenOptions::new().write(true).open(path) {
            let mut remaining = len;
            while remaining > 0 {
                let chunk = remaining.min(zeros.len());
                if file.write_all(&zeros[..chunk]).is_err() {
                    break;
                }
                remaining -= chunk;
            }
            let _ = file.flush();
        }
        zeros.zeroize();
    }
    Ok(())
}
