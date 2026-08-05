use std::fs;
use std::io::{Read, Write, stdin, stdout};
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use zeroize::Zeroize;

use safe_txt::DEFAULT_IDENTITY;
use safe_txt::crypto::{decrypt_file, encrypt_to_file, resolve_recipients};
use safe_txt::edit::edit_encrypted_file;
use safe_txt::keys::{keygen, load_identities, public_keys};

#[derive(Parser, Debug)]
#[command(
    name = "safe-txt",
    about = "Simple encrypted text vault (age / X25519)",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate a new identity (private key) file
    Keygen {
        /// Where to write the identity
        #[arg(short, long, default_value = DEFAULT_IDENTITY)]
        out: PathBuf,
        /// Protect the identity with a passphrase
        #[arg(short, long)]
        passphrase: bool,
    },
    /// Print public recipient key(s) for an identity
    Pubkey {
        #[arg(short, long, default_value = DEFAULT_IDENTITY)]
        identity: PathBuf,
    },
    /// Decrypt a vault file to stdout
    Cat {
        file: PathBuf,
        #[arg(short, long, default_value = DEFAULT_IDENTITY)]
        identity: PathBuf,
    },
    /// Decrypt, edit in $EDITOR / $VISUAL, and re-encrypt
    Edit {
        file: PathBuf,
        #[arg(short, long, default_value = DEFAULT_IDENTITY)]
        identity: PathBuf,
        /// Extra recipients (defaults to your identity's public key)
        #[arg(short, long = "recipient")]
        recipients: Vec<String>,
    },
    /// Encrypt a file (or stdin) to one or more recipients
    Encrypt {
        /// Input file (omit or use - for stdin)
        #[arg(short = 'f', long)]
        input: Option<PathBuf>,
        /// Output ciphertext path
        #[arg(short, long)]
        output: PathBuf,
        #[arg(short, long, default_value = DEFAULT_IDENTITY)]
        identity: PathBuf,
        #[arg(short, long = "recipient")]
        recipients: Vec<String>,
    },
    /// Decrypt a file (or stdout if --output omitted)
    Decrypt {
        /// Input ciphertext
        #[arg(short = 'f', long)]
        input: PathBuf,
        /// Output plaintext path (stdout if omitted)
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(short, long, default_value = DEFAULT_IDENTITY)]
        identity: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Keygen { out, passphrase } => {
            let recipient = keygen(&out, passphrase)?;
            eprintln!("Identity written to {}", out.display());
            eprintln!("Public key written to {}", safe_txt::keys::pubkey_path(&out).display());
            println!("{recipient}");
        }
        Commands::Pubkey { identity } => {
            for key in public_keys(&identity)? {
                println!("{key}");
            }
        }
        Commands::Cat { file, identity } => {
            let identities = load_identities(&identity)?;
            let mut plaintext = decrypt_file(&file, &identities)?;
            stdout()
                .write_all(&plaintext)
                .context("write plaintext to stdout")?;
            plaintext.zeroize();
        }
        Commands::Edit {
            file,
            identity,
            recipients,
        } => {
            edit_encrypted_file(&file, &identity, &recipients)?;
            eprintln!("Saved {}", file.display());
        }
        Commands::Encrypt {
            input,
            output,
            identity,
            recipients,
        } => {
            let mut plaintext = read_input(input.as_deref())?;
            let resolved = resolve_recipients(&recipients, &identity)?;
            encrypt_to_file(&plaintext, &resolved, &output)?;
            plaintext.zeroize();
            eprintln!("Encrypted to {}", output.display());
        }
        Commands::Decrypt {
            input,
            output,
            identity,
        } => {
            let identities = load_identities(&identity)?;
            let mut plaintext = decrypt_file(&input, &identities)?;
            match output {
                Some(path) => {
                    fs::write(&path, &plaintext)
                        .with_context(|| format!("write {}", path.display()))?;
                    eprintln!("Decrypted to {}", path.display());
                }
                None => {
                    stdout()
                        .write_all(&plaintext)
                        .context("write plaintext to stdout")?;
                }
            }
            plaintext.zeroize();
        }
    }
    Ok(())
}

fn read_input(input: Option<&std::path::Path>) -> Result<Vec<u8>> {
    match input {
        None => {
            let mut buf = Vec::new();
            stdin()
                .read_to_end(&mut buf)
                .context("read stdin")?;
            if buf.is_empty() {
                bail!("no input on stdin");
            }
            Ok(buf)
        }
        Some(path) if path.as_os_str() == "-" => {
            let mut buf = Vec::new();
            stdin()
                .read_to_end(&mut buf)
                .context("read stdin")?;
            Ok(buf)
        }
        Some(path) => fs::read(path).with_context(|| format!("read {}", path.display())),
    }
}
