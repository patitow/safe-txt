//! Shared crypto and editing helpers for the `safe-txt` CLI and GUI.

pub mod crypto;
pub mod edit;
pub mod keys;

pub const DEFAULT_IDENTITY: &str = "identity.safelock";
pub const DEFAULT_VAULT_NAME: &str = "vault.safetxt";
