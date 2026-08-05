//! Minimal GUI for safe-txt (feature = "gui").

use std::path::PathBuf;

use eframe::egui;
use safe_txt::{DEFAULT_IDENTITY, DEFAULT_VAULT_NAME};
use safe_txt::crypto::{decrypt_file, encrypt_to_file, resolve_recipients};
use safe_txt::keys::{keygen, load_identities, public_keys};

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([780.0, 560.0])
            .with_title("safe-txt"),
        ..Default::default()
    };
    eframe::run_native(
        "safe-txt",
        options,
        Box::new(|_cc| Ok(Box::new(SafeTxtApp::default()))),
    )
}

struct SafeTxtApp {
    identity_path: String,
    file_path: String,
    text: String,
    status: String,
    pubkey: String,
    dirty: bool,
}

impl Default for SafeTxtApp {
    fn default() -> Self {
        Self {
            identity_path: DEFAULT_IDENTITY.to_string(),
            file_path: String::new(),
            text: String::new(),
            status: "Open or create an encrypted vault.".into(),
            pubkey: String::new(),
            dirty: false,
        }
    }
}

impl eframe::App for SafeTxtApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        egui::Panel::top("toolbar").show(ui, |ui| {
            ui.horizontal(|ui| {
                if ui.button("New key").clicked() {
                    self.action_keygen();
                }
                if ui.button("Show pubkey").clicked() {
                    self.action_pubkey();
                }
                ui.separator();
                if ui.button("Open…").clicked() {
                    self.action_open();
                }
                if ui.button("Save").clicked() {
                    self.action_save(false);
                }
                if ui.button("Save as…").clicked() {
                    self.action_save(true);
                }
            });
            ui.horizontal(|ui| {
                ui.label("Identity:");
                ui.text_edit_singleline(&mut self.identity_path);
                if ui.button("Browse…").clicked() {
                    if let Some(path) = rfd::FileDialog::new()
                        .add_filter("safe-txt lock", &["safelock"])
                        .add_filter("All", &["*"])
                        .pick_file()
                    {
                        self.identity_path = path.display().to_string();
                    }
                }
            });
            ui.horizontal(|ui| {
                ui.label("File:");
                ui.label(if self.file_path.is_empty() {
                    "(none)"
                } else {
                    self.file_path.as_str()
                });
                if self.dirty {
                    ui.weak("• unsaved");
                }
            });
        });

        egui::Panel::bottom("status").show(ui, |ui| {
            ui.label(&self.status);
            if !self.pubkey.is_empty() {
                ui.horizontal(|ui| {
                    ui.label("Public key:");
                    ui.monospace(&self.pubkey);
                    if ui.button("Copy").clicked() {
                        ui.ctx().copy_text(self.pubkey.clone());
                        self.status = "Public key copied.".into();
                    }
                });
            }
        });

        egui::CentralPanel::default().show(ui, |ui| {
            let response = ui.add_sized(
                ui.available_size(),
                egui::TextEdit::multiline(&mut self.text).code_editor(),
            );
            if response.changed() {
                self.dirty = true;
            }
        });
    }
}

impl SafeTxtApp {
    fn action_keygen(&mut self) {
        let path = PathBuf::from(&self.identity_path);
        match keygen(&path, false) {
            Ok(recipient) => {
                self.pubkey = recipient.to_string();
                self.status = format!("Identity written to {}", path.display());
            }
            Err(err) => self.status = format!("Keygen failed: {err:#}"),
        }
    }

    fn action_pubkey(&mut self) {
        let path = PathBuf::from(&self.identity_path);
        match public_keys(&path) {
            Ok(keys) => {
                self.pubkey = keys.first().cloned().unwrap_or_default();
                self.status = "Loaded public key.".into();
            }
            Err(err) => self.status = format!("Pubkey failed: {err:#}"),
        }
    }

    fn action_open(&mut self) {
        let Some(path) = rfd::FileDialog::new()
            .add_filter("safe-txt vault", &["safetxt"])
            .add_filter("age (compat)", &["age"])
            .add_filter("All", &["*"])
            .pick_file()
        else {
            return;
        };

        let identity = PathBuf::from(&self.identity_path);
        match load_identities(&identity).and_then(|ids| decrypt_file(&path, &ids)) {
            Ok(bytes) => match String::from_utf8(bytes) {
                Ok(text) => {
                    self.text = text;
                    self.file_path = path.display().to_string();
                    self.dirty = false;
                    self.status = format!("Opened {}", path.display());
                }
                Err(_) => {
                    self.status = "File is not valid UTF-8 text.".into();
                }
            },
            Err(err) => self.status = format!("Open failed: {err:#}"),
        }
    }

    fn action_save(&mut self, force_dialog: bool) {
        let path = if force_dialog || self.file_path.is_empty() {
            let picked = rfd::FileDialog::new()
                .add_filter("safe-txt vault", &["safetxt"])
                .add_filter("age (compat)", &["age"])
                .set_file_name(DEFAULT_VAULT_NAME)
                .save_file();
            match picked {
                Some(p) => p,
                None => return,
            }
        } else {
            PathBuf::from(&self.file_path)
        };

        let identity = PathBuf::from(&self.identity_path);
        match resolve_recipients(&[], &identity)
            .and_then(|recipients| encrypt_to_file(self.text.as_bytes(), &recipients, &path))
        {
            Ok(()) => {
                self.file_path = path.display().to_string();
                self.dirty = false;
                self.status = format!("Saved {}", path.display());
            }
            Err(err) => self.status = format!("Save failed: {err:#}"),
        }
    }
}
