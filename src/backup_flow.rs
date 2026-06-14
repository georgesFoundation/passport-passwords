// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Portable encrypted backup/restore UI plumbing.
//!
//! Export writes a passphrase-encrypted `.vbpw` backup to a user-selected
//! directory. Restore reads a selected backup, decrypts it with the supplied
//! passphrase, stashes the records for confirmation, then the caller commits
//! them into the open keystore and persists the device-bound vault.

use std::sync::{Arc, Mutex};

use slint_keyos_platform::slint::{ComponentHandle, Weak};
use vaults_bridge_core::CredentialRecord;
use vaults_bridge_keystore::Keystore;

use crate::{AppWindow, Callbacks};

#[cfg(target_os = "xous")]
const BACKUP_FILE_NAME: &str = "passport-passwords-backup.vbpw";
#[cfg(target_os = "xous")]
const MAX_BACKUP_BYTES: usize = 4 * 1024 * 1024;

pub type PendingRestore = Arc<Mutex<Option<Vec<CredentialRecord>>>>;

pub fn new_pending_restore() -> PendingRestore { Arc::new(Mutex::new(None)) }

#[cfg(not(target_os = "xous"))]
pub fn export_encrypted_backup(
    _keystore: &Arc<Mutex<Keystore>>,
    _passphrase: &[u8],
    ui_weak: &Weak<AppWindow>,
) {
    set_error(ui_weak, "Backup export is only available on hardware.");
}

#[cfg(target_os = "xous")]
pub fn export_encrypted_backup(
    keystore: &Arc<Mutex<Keystore>>,
    passphrase: &[u8],
    ui_weak: &Weak<AppWindow>,
) {
    if passphrase.len() < 12 {
        set_error(ui_weak, "Use a backup passphrase of at least 12 characters.");
        return;
    }

    let backup = match keystore.lock().unwrap().export_backup(passphrase) {
        Ok(b) => b,
        Err(e) => {
            log::warn!("backup export failed: {e}");
            set_error(ui_weak, "Could not create encrypted backup.");
            return;
        }
    };

    let (dir, location) = match select_backup_dir() {
        Ok(Some(v)) => v,
        Ok(None) => return,
        Err(e) => {
            log::warn!("backup directory pick failed: {e}");
            set_error(ui_weak, "Could not choose a backup destination.");
            return;
        }
    };
    let path = join_dir(&dir, BACKUP_FILE_NAME);
    if let Err(e) = write_file(&path, location, &backup) {
        log::warn!("backup write failed: {e}");
        set_error(ui_weak, "Could not write the backup file.");
        return;
    }
    set_success(ui_weak, &format!("Encrypted backup saved to {path}. Keep its passphrase safe."));
}

#[cfg(not(target_os = "xous"))]
pub fn pick_restore_backup(_pending: &PendingRestore, _passphrase: &[u8], ui_weak: &Weak<AppWindow>) {
    set_error(ui_weak, "Backup restore is only available on hardware.");
}

#[cfg(target_os = "xous")]
pub fn pick_restore_backup(pending: &PendingRestore, passphrase: &[u8], ui_weak: &Weak<AppWindow>) {
    if passphrase.is_empty() {
        set_error(ui_weak, "Backup passphrase is required.");
        return;
    }

    let (path, location) = match select_backup_file() {
        Ok(Some(v)) => v,
        Ok(None) => return,
        Err(e) => {
            log::warn!("backup file pick failed: {e}");
            set_error(ui_weak, "Could not choose a backup file.");
            return;
        }
    };

    let bytes = match read_file(&path, location) {
        Ok(b) => b,
        Err(e) => {
            log::warn!("backup read failed: {e}");
            set_error(ui_weak, "Could not read the selected backup.");
            return;
        }
    };
    if bytes.len() > MAX_BACKUP_BYTES {
        set_error(ui_weak, "Backup file is too large.");
        return;
    }

    let records = match Keystore::records_from_backup(passphrase, &bytes) {
        Ok(records) => records,
        Err(e) => {
            log::warn!("backup decrypt failed: {e}");
            set_error(ui_weak, "Backup could not be opened. Check the passphrase.");
            return;
        }
    };
    if records.is_empty() {
        set_error(ui_weak, "Backup contains no passwords.");
        return;
    }

    let count = records.len();
    *pending.lock().unwrap() = Some(records);
    if let Some(ui) = ui_weak.upgrade() {
        let cb = ui.global::<Callbacks>();
        cb.set_backup_restore_count(count as i32);
        cb.set_backup_error("".into());
        cb.set_backup_success("".into());
    }
}

pub fn cancel_restore(pending: &PendingRestore) { *pending.lock().unwrap() = None; }

fn set_error(ui_weak: &Weak<AppWindow>, msg: &str) {
    if let Some(ui) = ui_weak.upgrade() {
        let cb = ui.global::<Callbacks>();
        cb.set_backup_error(msg.into());
        cb.set_backup_success("".into());
        cb.set_backup_restore_count(0);
    }
}

pub fn set_success(ui_weak: &Weak<AppWindow>, msg: &str) {
    if let Some(ui) = ui_weak.upgrade() {
        let cb = ui.global::<Callbacks>();
        cb.set_backup_success(msg.into());
        cb.set_backup_error("".into());
        cb.set_backup_restore_count(0);
    }
}

#[cfg(target_os = "xous")]
fn select_backup_dir() -> Result<Option<(String, slint_keyos_platform::fs::Location)>, String> {
    use slint_keyos_platform::{
        gui_server_api::navigation::filepicker::{AllowedLocations, SelectFileOptions},
        navigation::select_file,
    };

    use crate::gui_permissions::GuiPermissions;

    let opts = SelectFileOptions::default()
        .with_hidden_allowed(false)
        .with_dirs_allowed(true)
        .with_dir_selection_mode(true)
        .with_multiple_selection_mode(false)
        .with_allowed_locations(AllowedLocations::All);
    let selected = select_file::<GuiPermissions>(opts).map_err(|e| format!("{e:?}"))?;
    let Some((path, location)) = selected.and_then(|s| s.files().first().cloned()) else {
        return Ok(None);
    };
    Ok(Some((path, map_location(location))))
}

#[cfg(target_os = "xous")]
fn select_backup_file() -> Result<Option<(String, slint_keyos_platform::fs::Location)>, String> {
    use slint_keyos_platform::{
        gui_server_api::navigation::filepicker::{
            AllowedExtensions, AllowedLocations, SelectFileOptions,
        },
        navigation::select_file,
    };

    use crate::gui_permissions::GuiPermissions;

    let opts = SelectFileOptions::default()
        .with_hidden_allowed(false)
        .with_dirs_allowed(true)
        .with_dir_selection_mode(false)
        .with_multiple_selection_mode(false)
        .with_allowed_locations(AllowedLocations::All)
        .with_allowed_extensions(AllowedExtensions::specific(&["vbpw", "json"]));
    let selected = select_file::<GuiPermissions>(opts).map_err(|e| format!("{e:?}"))?;
    let Some((path, location)) = selected.and_then(|s| s.files().first().cloned()) else {
        return Ok(None);
    };
    Ok(Some((path, map_location(location))))
}

#[cfg(target_os = "xous")]
fn map_location(
    location: slint_keyos_platform::gui_server_api::navigation::filepicker::Location,
) -> slint_keyos_platform::fs::Location {
    use slint_keyos_platform::{fs, gui_server_api::navigation::filepicker::Location};
    match location {
        Location::Internal => fs::Location::User,
        Location::Airlock => fs::Location::Airlock,
        Location::External => fs::Location::Usb,
    }
}

#[cfg(target_os = "xous")]
fn write_file(path: &str, location: slint_keyos_platform::fs::Location, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;

    use slint_keyos_platform::fs::{FileSystem, OpenFlags};

    use crate::fs_permissions::FileSystemPermissions;

    let fs: FileSystem<FileSystemPermissions> = FileSystem::default();
    let mut file = fs
        .open_file(path.to_string(), location, OpenFlags { read: false, write: true, create: true })
        .map_err(|e| format!("open: {e:?}"))?;
    file.write_all(bytes).map_err(|e| format!("write: {e:?}"))?;
    file.flush().map_err(|e| format!("flush: {e:?}"))?;
    Ok(())
}

#[cfg(target_os = "xous")]
fn read_file(path: &str, location: slint_keyos_platform::fs::Location) -> Result<Vec<u8>, String> {
    use std::io::Read;

    use slint_keyos_platform::fs::{FileSystem, OpenFlags};

    use crate::fs_permissions::FileSystemPermissions;

    let fs: FileSystem<FileSystemPermissions> = FileSystem::default();
    let mut file = fs
        .open_file(path.to_string(), location, OpenFlags { read: true, write: false, create: false })
        .map_err(|e| format!("open: {e:?}"))?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).map_err(|e| format!("read: {e:?}"))?;
    Ok(buf)
}

#[cfg(target_os = "xous")]
fn join_dir(dir: &str, file: &str) -> String {
    let dir = dir.trim_end_matches('/');
    if dir.is_empty() {
        file.to_string()
    } else if dir == "/" {
        format!("/{file}")
    } else {
        format!("{dir}/{file}")
    }
}
