//! Resolves the credential for a command and keeps OAuth tokens fresh.

use std::fs::{self, File};
use std::path::PathBuf;

use crate::credential::{self, Credential, Source};
use crate::error::{Error, Result};
use crate::{oauth, store};

pub fn env_token() -> Option<String> {
    std::env::var(credential::ENV_VAR).ok()
}

/// The credential to use right now, refreshing a stored OAuth token first if
/// it is about to expire.
pub fn current() -> Result<(Credential, Source)> {
    let (cred, source) = credential::resolve(env_token(), store::load)?;
    if source == Source::Keychain && cred.needs_refresh(oauth::now()) {
        return Ok((refresh_stored()?, source));
    }
    Ok((cred, source))
}

/// Refresh under a cross-process lock. Linear rotates refresh tokens, so two
/// agents refreshing at once would invalidate each other. The lock file holds
/// no secret.
fn refresh_stored() -> Result<Credential> {
    let _lock = lock_file()?;
    // Another process may have refreshed while we waited.
    let cred = store::load()?.ok_or(Error::NotAuthenticated)?;
    if !cred.needs_refresh(oauth::now()) {
        return Ok(cred);
    }
    let fresh = oauth::refresh(&cred)?;
    store::save(&fresh)?;
    Ok(fresh)
}

fn lock_path() -> PathBuf {
    dirs::cache_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("lin")
        .join("refresh.lock")
}

/// Held around every keychain write (login, refresh, logout) so a refresh in
/// another process can't overwrite a newer login, or resurrect a logged-out one.
pub fn lock_file() -> Result<File> {
    let path = lock_path();
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(|e| Error::Keychain(format!("lock dir: {e}")))?;
    }
    let file = File::create(&path).map_err(|e| Error::Keychain(format!("lock file: {e}")))?;
    file.lock()
        .map_err(|e| Error::Keychain(format!("lock file: {e}")))?;
    Ok(file)
}
