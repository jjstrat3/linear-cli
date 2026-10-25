//! OS keychain access: Keychain on macOS, Credential Manager on Windows,
//! Secret Service (libsecret-compatible, over D-Bus) on Linux and WSL.
//!
//! Every call runs on a worker thread with a timeout, so a keychain that
//! blocks on an unlock prompt can't hang an agent.

use std::sync::{OnceLock, mpsc};
use std::time::Duration;

use keyring_core::{Entry, Error as KError};

use crate::credential::Credential;
use crate::error::{Error, Result};

#[cfg(not(test))]
const SERVICE: &str = "lin";
// Tests use their own entry so running them never touches a real login.
#[cfg(test)]
const SERVICE: &str = "lin-test";
const ACCOUNT: &str = "default";
const TIMEOUT: Duration = Duration::from_secs(3);

static INIT: OnceLock<std::result::Result<(), String>> = OnceLock::new();

fn init() -> Result<()> {
    INIT.get_or_init(|| {
        run_with_timeout(|| platform_store().map_err(|e| e.to_string()))
            .unwrap_or_else(|e| Err(e.to_string()))
    })
    .clone()
    .map_err(Error::KeychainUnavailable)
}

fn platform_store() -> keyring_core::Result<()> {
    #[cfg(target_os = "macos")]
    let store = apple_native_keyring_store::keychain::Store::new()?;
    #[cfg(target_os = "windows")]
    let store = windows_native_keyring_store::Store::new()?;
    #[cfg(all(unix, not(target_os = "macos")))]
    let store = zbus_secret_service_keyring_store::Store::new()?;
    keyring_core::set_default_store(store);
    Ok(())
}

fn run_with_timeout<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(TIMEOUT).map_err(|_| {
        Error::KeychainUnavailable(format!("no response within {}s", TIMEOUT.as_secs()))
    })
}

fn with_entry<T: Send + 'static>(
    f: impl FnOnce(&Entry) -> keyring_core::Result<T> + Send + 'static,
) -> Result<keyring_core::Result<T>> {
    init()?;
    run_with_timeout(move || Entry::new(SERVICE, ACCOUNT).and_then(|e| f(&e)))
}

fn map_err(e: KError) -> Error {
    match e {
        KError::NoStorageAccess(_) | KError::PlatformFailure(_) | KError::NoDefaultStore => {
            Error::KeychainUnavailable(e.to_string())
        }
        other => Error::Keychain(other.to_string()),
    }
}

pub fn load() -> Result<Option<Credential>> {
    match with_entry(|e| e.get_password())? {
        Ok(s) => Credential::from_json(&s).map(Some),
        Err(KError::NoEntry) => Ok(None),
        Err(e) => Err(map_err(e)),
    }
}

pub fn save(cred: &Credential) -> Result<()> {
    let json = cred.to_json();
    with_entry(move |e| e.set_password(&json))?.map_err(map_err)
}

/// Returns whether a credential was actually removed.
pub fn delete() -> Result<bool> {
    match with_entry(|e| e.delete_credential())? {
        Ok(()) => Ok(true),
        Err(KError::NoEntry) => Ok(false),
        Err(e) => Err(map_err(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Talks to the real OS keychain. CI runs it on every platform with
    /// `cargo test -- --ignored`.
    #[test]
    #[ignore]
    fn keychain_round_trip() {
        let cred = Credential::from_raw_token("lin_api_ci_round_trip");
        let _ = delete();
        assert_eq!(load().unwrap(), None);
        save(&cred).unwrap();
        assert_eq!(load().unwrap(), Some(cred));
        assert!(delete().unwrap());
        assert!(!delete().unwrap());
    }
}
