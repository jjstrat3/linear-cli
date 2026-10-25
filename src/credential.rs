use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

pub const ENV_VAR: &str = "LINEAR_API_TOKEN";

/// Refresh OAuth tokens this many seconds before they expire.
const REFRESH_MARGIN_SECS: u64 = 300;

/// A Linear credential. Stored as JSON in the OS keychain, never on disk.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Credential {
    ApiKey {
        key: String,
    },
    #[serde(rename = "oauth")]
    OAuth {
        access_token: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        refresh_token: Option<String>,
        /// Unix seconds. `None` when unknown (e.g. a bare token from the env var).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expires_at: Option<u64>,
        #[serde(default)]
        scopes: Vec<String>,
    },
}

// Hand-written so a stray `{:?}` can never leak a token into logs.
impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Credential::ApiKey { .. } => f.write_str("ApiKey { key: <redacted> }"),
            Credential::OAuth {
                expires_at, scopes, ..
            } => f
                .debug_struct("OAuth")
                .field("access_token", &"<redacted>")
                .field("expires_at", expires_at)
                .field("scopes", scopes)
                .finish(),
        }
    }
}

impl Credential {
    /// Interpret a raw token from `LINEAR_API_TOKEN`. Personal API keys start
    /// with `lin_api_`; anything else is treated as an OAuth access token.
    pub fn from_raw_token(token: &str) -> Credential {
        let token = token.trim().to_string();
        if token.starts_with("lin_api_") {
            Credential::ApiKey { key: token }
        } else {
            Credential::OAuth {
                access_token: token,
                refresh_token: None,
                expires_at: None,
                scopes: Vec::new(),
            }
        }
    }

    /// Value for the HTTP `Authorization` header. Linear takes personal API
    /// keys bare and OAuth tokens as `Bearer`.
    pub fn authorization_header(&self) -> String {
        match self {
            Credential::ApiKey { key } => key.clone(),
            Credential::OAuth { access_token, .. } => format!("Bearer {access_token}"),
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Credential::ApiKey { .. } => "api_key",
            Credential::OAuth { .. } => "oauth",
        }
    }

    pub fn needs_refresh(&self, now: u64) -> bool {
        match self {
            Credential::OAuth {
                refresh_token: Some(_),
                expires_at: Some(exp),
                ..
            } => now + REFRESH_MARGIN_SECS >= *exp,
            _ => false,
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("credential serializes")
    }

    pub fn from_json(s: &str) -> Result<Credential> {
        serde_json::from_str(s)
            .map_err(|e| Error::Keychain(format!("stored credential is unreadable: {e}")))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Env,
    Keychain,
}

impl Source {
    pub fn describe(self) -> &'static str {
        match self {
            Source::Env => "env:LINEAR_API_TOKEN",
            Source::Keychain => "keychain",
        }
    }
}

/// Pick the credential to use: the env var wins, then the keychain.
/// `keychain` is only called when the env var is unset or empty, so CI and
/// headless sessions never touch the secret service.
pub fn resolve(
    env_value: Option<String>,
    keychain: impl FnOnce() -> Result<Option<Credential>>,
) -> Result<(Credential, Source)> {
    if let Some(v) = env_value.filter(|v| !v.trim().is_empty()) {
        return Ok((Credential::from_raw_token(&v), Source::Env));
    }
    match keychain() {
        Ok(Some(c)) => Ok((c, Source::Keychain)),
        Ok(None) | Err(Error::KeychainUnavailable(_)) => Err(Error::NotAuthenticated),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oauth(exp: Option<u64>, refresh: bool) -> Credential {
        Credential::OAuth {
            access_token: "s3cr3t".into(),
            refresh_token: refresh.then(|| "ref".into()),
            expires_at: exp,
            scopes: vec!["read".into()],
        }
    }

    #[test]
    fn raw_token_kinds_and_headers() {
        let k = Credential::from_raw_token(" lin_api_abc\n");
        assert_eq!(k.authorization_header(), "lin_api_abc");
        let o = Credential::from_raw_token("lin_oauth_xyz");
        assert_eq!(o.authorization_header(), "Bearer lin_oauth_xyz");
    }

    #[test]
    fn env_wins_and_skips_keychain() {
        let (c, s) = resolve(Some("lin_api_x".into()), || panic!("keychain touched")).unwrap();
        assert_eq!(s, Source::Env);
        assert_eq!(c.kind(), "api_key");
    }

    #[test]
    fn empty_env_falls_through_to_keychain() {
        let (_, s) = resolve(Some("  ".into()), || Ok(Some(oauth(None, false)))).unwrap();
        assert_eq!(s, Source::Keychain);
    }

    #[test]
    fn missing_keychain_means_not_authenticated() {
        let r = resolve(None, || Err(Error::KeychainUnavailable("no bus".into())));
        assert!(matches!(r, Err(Error::NotAuthenticated)));
        assert!(matches!(
            resolve(None, || Ok(None)),
            Err(Error::NotAuthenticated)
        ));
    }

    #[test]
    fn refresh_window() {
        assert!(!oauth(Some(10_000), true).needs_refresh(1_000));
        assert!(oauth(Some(1_200), true).needs_refresh(1_000));
        assert!(!oauth(Some(1_200), false).needs_refresh(1_000));
        assert!(!oauth(None, true).needs_refresh(1_000));
    }

    #[test]
    fn json_round_trip_and_debug_redacts() {
        let c = oauth(Some(5), true);
        assert_eq!(Credential::from_json(&c.to_json()).unwrap(), c);
        let dbg = format!("{:?}", Credential::from_raw_token("lin_api_secret"));
        assert!(!dbg.contains("secret"));
        assert!(!format!("{c:?}").contains("s3cr3t"));
    }
}
