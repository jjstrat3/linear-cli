use serde_json::{Value, json};

pub type Result<T> = std::result::Result<T, Error>;

/// Every failure `lin` reports. Each variant maps to a stable `code` string
/// and exit status so agents can branch on them without parsing messages.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(
        "not signed in: run `lin auth login`, or set LINEAR_API_TOKEN for CI and headless sessions"
    )]
    NotAuthenticated,

    #[error("OS keychain unavailable ({0}); set LINEAR_API_TOKEN instead")]
    KeychainUnavailable(String),

    #[error("keychain error: {0}")]
    Keychain(String),

    #[error("OAuth error: {0}")]
    OAuth(String),

    #[error("network error: {0}")]
    Http(String),

    #[error("Linear API error: {message}")]
    Api { message: String, details: Value },

    #[error("{0}")]
    Usage(String),
}

impl Error {
    pub fn code(&self) -> &'static str {
        match self {
            Error::NotAuthenticated => "not_authenticated",
            Error::KeychainUnavailable(_) => "keychain_unavailable",
            Error::Keychain(_) => "keychain_error",
            Error::OAuth(_) => "oauth_error",
            Error::Http(_) => "network_error",
            Error::Api { .. } => "api_error",
            Error::Usage(_) => "usage_error",
        }
    }

    pub fn exit_code(&self) -> i32 {
        match self {
            Error::Usage(_) => 2,
            Error::NotAuthenticated
            | Error::KeychainUnavailable(_)
            | Error::Keychain(_)
            | Error::OAuth(_) => 3,
            Error::Http(_) | Error::Api { .. } => 4,
        }
    }

    pub fn to_json(&self) -> Value {
        let mut err = json!({ "code": self.code(), "message": self.to_string() });
        if let Error::Api { details, .. } = self {
            err["details"] = details.clone();
        }
        json!({ "error": err })
    }
}

impl From<ureq::Error> for Error {
    fn from(e: ureq::Error) -> Self {
        Error::Http(e.to_string())
    }
}
