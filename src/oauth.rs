//! OAuth 2.0 authorization code flow with PKCE, as a public client: no
//! client secret ships in the binary. See docs/adr/0001.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use url::Url;

use crate::credential::Credential;
use crate::error::{Error, Result};
use crate::http;

/// The "LinCLI" OAuth application. Client IDs are public by design.
pub const CLIENT_ID: &str = "46bcf230063ae8578c372635cbb0eb22";
pub const REDIRECT_PORT: u16 = 47823;
pub const REDIRECT_URI: &str = "http://127.0.0.1:47823/callback";
pub const DEFAULT_SCOPES: &[&str] = &["read", "issues:create", "comments:create"];

const AUTHORIZE_URL: &str = "https://linear.app/oauth/authorize";
const TOKEN_URL: &str = "https://api.linear.app/oauth/token";
const REVOKE_URL: &str = "https://api.linear.app/oauth/revoke";
const LOGIN_TIMEOUT: Duration = Duration::from_secs(300);

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn random_urlsafe(bytes: usize) -> Result<String> {
    let mut buf = vec![0u8; bytes];
    getrandom::fill(&mut buf).map_err(|e| Error::OAuth(format!("no secure randomness: {e}")))?;
    Ok(URL_SAFE_NO_PAD.encode(buf))
}

/// RFC 7636 S256 code challenge.
pub fn code_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

pub fn authorize_url(scopes: &[String], state: &str, challenge: &str) -> Url {
    let mut url = Url::parse(AUTHORIZE_URL).expect("valid authorize URL");
    url.query_pairs_mut()
        .append_pair("client_id", CLIENT_ID)
        .append_pair("redirect_uri", REDIRECT_URI)
        .append_pair("response_type", "code")
        .append_pair("scope", &scopes.join(","))
        .append_pair("state", state)
        .append_pair("code_challenge", challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("prompt", "consent");
    url
}

/// Run the browser login and return a fresh credential.
pub fn login(scopes: &[String], open_browser: bool) -> Result<Credential> {
    // Bind before showing the URL so a busy port fails immediately.
    let listener = TcpListener::bind(("127.0.0.1", REDIRECT_PORT)).map_err(|e| {
        Error::OAuth(format!(
            "can't listen on 127.0.0.1:{REDIRECT_PORT} for the login callback: {e}"
        ))
    })?;
    let verifier = random_urlsafe(32)?;
    let state = random_urlsafe(16)?;
    let url = authorize_url(scopes, &state, &code_challenge(&verifier));

    eprintln!("Open this URL to sign in to Linear:\n\n  {url}\n");
    if open_browser {
        open_in_browser(url.as_str());
    }

    let code = wait_for_code(&listener, &state)?;
    exchange_code(&code, &verifier)
}

fn wait_for_code(listener: &TcpListener, state: &str) -> Result<String> {
    listener
        .set_nonblocking(true)
        .map_err(|e| Error::OAuth(e.to_string()))?;
    let deadline = Instant::now() + LOGIN_TIMEOUT;
    while Instant::now() < deadline {
        match listener.accept() {
            Ok((stream, _)) => {
                if let Some(result) = handle_callback(stream, state) {
                    return result;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => return Err(Error::OAuth(e.to_string())),
        }
    }
    Err(Error::OAuth(
        "timed out waiting for the browser login".into(),
    ))
}

/// Returns `None` for requests that aren't the callback (e.g. favicon).
fn handle_callback(mut stream: TcpStream, state: &str) -> Option<Result<String>> {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut line = String::new();
    BufReader::new(&stream).read_line(&mut line).ok()?;
    let result = parse_callback(&line, state)?;
    let body = match &result {
        Ok(_) => "Signed in to lin. You can close this tab.",
        Err(_) => "lin sign-in failed. Check your terminal for details.",
    };
    let _ = write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    Some(result)
}

/// Parse an HTTP request line like `GET /callback?code=..&state=.. HTTP/1.1`.
pub fn parse_callback(request_line: &str, expected_state: &str) -> Option<Result<String>> {
    let target = request_line.split_whitespace().nth(1)?;
    let url = Url::parse(&format!("http://127.0.0.1{target}")).ok()?;
    if url.path() != "/callback" {
        return None;
    }
    let get = |k: &str| {
        url.query_pairs()
            .find(|(key, _)| key == k)
            .map(|(_, v)| v.into_owned())
    };
    if get("state").as_deref() != Some(expected_state) {
        return Some(Err(Error::OAuth(
            "state mismatch in callback; login aborted".into(),
        )));
    }
    if let Some(err) = get("error") {
        let desc = get("error_description").unwrap_or_default();
        return Some(Err(Error::OAuth(
            format!("{err} {desc}").trim().to_string(),
        )));
    }
    Some(get("code").ok_or_else(|| Error::OAuth("callback had no code".into())))
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    scope: Option<Value>,
}

fn parse_scopes(v: Option<Value>) -> Vec<String> {
    match v {
        Some(Value::String(s)) => s
            .split([' ', ','])
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect(),
        Some(Value::Array(a)) => a
            .into_iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect(),
        _ => Vec::new(),
    }
}

fn token_request(form: &[(&str, &str)]) -> Result<Credential> {
    let mut resp = http::agent()
        .post(TOKEN_URL)
        .send_form(form.iter().copied())?;
    let status = resp.status();
    let body = resp.body_mut().read_to_string()?;
    if !status.is_success() {
        return Err(Error::OAuth(format!(
            "token endpoint returned {status}: {}",
            body.trim()
        )));
    }
    let t: TokenResponse = serde_json::from_str(&body)
        .map_err(|e| Error::OAuth(format!("bad token response: {e}")))?;
    Ok(Credential::OAuth {
        access_token: t.access_token,
        refresh_token: t.refresh_token,
        expires_at: t.expires_in.map(|s| now() + s),
        scopes: parse_scopes(t.scope),
    })
}

pub fn exchange_code(code: &str, verifier: &str) -> Result<Credential> {
    token_request(&[
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", CLIENT_ID),
        ("code_verifier", verifier),
    ])
}

/// Linear rotates refresh tokens: the returned credential carries a new one.
pub fn refresh(old: &Credential) -> Result<Credential> {
    let Credential::OAuth {
        refresh_token: Some(rt),
        scopes,
        ..
    } = old
    else {
        return Err(Error::OAuth("credential has no refresh token".into()));
    };
    let mut fresh = token_request(&[
        ("grant_type", "refresh_token"),
        ("refresh_token", rt),
        ("client_id", CLIENT_ID),
    ])?;
    if let Credential::OAuth { scopes: s, .. } = &mut fresh
        && s.is_empty()
    {
        *s = scopes.clone();
    }
    Ok(fresh)
}

pub fn revoke(cred: &Credential) -> Result<()> {
    let Credential::OAuth {
        access_token,
        refresh_token,
        ..
    } = cred
    else {
        return Ok(());
    };
    // Revoking the refresh token ends the whole grant.
    let (token, hint) = match refresh_token {
        Some(rt) => (rt.as_str(), "refresh_token"),
        None => (access_token.as_str(), "access_token"),
    };
    let resp = http::agent()
        .post(REVOKE_URL)
        .send_form([("token", token), ("token_type_hint", hint)])?;
    match resp.status().as_u16() {
        200 | 400 => Ok(()), // 400: already revoked
        s => Err(Error::OAuth(format!("revoke returned HTTP {s}"))),
    }
}

fn open_in_browser(url: &str) {
    use std::process::{Command, Stdio};
    let mut cmd = if cfg!(target_os = "macos") {
        let mut c = Command::new("open");
        c.arg(url);
        c
    } else if cfg!(windows) {
        // Avoids `cmd /c start`, which would reparse `&` in the URL.
        let mut c = Command::new("rundll32");
        c.args(["url.dll,FileProtocolHandler", url]);
        c
    } else if std::env::var_os("WSL_DISTRO_NAME").is_some() {
        let mut c = Command::new("wslview");
        c.arg(url);
        c
    } else {
        let mut c = Command::new("xdg-open");
        c.arg(url);
        c
    };
    let _ = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc7636_s256_vector() {
        assert_eq!(
            code_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn verifier_length_is_valid() {
        let v = random_urlsafe(32).unwrap();
        assert!((43..=128).contains(&v.len()));
    }

    #[test]
    fn authorize_url_has_pkce_params() {
        let url = authorize_url(&["read".into(), "write".into()], "st", "ch");
        let q: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(q["client_id"], CLIENT_ID);
        assert_eq!(q["scope"], "read,write");
        assert_eq!(q["code_challenge_method"], "S256");
        assert_eq!(q["redirect_uri"], REDIRECT_URI);
    }

    #[test]
    fn callback_parsing() {
        let ok = parse_callback("GET /callback?code=abc&state=st HTTP/1.1\r\n", "st");
        assert_eq!(ok.unwrap().unwrap(), "abc");
        assert!(parse_callback("GET /favicon.ico HTTP/1.1", "st").is_none());
        let bad_state = parse_callback("GET /callback?code=abc&state=evil HTTP/1.1", "st");
        assert!(bad_state.unwrap().is_err());
        let denied = parse_callback("GET /callback?error=access_denied&state=st HTTP/1.1", "st");
        assert!(
            denied
                .unwrap()
                .unwrap_err()
                .to_string()
                .contains("access_denied")
        );
    }

    #[test]
    fn scopes_from_string_or_array() {
        assert_eq!(parse_scopes(Some("read write".into())), ["read", "write"]);
        assert_eq!(parse_scopes(Some("read,write".into())), ["read", "write"]);
        assert_eq!(parse_scopes(Some(serde_json::json!(["read"]))), ["read"]);
    }
}
