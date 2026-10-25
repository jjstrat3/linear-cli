mod api;
mod credential;
mod error;
mod http;
mod oauth;
mod output;
mod session;
mod store;

use std::io::{IsTerminal, Read};

use clap::{Parser, Subcommand};
use serde_json::{Value, json};

use credential::{Credential, Source};
use error::{Error, Result};
use output::Format;

/// A secure, fast Linear CLI for AI agents. Prints JSON by default.
#[derive(Parser)]
#[command(name = "lin", version)]
struct Cli {
    /// Human-readable output instead of JSON.
    #[arg(long, global = true)]
    human: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Sign in, check, or sign out.
    #[command(subcommand)]
    Auth(AuthCommand),
}

#[derive(Subcommand)]
enum AuthCommand {
    /// Sign in with OAuth in the browser, or store a personal API key.
    Login {
        /// Read a personal API key from stdin instead of using OAuth.
        #[arg(long)]
        with_token: bool,
        /// OAuth scopes, comma-separated. `read` is always included.
        #[arg(long, value_delimiter = ',', default_values_t = oauth::DEFAULT_SCOPES.iter().map(|s| s.to_string()))]
        scope: Vec<String>,
        /// Print the sign-in URL without opening a browser.
        #[arg(long)]
        no_browser: bool,
    },
    /// Show where the token comes from and who it belongs to.
    Status,
    /// Revoke the stored OAuth grant and remove it from the keychain.
    Logout,
}

fn main() {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) if !e.use_stderr() => e.exit(), // --help, --version
        Err(e) => {
            // Agents rely on JSON errors, even for bad arguments.
            let human = std::env::args().any(|a| a == "--human");
            let format = if human { Format::Human } else { Format::Json };
            let msg = e.render().to_string();
            let msg = msg.trim().trim_start_matches("error: ");
            let err = Error::Usage(msg.to_string());
            output::print_error(format, &err);
            std::process::exit(err.exit_code());
        }
    };
    let format = if cli.human {
        Format::Human
    } else {
        Format::Json
    };
    match run(cli.command) {
        Ok((value, code)) => {
            output::print(format, &value);
            std::process::exit(code);
        }
        Err(e) => {
            output::print_error(format, &e);
            std::process::exit(e.exit_code());
        }
    }
}

/// Returns the value to print and the exit code.
fn run(command: Command) -> Result<(Value, i32)> {
    match command {
        Command::Auth(AuthCommand::Login {
            with_token,
            scope,
            no_browser,
        }) => login(with_token, scope, !no_browser).map(|v| (v, 0)),
        Command::Auth(AuthCommand::Status) => Ok(status()),
        Command::Auth(AuthCommand::Logout) => logout().map(|v| (v, 0)),
    }
}

fn env_note(mut v: Value) -> Value {
    if session::env_token().is_some_and(|t| !t.trim().is_empty()) {
        v["note"] = json!("LINEAR_API_TOKEN is set and takes precedence over the keychain");
    }
    v
}

fn read_token_from_stdin() -> Result<String> {
    let mut stdin = std::io::stdin();
    let mut token = String::new();
    if stdin.is_terminal() {
        eprint!("Paste your Linear API key: ");
        stdin
            .read_line(&mut token)
            .map_err(|e| Error::Usage(e.to_string()))?;
    } else {
        stdin
            .read_to_string(&mut token)
            .map_err(|e| Error::Usage(e.to_string()))?;
    }
    let token = token.trim().to_string();
    if token.is_empty() {
        return Err(Error::Usage("no API key on stdin".into()));
    }
    Ok(token)
}

fn login(with_token: bool, mut scopes: Vec<String>, open_browser: bool) -> Result<Value> {
    let pasted = if with_token {
        Some(read_token_from_stdin()?)
    } else {
        None
    };
    // Fail before the browser dance if there's nowhere safe to keep the token.
    store::load()?;

    let cred = match pasted {
        Some(t) => Credential::from_raw_token(&t),
        None => {
            if !scopes.iter().any(|s| s == "read") {
                scopes.insert(0, "read".into());
            }
            oauth::login(&scopes, open_browser)?
        }
    };
    let me = api::Client::new(&cred).viewer()?;
    let _lock = session::lock_file()?;
    store::save(&cred)?;

    let mut v = json!({
        "status": "logged_in",
        "source": Source::Keychain.describe(),
        "kind": cred.kind(),
    });
    if let Credential::OAuth { scopes, .. } = &cred {
        v["scopes"] = json!(scopes);
    }
    v["user"] = me["user"].clone();
    v["organization"] = me["organization"].clone();
    Ok(env_note(v))
}

fn status() -> (Value, i32) {
    let (cred, source) = match session::current() {
        Ok(c) => c,
        Err(e) => {
            let keychain = match store::load() {
                Ok(_) => json!({ "available": true }),
                Err(Error::KeychainUnavailable(reason)) => {
                    json!({ "available": false, "reason": reason })
                }
                Err(e) => json!({ "available": true, "error": e.to_string() }),
            };
            let mut v = json!({ "authenticated": false, "source": null, "keychain": keychain });
            if !matches!(e, Error::NotAuthenticated) {
                v["error"] = e.to_json()["error"].clone();
            }
            return (v, 3);
        }
    };
    let mut v = json!({
        "authenticated": true,
        "source": source.describe(),
        "kind": cred.kind(),
    });
    if let Credential::OAuth {
        scopes, expires_at, ..
    } = &cred
    {
        v["scopes"] = json!(scopes);
        v["expires_at"] = json!(expires_at);
    }
    match api::Client::new(&cred).viewer() {
        Ok(me) => {
            v["user"] = me["user"].clone();
            v["organization"] = me["organization"].clone();
            (v, 0)
        }
        Err(e) => {
            v["authenticated"] = json!(false);
            v["error"] = e.to_json()["error"].clone();
            (v, e.exit_code())
        }
    }
}

fn logout() -> Result<Value> {
    let _lock = session::lock_file()?;
    let stored = store::load()?;
    let mut v = json!({ "status": "logged_out", "removed": false });
    if let Some(cred) = stored {
        match oauth::revoke(&cred) {
            Ok(()) => v["revoked"] = json!(cred.kind() == "oauth"),
            Err(e) => v["revoke_error"] = json!(e.to_string()),
        }
        v["removed"] = json!(store::delete()?);
    }
    Ok(env_note(v))
}
