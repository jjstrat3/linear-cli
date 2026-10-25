mod api;
mod commands;
mod credential;
mod error;
mod http;
mod oauth;
mod output;
mod session;
mod store;

use std::io::{IsTerminal, Read};
use std::path::PathBuf;

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
    /// Read, create, update and comment on issues.
    #[command(subcommand)]
    Issues(IssuesCommand),
    /// Upload files to Linear.
    #[command(subcommand)]
    Files(FilesCommand),
    /// Attach links to issues.
    #[command(subcommand)]
    Attachments(AttachmentsCommand),
}

#[derive(Subcommand)]
enum IssuesCommand {
    /// Read an issue by identifier (ENG-123) or UUID.
    Read { id: String },
    /// Update an issue. --description replaces the whole description.
    Update {
        id: String,
        #[arg(long)]
        title: Option<String>,
        /// New description (markdown). Use `-` to read it from stdin.
        #[arg(long, conflicts_with = "description_file")]
        description: Option<String>,
        /// Read the new description from a file.
        #[arg(long)]
        description_file: Option<PathBuf>,
    },
    /// Create an issue.
    Create {
        #[arg(long)]
        title: String,
        /// Team key, e.g. ENG. Optional with --parent-ticket (uses the parent's team).
        #[arg(long)]
        team: Option<String>,
        /// Description (markdown). Use `-` to read it from stdin.
        #[arg(long, conflicts_with = "description_file")]
        description: Option<String>,
        #[arg(long)]
        description_file: Option<PathBuf>,
        /// Make the new issue a sub-issue of this one.
        #[arg(long)]
        parent_ticket: Option<String>,
        /// Issues the new issue blocks (comma-separated or repeated).
        #[arg(long, value_delimiter = ',')]
        blocks: Vec<String>,
    },
    /// Start a new comment thread on an issue.
    Discuss {
        id: String,
        /// Comment body (markdown). Use `-` to read it from stdin.
        #[arg(
            long,
            conflicts_with = "body_file",
            required_unless_present = "body_file"
        )]
        body: Option<String>,
        #[arg(long)]
        body_file: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum FilesCommand {
    /// Upload a file; prints its asset URL and a markdown snippet.
    Upload {
        path: PathBuf,
        /// Override the MIME type guessed from the extension.
        #[arg(long)]
        content_type: Option<String>,
    },
}

#[derive(Subcommand)]
enum AttachmentsCommand {
    /// Attach a URL to an issue.
    Create {
        id: String,
        #[arg(long)]
        url: String,
        #[arg(long)]
        title: String,
        #[arg(long)]
        subtitle: Option<String>,
    },
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
        Command::Issues(cmd) => issues(cmd).map(|v| (v, 0)),
        Command::Files(FilesCommand::Upload { path, content_type }) => {
            commands::file_upload(&client()?, &path, content_type).map(|v| (v, 0))
        }
        Command::Attachments(AttachmentsCommand::Create {
            id,
            url,
            title,
            subtitle,
        }) => commands::attachment_create(
            &client()?,
            &id,
            commands::NewAttachment {
                url,
                title,
                subtitle,
            },
        )
        .map(|v| (v, 0)),
    }
}

fn client() -> Result<api::Client> {
    let (cred, _) = session::current()?;
    Ok(api::Client::new(&cred))
}

/// Text from `--x <TEXT>` (where `-` means stdin) or `--x-file <PATH>`.
fn text_arg(inline: Option<String>, file: Option<PathBuf>) -> Result<Option<String>> {
    match (inline, file) {
        (Some(t), _) if t == "-" => {
            let mut s = String::new();
            std::io::stdin()
                .read_to_string(&mut s)
                .map_err(|e| Error::Usage(format!("reading stdin: {e}")))?;
            Ok(Some(s))
        }
        (Some(t), _) => Ok(Some(t)),
        (None, Some(path)) => std::fs::read_to_string(&path)
            .map(Some)
            .map_err(|e| Error::Usage(format!("can't read {}: {e}", path.display()))),
        (None, None) => Ok(None),
    }
}

fn issues(cmd: IssuesCommand) -> Result<Value> {
    match cmd {
        IssuesCommand::Read { id } => commands::issue_read(&client()?, &id),
        IssuesCommand::Update {
            id,
            title,
            description,
            description_file,
        } => {
            let description = text_arg(description, description_file)?;
            commands::issue_update(
                &client()?,
                &id,
                commands::IssueChanges { title, description },
            )
        }
        IssuesCommand::Create {
            title,
            team,
            description,
            description_file,
            parent_ticket,
            blocks,
        } => {
            let description = text_arg(description, description_file)?;
            commands::issue_create(
                &client()?,
                commands::NewIssue {
                    title,
                    description,
                    team,
                    parent: parent_ticket,
                    blocks,
                },
            )
        }
        IssuesCommand::Discuss {
            id,
            body,
            body_file,
        } => {
            let body = text_arg(body, body_file)?.unwrap_or_default();
            if body.trim().is_empty() {
                return Err(Error::Usage("comment body is empty".into()));
            }
            commands::issue_discuss(&client()?, &id, &body)
        }
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
