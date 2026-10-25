# linear-cli

A Rust-based Linear CLI that your agents will love regardless of your platform.

The binary is called `lin`. It prints one line of JSON per command by default, so agents can parse it cheaply. Add `--human` for readable output.

## Why

Tokens are stored in the OS keychain, never on disk:

| Platform | Store |
|---|---|
| macOS | Keychain |
| Windows | Credential Manager |
| Linux / WSL | Secret Service (GNOME Keyring, KWallet, …) over D-Bus |

If no keychain is reachable, which is common on headless WSL, CI and cloud agent sessions, `lin` refuses to store anything. In that case, set `LINEAR_API_TOKEN` instead. See [docs/adr/0001](docs/adr/0001-token-storage-and-auth.md).

## Auth

```sh
lin auth login                        # OAuth (PKCE) in the browser
lin auth login --scope write          # also allow updating issues
lin auth login --no-browser           # just print the URL
lin auth login --with-token < key.txt # store a personal API key from stdin
lin auth status                       # where the token came from and who it is
lin auth logout                       # revoke the OAuth grant and remove it
```

- **Token order:** `LINEAR_API_TOKEN` first, then the keychain. The variable can hold either a personal API key (`lin_api_…`) or an OAuth access token.
- **Scopes:** by default OAuth asks for `read,issues:create,comments:create`. Updating issues needs Linear's broader `write` scope.
- **Callback ports:** OAuth login listens on `127.0.0.1` on the first free port of 7823, 4823 and 9823. Linear requires exact redirect URIs, and the ports are spread out so WSL mirrored networking on Windows (which reserves a moving 4096-port block) can never cover all three.
- **Refresh:** OAuth access tokens last 24 hours. `lin` refreshes them automatically, under a lock, so parallel agents don't clash.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ok |
| 2 | usage error |
| 3 | not signed in, or the keychain/OAuth failed |
| 4 | network or Linear API error |

Errors go to stderr as `{"error":{"code":"…","message":"…"}}`.

## Development

```sh
cargo test
cargo test -- --ignored   # round-trip through the real OS keychain
```
