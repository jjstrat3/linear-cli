# 0001: Token storage and auth

Status: accepted (2026-10-25).

## Decision

1. **Keychain library:** use `keyring-core` 1.x with one store crate per OS, not the all-in-one `keyring` 4.x crate. keyring 4's own docs recommend this for apps that want to control their stores.
   - Linux / WSL: `zbus-secret-service-keyring-store` with `crypto-rust`. This is pure Rust, so it needs no libdbus or OpenSSL and keeps static musl builds possible.
   - macOS: `apple-native-keyring-store` (`keychain` feature).
   - Windows: `windows-native-keyring-store`.
2. **Token source order:**
   1. `LINEAR_API_TOKEN` env var
   2. OS keychain
   3. Fail with a clear error that names both options

   `auth status` reports which source was used, and never prints the token itself.
3. **Headless WSL / no secret service:** never fall back to a file. If the keychain can't be reached, `auth login` refuses to save the token and tells the user to set `LINEAR_API_TOKEN`. Jay agreed this on 2026-10-25. A passphrase-encrypted file stays a possible later option.
4. **OAuth PKCE in v1** as a public client, so no client secret ships in the binary.

## Spike results (Linux container, keyring-core 1.0.1 + zbus store 1.0.1)

| Scenario | Result | Time |
|---|---|---|
| No D-Bus session bus (typical headless WSL / CI) | `Store::new()` returns `PlatformFailure(Zbus(Connection … NotFound))` | under 1 ms |
| Session bus, keyring daemon auto-started but locked / no default collection | store initializes, then `set_password` returns `NoStorageAccess` | under 1 ms |
| Session bus + unlocked gnome-keyring | set, get and delete all work; get after delete gives `NoEntry` | set 6 ms, get 1 ms |

All failures were fast and nothing hung, so we can detect a missing keychain cheaply on every call and fall back without hurting startup time. The release spike binary is about 5 MB before stripping.

**Not tested yet:** macOS Keychain, Windows Credential Manager, and a desktop Linux session where an unlock prompt might block. These will be covered by the CI matrix in step 2. As a safeguard, wrap keychain calls in a timeout of about 3 s.

## OAuth PKCE notes

From Linear's [OAuth 2.0 docs](https://linear.app/developers/oauth-2-0-authentication):

- **Endpoints:** authorize `https://linear.app/oauth/authorize`, token `https://api.linear.app/oauth/token`, revoke `https://api.linear.app/oauth/revoke`.
- **PKCE:** use `S256`. `client_secret` is optional when PKCE is used.
- **Tokens:** access tokens last **24 h**. Refresh tokens **rotate on every refresh**, and a lost refresh can be replayed within 30 min.
  - So we store both the access and refresh tokens in the keychain.
  - We refresh shortly before expiry.
  - We take a lock file (it holds no secret) around refresh, so that parallel agent processes don't race the rotation.
- **Scopes:** `read`, `write`, `issues:create` (also covers attachments), `comments:create`, `admin`.
  - `issues update` and probably `files upload` need full `write`. Linear has no narrower update scope.
  - Proposal: `auth login` defaults to `read,issues:create,comments:create`, and `--scope write` is an opt-in.
- **Redirect:** the docs don't say whether loopback redirects with any port are allowed. Tested 2026-10-25: Linear rejects unregistered ports ("Invalid redirect_uri parameter"), even with a portless loopback URI registered, so ports must be fixed and registered.
- **Headers:** personal API keys go in `Authorization: <key>`, while OAuth tokens use `Authorization: Bearer <token>`. The env var path should accept either, telling them apart by the `lin_api_` prefix.

## Resolved

- Repo: `jjstrat3/linear-cli`.
- OAuth app "LinCLI" (Linear disallows "Linear" in app names). Client ID `46bcf230063ae8578c372635cbb0eb22`, callbacks `http://127.0.0.1:{7823,4823,9823}/callback`, tried in that order. On Windows with WSL `networkingMode=mirrored`, WSL reserves a 4096-port block on the host (44620–48715 on Jay's machine) that moves on each boot and fails binds with os error 10048. The ports are below 10000 and spread at least 4096 apart, so one block can never cover all three.
- Binary name: `lin`.
