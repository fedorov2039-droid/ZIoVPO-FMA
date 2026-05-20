# Task 2.3: Accounts Authentication Activation and Licensing

## Requirements

| Area | Requirement | Implementation |
|------|-------------|----------------|
| Service | Authenticate through HTTPS web-service client. | `AuthHttpClient` is the production HTTPS boundary and rejects non-HTTPS base URLs; current coursework flow uses deterministic mock behavior for local demonstration. |
| Service | Keep sensitive auth material only in RAM. | `AuthManager` stores internal session proofs in private memory fields and never writes them to disk or returns them through RPC. |
| Service | Support logout. | `AvLogout` clears auth state and also clears license state. |
| Service | Support license state and activation. | `LicenseManager` reports license state and accepts demo activation code `DEMO-1234`. |
| Service | Do not pass raw JWT/license ticket to GUI. | RPC DTOs contain only booleans, display name/login, license expiry, feature state, and sanitized errors. |
| Service | Register RPC interfaces for GUI auth/license. | `rpc/AntivirusRpc.idl` adds `AvGetAuthState`, `AvLogin`, `AvLogout`, `AvGetLicenseState`, `AvActivateProduct`, and `AvGetFeatureState`. |
| Service | Block features without license. | `FeatureGate` reports blocked state until auth and license are active. |
| GUI | Request current authenticated user on startup. | `MainWindow` polls RPC state and updates account/license labels. |
| GUI | Show login when unauthenticated. | `AuthDialog` prompts for login/password. |
| GUI | Show activation when license is missing. | `ActivationDialog` prompts for activation code. |
| GUI | Poll license state every 5-10 seconds. | `MainWindow` uses a 7 second `QTimer`. |
| GUI | Add account/logout menu. | `Аккаунт -> Выйти из аккаунта` calls RPC logout. |

## RPC Methods

- `AvGetAuthState`
- `AvLogin`
- `AvLogout`
- `AvGetLicenseState`
- `AvActivateProduct`
- `AvGetFeatureState`

## Safe DTO Fields

GUI receives only:

- `authenticated`
- `displayName`
- `login`
- `licenseActive`
- `licenseExpiresAt`
- `activationRequired`
- `featureBlockedReason`
- `lastError`

Raw JWT, refresh/access secrets, and license proof data stay in service RAM and are not persisted.

## Mock Mode

The current coursework build uses deterministic mock responses for demonstration:

- Login succeeds with any non-empty login/password except password `fail`.
- Login fails when password is empty or equals `fail`.
- License is absent after login.
- Activation succeeds with code `DEMO-1234`.
- Activation fails for other codes.

## Manual Scenario

1. Start service.
2. Start GUI through service, or use `--allow-standalone-debug` for local UI debugging.
3. Observe unauthenticated state and login form.
4. Enter password `fail` and verify an error is shown.
5. Enter a non-empty password and verify the user is shown.
6. Observe missing license and activation form.
7. Enter an invalid activation code and verify an error is shown.
8. Enter `DEMO-1234` and verify license expiry is shown.
9. Use `Аккаунт -> Выйти из аккаунта` and verify auth/license state is cleared.

## Build Verification

```powershell
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
rg -n "jwt|access|refresh|licenseTicket|ticket|token" src
```

## Limitations

- Real backend endpoints are represented by `AuthHttpClient` and can be wired to the previous server assignment URL later.
- Demo secrets are private in-memory placeholders; they are never logged or written to disk.
