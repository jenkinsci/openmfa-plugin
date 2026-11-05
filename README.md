# OpenMFA Plugin

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/jenkinsci/openmfa-plugin/master/LICENSE.md)
[![Jenkins Plugin](https://img.shields.io/jenkins/plugin/v/openmfa.svg)](https://plugins.jenkins.io/openmfa)
[![GitHub release](https://img.shields.io/github/release/jenkinsci/openmfa-plugin.svg?label=changelog)](https://github.com/jenkinsci/openmfa-plugin/releases/latest)
[![Jenkins Plugin Installs](https://img.shields.io/jenkins/plugin/i/openmfa.svg?color=blue)](https://plugins.jenkins.io/openmfa)

<img src="./images/mfa-logo-head.png" width="256" />

OpenMFA is a [Jenkins](https://www.jenkins.io/) plugin that adds TOTP-based MFA for interactive logins.
It introduces setup, verification, and management flows for user accounts inside Jenkins.

## Table of Contents

- [OpenMFA Plugin](#openmfa-plugin)
  - [Table of Contents](#table-of-contents)
  - [Features](#features)
  - [Requirements](#requirements)
  - [Getting Started](#getting-started)
  - [User Flow](#user-flow)
  - [MFA User Management](#mfa-user-management)
  - [Remember MFA ("Keep me signed in")](#remember-mfa-keep-me-signed-in)
  - [Security Keys (WebAuthn)](#security-keys-webauthn)
  - [Configuration as Code (JCasC)](#configuration-as-code-jcasc)
  - [MFA Exemptions](#mfa-exemptions)
  - [Ephemeral JENKINS_HOME (Kubernetes / jenkins-operator)](#ephemeral-jenkins_home-kubernetes--jenkins-operator)
  - [Security Notes](#security-notes)
  - [Development](#development)
    - [VS Code Debugging](#vs-code-debugging)
    - [Using the `.env` File](#using-the-env-file)
    - [Code Style](#code-style)
  - [License](#license)

## Features

- TOTP MFA using authenticator apps (RFC 6238 compatible)
- QR-based enrollment flow for end users
- Global admin configuration for issuer and enforcement
- MFA user management page for administrators
- Session-based MFA verification after primary login
- Remember MFA across sessions for users who check "Keep me signed in"
  (signed cookie, configurable duration, disabled by setting it to 0)
- WebAuthn (FIDO2) security keys and platform authenticators as an
  alternative second factor on top of TOTP
- Basic brute-force protection on code verification attempts
- Supports Jenkins dark theme for all UI elements
- Configurable exemptions for service accounts and specific roles

## Requirements

- Jenkins `2.568.3` or newer

## Getting Started

1. Install the plugin from the [Jenkins Plugin Manager](https://plugins.jenkins.io/openmfa-plugin/) or build it from source.
2. Go to `Manage Jenkins` -> `Security` -> `OpenMFA Configuration`.
3. Configure:
   - `Issuer Name`
   - `Require MFA for all users`
   - `Remember MFA for "Keep me signed in" (hours)` (default: 24, 0 disables)
   - `Exempt Users` (optional)
   - `Exempt Roles` (optional)
4. Save settings.
5. Ask users to enroll via the OpenMFA setup page before broad enforcement.

**Showcases**

![OpenMFA Global Configuration screen in Manage Jenkins](./images/mfa-global-configuration.png)
(OpenMFA Global Configuration: `Manage Jenkins` > `Security` > `OpenMFA Configuration`)

## User Flow

1. User signs in with username/password.
2. If MFA is required and the user is not enrolled, user is redirected to MFA setup.
3. User scans QR code in authenticator app and verifies setup.
4. On future logins, user enters a 6-digit TOTP code.

**Showcases**

![MFA setup page with QR code and verification input](./images/mfa-setup.png)
(MFA setup page: `User Property` > `Security` > `Setup MFA`)

![MFA login challenge page (6-digit code prompt)](./images/mfa-login-challenge.png)
(MFA login challenge: after Jenkins `login`)

![MFA enabled](./images/mfa-setup-enabled.png)
(MFA enabled: `User Property` > `Security` > `Manage MFA` )

![MFA User Property](./images/mfa-user-property.png)
(MFA enabled: `User Property` > `Security`)

## MFA User Management

- Go to `Manage Jenkins` > `MFA User Management`.
- Use this page to inspect enrollment state and perform admin-side MFA operations.

**Showcases**

![MFA user management table/actions page](./images/mfa-user-management.png)
(MFA user management: `Manage Jenkins` > `MFA User Management`)

## Remember MFA ("Keep me signed in")

By default, MFA verification lives only in the HTTP session, so every new
session (new browser session, session timeout, controller restart) triggers a
new MFA challenge -- even for users who checked Jenkins' "Keep me signed in"
at login.

With this feature, users who logged in with "Keep me signed in" receive a
long-lived `openmfa-remember` cookie after passing MFA and are not challenged
again until it expires. Users who log in without "Keep me signed in" keep the
per-session behavior.

How it works:

- The cookie is a stateless, HMAC-SHA256-signed token bound to the username,
  an absolute expiry, and the user's **MFA epoch** -- a method-agnostic
  value independent of any particular TOTP secret or security key, so the
  same binding and the same cookie work for either method (see
  [Security Keys (WebAuthn)](#security-keys-webauthn)). Nothing is stored
  server-side per device.
- Duration is configured by `Remember MFA for "Keep me signed in" (hours)`
  (default: 24). Setting it to `0` disables the feature entirely.
- The epoch -- and therefore every outstanding remember-MFA cookie for that
  user -- rotates on: re-enrolling or disabling TOTP, removing a security
  key, or an admin's full MFA reset. Adding a security key does **not**
  rotate it.
- Logging out clears the cookie.
- The signing key is generated automatically on first use and persisted in the
  global configuration. Rotating the key (or setting a new one via JCasC)
  immediately invalidates all issued remember-MFA cookies -- this is the
  emergency "forget all remembered devices" switch.

No configuration is required on a standard installation with a persistent
`JENKINS_HOME`. For ephemeral setups, see
[Ephemeral JENKINS_HOME](#ephemeral-jenkins_home-kubernetes--jenkins-operator).

## Security Keys (WebAuthn)

Enrolled users can register WebAuthn (FIDO2) security keys -- hardware keys
(YubiKey, Titan), platform authenticators (Touch ID, Windows Hello) or
passkeys -- as an alternative way to pass the MFA challenge.

- Keys require an **active TOTP enrollment**; TOTP stays the mandatory base
  method and the recovery path if every key is lost.
- Setup page: **registration is self-service only** (admins cannot register
  on a user's behalf); **removal is self-or-admin** (with an admin notice).
  Both require the acting session to have **passed MFA**, since the setup
  page is reachable before verification and a password alone must not add a
  key. No freshness window: a once-verified session stays eligible.
- Up to **10 keys** per user, names up to **64 characters**.
- Removing a key **rotates the MFA epoch**, invalidating all remember-MFA
  cookies for that user; adding one does not.
- Disabling TOTP (only while "Require MFA for all users" is off) deletes all
  keys in the same action and rotates the epoch; the dialog says so.
- The challenge defaults to the last successful method, with "Use code
  instead" / "Use security key" links; TOTP is always available.
- Remember-MFA is method-agnostic: either method issues the same cookie.
- **Admin side:** MFA User Management shows TOTP status and key count/names
  per user, and allows per-key removal or a full reset (TOTP + all keys). Key
  removal there needs only `Jenkins.ADMINISTER`: not gated by the admin's own
  MFA state, and works with `allowWebAuthn` off (it runs no ceremony).

### Configuration

- `allowWebAuthn` (default: on) -- kill switch; when off, WebAuthn UI is
  hidden and ceremony endpoints refuse. TOTP is unaffected.
- `webAuthnRpId` (advanced, default: empty = root URL hostname). **The RP ID
  is effectively permanent**: changing it invalidates every registered key.
- `webAuthnAllowedOrigins` (advanced, default: none) -- extra accepted
  origins. The root URL's origin is always allowed; an RP ID override adds
  **no** origin, so list every hostname Jenkins is served under.

```yaml
security:
  openMFA:
    allowWebAuthn: true
    webAuthnRpId: '' # empty derives it from the root URL hostname
    webAuthnAllowedOrigins:
      - 'https://jenkins.example.com'
```

### Threat model / operational notes

- Browsers require a secure context (HTTPS); `localhost` counts as secure,
  so `mvn hpi:run` works over HTTP.
- With no root URL and no `webAuthnRpId`, WebAuthn endpoints refuse with an
  error asking the admin to set the root URL; TOTP keeps working.
- The setup page is reachable before MFA (pre-existing lockout-recovery
  posture). Key registration is gated on a verified session; TOTP disable
  is not, and TOTP re-enrollment (`doEnable`) also marks the session
  verified -- so a password-only attacker could re-enroll TOTP and then pass
  the key gate. With `requireMFA` off the gate bounds rather than blocks
  this: re-enrollment is loud (the victim's authenticator stops working) and
  remembered-device cookies die on epoch rotation. Pre-existing upstream
  behavior, documented rather than changed.
- `java-webauthn-server` pins `com.upokecenter:cbor` `5.0.0-alpha2` (it
  parses attacker-controlled CBOR) plus `httpclient5` `5.7-beta1` and
  `httpcore5` `5.5-beta4`; revisit when upstream moves to stable releases.

### Manual end-to-end test script

HtmlUnit cannot drive `navigator.credentials`, so run this by hand with
Chrome's virtual authenticator and record pass/fail per step in the PR:

1. `mvn hpi:run`, open http://localhost:8080/jenkins. In DevTools -> More tools -> **WebAuthn**, enable the virtual authenticator environment and add one (`ctap2`, `internal` or `usb`, Resident Key + User verification).
2. Log in, enroll and verify TOTP; the key section appears (before verifying, a "verify MFA first" prompt replaces it). **Add security key** with a name; it lists with "last used: never".
3. Log out, log in with **Keep me signed in**: the challenge defaults to the key prompt, auto-completes, lands on the original page, and an `openmfa-remember` cookie is set.
4. In a new session (clear the session cookie or use Incognito with the same authenticator) the remember cookie alone admits you.
5. On the challenge page, **Use code instead** then **Use security key**: both toggle and the prompt re-triggers.
6. Click **Remove** on the setup page and confirm the dialog: removal must succeed. This is a plain form relying on `hudson-behavior` crumb injection (not `fetch`) -- check it is not rejected for a missing/stale crumb.
7. With the remember cookie still present, reload a protected page: a fresh MFA challenge appears (epoch rotated).
8. Re-add a key, disable TOTP from **Manage MFA**: the dialog warns keys will be removed, and both TOTP and the key are gone afterwards.
9. In the network tab, both the `webauthn-verify` assertion and the `webauthn-register-finish` attestation bodies **include** `clientExtensionResults` (typically `{}`) and are accepted. `webauthn-server-core` models it as non-null, so omitting it fails parsing -- a bug unit fixtures can miss.

## Configuration as Code (JCasC)

This plugin exposes global configuration and can be managed through Jenkins Configuration as Code.

Recommended workflow:

1. Configure OpenMFA once from the Jenkins UI.
2. Export current JCasC from your Jenkins instance.
3. Copy the OpenMFA section into your managed JCasC repository.
4. Apply via your standard `CASC_JENKINS_CONFIG` workflow.

Example:

```yaml
security:
  openMFA:
    issuer: 'Jenkins'
    requireMFA: true
    rememberMfaHours: 24
    # Optional. Omit to let the plugin generate and persist a key in
    # JENKINS_HOME. Set it explicitly (via any JCasC secret source, e.g.
    # Vault, env var, or mounted secret) when JENKINS_HOME is ephemeral,
    # so remember-MFA cookies survive restarts.
    rememberMfaKey: ${OPENMFA_REMEMBER_KEY}
    allowWebAuthn: true
    # Empty/omitted derives the RP ID from the Jenkins root URL hostname.
    # See "Security Keys (WebAuthn)" below before setting this explicitly --
    # changing it later invalidates every registered security key.
    webAuthnRpId: ''
    # Only needed when Jenkins is reachable under more than one hostname;
    # the root URL's own origin is always allowed implicitly.
    webAuthnAllowedOrigins: []
    exemptUsers:
      - svc-deploy
      - break-glass
    exemptRoles:
      - ci-agents
      - service-accounts
```

## MFA Exemptions

You can exempt specific users or roles from MFA requirements:

- **Exempt Users**: Individual usernames that bypass MFA (case-insensitive)
- **Exempt Roles**: Group/role names that bypass MFA for all members

Exemptions are useful for:

- Service accounts used by CI/CD pipelines
- Emergency break-glass accounts
- Automated agents that cannot complete MFA

**Note:** Exempted users bypass MFA entirely. Do not exempt regular user accounts.

## Ephemeral JENKINS_HOME (Kubernetes / jenkins-operator)

On setups where `JENKINS_HOME` does not survive restarts (e.g.
[jenkins-operator](https://github.com/jenkinsci/kubernetes-operator) with its
default ephemeral home), two pieces of state need attention:

- **Remember-MFA signing key** -- set `rememberMfaKey` via JCasC from an
  external secret source (Vault, Kubernetes Secret, env var). The key is then
  re-applied on every boot and issued cookies stay valid across pod restarts.
  Without it, each fresh instance generates a new key and all remembered
  devices are challenged again.
- **User TOTP enrollments** -- stored by Jenkins in `$JENKINS_HOME/users/` and
  encrypted with `$JENKINS_HOME/secrets/master.key`. These are runtime user
  data and cannot come from configuration: persist `users/` and `secrets/`
  together (PVC mounts or backup/restore), always as a pair -- one without the
  other is unusable.

## Security Notes

- Treat JCasC files and Jenkins configuration files as privileged, since they control authentication behavior.
- API token authentication is not challenged with interactive MFA. Basic auth with a real password is challenged; use API tokens for scripted access.
- OpenMFA uses per-session verification and redirects back to the original destination after successful MFA.
- The remember-MFA cookie is `HttpOnly`, `Secure` on HTTPS, HMAC-SHA256 signed
  with constant-time comparison, and carries no secret material -- only the
  username, expiry, and signature.
- See [Security Keys (WebAuthn)](#security-keys-webauthn) for the
  WebAuthn-specific threat model (RP ID permanence, HTTPS requirement, and
  the registration-gating rationale).

## Development

The `maven-hpi-plugin` offers important commands for Jenkins plugin development:

- **Build and package your plugin (.hpi):**

  ```bash
  mvn install
  ```

  This compiles the plugin and creates the `.hpi` file (e.g., `target/openmfa-plugin.hpi`), suitable for installation in Jenkins.

- **Run Jenkins in development mode with your plugin:**
  ```bash
  mvn hpi:run
  ```
  This starts a local Jenkins controller instance with your plugin pre-installed, typically at [http://localhost:8080/jenkins/](http://localhost:8080/jenkins/).

### VS Code Debugging

If you use Visual Studio Code, the repo includes a sample `.vscode/launch.json` for debugging Jenkins plugin development:

- **Debug Jenkins Plugin**:
  Attaches to a Jenkins process started with `mvn hpi:run` in debug mode (`-Dmaven.surefire.debug`), listening on port `5005`.

- **Debug Jenkins Plugin (mvnDebug)**:
  Attaches to Jenkins launched with `mvnDebug`, typically listening on port `8000`.

To use:

1. Open this repository in VS Code.
2. In VS Code, go to the "Run and Debug" panel and select a launch configuration.

You can set breakpoints in your Java code immediately.

### Using the `.env` File

You can configure your development environment by creating a `.env` file in the project root. This file is used to provide environment variables, such as `JAVA_HOME`, which are required for Maven or Jenkins commands.

- **Sample `.env` file:**
  ```
  JAVA_HOME=/path/to/your/java
  # JENKINS_HOME=/path/to/jenkins_home (optional)
  ```

**How to use:**

1. Copy `.env.example` to `.env`:
   ```bash
   cp .env.example .env
   ```
2. Edit `.env`, setting `JAVA_HOME` to your local Java installation and any other variables as needed.
3. The `.env` file is automatically loaded when running development commands via the provided `.vscode/run.sh` (used in `vscode/tasks.json`) script, ensuring your environment variables (like `JAVA_HOME`) are available.

**Tip:**
`.env` is ignored by git, so your local secrets and paths are not committed. Use `.env.example` as a starting point for other developers.

### Code Style

This project uses Spotless with Eclipse formatter rules from `fmt.xml`. It also ships a `prek` config in `.pre-commit-config.yaml`.

- Install git hooks with `prek`:

  ```bash
  prek install
  ```

- Run all configured checks/formatters with `prek`:

  ```bash
  prek run --all-files
  ```

- Check formatting:

  ```bash
  mvn spotless:check
  ```

- Apply formatting:
  ```bash
  mvn spotless:apply
  ```

Spotless checks are also executed during Maven `compile`, so formatting issues fail the build.

## License

MIT. See `LICENSE.md`.
