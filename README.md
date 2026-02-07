# OpenMFA Plugin

A [Jenkins](https://www.jenkins.io/) plugin that adds **TOTP-based Multi-Factor Authentication (MFA)**. Users enroll with a compatible authenticator app (e.g. Google Authenticator, Authy) and enter a one-time code at login.

## Features

- **TOTP (RFC 6238)** with QR code enrollment
- **Global settings**: issuer name, require MFA for all users
- **User-level**: users manage and reset MFA from their profile

## Requirements

- Jenkins 2.516.3 or later

## Installation

1. Install the plugin from the [Jenkins Plugin Manager](https://plugins.jenkins.io/openmfa-plugin/) or build from source (see [Development](#development)).
2. In **Manage Jenkins → Security → OpenMFA Global Configuration** (issuer, require MFA).

## Usage

- **Enrolling MFA**: After logging in, go to the MFA setup link (from user profile) and scan the QR code with your authenticator app.
- **Logging in**: Enter username and password as usual, then enter the 6-digit code from your app when prompted.

## Development

```bash
mvn clean package
```

The `.hpi` is in `target/openmfa-plugin.hpi`. Run Jenkins with the plugin:

```bash
mvn jenkins:run
```

## License

MIT — see [LICENSE.md](LICENSE.md).
