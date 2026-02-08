# Jenkins Secret management

Source: https://wiki.jenkins.io/display/JENKINS/Secret+management

## Overview

`hudson.util.Secret` manages sensitive data in Jenkins plugins. Values are encrypted using a confidential key generated the first time Jenkins starts on a fresh `JENKINS_HOME`. Used for storing secrets in XML config files, rendering password fields in the web UI, etc.

## Web UI (Stapler)

Stapler is configured to support `Secret` for data binding. You can use `Secret` in:

- `DataBoundConstructor` / `DataBoundSetter` arguments
- Getters

To accept a plain-text password and convert it: `Secret.fromString(plainText)`.

**`<f:password>`** (Jelly): Renders a `Secret` as an encrypted string so the real value is not exposed in the HTML DOM. If the user does not change the field, the encrypted value is bound back to a `Secret` by Stapler.

## Retrieving the plain value

Use **`Secret.toString(Secret)`** to get the decrypted plain text. The method accepts `null`.

**Avoid** relying on `Object.toString()` for decryption. Since 1.356 it is deprecated (it dumps the decrypted value). Because it is inherited from `Object`, the compiler may not warn when you accidentally use it—e.g. via string concatenation with `+`.
