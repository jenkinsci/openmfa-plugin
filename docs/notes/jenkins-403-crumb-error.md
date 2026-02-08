# HTTP ERROR 403: No Valid Crumb Was Included in the Request

## Overview

The HTTP ERROR 403 "No valid crumb was included in the request" is a security error, almost exclusively encountered in the Jenkins automation server environment, caused by its Cross-Site Request Forgery (CSRF) protection feature. This protection mechanism requires a unique security token (a "crumb") for certain actions, and the error occurs when this token is missing or invalid.

## Common Causes

### Missing or Invalid CSRF Token
The most direct cause, often when a script or integration (like a GitHub webhook, Ansible, or an API call) fails to provide a valid crumb with its request.

### Session Misalignment
The crumb is tied to a specific web session ID. If the subsequent request does not retain the same session ID (e.g., due to browser cookie issues or proxy configurations), the crumb is rejected.

### Incorrect Jenkins URL Configuration
Mismatches between the URL used to access Jenkins (e.g., via a load balancer or VPN) and the URL configured in the system settings can invalidate crumbs.

### Plugin Conflicts or Outdated Plugins
The issue can arise after a Jenkins upgrade or an Active Directory plugin update, which may reset or conflict with security settings.

### External Interference
Firewalls, proxies, or antivirus software might strip necessary cookies or headers from the request.

## Troubleshooting Steps

### For Browser Users

1. **Clear browser cache and cookies**: Outdated data can cause session misalignment. Clear your browser's cache and cookies for the Jenkins domain.

2. **Use a consistent URL**: Ensure you consistently use the exact same hostname and protocol (e.g., `https://ci.example.com`, not mixing with `localhost` or an IP address) to access Jenkins.

3. **Use an incognito window**: This helps rule out issues with browser extensions or corrupted existing session data.

4. **Check for external interference**: Try accessing Jenkins from a different network or after temporarily disabling any VPN, antivirus, or firewall to see if they are stripping necessary information from the request.

5. **Check the server's clock**: Ensure the server's system clock is accurate, as time discrepancies can affect session validation.

6. **Enable proxy compatibility**: If Jenkins is behind a reverse proxy, go to **Manage Jenkins** → **Configure Global Security** → Under **CSRF Protection**, check **Enable proxy compatibility**.

### For API and Script Users

When making scripted or automated requests, using an API token is the recommended and most reliable approach, as it does not require a CSRF crumb.

1. **Generate an API Token**: In Jenkins, go to your user's **Configure** page and generate a new API token.

2. **Use the Token for Authentication**: Use the generated token in your script's HTTP requests for basic authentication (with your username and the token as the password). This bypasses the crumb requirement.

   Example:
   ```bash
   curl -X POST http://jenkins-url:8080/job/<job-name>/buildWithParameters?param=value --user <username>:<token>
   ```

3. **Use the Correct Webhook URL (for GitHub)**: If configuring a GitHub webhook, ensure you use the `JENKINS_URL/github-webhook/` endpoint, not the remote build trigger URL, as the former is designed to work with the GitHub plugin's authentication method. **Important**: Include the trailing slash `/` in the webhook URL.

4. **Install the Strict Crumb Issuer Plugin (Advanced)**: If using API tokens is not immediately feasible, you can install the **Strict Crumb Issuer Plugin** in Jenkins to adjust security settings, such as excluding the session ID from validation.

### Alternative: Using Crumbs with Session Management

If you must use crumbs (not recommended for scripts), you need to:

1. **Get the crumb with session cookie**:
   ```bash
   CRUMB=$(curl --cookie-jar ./cookie -sX GET https://jenkins-url/crumbIssuer/api/json --user <username>:<password> | cut -d'"' -f8)
   ```

2. **Use the same session cookie for subsequent requests**:
   ```bash
   curl --cookie ./cookie -X POST https://jenkins-url/job/<job-name>/build -H "Jenkins-Crumb: $CRUMB" --user <username>:<password>
   ```

**Note**: Since Jenkins 2.176.2, crumbs are only valid for the web session they were created in. Scripts must retain the web session ID between requests.

## Additional Solutions

### For Reverse Proxy Setups

If Jenkins is behind a reverse proxy (nginx, Apache, etc.):

1. Enable **Enable proxy compatibility** in **Manage Jenkins** → **Configure Global Security** → **CSRF Protection**
2. Ensure proper headers are forwarded:
   - `X-Forwarded-Host`
   - `X-Forwarded-Port`
   - `X-Forwarded-Proto`

### For Multibranch Pipelines

When using GitLab or GitHub webhooks with multibranch pipelines, use `/project/` instead of `/job/` in the webhook URL:
- ❌ `http://jenkins-url:8080/job/repo-name`
- ✅ `http://jenkins-url:8080/project/repo-name`

## When to Check System Logs

If the problem persists, consulting the Jenkins system logs can provide specific details, such as "Invalid crumb" warnings, to help diagnose the exact cause. Check:
- Jenkins system logs (`$JENKINS_HOME/logs/`)
- Browser developer console for network errors
- Reverse proxy logs (if applicable)

## Security Considerations

⚠️ **Important**: Do not disable CSRF protection unless absolutely necessary and only in isolated, secure environments. CSRF protection is a critical security feature that prevents unauthorized actions.

If you must disable CSRF protection (not recommended):
- Go to **Manage Jenkins** → **Configure Global Security**
- Uncheck **Prevent Cross Site Request Forgery exploits**
- Note: This option may not be available in newer Jenkins versions (2.303+)

## Source Code Implementation

The crumb functionality is implemented in Jenkins core. Here are the key classes:

### Base Class: `CrumbIssuer`

**Location**: `core/src/main/java/hudson/security/csrf/CrumbIssuer.java`

Abstract base class that defines the crumb issuing and validation interface. Key methods:
- `getCrumb(ServletRequest request)` - Retrieves or generates a crumb for the request
- `validateCrumb(ServletRequest request)` - Validates a crumb from request parameters
- `issueCrumb(ServletRequest request, String salt)` - Abstract method to create a crumb
- `validateCrumb(ServletRequest request, String salt, String crumb)` - Abstract method to validate a crumb

**Source**: [GitHub: CrumbIssuer.java](https://github.com/jenkinsci/jenkins/blob/master/core/src/main/java/hudson/security/csrf/CrumbIssuer.java)

### Default Implementation: `DefaultCrumbIssuer`

**Location**: `core/src/main/java/hudson/security/csrf/DefaultCrumbIssuer.java`

The default crumb issuer implementation. Key implementation details:

#### Crumb Generation (`issueCrumb` method)

```java
protected synchronized String issueCrumb(ServletRequest request, String salt) {
    if (request instanceof HttpServletRequest req) {
        if (md != null) {
            StringBuilder buffer = new StringBuilder();
            Authentication a = Jenkins.getAuthentication2();
            buffer.append(a.getName());
            if (!EXCLUDE_SESSION_ID) {
                buffer.append(';');
                buffer.append(req.getSession().getId());
            }

            md.update(buffer.toString().getBytes(StandardCharsets.UTF_8));
            return Util.toHexString(md.digest(salt.getBytes(StandardCharsets.US_ASCII)));
        }
    }
    return null;
}
```

**How it works**:
1. Gets the authenticated user's name from `Jenkins.getAuthentication2()`
2. Appends the session ID (unless `EXCLUDE_SESSION_ID` is set)
3. Creates a SHA-256 hash of: `username;sessionId` + salt
4. Returns the hexadecimal representation of the hash

#### Crumb Validation (`validateCrumb` method)

```java
public boolean validateCrumb(ServletRequest request, String salt, String crumb) {
    if (request instanceof HttpServletRequest) {
        String newCrumb = issueCrumb(request, salt);
        if (newCrumb != null && crumb != null) {
            return MessageDigest.isEqual(newCrumb.getBytes(StandardCharsets.US_ASCII),
                    crumb.getBytes(StandardCharsets.US_ASCII));
        }
    }
    return false;
}
```

**How it works**:
1. Generates a new crumb using the current request's user and session
2. Compares it with the submitted crumb using constant-time comparison (`MessageDigest.isEqual`)
3. Returns `true` only if they match exactly

#### Important Notes

- **Session ID binding**: Since Jenkins 2.176.2, crumbs are tied to the session ID. The crumb generated for one session won't validate for another session.
- **Salt**: A secret salt value is stored in `HexStringConfidentialKey` and is used to prevent crumb forgery.
- **SHA-256**: Uses SHA-256 message digest for cryptographic hashing.
- **Constant-time comparison**: Uses `MessageDigest.isEqual()` instead of `String.equals()` to prevent timing attacks.

**Source**: [GitHub: DefaultCrumbIssuer.java](https://github.com/jenkinsci/jenkins/blob/master/core/src/main/java/hudson/security/csrf/DefaultCrumbIssuer.java)

### API Endpoint

The `/crumbIssuer/api/json` endpoint is handled by the `CrumbIssuer` class's REST API implementation, which returns:

```json
{
    "_class": "hudson.security.csrf.DefaultCrumbIssuer",
    "crumb": "<hex-hash-value>",
    "crumbRequestField": "Jenkins-Crumb"
}
```

The crumb value is generated on-demand using `getCrumb()` which calls `issueCrumb()` with the current request context.

## References

- [Baeldung: Jenkins "No Valid Crumb" Request Error](https://www.baeldung.com/ops/jenkins-valid-crumb-request-error)
- [Stack Overflow: Jenkins 403 No valid crumb was included in the request](https://stackoverflow.com/questions/44711696/jenkins-403-no-valid-crumb-was-included-in-the-request)
- [Jenkins Documentation: Remote Access API](https://www.jenkins.io/doc/book/using/remote-access-api/)
- [Jenkins Security Advisory: SECURITY-626](https://www.jenkins.io/security/advisory/2019-06-25/)
- [GitHub: CrumbIssuer.java Source](https://github.com/jenkinsci/jenkins/blob/master/core/src/main/java/hudson/security/csrf/CrumbIssuer.java)
- [GitHub: DefaultCrumbIssuer.java Source](https://github.com/jenkinsci/jenkins/blob/master/core/src/main/java/hudson/security/csrf/DefaultCrumbIssuer.java)
