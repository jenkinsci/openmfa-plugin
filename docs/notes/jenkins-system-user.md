# Jenkins SYSTEM User

Jenkins has a built-in `SYSTEM` user (`ACL.SYSTEM2`) that represents the system itself. This user has full permissions and is used for internal operations.

## Why Does Jenkins Need the SYSTEM User?

Jenkins runs many background operations that aren't triggered by a human user:
- SCM polling and webhooks
- Scheduled/timed builds
- Pipeline steps and internal queue processing
- Plugin initialization and cleanup tasks
- API calls from external systems

These operations need permissions to access jobs, workspaces, and credentials. The SYSTEM user provides a privileged context with full permissions so these internal operations can execute without being blocked by authorization checks.

## SYSTEM vs ANONYMOUS

| Aspect               | SYSTEM (`ACL.SYSTEM2`)                | ANONYMOUS                                               |
| -------------------- | ------------------------------------- | ------------------------------------------------------- |
| **Purpose**          | Internal Jenkins operations           | Unauthenticated external requests                       |
| **Permissions**      | Full access (superuser)               | Only permissions explicitly granted to "Anonymous" role |
| **When used**        | Background tasks, triggers, pipelines | HTTP requests without credentials                       |
| **`User.current()`** | Returns `null`                        | Returns `null`                                          |
| **Authentication**   | Represents Jenkins itself             | Represents no authentication                            |

Both return `null` from `User.current()` because neither represents an actual human user account. To distinguish them, check the security context via `Jenkins.getAuthentication()`.

## Key Points

- `User.current()` returns `null` when code runs as the SYSTEM user
- SYSTEM exists as both a security principal (`ACL.SYSTEM2`) AND a `User` record in the user database
- Always check for `null` before accessing user properties when `User.current()` might return the SYSTEM context

## SYSTEM in User.getAll()

SYSTEM **does appear** in `hudson.model.User.getAll()` as a regular `User` object with `id = "SYSTEM"`. Jenkins creates a User record for SYSTEM when it's referenced (e.g., build causes, changelogs).

To filter SYSTEM out of user lists:

```java
User.getAll().stream()
    .filter(u -> !ACL.SYSTEM_USERNAME.equals(u.getId()))
    .collect(Collectors.toList());
```

Or simply:

```java
if ("SYSTEM".equals(user.getId())) {
    // Skip the SYSTEM user
}
```

## Checking Current Security Context

To check if code is running as SYSTEM:

```java
import jenkins.model.Jenkins;
import hudson.security.ACL;

Authentication auth = Jenkins.getAuthentication();
if (auth == ACL.SYSTEM2) {
    // Running as SYSTEM
}

// Or by name:
if (ACL.SYSTEM_USERNAME.equals(auth.getName())) {
    // Running as SYSTEM
}
```

## Example Null Check

```java
User user = User.current();
if (user == null) {
    // Running as SYSTEM or anonymous
    return;
}
String userId = user.getId();
```
