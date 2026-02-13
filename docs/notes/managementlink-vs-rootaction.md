# ManagementLink vs RootAction

Technical reference for choosing between Jenkins extension points for admin-only UI entry points.

## Overview

| Aspect | RootAction | ManagementLink |
|--------|------------|----------------|
| **Purpose** | Global URL endpoints visible to users | Admin-only links on the Manage Jenkins page |
| **Base** | `implements RootAction` | `extends ManagementLink` |
| **URL location** | Root, e.g. `/mfa-management` | Under `/manage/`, e.g. `/manage/mfa-management` |
| **Visibility** | Sidebar, top-level link (if icon returned) | Manage Jenkins page only |
| **Permission model** | Implementer decides via `getIconFileName()` returning `null` | Built-in `getRequiredPermission()` |

## RootAction

**Package:** `hudson.model.RootAction`

RootAction is an action bound at the Jenkins root URL. Implementations appear as top-level links (often in the sidebar) when `getIconFileName()` returns a non-null value.

### Behavior

- **URL:** `<root>/<getUrlName()>` (e.g. `/mfa-management`)
- **Visibility control:** Return `null` from `getIconFileName()` for users without permission; otherwise the link appears in the sidebar for everyone who sees it
- **Security:** No built-in permission check. You must implement your own (e.g. `checkPermission()`, conditional icon) and enforce it in every `do*` method and data getter

### Example

```java
@Extension
public class MyAction implements RootAction {
  @Override
  public String getIconFileName() {
    return Jenkins.get().hasPermission(Jenkins.ADMINISTER) ? "symbol-settings" : null;
  }
  // Must check permission in every do* method and getter
}
```

## ManagementLink

**Package:** `hudson.model.ManagementLink`  
**Since:** Jenkins 1.194

ManagementLink is an extension point for adding links to the Manage Jenkins page (`/manage`). It is intended for admin-only features.

### Behavior

- **URL:** `<root>/manage/<getUrlName()>` (e.g. `/manage/mfa-management`)
- **Visibility control:** Jenkins shows the link only to users with `getRequiredPermission()`; no need to return `null` from `getIconFileName()` based on permission
- **Security:** `getRequiredPermission()` defines who sees the link; access to the Manage Jenkins page is already restricted

### Key Methods

| Method | Purpose | Default |
|--------|---------|---------|
| `getIconFileName()` | SVG icon (e.g. `symbol-lock-closed`) | abstract, required |
| `getUrlName()` | URL path segment under `/manage/` | abstract, required |
| `getRequiredPermission()` | Minimum permission to see the link | `Jenkins.ADMINISTER` (historical) |
| `getDescription()` | Grey subtitle text on Manage Jenkins | optional |
| `getCategory()` | Section on Manage Jenkins page | `UNCATEGORIZED` |
| `getRequiresPOST()` | Whether link uses POST | `false` |
| `getRequiresConfirmation()` | Show confirmation before navigation | `false` |

### Categories (`ManagementLink.Category`)

- `SECURITY` – Security-related options (e.g. MFA Management)
- `CONFIGURATION` – Config pages
- `STATUS` – Status/info
- `TOOLS` – Admin tools (CLI, Script Console)
- `TROUBLESHOOTING` – Diagnostic utilities
- `MISC` – Other
- `UNCATEGORIZED` – Default

### Example

```java
@Extension
public class MFAManagementAction extends ManagementLink {
  @Override
  public String getIconFileName() {
    return "symbol-lock-closed";
  }
  @Override
  public String getUrlName() {
    return "mfa-management";
  }
  @Override
  public Permission getRequiredPermission() {
    return Jenkins.ADMINISTER;
  }
  @Override
  public Category getCategory() {
    return Category.SECURITY;
  }
  @Override
  public String getDescription() {
    return "View and manage MFA status for all users";
  }
}
```

## Security Comparison

| Concern | RootAction | ManagementLink |
|---------|------------|----------------|
| **Link visibility** | Manual (return null from `getIconFileName`) | Automatic via `getRequiredPermission()` |
| **Page access** | Must enforce in every handler | Page is under `/manage/`; link shown only to permitted users |
| **Risk of oversight** | High – easy to miss checks in new methods | Lower – permission applies to visibility and access |
| **CSRF** | Same (`@RequirePOST`, crumbs) | Same |

**Recommendation:** Use ManagementLink for admin-only dashboards and tools. Use RootAction for user-facing entry points (e.g. login, setup) or when the action must appear outside the Manage Jenkins page.

## References

- [ManagementLink Javadoc](https://javadoc.jenkins.io/hudson/model/ManagementLink.html)
- [ManagementLink.Category](https://javadoc.jenkins.io/hudson/model/ManagementLink.Category.html)
- [RootAction Javadoc](https://javadoc.jenkins.io/hudson/model/RootAction.html)
- OpenMFA: `MFAManagementAction` (ManagementLink)
