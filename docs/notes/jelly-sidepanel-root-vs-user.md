# Layout Side Panel: Root vs User Context

Technical note on when to use `app` vs `targetUser` (or similar) for the side panel in Jenkins Jelly layouts.

## What is `it`?

`it` is the **Stapler object that owns the current view**. It is the Java object whose Jelly view is being rendered.

## Where does `it` come from?

Stapler sets `it` automatically when it renders a Jelly view. The URL is routed to an object (via Stapler's request routing), and that object becomes `it`. For example:

- Request `/user/joe/mfa-setup` → routed to `MFASetupAction` (attached to User "joe") → `it` = `MFASetupAction`
- Request `/mfa-management` → routed to `MFAManagementAction` (at Jenkins root) → `it` = `MFAManagementAction`

The `it` variable is available in all Jelly tags and expressions within that view. Expressions like `${it.descriptor}` or `${it.targetUser}` resolve against this object.

The `<st:include>` tag has its own `it` attribute: it passes whichever object you specify as the `it` for the *included* page. So `<st:include page="sidepanel.jelly" it="${app}">` renders `sidepanel.jelly` with `it` = Jenkins instance, while `it="${it.targetUser}"` renders it with `it` = the target user.

## Issue

When using `<l:layout>` with `<l:side-panel>`, the `it` attribute of `<st:include page="sidepanel.jelly">` determines which side panel is shown. Using the wrong context breaks navigation expectations.

## Rule

| Action context | Side panel `it` | URL example |
|----------------|-----------------|-------------|
| Root-level page | `${app}` | `/mfa-management` |
| User-scoped page | `${it.targetUser}` (or the user object) | `/user/joe/mfa-setup` |

## Rationale

- **Root-level actions** (e.g. `MFAManagementAction` at `/mfa-management`): The page is under Jenkins root. The side panel should show the Jenkins root side panel (build queue, manage Jenkins, etc.) → use `it="${app}"`.

- **User-scoped actions** (e.g. `MFASetupAction` at `/user/<id>/mfa-setup`): The page is under a user. The side panel should show the user's side panel (user config, profile, etc.) → use `it="${it.targetUser}"`.

## OpenMFA usage

- **MFASetupAction** (`/user/<id>/mfa-setup`): `it="${it.targetUser}"` — user context
- **MFAManagementAction** (`/mfa-management`): `it="${app}"` — root context
