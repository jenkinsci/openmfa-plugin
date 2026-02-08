# Publishing Jenkins Plugins

Short guide from [Requesting Hosting](https://www.jenkins.io/doc/developer/publishing/requesting-hosting/) and [Releasing via CD](https://www.jenkins.io/doc/developer/publishing/releasing-cd/).

## 1. Request plugin hosting

**Before requesting:**
- Satisfy preparation steps on the hosting page
- Follow plugin naming (style guides)
- Have a **public GitHub repo** with the plugin source

**Request:**
- Open a **new issue** in [repository-permissions-updater](https://github.com/jenkins-infra/repository-permissions-updater)
- Fill all required fields
- Hosting team will fork your repo into `jenkinsci` and invite you
- **Then:** delete your original repo (so `jenkinsci` is the canonical one); you can re-fork from `jenkinsci` afterward

**After hosting:**
- Add a `Jenkinsfile` for CI on ci.jenkins.io
- Request upload/release permissions (see that repo’s README)
- Optionally set up CD (below)

## 2. Releasing via Continuous Delivery (CD)

CD lets ci.jenkins.io builds of the default branch trigger releases to Artifactory; no local credentials needed.

**Prerequisites:**
- Plugin already **incrementified**: `pom.xml` has `<version>${revision}${changelist}</version>`, and `.mvn/extensions.xml` + `.mvn/maven.config` exist

**Steps (do in a branch, then open a PR; do not push directly to default):**

1. **CD workflow**
   - `mkdir -p .github/workflows`
   - Download and add `.github/workflows/cd.yaml` from [jenkinsci/.github workflow-templates/cd.yaml](https://raw.githubusercontent.com/jenkinsci/.github/master/workflow-templates/cd.yaml)
   - Optional: remove `check_run` trigger in `cd.yaml` to avoid auto-release on every merge (keep only `workflow_dispatch` for manual release)

2. **Release Drafter**
   - Remove existing Release Drafter config and workflow (e.g. `.github/release-drafter*.yml`, `.github/workflows/release-drafter*.yml`) so CD workflow handles releases

3. **Dependabot**
   - Add/update `.github/dependabot.yml` to include `github-actions` (or use archetype’s file). Skip if using Renovate.

4. **Maven / versioning**
   - In `.mvn/maven.config` add: `-Dchangelist.format=%d.v%s`
   - In `pom.xml` pick one:
     - **Fully automated:** `<version>${changelist}</version>`, `<changelist>999999-SNAPSHOT</changelist>`, drop `revision` and `project.build.outputTimestamp` → versions like `123.v<commit-hash>`
     - **Manual prefix:** Keep `revision`, use `<version>${revision}.${changelist}</version>`, `<changelist>999999-SNAPSHOT</changelist>` → e.g. `1.321.v<commit-hash>`
     - **Wrapped component:** `<version>${revision}-${changelist}</version>` → e.g. `4.0.0-123.v<commit-hash>`
   - Remove `project.build.outputTimestamp` when switching to CD versioning

5. **Enable CD in permissions**
   - In [repository-permissions-updater](https://github.com/jenkins-infra/repository-permissions-updater), add to your plugin’s `permissions/plugin-xxx.yml`:
     - `cd:\n  enabled: true`
   - In the PR, link to your plugin’s PR that contains the CD changes
   - After merge, confirm `MAVEN_TOKEN` and `MAVEN_USERNAME` under repo **Settings → Secrets and variables → Actions**

**Releasing:**
- **With default cd.yaml:** Merge PRs that have a user-facing label (e.g. `enhancement`, `bug`); successful build on default branch can trigger release. Or run the **cd** workflow manually from the Actions tab.
- **If you removed `check_run`:** Trigger release only via **Run workflow** on the cd workflow.

**Breaking changes:** Set `hpi.compatibleSinceVersion` in the PR (e.g. next version number) and use label `breaking` or `removed`.

**Troubleshooting:** 401 → credentials/secrets issue (check INFRA or #jenkins-infra). 403 → wrong path or release already exists (no overwrite).
