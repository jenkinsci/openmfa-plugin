package io.jenkins.plugins.openmfa;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.ExtensionList;
import hudson.util.Secret;
import io.jenkins.plugins.openmfa.constant.UIConstants;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import jenkins.model.GlobalConfiguration;
import jenkins.model.GlobalConfigurationCategory;
import lombok.Getter;
import lombok.Setter;
import net.sf.json.JSONObject;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.StaplerRequest2;

/**
 * Global configuration for OpenMFA plugin.
 * Provides system-wide settings for MFA functionality.
 */
@Extension
@Getter
@Setter
@Symbol("openMFA")
public class MFAGlobalConfiguration extends GlobalConfiguration {

  /**
   * Cached instance for fallback when ExtensionList is not available.
   */
  private static final AtomicReference<MFAGlobalConfiguration> FALLBACK_INSTANCE =
    new AtomicReference<>();

  private static final SecureRandom RANDOM = new SecureRandom();

  /**
   * Get the singleton instance of this configuration.
   */
  @NonNull
  public static MFAGlobalConfiguration get() {
    // Try to get from ExtensionList first (works when Jenkins is fully initialized)
    try {
      return ExtensionList.lookupSingleton(MFAGlobalConfiguration.class);
    } catch (IllegalStateException e) {
      // Fallback: use a cached instance if ExtensionList is not available
      // This can happen in some test scenarios
      FALLBACK_INSTANCE.compareAndSet(null, new MFAGlobalConfiguration());
      return FALLBACK_INSTANCE.get();
    }
  }

  /**
   * Reset the fallback instance. For test use only.
   */
  public static void resetFallbackInstance() {
    FALLBACK_INSTANCE.set(null);
  }

  private static List<String> splitLines(String text) {
    if (text == null || text.isBlank()) {
      return List.of();
    }
    return Arrays.stream(text.split("\n"))
      .map(String::trim)
      .filter(s -> !s.isEmpty())
      .toList();
  }

  /** Roles/groups exempt from MFA */
  private List<String> exemptRoles = List.of();

  /** Usernames exempt from MFA */
  private List<String> exemptUsers = List.of();

  /** The issuer name shown in authenticator apps */
  private String issuer = UIConstants.Defaults.DEFAULT_ISSUER;

  /**
   * How many hours a "remember MFA" cookie stays valid after a user who chose
   * "Keep me signed in" passes MFA. 0 disables the feature.
   */
  private int rememberMfaHours = UIConstants.Defaults.DEFAULT_REMEMBER_MFA_HOURS;

  /**
   * HMAC key used to sign remember-MFA tokens. Generated on first use;
   * can be set explicitly (e.g. via JCasC) so tokens survive JENKINS_HOME
   * resets. Rotating it invalidates all issued remember-MFA cookies.
   */
  private Secret rememberMfaKey;

  /** Whether MFA is required for all users */
  private boolean requireMFA = UIConstants.Defaults.DEFAULT_REQUIRE_MFA;

  public MFAGlobalConfiguration() {
    // Load persisted configuration when Jenkins starts
    load();
  }

  @Override
  public boolean configure(StaplerRequest2 req, JSONObject json)
    throws FormException {
    // The UI submits exemptions as textarea text (one entry per line);
    // convert to the list form before binding the rest
    setExemptUsers(splitLines(json.optString("exemptUsers", "")));
    setExemptRoles(splitLines(json.optString("exemptRoles", "")));
    json.remove("exemptUsers");
    json.remove("exemptRoles");
    req.bindJSON(this, json); // Bind the JSON object to the configuration object
    save(); // Save the configuration object
    return true;
  }

  @NonNull
  @Override
  public GlobalConfigurationCategory getCategory() {
    return GlobalConfigurationCategory
      .get(GlobalConfigurationCategory.Security.class);
  }

  /**
   * Get the default issuer name (for Jelly views).
   */
  public String getDefaultIssuer() {
    return UIConstants.Defaults.DEFAULT_ISSUER;
  }

  @NonNull
  @Override
  public String getDisplayName() {
    return Messages.DisplayNames_OPENMFA_GLOBAL_CONFIGURATION();
  }

  /**
   * Exempt roles as text for the Jelly textarea, one role per line.
   */
  public String getExemptRolesText() {
    return String.join("\n", exemptRoles);
  }

  /**
   * Exempt users as text for the Jelly textarea, one user per line.
   */
  public String getExemptUsersText() {
    return String.join("\n", exemptUsers);
  }

  /**
   * Returns the remember-MFA signing key, generating and persisting one on
   * first use.
   */
  @NonNull
  public synchronized Secret getOrCreateRememberMfaKey() {
    if (rememberMfaKey == null || rememberMfaKey.getPlainText().isEmpty()) {
      byte[] keyBytes = new byte[32];
      RANDOM.nextBytes(keyBytes);
      rememberMfaKey =
        Secret.fromString(Base64.getEncoder().encodeToString(keyBytes));
      save();
    }
    return rememberMfaKey;
  }

  public synchronized Secret getRememberMfaKey() {
    return rememberMfaKey;
  }

  @DataBoundSetter
  public void setExemptRoles(List<String> exemptRoles) {
    this.exemptRoles = exemptRoles != null ? List.copyOf(exemptRoles) : List.of();
  }

  @DataBoundSetter
  public void setExemptUsers(List<String> exemptUsers) {
    this.exemptUsers = exemptUsers != null ? List.copyOf(exemptUsers) : List.of();
  }

  @DataBoundSetter
  public void setIssuer(String issuer) {
    this.issuer =
      issuer != null
        && !issuer.trim().isEmpty()
          ? issuer.trim()
          : UIConstants.Defaults.DEFAULT_ISSUER;
  }

  @DataBoundSetter
  public void setRememberMfaHours(int rememberMfaHours) {
    this.rememberMfaHours = Math.max(0, rememberMfaHours);
  }

  @DataBoundSetter
  public synchronized void setRememberMfaKey(Secret rememberMfaKey) {
    this.rememberMfaKey = rememberMfaKey;
  }

  @DataBoundSetter
  public void setRequireMFA(boolean requireMFA) {
    this.requireMFA = requireMFA;
  }
}
