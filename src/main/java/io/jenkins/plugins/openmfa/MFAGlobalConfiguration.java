package io.jenkins.plugins.openmfa;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.ExtensionList;
import io.jenkins.plugins.openmfa.constant.UIConstants;
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
      return FALLBACK_INSTANCE.compareAndSet(null, new MFAGlobalConfiguration())
        ? FALLBACK_INSTANCE.get()
        : FALLBACK_INSTANCE.get();
    }
  }

  /**
   * Reset the fallback instance. For test use only.
   */
  public static void resetFallbackInstance() {
    FALLBACK_INSTANCE.set(null);
  }

  /** Comma/newline-separated list of roles/groups exempt from MFA */
  private String exemptRoles = "";

  /** Comma/newline-separated list of usernames exempt from MFA */
  private String exemptUsers = "";

  /** The issuer name shown in authenticator apps */
  private String issuer = UIConstants.Defaults.DEFAULT_ISSUER;

  /** Whether MFA is required for all users */
  private boolean requireMFA = UIConstants.Defaults.DEFAULT_REQUIRE_MFA;

  public MFAGlobalConfiguration() {
    // Load persisted configuration when Jenkins starts
    load();
  }

  @Override
  public boolean configure(StaplerRequest2 req, JSONObject json)
    throws FormException {
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
   * Get the list of exempt roles (for Jelly view).
   * Returns one role per line for easier editing.
   */
  public String getExemptRoles() {
    return exemptRoles;
  }

  /**
   * Get the list of exempt users (for Jelly view).
   * Returns one user per line for easier editing.
   */
  public String getExemptUsers() {
    return exemptUsers;
  }

  @DataBoundSetter
  public void setExemptRoles(String exemptRoles) {
    this.exemptRoles = exemptRoles != null ? exemptRoles : "";
  }

  @DataBoundSetter
  public void setExemptUsers(String exemptUsers) {
    this.exemptUsers = exemptUsers != null ? exemptUsers : "";
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
  public void setRequireMFA(boolean requireMFA) {
    this.requireMFA = requireMFA;
  }
}
