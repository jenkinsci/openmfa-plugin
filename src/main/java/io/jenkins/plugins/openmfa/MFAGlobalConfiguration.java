package io.jenkins.plugins.openmfa;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.ExtensionList;
import io.jenkins.plugins.openmfa.constant.UIConstants;
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
   * Get the singleton instance of this configuration.
   */
  @NonNull
  public static MFAGlobalConfiguration get() {
    return ExtensionList.lookupSingleton(MFAGlobalConfiguration.class);
  }

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
    return UIConstants.DisplayNames.OPENMFA_GLOBAL_CONFIGURATION;
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
