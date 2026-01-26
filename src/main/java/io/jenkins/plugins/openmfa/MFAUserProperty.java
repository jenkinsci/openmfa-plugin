package io.jenkins.plugins.openmfa;

import java.io.IOException;

import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;

import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.model.User;
import hudson.model.UserProperty;
import hudson.util.Secret;
import io.jenkins.plugins.openmfa.base.MFAContext;
import io.jenkins.plugins.openmfa.constant.PluginConstants;
import io.jenkins.plugins.openmfa.constant.UIConstants;
import io.jenkins.plugins.openmfa.service.TOTPService;
import lombok.Getter;
import lombok.Setter;

/**
 * User property to store MFA secret and status.
 */
@Getter
@Setter
public class MFAUserProperty extends UserProperty {

  @CheckForNull
  @DataBoundSetter
  private Secret secret;

  @DataBoundSetter
  private boolean enabled = UIConstants.Defaults.DEFAULT_MFA_ENABLED;

  @DataBoundConstructor
  public MFAUserProperty() {
    this.enabled = UIConstants.Defaults.DEFAULT_MFA_ENABLED;
  }

  public MFAUserProperty(Secret secret, boolean enabled) {
    this.secret = secret;
    this.enabled = enabled;
  }

  public User getUser() {
    return super.user;
  }

  /**
   * Check if MFA is configured for this user.
   */
  public boolean isConfigured() {
    return secret != null && !Secret.toString(secret).isEmpty();
  }

  /**
   * Verify a TOTP code for this user.
   */
  public boolean verifyCode(String code) {
    if (!isConfigured() || !enabled) {
      return false;
    }
    TOTPService totpService = MFAContext.i().getService(TOTPService.class);
    return totpService.verifyCode(secret, code);
  }

  /**
   * Gets the MFA property for a user, or null if not found.
   */
  @CheckForNull
  public static MFAUserProperty forUser(User user) {
    return user.getProperty(MFAUserProperty.class);
  }

  /**
   * Gets or creates the MFA property for a user.
   */
  @NonNull
  public static MFAUserProperty getOrCreate(User user) throws IOException {
    MFAUserProperty property = forUser(user);
    if (property == null) {
      property = new MFAUserProperty();
      property.setUser(user);
      user.addProperty(property);
    }
    return property;
  }

  @NonNull
  public String getSetupActionUrl() {
    return PluginConstants.Urls.SETUP_ACTION_URL;
  }
}
