package io.jenkins.plugins.openmfa;

import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import hudson.model.User;
import hudson.model.UserProperty;
import hudson.util.Secret;
import io.jenkins.plugins.openmfa.base.MFAContext;
import io.jenkins.plugins.openmfa.constant.PluginConstants;
import io.jenkins.plugins.openmfa.service.TOTPService;
import java.io.IOException;
import lombok.Getter;
import lombok.Setter;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;

/**
 * User property to store MFA secret and status.
 */
@Getter
@Setter
public class MFAUserProperty extends UserProperty {

  /**
   * Gets the MFA property for a user.
   *
   * @param user
   *          The user to get the property for.
   * @return The MFA property for the user, or null if not found.
   */
  @CheckForNull
  public static MFAUserProperty forUser(@Nullable User user) {
    if (user == null) {
      return null;
    }
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

  @CheckForNull
  @DataBoundSetter
  private Secret secret;

  @DataBoundConstructor
  public MFAUserProperty() {
  }

  public MFAUserProperty(Secret secret) {
    this.secret = secret;
  }

  @NonNull
  public String getSetupActionUrl() {
    return PluginConstants.Urls.SETUP_ACTION_URL;
  }

  public User getUser() {
    return super.user;
  }

  /**
   * Check if MFA is enabled for this user.
   */
  public boolean isEnabled() {
    return secret != null && !Secret.toString(secret).isEmpty();
  }

  /**
   * Verify a TOTP code for this user.
   */
  public boolean verifyCode(String code) {
    if (!isEnabled()) {
      return false;
    }
    return MFAContext.i()
      .getService(TOTPService.class)
      .verifyCode(secret, code);
  }
}
