package io.jenkins.plugins.openmfa;

import hudson.Extension;
import hudson.model.UnprotectedRootAction;
import hudson.model.User;
import io.jenkins.plugins.openmfa.constant.PluginConstants;
import io.jenkins.plugins.openmfa.constant.UIConstants;

/**
 * Action that provides the MFA login page where users enter their TOTP code.
 */
@Extension
public class MFALoginAction implements UnprotectedRootAction {

  @Override
  public String getIconFileName() {
    return null; // Don't show in sidebar
  }

  @Override
  public String getDisplayName() {
    return UIConstants.DisplayNames.MFA_LOGIN;
  }

  @Override
  public String getUrlName() {
    return PluginConstants.Urls.LOGIN_ACTION_URL;
  }

  /**
   * Gets the username from the current user.
   */
  public String getPendingUsername() {
    User user = User.current();
    if (user != null) {
      return user.getId();
    }
    return null;
  }

  /**
   * Check if there's a pending MFA authentication.
   */
  public boolean hasPendingAuth() {
    return getPendingUsername() != null;
  }

  /**
   * Get the form parameter name for TOTP code (for Jelly views).
   */
  public String getFormParamTotpCode() {
    return PluginConstants.FormParameters.TOTP_CODE;
  }

  /**
   * Get the security check endpoint (for Jelly views).
   */
  public String getSecurityCheckEndpoint() {
    return PluginConstants.Urls.SECURITY_CHECK_ENDPOINT;
  }
}
