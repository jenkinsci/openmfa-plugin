package io.jenkins.plugins.openmfa.service.model;

import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * Data transfer object containing user MFA status information.
 */
@Getter
@AllArgsConstructor
public class UserInfo {

  /** The user's unique identifier */
  private final String userId;

  /** The user's display name */
  private final String fullName;

  /** Whether MFA is currently enabled for this user */
  private final boolean mfaEnabled;

  public boolean isMfaEnabled() {
    return mfaEnabled;
  }

  /**
   * Returns a human-readable status string for the MFA state.
   */
  public String getStatusText() {
    return mfaEnabled ? "Enabled" : "Disabled";
  }

  /**
   * Returns the CSS class to use for the status badge.
   */
  public String getStatusClass() {
    return mfaEnabled ? "mfa-status-enabled" : "mfa-status-disabled";
  }

}
