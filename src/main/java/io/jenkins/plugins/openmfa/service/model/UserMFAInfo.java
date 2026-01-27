package io.jenkins.plugins.openmfa.service.model;

import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * Data transfer object containing user MFA status information.
 */
@Getter
@AllArgsConstructor
public class UserMFAInfo {

  /** The user's unique identifier */
  private final String userId;

  /** The user's display name */
  private final String fullName;

  /** Whether MFA is currently enabled for this user */
  private final boolean mfaEnabled;

  /** Whether MFA has been configured (secret exists) for this user */
  private final boolean mfaConfigured;

  /**
   * Returns a human-readable status string for the MFA state.
   */
  public String getStatusText() {
    if (mfaEnabled && mfaConfigured) {
      return "Enabled";
    } else if (mfaConfigured) {
      return "Configured (Disabled)";
    } else {
      return "Not Configured";
    }
  }

  /**
   * Returns the CSS class to use for the status badge.
   */
  public String getStatusClass() {
    if (mfaEnabled && mfaConfigured) {
      return "mfa-status-enabled";
    } else if (mfaConfigured) {
      return "mfa-status-configured";
    } else {
      return "mfa-status-disabled";
    }
  }
}
