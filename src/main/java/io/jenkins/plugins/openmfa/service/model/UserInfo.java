package io.jenkins.plugins.openmfa.service.model;

import java.util.List;
import lombok.Getter;

/**
 * Data transfer object containing user MFA status information.
 */
@Getter
public class UserInfo {

  /** The user's display name */
  private final String fullName;

  /** Whether MFA is currently enabled for this user */
  private final boolean mfaEnabled;

  /** The user's unique identifier */
  private final String userId;

  /**
   * The user's registered WebAuthn credentials, for the method summary and
   * per-key removal on the management page. Never {@code null}.
   */
  private final List<WebAuthnCredential> webAuthnCredentials;

  public UserInfo(final String userId, final String fullName,
    final boolean mfaEnabled) {
    this(userId, fullName, mfaEnabled, List.of());
  }

  public UserInfo(final String userId, final String fullName,
    final boolean mfaEnabled,
    final List<WebAuthnCredential> webAuthnCredentials) {
    this.userId = userId;
    this.fullName = fullName;
    this.mfaEnabled = mfaEnabled;
    this.webAuthnCredentials =
      webAuthnCredentials == null ? List.of() : List.copyOf(webAuthnCredentials);
  }

  /**
   * Returns a human-readable status string for the MFA state.
   */
  public String getStatusText() {
    return mfaEnabled ? "Enabled" : "Disabled";
  }

  /**
   * Returns the number of registered WebAuthn credentials, for the method
   * summary on the management page.
   */
  public int getWebAuthnKeyCount() {
    return webAuthnCredentials.size();
  }

  /**
   * Whether this user has at least one registered WebAuthn credential.
   */
  public boolean hasWebAuthn() {
    return !webAuthnCredentials.isEmpty();
  }

  public boolean isMfaEnabled() {
    return mfaEnabled;
  }

}
