package io.jenkins.plugins.openmfa.service;

import hudson.model.User;
import hudson.security.ACL;
import hudson.security.HudsonPrivateSecurityRealm;
import hudson.security.SecurityRealm;
import io.jenkins.plugins.openmfa.MFAUserProperty;
import io.jenkins.plugins.openmfa.base.Service;
import io.jenkins.plugins.openmfa.service.model.UserInfo;
import io.jenkins.plugins.openmfa.service.model.WebAuthnCredential;
import io.jenkins.plugins.openmfa.util.JenkinsUtil;
import io.jenkins.plugins.openmfa.util.TOTPUtil;
import java.io.IOException;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import jenkins.model.Jenkins;
import jenkins.security.LastGrantedAuthoritiesProperty;
import lombok.extern.java.Log;

/**
 * Service for managing user MFA operations.
 */
@Log
@Service
public class UserService {

  /**
   * Gets all users with their MFA status information.
   *
   * @return Collection of UserMFAInfo objects for all users
   */
  public Collection<UserInfo> getAllUsersWithMFAStatus() {
    return getUsers()
      .stream()
      .filter(u -> !ACL.SYSTEM_USERNAME.equals(u.getId()))
      .map(this::getUserMFAInfo)
      .toList();
  }

  /**
   * Gets the count of users with MFA enabled.
   *
   * @return Number of users with MFA enabled
   */
  public long getEnabledMFACount() {
    return getUsers()
      .stream()
      .filter(this::isMFAEnabled)
      .count();
  }

  /**
   * Gets the total number of users.
   *
   * @return Total user count
   */
  public long getTotalUserCount() {
    return getUsers().size();
  }

  /**
   * Gets MFA status information for a specific user.
   *
   * @param user
   *          The user to get MFA info for
   * @return UserMFAInfo containing the user's MFA status
   */
  public UserInfo getUserMFAInfo(User user) {
    MFAUserProperty property = MFAUserProperty.forUser(user);
    List<WebAuthnCredential> webAuthnCredentials =
      property == null ? List.of() : property.getWebAuthnCredentials();
    return new UserInfo(
      user.getId(),
      user.getFullName(),
      TOTPUtil.isMFAEnabled(user),
      webAuthnCredentials
    );
  }

  /**
   * Checks if a user has MFA enabled.
   *
   * @param user
   *          The user to check
   * @return true if MFA is enabled, false otherwise
   */
  public boolean isMFAEnabled(User user) {
    return TOTPUtil.isMFAEnabled(user);
  }

  /**
   * Removes one of a user's registered WebAuthn credentials.
   *
   * @param user
   *          the user to remove a credential from
   * @param credentialId
   *          the credential id to remove
   * @return whether a credential was found and removed
   */
  public boolean removeWebAuthnCredential(User user, String credentialId) {
    JenkinsUtil.checkAdminPermission();

    MFAUserProperty property = MFAUserProperty.forUser(user);
    if (property == null) {
      return false;
    }
    boolean removed = property.removeWebAuthnCredential(credentialId);
    if (removed) {
      log.info(
        String.format(
          "Admin removed a WebAuthn credential for user: %s", user.getId()
        )
      );
    }
    return removed;
  }

  /**
   * Resets MFA for a user, clearing their secret and disabling MFA.
   *
   * @param user
   *          The user to reset MFA for
   * @throws IOException
   *           if saving the user fails
   */
  public void resetMFA(User user) throws IOException {
    JenkinsUtil.checkAdminPermission();

    MFAUserProperty property = MFAUserProperty.forUser(user);
    if (property != null) {
      // Clears the TOTP secret and every registered security key, and
      // rotates the MFA epoch, so a full reset leaves no second factor
      // behind and invalidates any remember-MFA cookie.
      property.clearAllFactors();
      log.info(String.format("MFA reset for user: %s by admin", user.getId()));
    }
  }

  private Collection<User> getUsers() {
    Optional<Jenkins> jenkins = JenkinsUtil.getJenkins();

    if (jenkins.isPresent()) {
      SecurityRealm realm = jenkins.get().getSecurityRealm();
      if (realm instanceof HudsonPrivateSecurityRealm) {
        return ((HudsonPrivateSecurityRealm) realm).getAllUsers();
      }
    }

    return User.getAll()
      .stream()
      .filter(u -> u.getProperty(LastGrantedAuthoritiesProperty.class) != null)
      .toList();
  }
}
