package io.jenkins.plugins.openmfa.service;

import java.io.IOException;
import java.util.Collection;

import hudson.model.User;
import io.jenkins.plugins.openmfa.MFAUserProperty;
import io.jenkins.plugins.openmfa.base.Service;
import io.jenkins.plugins.openmfa.service.model.UserMFAInfo;
import lombok.extern.java.Log;

/**
 * Service for managing user MFA operations.
 */
@Log
@Service
public class MFAUserService {

  /**
   * Gets all users with their MFA status information.
   *
   * @return Collection of UserMFAInfo objects for all users
   */
  public Collection<UserMFAInfo> getAllUsersWithMFAStatus() {
    return User.getAll().stream()
      .map(this::getUserMFAInfo)
      .toList();
  }

  /**
   * Gets MFA status information for a specific user.
   *
   * @param user The user to get MFA info for
   * @return UserMFAInfo containing the user's MFA status
   */
  public UserMFAInfo getUserMFAInfo(User user) {
    MFAUserProperty prop = MFAUserProperty.forUser(user);
    return new UserMFAInfo(
      user.getId(),
      user.getFullName(),
      prop != null && prop.isEnabled(),
      prop != null && prop.isConfigured()
    );
  }

  /**
   * Resets MFA for a user, clearing their secret and disabling MFA.
   *
   * @param user The user to reset MFA for
   * @throws IOException if saving the user fails
   */
  public void resetMFA(User user) throws IOException {
    MFAUserProperty property = MFAUserProperty.forUser(user);
    if (property != null) {
      property.setSecret(null);
      property.setEnabled(false);
      user.save();
      log.info(String.format("MFA reset for user: %s by admin", user.getId()));
    }
  }

  /**
   * Checks if a user has MFA enabled.
   *
   * @param user The user to check
   * @return true if MFA is enabled, false otherwise
   */
  public boolean isMFAEnabled(User user) {
    MFAUserProperty prop = MFAUserProperty.forUser(user);
    return prop != null && prop.isEnabled() && prop.isConfigured();
  }

  /**
   * Gets the count of users with MFA enabled.
   *
   * @return Number of users with MFA enabled
   */
  public long getEnabledMFACount() {
    return User.getAll().stream()
      .filter(this::isMFAEnabled)
      .count();
  }

  /**
   * Gets the total number of users.
   *
   * @return Total user count
   */
  public long getTotalUserCount() {
    return User.getAll().size();
  }
}
