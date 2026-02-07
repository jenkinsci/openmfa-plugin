package io.jenkins.plugins.openmfa.service;

import hudson.model.User;
import hudson.security.ACL;
import io.jenkins.plugins.openmfa.MFAUserProperty;
import io.jenkins.plugins.openmfa.base.Service;
import io.jenkins.plugins.openmfa.service.model.UserInfo;
import io.jenkins.plugins.openmfa.util.JenkinsUtil;
import io.jenkins.plugins.openmfa.util.TOTPUtil;
import java.io.IOException;
import java.util.Collection;
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
    return new UserInfo(
      user.getId(),
      user.getFullName(),
      TOTPUtil.isMFAEnabled(user)
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
      property.setSecret(null);
      user.save();
      log.info(String.format("MFA reset for user: %s by admin", user.getId()));
    }
  }

  private Collection<User> getUsers() {
    return User.getAll()
      .stream()
      .filter(u -> !ACL.SYSTEM_USERNAME.equals(u.getId()))
      .toList();
  }

}
