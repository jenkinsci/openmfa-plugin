package io.jenkins.plugins.openmfa.util;

import hudson.model.User;
import hudson.security.Permission;
import hudson.util.VersionNumber;
import jenkins.model.Jenkins;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.util.Optional;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class JenkinsUtil {

  public static Optional<Jenkins> getJenkins() {
    return Optional.ofNullable(Jenkins.getInstanceOrNull());
  }

  public static Optional<VersionNumber> getJenkinsVersion() {
    return getJenkins().map(j -> Jenkins.getVersion());
  }

  public static Optional<String> getJenkinsRootUrl() {
    return getJenkins().map(Jenkins::getRootUrl);
  }

  public static boolean isSecurityEnabled() {
    return getJenkins()
      .map(Jenkins::isUseSecurity)
      .orElse(false);
  }

  /**
   * Gets the {@link User} object representing the currently logged-in user, or
   * null if the current user is anonymous.
   */
  public static Optional<User> getCurrentUser() {
    return Optional.ofNullable(User.current());
  }

  /**
   * Checks whether the current user has the specified permission.
   *
   * @param permission the permission to check
   * @return true if Jenkin's security mode is enabled and the current user has
   *         the specified permission, false
   *         otherwise
   */
  public static boolean hasPermission(Permission permission) {
    return !isSecurityEnabled() || getCurrentUser()
      .map(u -> u.hasPermission(permission))
      .orElse(false);
  }

  /**
   * Checks whether the current user has the specified permission.
   *
   * @param permission the permission to check
   * @throws AccessDeniedException if Jenkin's security mode is enabled and the
   *                               current user does not have the specified
   *                               permission
   */
  public static void checkPermission(Permission permission) {
    if (!isSecurityEnabled()) {
      return;
    }
    Jenkins.get().checkPermission(permission);
  }

  /**
   * Checks whether the current user is an administrator.
   *
   * @return true if Jenkin's security mode is enabled and the current user is
   *         an administrator, false
   *         otherwise
   */
  public static boolean isAdmin() {
    return hasPermission(Jenkins.ADMINISTER);
  }

  /**
   * Checks whether the current user is an administrator.
   *
   * @throws AccessDeniedException if Jenkin's security mode is enabled and the
   *                               current user is not an administrator
   */
  public static void checkAdminPermission() {
    checkPermission(Jenkins.ADMINISTER);
  }

}
