package io.jenkins.plugins.openmfa.util;

import hudson.model.User;
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
}
