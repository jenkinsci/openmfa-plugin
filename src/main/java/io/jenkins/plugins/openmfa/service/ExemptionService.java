package io.jenkins.plugins.openmfa.service;

import hudson.model.User;
import io.jenkins.plugins.openmfa.MFAGlobalConfiguration;
import io.jenkins.plugins.openmfa.base.Service;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import lombok.extern.java.Log;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

/**
 * Service for checking if a user is exempt from MFA requirements.
 * Exemptions can be configured by username or by role/group membership.
 */
@Log
@Service
public class ExemptionService {

  /**
   * Checks if the given user is exempt from MFA requirements.
   * A user is exempt if:
   * - Their username is in the exempt users list (case-insensitive)
   * - They have any role/group in the exempt roles list
   *
   * @param user
   *          the user to check
   * @return true if the user is exempt, false otherwise
   */
  public boolean isExempt(User user) {
    if (user == null) {
      return false;
    }

    MFAGlobalConfiguration config = MFAGlobalConfiguration.get();

    // Check username exemption
    if (isExemptByUsername(user, config)) {
      log.fine("User " + user.getId() + " is exempt by username");
      return true;
    }

    // Check role exemption
    if (isExemptByRole(user, config)) {
      log.fine("User " + user.getId() + " is exempt by role");
      return true;
    }

    return false;
  }

  private boolean isExemptByRole(User user, MFAGlobalConfiguration config) {
    List<String> exemptRoles = parseList(config.getExemptRoles());
    if (exemptRoles.isEmpty()) {
      return false;
    }

    // Get user's authentication to check authorities
    Authentication auth = user.impersonate2();

    return auth.getAuthorities().stream()
      .map(GrantedAuthority::getAuthority)
      .anyMatch(
        role -> exemptRoles.stream()
          .anyMatch(exempt -> exempt.equalsIgnoreCase(role))
      );
  }

  private boolean isExemptByUsername(User user, MFAGlobalConfiguration config) {
    List<String> exemptUsers = parseList(config.getExemptUsers());
    if (exemptUsers.isEmpty()) {
      return false;
    }

    String userId = user.getId().toLowerCase().trim();
    return exemptUsers.stream()
      .anyMatch(exempt -> exempt.toLowerCase().trim().equals(userId));
  }

  private List<String> parseList(String input) {
    if (input == null || input.trim().isEmpty()) {
      return Collections.emptyList();
    }

    return Arrays.stream(input.split("\n"))
      .map(String::trim)
      .filter(s -> !s.isEmpty())
      .toList();
  }
}
