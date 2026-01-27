package io.jenkins.plugins.openmfa;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Collection;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.MockAuthorizationStrategy;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.springframework.security.access.AccessDeniedException;

import hudson.model.User;
import hudson.security.ACL;
import io.jenkins.plugins.openmfa.base.MFAContext;
import io.jenkins.plugins.openmfa.service.MFAUserService;
import io.jenkins.plugins.openmfa.service.TOTPService;
import io.jenkins.plugins.openmfa.service.model.UserMFAInfo;
import jenkins.model.Jenkins;

@WithJenkins
class MFAManagementActionTest {

  private MFAManagementAction action;
  private TOTPService totpService;
  private MFAUserService userService;

  @BeforeEach
  void setUp() {
    action = new MFAManagementAction();
    totpService = MFAContext.i().getService(TOTPService.class);
    userService = MFAContext.i().getService(MFAUserService.class);
  }

  @Test
  void testGetDisplayName(JenkinsRule j) {
    assertEquals("MFA Management", action.getDisplayName());
  }

  @Test
  void testGetUrlName(JenkinsRule j) {
    assertEquals("mfa-management", action.getUrlName());
  }

  @Test
  void testGetAllUsersAsAdmin(JenkinsRule j) throws Exception {
    // Create test users
    User adminUser = User.getById("admin", true);
    User testUser = User.getById("testuser", true);

    // Set up MFA for testuser
    MFAUserProperty prop = MFAUserProperty.getOrCreate(testUser);
    prop.setSecret(totpService.generateSecret());
    prop.setEnabled(true);
    testUser.save();

    // Configure admin authorization
    j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
    j.jenkins.setAuthorizationStrategy(
      new MockAuthorizationStrategy()
        .grant(Jenkins.ADMINISTER).everywhere().to("admin")
    );

    // Get all users as admin
    try (var ctx = ACL.as2(adminUser.impersonate2())) {
      Collection<UserMFAInfo> users = action.getAllUsers();
      assertNotNull(users);
      assertTrue(users.size() >= 2);

      // Find testuser in the list
      UserMFAInfo testUserInfo = users.stream()
        .filter(u -> "testuser".equals(u.getUserId()))
        .findFirst()
        .orElse(null);

      assertNotNull(testUserInfo);
      assertTrue(testUserInfo.isMfaEnabled());
      assertTrue(testUserInfo.isMfaConfigured());
    }
  }

  @Test
  void testGetAllUsersWithoutAdminPermission(JenkinsRule j) throws Exception {
    // Create a regular user
    User regularUser = User.getById("regularuser", true);

    // Configure authorization - regular user has no admin rights
    j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
    j.jenkins.setAuthorizationStrategy(
      new MockAuthorizationStrategy()
        .grant(Jenkins.READ).everywhere().to("regularuser")
    );

    // Act as regular user
    try (var ctx = ACL.as2(regularUser.impersonate2())) {
      assertThrows(AccessDeniedException.class, () -> {
        action.getAllUsers();
      });
    }
  }

  @Test
  void testUserMFAInfoStatusText(JenkinsRule j) {
    // Test enabled status
    UserMFAInfo enabledUser = new UserMFAInfo("user1", "User One", true, true);
    assertEquals("Enabled", enabledUser.getStatusText());
    assertEquals("mfa-status-enabled", enabledUser.getStatusClass());

    // Test configured but disabled
    UserMFAInfo configuredUser = new UserMFAInfo("user2", "User Two", false, true);
    assertEquals("Configured (Disabled)", configuredUser.getStatusText());
    assertEquals("mfa-status-configured", configuredUser.getStatusClass());

    // Test not configured
    UserMFAInfo notConfiguredUser = new UserMFAInfo("user3", "User Three", false, false);
    assertEquals("Not Configured", notConfiguredUser.getStatusText());
    assertEquals("mfa-status-disabled", notConfiguredUser.getStatusClass());
  }

  @Test
  void testMFAUserServiceResetMFA(JenkinsRule j) throws Exception {
    // Create user with MFA enabled
    User user = User.getById("resetuser", true);
    MFAUserProperty prop = MFAUserProperty.getOrCreate(user);
    prop.setSecret(totpService.generateSecret());
    prop.setEnabled(true);
    user.save();

    // Verify MFA is enabled
    assertTrue(userService.isMFAEnabled(user));

    // Reset MFA
    userService.resetMFA(user);

    // Verify MFA is now disabled
    assertFalse(userService.isMFAEnabled(user));

    // Verify property is cleared
    MFAUserProperty updatedProp = MFAUserProperty.forUser(user);
    assertNotNull(updatedProp);
    assertFalse(updatedProp.isEnabled());
    assertFalse(updatedProp.isConfigured());
  }

  @Test
  void testMFAUserServiceCounts(JenkinsRule j) throws Exception {
    // Create users with different MFA states
    User enabledUser = User.getById("enabled_user", true);
    MFAUserProperty enabledProp = MFAUserProperty.getOrCreate(enabledUser);
    enabledProp.setSecret(totpService.generateSecret());
    enabledProp.setEnabled(true);
    enabledUser.save();

    // Create another user without MFA configured
    User.getById("disabled_user", true);

    // Test counts
    long total = userService.getTotalUserCount();
    long enabled = userService.getEnabledMFACount();

    assertTrue(total >= 2);
    assertTrue(enabled >= 1);
    assertTrue(enabled <= total);
  }

  @Test
  void testIconVisibleOnlyForAdmins(JenkinsRule j) throws Exception {
    // Configure authorization
    j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
    j.jenkins.setAuthorizationStrategy(
      new MockAuthorizationStrategy()
        .grant(Jenkins.ADMINISTER).everywhere().to("admin")
        .grant(Jenkins.READ).everywhere().to("regularuser")
    );

    // As admin, icon should be visible
    User admin = User.getById("admin", true);
    try (var ctx = ACL.as2(admin.impersonate2())) {
      assertNotNull(action.getIconFileName());
    }

    // As regular user, icon should be null
    User regular = User.getById("regularuser", true);
    try (var ctx = ACL.as2(regular.impersonate2())) {
      assertNull(action.getIconFileName());
    }
  }
}
