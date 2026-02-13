package io.jenkins.plugins.openmfa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import hudson.model.ManagementLink;
import hudson.model.User;
import hudson.security.ACL;
import io.jenkins.plugins.openmfa.base.MFAContext;
import io.jenkins.plugins.openmfa.service.TOTPService;
import io.jenkins.plugins.openmfa.service.UserService;
import io.jenkins.plugins.openmfa.service.model.UserInfo;
import java.util.Collection;
import jenkins.model.Jenkins;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.MockAuthorizationStrategy;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.springframework.security.access.AccessDeniedException;

@WithJenkins
class MFAManagementActionTest {

  private MFAManagementAction action;
  private TOTPService totpService;
  private UserService userService;

  @BeforeEach
  void setUp() {
    action = new MFAManagementAction();
    totpService = MFAContext.i().getService(TOTPService.class);
    userService = MFAContext.i().getService(UserService.class);
  }

  @Test
  void testGetAllUsersAsAdmin(JenkinsRule j) throws Exception {
    // Create test users
    User adminUser = User.getById("admin", true);
    User testUser = User.getById("testuser", true);

    // Set up MFA for testuser
    MFAUserProperty prop = MFAUserProperty.getOrCreate(testUser);
    prop.setSecret(totpService.generateSecret());
    testUser.save();

    // Configure admin authorization
    j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
    j.jenkins.setAuthorizationStrategy(
      new MockAuthorizationStrategy()
        .grant(Jenkins.ADMINISTER).everywhere().to("admin")
    );

    // Get all users as admin
    try (var ctx = ACL.as2(adminUser.impersonate2())) {
      Collection<UserInfo> users = action.getAllUsers();
      assertNotNull(users);
      assertTrue(users.size() >= 2);

      // Find testuser in the list
      UserInfo testUserInfo =
        users.stream()
          .filter(u -> "testuser".equals(u.getUserId()))
          .findFirst()
          .orElse(null);

      assertNotNull(testUserInfo);
      assertTrue(testUserInfo.isMfaEnabled());
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
  void testGetDisplayName(JenkinsRule j) {
    assertEquals("MFA Management", action.getDisplayName());
  }

  @Test
  void testGetUrlName(JenkinsRule j) {
    assertEquals("mfa-management", action.getUrlName());
  }

  @Test
  void testIconAndCategory(JenkinsRule j) {
    assertNotNull(action.getIconFileName());
    assertEquals(ManagementLink.Category.SECURITY, action.getCategory());
  }

  @Test
  void testMFAUserServiceCounts(JenkinsRule j) throws Exception {
    // Create users with different MFA states
    User enabledUser = User.getById("enabled_user", true);
    MFAUserProperty enabledProp = MFAUserProperty.getOrCreate(enabledUser);
    enabledProp.setSecret(totpService.generateSecret());
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
  void testMFAUserServiceResetMFA(JenkinsRule j) throws Exception {
    // Create user with MFA enabled
    User user = User.getById("resetuser", true);
    MFAUserProperty prop = MFAUserProperty.getOrCreate(user);
    prop.setSecret(totpService.generateSecret());
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
  }

  @Test
  void testManagementLinkRegistration(JenkinsRule j) {
    assertTrue(
      ManagementLink.all().stream().anyMatch(MFAManagementAction.class::isInstance)
    );
  }

  @Test
  void testRequiredPermissionIsAdminister(JenkinsRule j) {
    assertEquals(Jenkins.ADMINISTER, action.getRequiredPermission());
  }

  @Test
  void testUserMFAInfoStatusText(JenkinsRule j) {
    // Test enabled status
    UserInfo enabledUser = new UserInfo("user1", "User One", true);
    assertEquals("Enabled", enabledUser.getStatusText());

    // Test disabled status
    UserInfo disabledUser =
      new UserInfo("user2", "User Two", false);
    assertEquals("Disabled", disabledUser.getStatusText());
  }
}
