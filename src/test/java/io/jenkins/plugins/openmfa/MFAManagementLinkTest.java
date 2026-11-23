package io.jenkins.plugins.openmfa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import hudson.model.ManagementLink;
import hudson.model.User;
import hudson.security.ACL;
import io.jenkins.plugins.openmfa.base.MFAContext;
import io.jenkins.plugins.openmfa.service.TOTPService;
import io.jenkins.plugins.openmfa.service.UserService;
import io.jenkins.plugins.openmfa.service.model.UserInfo;
import io.jenkins.plugins.openmfa.service.model.WebAuthnCredential;
import java.net.URL;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import jenkins.model.Jenkins;
import org.htmlunit.HttpMethod;
import org.htmlunit.Page;
import org.htmlunit.WebRequest;
import org.htmlunit.util.NameValuePair;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.MockAuthorizationStrategy;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.springframework.security.access.AccessDeniedException;

@WithJenkins
class MFAManagementLinkTest {

  private MFAManagementLink action;
  private TOTPService totpService;
  private UserService userService;

  @BeforeEach
  void setUp() {
    action = new MFAManagementLink();
    totpService = MFAContext.i().getService(TOTPService.class);
    userService = MFAContext.i().getService(UserService.class);
  }

  /**
   * A POST with no {@code credentialId} at all is a client error, never a
   * redirect or a 500.
   */
  @Test
  void testDoRemoveWebAuthnCredentialMissingCredentialIdIsBadRequest(
    JenkinsRule j) throws Exception {
    try (var wc = adminExemptWebClient(j, "missingcredidadmin")) {
      WebRequest request =
        new WebRequest(
          new URL(j.getURL(), "mfa-management/removeWebAuthnCredential"),
          HttpMethod.POST
        );
      request.setRequestParameters(
        List.of(new NameValuePair("userId", "someone"))
      );
      Page page = wc.getPage(wc.addCrumb(request));
      assertEquals(
        400, page.getWebResponse().getStatusCode(),
        "A missing credentialId should be a client error"
      );
    }
  }

  /**
   * A POST with no {@code userId} at all is a client error, never a
   * redirect or a 500.
   */
  @Test
  void testDoRemoveWebAuthnCredentialMissingUserIdIsBadRequest(JenkinsRule j)
    throws Exception {
    try (var wc = adminExemptWebClient(j, "missinguseridadmin")) {
      WebRequest request =
        new WebRequest(
          new URL(j.getURL(), "mfa-management/removeWebAuthnCredential"),
          HttpMethod.POST
        );
      request.setRequestParameters(
        List.of(new NameValuePair("credentialId", "cred-x"))
      );
      Page page = wc.getPage(wc.addCrumb(request));
      assertEquals(
        400, page.getWebResponse().getStatusCode(),
        "A missing userId should be a client error"
      );
    }
  }

  /**
   * A caller without ADMINISTER must not be able to remove another user's
   * WebAuthn credential.
   */
  @Test
  void testDoRemoveWebAuthnCredentialRequiresAdminPermission(JenkinsRule j)
    throws Exception {
    User regularUser = User.getById("removeregularuser", true);
    User victim = User.getById("removevictim", true);
    MFAUserProperty prop = MFAUserProperty.getOrCreate(victim);
    prop.setSecret(totpService.generateSecret());
    prop.addWebAuthnCredential(
      new WebAuthnCredential(
        "cred-victim", "cose-victim", 0, "Victim Key",
        Instant.now().toString(), null
      )
    );
    victim.save();

    j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
    j.jenkins.setAuthorizationStrategy(
      new MockAuthorizationStrategy()
        .grant(Jenkins.READ).everywhere().to("removeregularuser")
    );

    try (var ctx = ACL.as2(regularUser.impersonate2())) {
      assertThrows(AccessDeniedException.class, () -> {
        action.doRemoveWebAuthnCredential("removevictim", "cred-victim");
      });
    }

    assertTrue(
      MFAUserProperty.forUser(victim).hasWebAuthn(),
      "Credential must remain when the caller lacks ADMINISTER"
    );
  }

  /**
   * An unknown credential on a real user redirects with
   * {@code error=webauthn_not_found} (like doResetMFA), not a 4xx.
   */
  @Test
  void testDoRemoveWebAuthnCredentialUnknownCredentialRedirectsWithError(
    JenkinsRule j) throws Exception {
    User victim = User.getById("unknowncredvictim", true);
    MFAUserProperty.getOrCreate(victim).setSecret(totpService.generateSecret());
    victim.save();

    try (var wc = adminExemptWebClient(j, "unknowncredadmin")) {
      wc.getOptions().setRedirectEnabled(false);

      WebRequest request =
        new WebRequest(
          new URL(j.getURL(), "mfa-management/removeWebAuthnCredential"),
          HttpMethod.POST
        );
      request.setRequestParameters(
        List.of(
          new NameValuePair("userId", "unknowncredvictim"),
          new NameValuePair("credentialId", "no-such-credential")
        )
      );
      Page page = wc.getPage(wc.addCrumb(request));
      assertEquals(
        302, page.getWebResponse().getStatusCode(),
        "An unknown credential on a real user should redirect, not error"
      );
      String location = page.getWebResponse().getResponseHeaderValue("Location");
      assertNotNull(location, "A redirect must carry a Location header");
      assertTrue(
        location.contains("error=webauthn_not_found"),
        "The redirect should carry the webauthn_not_found error, got: "
          + location
      );
    }
  }

  /**
   * An unknown user is a 404: there is nothing to redirect back to, unlike
   * the unknown-credential case below.
   */
  @Test
  void testDoRemoveWebAuthnCredentialUnknownUserIsNotFound(JenkinsRule j)
    throws Exception {
    try (var wc = adminExemptWebClient(j, "unknownuseradmin")) {
      WebRequest request =
        new WebRequest(
          new URL(j.getURL(), "mfa-management/removeWebAuthnCredential"),
          HttpMethod.POST
        );
      request.setRequestParameters(
        List.of(
          new NameValuePair("userId", "no-such-user-at-all"),
          new NameValuePair("credentialId", "cred-x")
        )
      );
      Page page = wc.getPage(wc.addCrumb(request));
      assertEquals(
        404, page.getWebResponse().getStatusCode(),
        "An unknown user should be a 404"
      );
    }
  }

  /**
   * Admin removal needs only ADMINISTER + POST + crumb (works unverified and
   * with WebAuthn off), removes only the target and rotates the epoch.
   */
  @Test
  void testDoRemoveWebAuthnCredentialWorksForExemptUnverifiedAdmin(
    JenkinsRule j) throws Exception {
    j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
    j.jenkins.setAuthorizationStrategy(
      new MockAuthorizationStrategy()
        .grant(Jenkins.ADMINISTER).everywhere().to("httpremoveadmin")
    );
    // The admin is MFA-exempt (so the filter never sends them through MFA
    // verification) and the feature toggle is off entirely.
    MFAGlobalConfiguration.get().setExemptUsers(List.of("httpremoveadmin"));
    MFAGlobalConfiguration.get().setAllowWebAuthn(false);

    User victim = User.getById("httpremovevictim", true);
    MFAUserProperty prop = MFAUserProperty.getOrCreate(victim);
    prop.setSecret(totpService.generateSecret());
    prop.addWebAuthnCredential(
      new WebAuthnCredential(
        "cred-keep", "cose-keep", 0, "Keep",
        Instant.now().toString(), null
      )
    );
    prop.addWebAuthnCredential(
      new WebAuthnCredential(
        "cred-remove", "cose-remove", 0, "Remove Me",
        Instant.now().toString(), null
      )
    );
    victim.save();
    String epochBefore = prop.getOrCreateMfaEpoch();

    try (var wc = j.createWebClient()) {
      wc.setThrowExceptionOnFailingStatusCode(false);
      // HtmlUnit cannot parse the management page's script; HTTP only.
      wc.getOptions().setJavaScriptEnabled(false);
      // Password-only login: this admin's session never passes MFA.
      wc.login("httpremoveadmin");

      WebRequest request =
        new WebRequest(
          new URL(j.getURL(), "mfa-management/removeWebAuthnCredential"),
          HttpMethod.POST
        );
      request.setRequestParameters(
        List.of(
          new NameValuePair("userId", "httpremovevictim"),
          new NameValuePair("credentialId", "cred-remove")
        )
      );
      Page page = wc.getPage(wc.addCrumb(request));
      assertTrue(
        page.getWebResponse().getStatusCode() < 400,
        "Admin removal must succeed with WebAuthn disabled globally and an "
          + "unverified admin session, got: "
          + page.getWebResponse().getStatusCode()
      );
    }

    MFAUserProperty updated = MFAUserProperty.forUser(victim);
    List<String> remainingIds =
      updated.getWebAuthnCredentials()
        .stream()
        .map(WebAuthnCredential::getCredentialId)
        .toList();
    assertEquals(
      List.of("cred-keep"), remainingIds,
      "Only the targeted credential should be removed"
    );
    assertNotEquals(
      epochBefore, updated.getOrCreateMfaEpoch(),
      "Removing a credential must rotate the MFA epoch"
    );
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

      // Find testuser in the list
      UserInfo testUserInfo =
        users.stream()
          .filter(u -> "testuser".equals(u.getUserId()))
          .findFirst()
          .orElse(null);

      assertNull(testUserInfo);
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
    assertEquals("MFA User Management", Messages.DisplayNames_MFA_USER_MANAGEMENT());
  }

  @Test
  void testGetUrlName(JenkinsRule j) {
    assertEquals("mfa-management", action.getUrlName());
  }

  /**
   * Method summary for the management page: a user with two registered
   * security keys reports both the key count and the full credential list.
   */
  @Test
  void testGetUserMFAInfoIncludesWebAuthnMethodSummary(JenkinsRule j)
    throws Exception {
    User testUser = User.getById("summaryuser", true);
    MFAUserProperty prop = MFAUserProperty.getOrCreate(testUser);
    prop.setSecret(totpService.generateSecret());
    prop.addWebAuthnCredential(
      new WebAuthnCredential(
        "cred-summary-1", "cose-summary-1", 0, "Key One",
        Instant.now().toString(), null
      )
    );
    prop.addWebAuthnCredential(
      new WebAuthnCredential(
        "cred-summary-2", "cose-summary-2", 0, "Key Two",
        Instant.now().toString(), null
      )
    );
    testUser.save();

    UserInfo info = userService.getUserMFAInfo(testUser);

    assertTrue(info.isMfaEnabled());
    assertTrue(info.hasWebAuthn());
    assertEquals(2, info.getWebAuthnKeyCount());
    assertEquals(2, info.getWebAuthnCredentials().size());
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

    assertTrue(enabled <= total);
  }

  @Test
  void testMFAUserServiceResetMFA(JenkinsRule j) throws Exception {
    // Create user with MFA enabled, plus a registered security key
    User user = User.getById("resetuser", true);
    MFAUserProperty prop = MFAUserProperty.getOrCreate(user);
    prop.setSecret(totpService.generateSecret());
    prop.addWebAuthnCredential(
      new WebAuthnCredential(
        "cred-resetuser", "cose-resetuser", 0, "Reset Key",
        Instant.now().toString(), null
      )
    );
    user.save();
    String epochBefore = prop.getOrCreateMfaEpoch();

    // Verify MFA is enabled
    assertTrue(userService.isMFAEnabled(user));
    assertTrue(prop.hasWebAuthn());

    // Reset MFA
    userService.resetMFA(user);

    // Verify MFA is now disabled
    assertFalse(userService.isMFAEnabled(user));

    // Verify property is cleared: both TOTP and WebAuthn credentials, with
    // the MFA epoch rotated along the way.
    MFAUserProperty updatedProp = MFAUserProperty.forUser(user);
    assertNotNull(updatedProp);
    assertFalse(updatedProp.isEnabled(), "TOTP should be cleared");
    assertFalse(
      updatedProp.hasWebAuthn(),
      "WebAuthn credentials should be cleared by a full reset"
    );
    assertNotEquals(
      epochBefore, updatedProp.getOrCreateMfaEpoch(),
      "A full reset must rotate the MFA epoch"
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

  /** {@code error=webauthn_not_found} renders as a localized notification. */
  @Test
  void testWebAuthnNotFoundErrorRendersLocalizedNotification(JenkinsRule j)
    throws Exception {
    try (var wc = adminExemptWebClient(j, "notifyadmin")) {
      Page page =
        wc.getPage(
          new URL(
            j.getURL(),
            "mfa-management/?error=webauthn_not_found&user_id=someone"
          )
        );
      String html = page.getWebResponse().getContentAsString();
      assertTrue(
        html.contains("id=\"mfa-notification-data\""),
        "The notification element should render"
      );
      assertTrue(
        html.contains("data-type=\"error\""),
        "The notification should be flagged as an error"
      );
      assertTrue(
        html.contains(
          "The security key could not be found. It may have already been removed."
        ),
        "The localized not-found message should render in the notification"
      );
    }
  }

  /**
   * WebClient for an MFA-exempt administrator, with JavaScript disabled
   * (HtmlUnit cannot parse the management page's script).
   */
  private JenkinsRule.WebClient adminExemptWebClient(
    JenkinsRule j, String adminId) throws Exception {
    j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
    j.jenkins.setAuthorizationStrategy(
      new MockAuthorizationStrategy()
        .grant(Jenkins.ADMINISTER).everywhere().to(adminId)
    );
    MFAGlobalConfiguration.get().setExemptUsers(List.of(adminId));

    JenkinsRule.WebClient wc = j.createWebClient();
    wc.setThrowExceptionOnFailingStatusCode(false);
    wc.getOptions().setJavaScriptEnabled(false);
    wc.login(adminId);
    return wc;
  }
}
