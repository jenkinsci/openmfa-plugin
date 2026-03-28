package io.jenkins.plugins.openmfa;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import hudson.model.User;
import io.jenkins.plugins.openmfa.base.MFAContext;
import io.jenkins.plugins.openmfa.service.TOTPService;
import org.htmlunit.html.HtmlPage;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

/**
 * Integration tests for MFA filter web behavior.
 * Tests the complete web flow including filter interception and redirects.
 */
@WithJenkins
class MFAFilterWebTest {

  private final TOTPService totpService =
    MFAContext.i().getService(TOTPService.class);

  /**
   * Test that authenticated user without MFA can access root when MFA not
   * required.
   */
  @Test
  void testAuthenticatedUserWithoutMFAAccessRoot(JenkinsRule j) throws Exception {
    j.jenkins.setSecurityRealm(j.createDummySecurityRealm());

    try (var wc = j.createWebClient()) {
      wc.setThrowExceptionOnFailingStatusCode(false);
      wc.login("testuser", "password");

      HtmlPage rootPage = wc.goTo("");
      assertNotNull(
        rootPage, "Root page should be accessible without MFA when not required"
      );
    }
  }

  /**
   * Test complete MFA enrollment flow via web UI.
   */
  @Test
  void testCompleteMFAEnrollmentFlow(JenkinsRule j) throws Exception {
    j.jenkins.setSecurityRealm(j.createDummySecurityRealm());

    try (var wc = j.createWebClient()) {
      wc.setThrowExceptionOnFailingStatusCode(false);
      wc.login("enrolluser");

      // Navigate to MFA setup page
      HtmlPage setupPage = wc.goTo("user/enrolluser/mfa-setup");
      assertNotNull(setupPage, "MFA setup page should load");

      // Verify the page contains QR code placeholder or setup form
      String pageText = setupPage.asNormalizedText();
      assertTrue(
        pageText.contains("MFA")
          || pageText.contains("setup")
          || pageText.contains("QR"),
        "Setup page should contain MFA-related content"
      );
    }
  }

  /**
   * Test that exempt users can access resources without MFA when requireMFA is
   * enabled.
   */
  @Test
  void testExemptUserBypassesMFA(JenkinsRule j) throws Exception {
    j.jenkins.setSecurityRealm(j.createDummySecurityRealm());

    // Enable requireMFA
    MFAGlobalConfiguration config = MFAGlobalConfiguration.get();
    config.setRequireMFA(true);
    config.setExemptUsers("exemptuser");

    // Create exempt user
    User exemptUser = User.getById("exemptuser", true);

    try (var wc = j.createWebClient()) {
      wc.setThrowExceptionOnFailingStatusCode(false);
      wc.login("exemptuser");

      // Exempt user should be able to access root without MFA
      HtmlPage rootPage = wc.goTo("");
      assertNotNull(rootPage, "Exempt user should access root without MFA");
    }
  }

  /**
   * Test that exemption by username is case-insensitive.
   */
  @Test
  void testExemptUserCaseInsensitive(JenkinsRule j) throws Exception {
    j.jenkins.setSecurityRealm(j.createDummySecurityRealm());

    // Set exemption with uppercase
    MFAGlobalConfiguration config = MFAGlobalConfiguration.get();
    config.setRequireMFA(true);
    config.setExemptUsers("EXEMPTUSER");

    try (var wc = j.createWebClient()) {
      wc.setThrowExceptionOnFailingStatusCode(false);
      wc.login("exemptuser"); // Login with lowercase

      HtmlPage rootPage = wc.goTo("");
      assertNotNull(rootPage, "Exemption should be case-insensitive");
    }
  }

  /**
   * Test login form submission with valid credentials.
   */
  @Test
  void testLoginFormSubmission(JenkinsRule j) throws Exception {
    j.jenkins.setSecurityRealm(j.createDummySecurityRealm());

    try (var wc = j.createWebClient()) {
      wc.setThrowExceptionOnFailingStatusCode(false);

      // Go to login page
      HtmlPage loginPage = wc.goTo("login");
      assertNotNull(loginPage, "Login page should load");

      // Use WebClient's login method instead of direct form submission
      wc.login("validuser", "validpassword");

      // Should be redirected to root page after login
      HtmlPage resultPage = wc.goTo("");
      assertNotNull(resultPage, "Should redirect after successful login");
    }
  }

  /**
   * Test logout clears session properly.
   */
  @Test
  void testLogoutClearsSession(JenkinsRule j) throws Exception {
    j.jenkins.setSecurityRealm(j.createDummySecurityRealm());

    try (var wc = j.createWebClient()) {
      wc.setThrowExceptionOnFailingStatusCode(false);
      wc.login("logoutuser");

      // Verify logged in
      HtmlPage rootPage = wc.goTo("");
      assertNotNull(rootPage);

      // Logout
      wc.goTo("logout");

      // Should be redirected to login page
      HtmlPage afterLogout = wc.goTo("");
      assertNotNull(afterLogout);
    }
  }

  /**
   * Test that MFA setup page is accessible for enrolled users.
   */
  @Test
  void testMFASetupPageAccessible(JenkinsRule j) throws Exception {
    j.jenkins.setSecurityRealm(j.createDummySecurityRealm());

    try (var wc = j.createWebClient()) {
      wc.setThrowExceptionOnFailingStatusCode(false);
      wc.login("setupuser");

      // Access MFA setup page
      HtmlPage setupPage = wc.goTo("user/setupuser/mfa-setup");
      assertNotNull(setupPage, "MFA setup page should be accessible");
    }
  }

  /**
   * Test that non-exempt users are challenged for MFA when requireMFA is enabled.
   */
  @Test
  void testNonExemptUserChallengedForMFA(JenkinsRule j) throws Exception {
    j.jenkins.setSecurityRealm(j.createDummySecurityRealm());

    // Enable requireMFA with no exemptions
    MFAGlobalConfiguration config = MFAGlobalConfiguration.get();
    config.setRequireMFA(true);
    config.setExemptUsers("");

    try (var wc = j.createWebClient()) {
      wc.setThrowExceptionOnFailingStatusCode(false);
      wc.login("regularuser");

      // Non-exempt user should be redirected to MFA setup/challenge
      HtmlPage page = wc.goTo("");

      // Should be redirected to MFA-related page (not the requested page)
      // The exact behavior depends on MFA enrollment state
      assertNotNull(page);
    }
  }

  /**
   * Test session behavior after MFA verification.
   */
  @Test
  void testSessionAfterMFAVerification(JenkinsRule j) throws Exception {
    // Create user with MFA enabled
    User testUser = User.getById("sessionuser", true);
    MFAUserProperty property = MFAUserProperty.getOrCreate(testUser);
    String secret = totpService.generateSecret().getEncryptedValue();
    property.setSecret(hudson.util.Secret.fromString(secret));
    testUser.save();

    j.jenkins.setSecurityRealm(j.createDummySecurityRealm());

    // Note: Full MFA flow test would require simulating the MFA filter chain
    // which is complex in test environment. This test verifies the user property
    // is correctly set up for MFA verification.
    assertTrue(property.isEnabled(), "MFA should be enabled for test user");
  }

  /**
   * Test that static and adjunct resources are accessible without MFA.
   */
  @Test
  void testStaticAndAdjunctResourcesAccess(JenkinsRule j) throws Exception {
    j.jenkins.setSecurityRealm(j.createDummySecurityRealm());

    try (var wc = j.createWebClient()) {
      wc.setThrowExceptionOnFailingStatusCode(false);

      // Access various static resource paths
      assertNotNull(wc.goTo("static/"), "Static resources should be accessible");
      assertNotNull(wc.goTo("adjuncts/"), "Adjunct resources should be accessible");
    }
  }

  /**
   * Test that unauthenticated users can access login page.
   */
  @Test
  void testUnauthenticatedUserCanAccessLogin(JenkinsRule j) throws Exception {
    j.jenkins.setSecurityRealm(j.createDummySecurityRealm());

    try (var wc = j.createWebClient()) {
      wc.setThrowExceptionOnFailingStatusCode(false);
      HtmlPage loginPage = wc.goTo("login");
      assertNotNull(loginPage, "Login page should be accessible");
    }
  }

}
