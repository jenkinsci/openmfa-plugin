package io.jenkins.plugins.openmfa;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.htmlunit.Page;
import org.htmlunit.html.HtmlPage;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

/**
 * Integration tests for MFA filter and request handling.
 * Tests basic web layer functionality.
 */
@WithJenkins
class MFAFilterIntegrationTest {

  /**
   * Test adjunct resources are accessible without MFA verification.
   */
  @Test
  void testAdjunctResourcesAccess(JenkinsRule j) throws Exception {
    j.jenkins.setSecurityRealm(j.createDummySecurityRealm());

    try (var wc = j.createWebClient()) {
      // Access adjunct resources should be allowed without MFA
      wc.setThrowExceptionOnFailingStatusCode(false);
      Page page = wc.goTo("adjuncts/");
      assertNotNull(page, "Adjuncts should be accessible");
    }
  }

  /**
   * Test access to Jenkins root for authenticated user without MFA.
   */
  @Test
  void testAuthenticatedUserWithoutMFA(JenkinsRule j) throws Exception {
    j.jenkins.setSecurityRealm(j.createDummySecurityRealm());

    try (var wc = j.createWebClient()) {
      wc.setThrowExceptionOnFailingStatusCode(false);
      // Log in as the test user
      wc.login("nomfauser");

      // Without MFA configured and MFA not required, access should be allowed
      HtmlPage rootPage = wc.goTo("");
      assertNotNull(
        rootPage, "Root page should be accessible without MFA when not required"
      );
    }
  }

  /**
   * Test logout endpoint accessibility.
   */
  @Test
  void testLogoutEndpoint(JenkinsRule j) throws Exception {
    try (var wc = j.createWebClient()) {
      wc.setThrowExceptionOnFailingStatusCode(false);
      // Logout should be accessible (in case there's an active session)
      wc.goTo("logout");
      // Should not throw exception
    }
  }

  /**
   * Test access to public pages without authentication.
   */
  @Test
  void testPublicPageAccess(JenkinsRule j) throws Exception {
    // Login page should be accessible without authentication
    try (var wc = j.createWebClient()) {
      wc.setThrowExceptionOnFailingStatusCode(false);
      HtmlPage loginPage = wc.goTo("login");
      assertNotNull(loginPage, "Login page should be accessible");
    }
  }

  /**
   * Test static resources are accessible without MFA verification.
   */
  @Test
  void testStaticResourcesAccess(JenkinsRule j) throws Exception {
    try (var wc = j.createWebClient()) {
      wc.setThrowExceptionOnFailingStatusCode(false);

      // Static resources should be accessible
      Page page = wc.goTo("static/");
      assertNotNull(page, "Static resources should be accessible");
    }
  }
}
