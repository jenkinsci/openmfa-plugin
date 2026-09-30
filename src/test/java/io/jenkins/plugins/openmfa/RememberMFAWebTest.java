package io.jenkins.plugins.openmfa;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import hudson.model.User;
import hudson.util.Secret;
import io.jenkins.plugins.openmfa.base.MFAContext;
import io.jenkins.plugins.openmfa.constant.PluginConstants;
import io.jenkins.plugins.openmfa.service.RememberMFAService;
import io.jenkins.plugins.openmfa.service.TOTPService;
import java.net.URL;
import java.util.List;
import org.htmlunit.HttpMethod;
import org.htmlunit.Page;
import org.htmlunit.WebRequest;
import org.htmlunit.util.NameValuePair;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

/**
 * Integration tests for the remember-MFA cookie tied to "Keep me signed in".
 */
@WithJenkins
class RememberMFAWebTest {

  private static final long ONE_DAY_MS = 24L * 60 * 60 * 1000;

  private final RememberMFAService rememberMFAService =
    MFAContext.i().getService(RememberMFAService.class);

  private final TOTPService totpService =
    MFAContext.i().getService(TOTPService.class);

  /**
   * A valid remember-MFA cookie lets a fresh session through without an MFA
   * challenge.
   */
  @Test
  void testFilterAcceptsValidRememberCookie(JenkinsRule j) throws Exception {
    j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
    Secret secret = enrollUser("rememberuser");

    try (var wc = j.createWebClient()) {
      wc.setThrowExceptionOnFailingStatusCode(false);
      wc.login("rememberuser");

      String token =
        rememberMFAService.createTokenValue(
          "rememberuser", secret, System.currentTimeMillis() + ONE_DAY_MS
        );
      URL url = j.getURL();
      wc.getCookieManager()
        .addCookie(
          new org.htmlunit.util.Cookie(
            url.getHost(),
            PluginConstants.RememberMFA.COOKIE_NAME,
            token,
            url.getPath(),
            null,
            false
          )
        );

      Page page = wc.goTo("");
      assertFalse(
        page.getUrl().toString().contains("mfa-login"),
        "Valid remember-MFA cookie should skip the MFA challenge"
      );
    }
  }

  /**
   * A tampered remember-MFA cookie is ignored and the user is challenged.
   */
  @Test
  void testFilterChallengesWithInvalidRememberCookie(JenkinsRule j)
    throws Exception {
    j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
    enrollUser("tampereduser");

    try (var wc = j.createWebClient()) {
      wc.setThrowExceptionOnFailingStatusCode(false);
      wc.login("tampereduser");

      URL url = j.getURL();
      wc.getCookieManager()
        .addCookie(
          new org.htmlunit.util.Cookie(
            url.getHost(),
            PluginConstants.RememberMFA.COOKIE_NAME,
            "bm90:12345678901234:dmFsaWQ",
            url.getPath(),
            null,
            false
          )
        );

      Page page = wc.goTo("");
      assertTrue(
        page.getUrl().toString().contains("mfa-login"),
        "Invalid remember-MFA cookie should not skip the MFA challenge"
      );
    }
  }

  /**
   * Without a remember-MFA cookie a fresh session is challenged for MFA.
   */
  @Test
  void testFilterChallengesWithoutRememberCookie(JenkinsRule j)
    throws Exception {
    j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
    enrollUser("challengeduser");

    try (var wc = j.createWebClient()) {
      wc.setThrowExceptionOnFailingStatusCode(false);
      wc.login("challengeduser");

      Page page = wc.goTo("");
      assertTrue(
        page.getUrl().toString().contains("mfa-login"),
        "Without a remember-MFA cookie the user should be challenged"
      );
    }
  }

  /**
   * A valid remember-MFA cookie is ignored when the feature is disabled.
   */
  @Test
  void testFilterIgnoresCookieWhenDisabled(JenkinsRule j) throws Exception {
    j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
    Secret secret = enrollUser("disabledfilteruser");

    try (var wc = j.createWebClient()) {
      wc.setThrowExceptionOnFailingStatusCode(false);
      wc.login("disabledfilteruser");

      String token =
        rememberMFAService.createTokenValue(
          "disabledfilteruser", secret, System.currentTimeMillis() + ONE_DAY_MS
        );
      MFAGlobalConfiguration.get().setRememberMfaHours(0);

      URL url = j.getURL();
      wc.getCookieManager()
        .addCookie(
          new org.htmlunit.util.Cookie(
            url.getHost(),
            PluginConstants.RememberMFA.COOKIE_NAME,
            token,
            url.getPath(),
            null,
            false
          )
        );

      Page page = wc.goTo("");
      assertTrue(
        page.getUrl().toString().contains("mfa-login"),
        "Remember-MFA cookie should be ignored when the feature is disabled"
      );
    }
  }

  /**
   * Logging out clears the remember-MFA cookie.
   */
  @Test
  void testLogoutClearsRememberCookie(JenkinsRule j) throws Exception {
    j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
    Secret secret = enrollUser("logoutuser");

    try (var wc = j.createWebClient()) {
      wc.setThrowExceptionOnFailingStatusCode(false);
      wc.login("logoutuser", "logoutuser", true);

      postVerify(j, wc, totpService.generateTOTP(secret));
      assertNotNull(
        findRememberCookie(wc),
        "Remember-MFA cookie should exist before logout"
      );

      wc.goTo("logout");

      assertNull(
        findRememberCookie(wc),
        "Remember-MFA cookie should be cleared on logout"
      );
    }
  }

  /**
   * Passing MFA with the Jenkins remember-me cookie present issues a
   * remember-MFA cookie.
   */
  @Test
  void testVerifyIssuesCookieWithRememberMe(JenkinsRule j) throws Exception {
    j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
    Secret secret = enrollUser("keepmeuser");

    try (var wc = j.createWebClient()) {
      wc.setThrowExceptionOnFailingStatusCode(false);
      wc.login("keepmeuser", "keepmeuser", true);

      postVerify(j, wc, totpService.generateTOTP(secret));

      assertNotNull(
        findRememberCookie(wc),
        "Remember-MFA cookie should be issued when 'Keep me signed in' is used"
      );
    }
  }

  /**
   * No remember-MFA cookie is issued when the feature is disabled.
   */
  @Test
  void testVerifyIssuesNoCookieWhenDisabled(JenkinsRule j) throws Exception {
    j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
    MFAGlobalConfiguration.get().setRememberMfaHours(0);
    Secret secret = enrollUser("disableduser");

    try (var wc = j.createWebClient()) {
      wc.setThrowExceptionOnFailingStatusCode(false);
      wc.login("disableduser", "disableduser", true);

      postVerify(j, wc, totpService.generateTOTP(secret));

      assertNull(
        findRememberCookie(wc),
        "No remember-MFA cookie should be issued when the feature is disabled"
      );
    }
  }

  /**
   * Passing MFA without the Jenkins remember-me cookie does not issue a
   * remember-MFA cookie.
   */
  @Test
  void testVerifyIssuesNoCookieWithoutRememberMe(JenkinsRule j)
    throws Exception {
    j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
    Secret secret = enrollUser("plainuser");

    try (var wc = j.createWebClient()) {
      wc.setThrowExceptionOnFailingStatusCode(false);
      wc.login("plainuser");

      postVerify(j, wc, totpService.generateTOTP(secret));

      assertNull(
        findRememberCookie(wc),
        "No remember-MFA cookie should be issued without 'Keep me signed in'"
      );
    }
  }

  /**
   * Creates a user with MFA enabled and returns their TOTP secret.
   */
  private Secret enrollUser(String username) throws Exception {
    User user = User.getById(username, true);
    MFAUserProperty property = MFAUserProperty.getOrCreate(user);
    Secret secret = totpService.generateSecret();
    property.setSecret(secret);
    user.save();
    return secret;
  }

  /**
   * Finds the remember-MFA cookie in the web client, or null.
   */
  private org.htmlunit.util.Cookie findRememberCookie(
    JenkinsRule.WebClient wc) {
    return wc.getCookieManager()
      .getCookies()
      .stream()
      .filter(
        c -> PluginConstants.RememberMFA.COOKIE_NAME.equals(c.getName())
      )
      .findFirst()
      .orElse(null);
  }

  /**
   * Submits a TOTP code to the MFA verify endpoint.
   */
  private Page postVerify(JenkinsRule j, JenkinsRule.WebClient wc, String code)
    throws Exception {
    WebRequest request =
      new WebRequest(
        new URL(j.getURL(), "mfa-login/verify"), HttpMethod.POST
      );
    request.setRequestParameters(
      List.of(
        new NameValuePair(PluginConstants.FormParameters.TOTP_CODE, code)
      )
    );
    return wc.getPage(wc.addCrumb(request));
  }
}
