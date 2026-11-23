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
import java.io.IOException;
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
    enrollUser("rememberuser");

    try (var wc = j.createWebClient()) {
      wc.setThrowExceptionOnFailingStatusCode(false);
      wc.login("rememberuser");

      String token =
        rememberMFAService.createTokenValue(
          "rememberuser",
          epochForUser("rememberuser"),
          System.currentTimeMillis() + ONE_DAY_MS
        );
      addRememberCookie(j, wc, token);

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

      addRememberCookie(j, wc, "bm90:12345678901234:dmFsaWQ");

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
    enrollUser("disabledfilteruser");

    try (var wc = j.createWebClient()) {
      wc.setThrowExceptionOnFailingStatusCode(false);
      wc.login("disabledfilteruser");

      String token =
        rememberMFAService.createTokenValue(
          "disabledfilteruser",
          epochForUser("disabledfilteruser"),
          System.currentTimeMillis() + ONE_DAY_MS
        );
      MFAGlobalConfiguration.get().setRememberMfaHours(0);

      addRememberCookie(j, wc, token);

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
   * TOTP re-enrollment rotates the epoch, invalidating old remember-MFA
   * cookies. Separate WebClients keep a verified session from masking this.
   */
  @Test
  void testReEnrollmentInvalidatesRememberCookie(JenkinsRule j)
    throws Exception {
    j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
    enrollUser("reenrolluser");

    String tokenBeforeReEnrollment =
      rememberMFAService.createTokenValue(
        "reenrolluser",
        epochForUser("reenrolluser"),
        System.currentTimeMillis() + ONE_DAY_MS
      );

    // Sanity check, on a disposable client/session: the token issued under
    // the pre-re-enrollment epoch is accepted before anything changes.
    try (var sanityWc = j.createWebClient()) {
      sanityWc.setThrowExceptionOnFailingStatusCode(false);
      sanityWc.login("reenrolluser");
      addRememberCookie(j, sanityWc, tokenBeforeReEnrollment);

      Page before = sanityWc.goTo("");
      assertFalse(
        before.getUrl().toString().contains("mfa-login"),
        "Remember-MFA cookie should be valid before re-enrollment"
      );
    }

    // Re-enroll from its own session so its verified state cannot leak.
    try (var reEnrollWc = j.createWebClient()) {
      reEnrollWc.setThrowExceptionOnFailingStatusCode(false);
      reEnrollWc.login("reenrolluser");
      Secret newSecret = totpService.generateSecret();
      postEnable(
        j, reEnrollWc, "reenrolluser", newSecret,
        totpService.generateTOTP(newSecret)
      );
    }

    // A fresh, never-before-verified client/session presenting the same
    // old-epoch cookie must now be challenged.
    try (var afterWc = j.createWebClient()) {
      afterWc.setThrowExceptionOnFailingStatusCode(false);
      afterWc.login("reenrolluser");
      addRememberCookie(j, afterWc, tokenBeforeReEnrollment);

      Page after = afterWc.goTo("");
      assertTrue(
        after.getUrl().toString().contains("mfa-login"),
        "Remember-MFA cookie issued under the old secret must be rejected "
          + "once TOTP is re-enrolled with a new one"
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
   * Installs a remember-MFA cookie with the given token value on the given
   * web client.
   */
  private void addRememberCookie(
    JenkinsRule j, JenkinsRule.WebClient wc, String token)
    throws IOException {
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
   * Returns the current MFA epoch for an already-enrolled user.
   */
  private String epochForUser(String username) {
    MFAUserProperty property = MFAUserProperty.forUser(User.getById(username, false));
    return property.getOrCreateMfaEpoch();
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
   * Submits a (re-)enrollment to the MFA setup "enable" endpoint for the
   * given user, with the given secret and matching TOTP code.
   */
  private Page postEnable(
    JenkinsRule j, JenkinsRule.WebClient wc, String username, Secret secret,
    String code) throws Exception {
    WebRequest request =
      new WebRequest(
        new URL(j.getURL(), "user/" + username + "/mfa-setup/enable"),
        HttpMethod.POST
      );
    request.setRequestParameters(
      List.of(
        new NameValuePair(
          PluginConstants.FormParameters.SECRET, secret.getPlainText()
        ),
        new NameValuePair(PluginConstants.FormParameters.CODE, code)
      )
    );
    return wc.getPage(wc.addCrumb(request));
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
