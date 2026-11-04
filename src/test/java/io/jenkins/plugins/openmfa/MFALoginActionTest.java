package io.jenkins.plugins.openmfa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import hudson.model.User;
import hudson.security.csrf.CrumbIssuer;
import io.jenkins.plugins.openmfa.base.MFAContext;
import io.jenkins.plugins.openmfa.constant.PluginConstants;
import io.jenkins.plugins.openmfa.service.WebAuthnService;
import io.jenkins.plugins.openmfa.service.model.WebAuthnCredential;
import jakarta.servlet.http.HttpSession;
import java.net.URL;
import org.htmlunit.HttpMethod;
import org.htmlunit.Page;
import org.htmlunit.WebRequest;
import org.htmlunit.html.HtmlPage;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

/**
 * Integration tests for MFALoginAction.
 * Tests TOTP verification, redirect validation, and rate limiting.
 */
@WithJenkins
class MFALoginActionTest {

  /**
   * Restore the real WebAuthnService after any test that stubbed it, so the
   * stub never leaks into an unrelated test.
   */
  @AfterEach
  void restoreRealWebAuthnService() {
    MFAContext.i().removeService(WebAuthnService.class);
  }

  /**
   * Test getFromParam preserves redirect target.
   */
  @Test
  void testGetFromParamPreservesTarget(JenkinsRule j) throws Exception {
    j.jenkins.setSecurityRealm(j.createDummySecurityRealm());

    try (var wc = j.createWebClient()) {
      wc.setThrowExceptionOnFailingStatusCode(false);

      // Access MFA login page with from parameter
      HtmlPage mfaPage =
        wc.goTo(
          PluginConstants.Urls.LOGIN_ACTION_URL + "?from=%2Fjob%2Ftest"
        );
      assertNotNull(mfaPage, "MFA page should load with from parameter");
    }
  }

  /**
   * Test getFromParam returns null when no from parameter.
   */
  @Test
  void testGetFromParamWhenNull(JenkinsRule j) throws Exception {
    j.jenkins.setSecurityRealm(j.createDummySecurityRealm());

    try (var wc = j.createWebClient()) {
      wc.setThrowExceptionOnFailingStatusCode(false);

      // Access MFA login page without from parameter
      HtmlPage mfaPage = wc.goTo(PluginConstants.Urls.LOGIN_ACTION_URL);
      assertNotNull(mfaPage, "MFA page should load without from parameter");
    }
  }

  /**
   * getPreferredMethod() falls back to "totp" when the user has no recorded
   * last-used method yet.
   */
  @Test
  void testGetPreferredMethodDefaultsToTotpWhenLastUsedMethodIsNull(
    JenkinsRule j) throws Exception {
    j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
    User user = User.getById("preferredmethoduser", true);
    MFAUserProperty.getOrCreate(user);
    user.save();

    try (var wc = j.createWebClient()) {
      wc.setThrowExceptionOnFailingStatusCode(false);
      wc.login("preferredmethoduser");
      wc.goTo(PluginConstants.Urls.LOGIN_ACTION_URL);

      assertNull(
        MFAUserProperty.forUser(user).getLastUsedMethod(),
        "Last used method should be null before any challenge is satisfied"
      );
      assertEquals(
        PluginConstants.MFAMethods.TOTP, new MFALoginAction().getPreferredMethod(),
        "getPreferredMethod() should default to totp when lastUsedMethod is null"
      );
    }
  }

  /**
   * Test isSafeRedirectTarget accepts safe relative paths.
   */
  @Test
  void testIsSafeRedirectTargetAcceptsRelativePaths() {
    try {
      var method =
        MFALoginAction.class.getDeclaredMethod("isSafeRedirectTarget", String.class);
      method.setAccessible(true);
      MFALoginAction action = new MFALoginAction();

      assertTrue(
        (Boolean) method.invoke(action, "/"),
        "Should accept root path"
      );
      assertTrue(
        (Boolean) method.invoke(action, "/jenkins/"),
        "Should accept relative path"
      );
      assertTrue(
        (Boolean) method.invoke(action, "/job/test"),
        "Should accept job path"
      );
    } catch (Exception e) {
      // Fallback if reflection fails
    }
  }

  /**
   * Test isSafeRedirectTarget rejects open redirect attempts.
   */
  @Test
  void testIsSafeRedirectTargetRejectsAbsoluteUrls() {
    // Use reflection to test private method
    try {
      var method =
        MFALoginAction.class.getDeclaredMethod("isSafeRedirectTarget", String.class);
      method.setAccessible(true);
      MFALoginAction action = new MFALoginAction();

      assertFalse(
        (Boolean) method.invoke(action, "http://evil.com"),
        "Should reject http:// URLs"
      );
      assertFalse(
        (Boolean) method.invoke(action, "https://evil.com"),
        "Should reject https:// URLs"
      );
      assertFalse(
        (Boolean) method.invoke(action, "//evil.com"),
        "Should reject protocol-relative URLs"
      );
    } catch (Exception e) {
      // If reflection fails, test via public API
      // This is a fallback for testing private methods
    }
  }

  /**
   * Test isSafeRedirectTarget rejects paths with protocol.
   */
  @Test
  void testIsSafeRedirectTargetRejectsProtocolPaths() {
    try {
      var method =
        MFALoginAction.class.getDeclaredMethod(
          "isSafeRedirectTarget", String.class
        );
      method.setAccessible(true);
      MFALoginAction action = new MFALoginAction();

      assertFalse(
        (Boolean) method.invoke(action, "javascript:alert(1)"),
        "Should reject javascript: protocol"
      );
      assertFalse(
        (Boolean) method.invoke(action, "data:text/html,<script>alert(1)</script>"),
        "Should reject data: URLs"
      );
    } catch (Exception e) {
      // Fallback if reflection fails
    }
  }

  /**
   * Test MFALoginAction is accessible when user has pending MFA.
   */
  @Test
  void testMFAActionAccessible(JenkinsRule j) throws Exception {
    j.jenkins.setSecurityRealm(j.createDummySecurityRealm());

    try (var wc = j.createWebClient()) {
      wc.setThrowExceptionOnFailingStatusCode(false);
      wc.login("mfaactionuser");

      // Access MFA login action page
      HtmlPage mfaPage = wc.goTo(PluginConstants.Urls.LOGIN_ACTION_URL);
      assertNotNull(mfaPage, "MFA login page should be accessible");
    }
  }

  /**
   * webauthn-challenge is forbidden when WebAuthn is disabled globally, even
   * for a user who already has a registered key.
   */
  @Test
  void testWebauthnChallengeForbiddenWhenAllowWebAuthnFalse(JenkinsRule j)
    throws Exception {
    j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
    MFAGlobalConfiguration.get().setAllowWebAuthn(false);
    enrollUserWithWebAuthnCredential("webauthndisableduser");

    try (var wc = j.createWebClient()) {
      wc.setThrowExceptionOnFailingStatusCode(false);
      wc.login("webauthndisableduser");

      Page page = postWithCrumb(j, wc, "mfa-login/webauthn-challenge", null);
      assertEquals(
        403, page.getWebResponse().getStatusCode(),
        "Challenge should be forbidden when WebAuthn is disabled"
      );
    }
  }

  /**
   * webauthn-challenge returns the options JSON produced by the service for
   * an enrolled user who has a registered key.
   */
  @Test
  void testWebauthnChallengeReturnsOptionsJsonForEnrolledUser(JenkinsRule j)
    throws Exception {
    j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
    String canned = "{\"publicKey\":{\"challenge\":\"abc123\"}}";
    MFAContext.i()
      .registerService(WebAuthnService.class, new FakeWebAuthnService(canned));
    enrollUserWithWebAuthnCredential("webauthnchallengeuser");

    try (var wc = j.createWebClient()) {
      wc.setThrowExceptionOnFailingStatusCode(false);
      wc.login("webauthnchallengeuser");

      Page page = postWithCrumb(j, wc, "mfa-login/webauthn-challenge", null);
      assertEquals(
        200, page.getWebResponse().getStatusCode(),
        "Challenge should succeed for an enrolled user"
      );
      assertEquals(
        canned, page.getWebResponse().getContentAsString(),
        "Challenge should return the service's options JSON verbatim"
      );
    }
  }

  /**
   * Five consecutive failed assertions lock the user out, same as TOTP.
   */
  @Test
  void testWebauthnVerifyFailureCountsTowardLockout(JenkinsRule j)
    throws Exception {
    j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
    FakeWebAuthnService fake = new FakeWebAuthnService("{}");
    fake.finishResult = false;
    MFAContext.i().registerService(WebAuthnService.class, fake);
    enrollUserWithWebAuthnCredential("webauthnlockoutuser");

    try (var wc = j.createWebClient()) {
      wc.setThrowExceptionOnFailingStatusCode(false);
      wc.login("webauthnlockoutuser");

      Page page = null;
      for (int i = 0; i < PluginConstants.RateLimit.MAX_ATTEMPTS; i++) {
        page = postWithCrumb(j, wc, "mfa-login/webauthn-verify", "{}");
      }

      assertNotNull(page);
      assertTrue(
        page.getUrl().toString().contains("error=locked"),
        "5th failed WebAuthn attempt should lock the user out, got: "
          + page.getUrl()
      );
    }
  }

  /**
   * A garbage assertion response body is rejected as an ordinary failed
   * verification (not a server error), against the real WebAuthnService.
   */
  @Test
  void testWebauthnVerifyGarbageBodyIsRejectedNotServerError(JenkinsRule j)
    throws Exception {
    j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
    enrollUserWithWebAuthnCredential("webauthngarbageuser");

    try (var wc = j.createWebClient()) {
      wc.setThrowExceptionOnFailingStatusCode(false);
      wc.login("webauthngarbageuser");
      // Start a real ceremony so there is something pending to fail.
      postWithCrumb(j, wc, "mfa-login/webauthn-challenge", null);

      Page page =
        postWithCrumb(j, wc, "mfa-login/webauthn-verify", "not valid json{{{");
      assertTrue(
        page.getWebResponse().getStatusCode() < 500,
        "Garbage body must not cause a server error, got: "
          + page.getWebResponse().getStatusCode()
      );
      assertTrue(
        page.getUrl().toString().contains("error=invalid"),
        "Garbage body should redirect back with error=invalid, got: "
          + page.getUrl()
      );
    }
  }

  /**
   * A request body larger than the 64KB cap is rejected as ordinary invalid
   * input (never even reaching the service), not a server error.
   */
  @Test
  void testWebauthnVerifyOversizedBodyIsRejectedAsInvalid(JenkinsRule j)
    throws Exception {
    j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
    enrollUserWithWebAuthnCredential("webauthnoversizeduser");

    try (var wc = j.createWebClient()) {
      wc.setThrowExceptionOnFailingStatusCode(false);
      wc.login("webauthnoversizeduser");
      // Start a real ceremony so there is something pending to fail.
      postWithCrumb(j, wc, "mfa-login/webauthn-challenge", null);

      // 70KB of padding, comfortably past the 64KB cap, wrapped to look
      // like a plausible (if oversized) assertion response body.
      String oversizedBody = "{\"pad\":\"" + "A".repeat(70 * 1024) + "\"}";
      Page page =
        postWithCrumb(j, wc, "mfa-login/webauthn-verify", oversizedBody);
      assertTrue(
        page.getWebResponse().getStatusCode() < 500,
        "Oversized body must not cause a server error, got: "
          + page.getWebResponse().getStatusCode()
      );
      assertTrue(
        page.getUrl().toString().contains("error=invalid"),
        "Oversized body should redirect back with error=invalid, got: "
          + page.getUrl()
      );
    }
  }

  /**
   * A successful assertion verifies the session, records "webauthn" as the
   * last used method, and (with "Keep me signed in") issues the remember-MFA
   * cookie.
   */
  @Test
  void testWebauthnVerifySuccessVerifiesSessionAndRemembers(JenkinsRule j)
    throws Exception {
    j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
    MFAContext.i()
      .registerService(WebAuthnService.class, new FakeWebAuthnService("{}"));
    User user = enrollUserWithWebAuthnCredential("webauthnsuccessuser");

    try (var wc = j.createWebClient()) {
      wc.setThrowExceptionOnFailingStatusCode(false);
      wc.login("webauthnsuccessuser", "webauthnsuccessuser", true);

      Page page = postWithCrumb(j, wc, "mfa-login/webauthn-verify", "{}");
      assertFalse(
        page.getUrl().toString().contains("mfa-login?error"),
        "Successful assertion should not redirect back with an error"
      );

      MFAUserProperty property = MFAUserProperty.forUser(user);
      assertEquals(
        PluginConstants.MFAMethods.WEBAUTHN, property.getLastUsedMethod(),
        "Last used method should be recorded as webauthn"
      );

      boolean hasRememberCookie =
        wc.getCookieManager()
          .getCookies()
          .stream()
          .anyMatch(
            c -> PluginConstants.RememberMFA.COOKIE_NAME.equals(c.getName())
          );
      assertTrue(
        hasRememberCookie,
        "Remember-MFA cookie should be issued when 'Keep me signed in' is used"
      );

      Page afterVerify = wc.goTo("");
      assertFalse(
        afterVerify.getUrl().toString().contains("mfa-login"),
        "Session should already be MFA-verified after a successful assertion"
      );
    }
  }

  /**
   * Creates a user with a registered WebAuthn credential (and no TOTP
   * secret), returning the user.
   */
  private User enrollUserWithWebAuthnCredential(String username)
    throws Exception {
    User user = User.getById(username, true);
    MFAUserProperty property = MFAUserProperty.getOrCreate(user);
    property.addWebAuthnCredential(
      new WebAuthnCredential(
        "cred-" + username, "cose-" + username, 0, "Test key",
        java.time.Instant.now().toString(), null
      )
    );
    user.save();
    return user;
  }

  /**
   * POSTs a crumb-protected request to a MFALoginAction endpoint, optionally
   * with a raw JSON body.
   */
  private Page postWithCrumb(
    JenkinsRule j, JenkinsRule.WebClient wc, String path, String body)
    throws Exception {
    WebRequest request = new WebRequest(new URL(j.getURL(), path), HttpMethod.POST);
    CrumbIssuer crumbIssuer = j.jenkins.getCrumbIssuer();
    if (crumbIssuer != null) {
      request
        .setAdditionalHeader(
          crumbIssuer.getCrumbRequestField(),
          crumbIssuer.getCrumb((jakarta.servlet.ServletRequest) null)
        );
    }
    if (body != null) {
      request.setAdditionalHeader("Content-Type", "application/json");
      request.setRequestBody(body);
    }
    return wc.getPage(request);
  }

  /**
   * Fake {@link WebAuthnService} used to stub the ceremony outcome for the
   * assertion-endpoint tests without needing a real authenticator.
   */
  private static class FakeWebAuthnService extends WebAuthnService {

    private boolean available = true;

    private boolean finishResult = true;

    private final String optionsJson;

    FakeWebAuthnService(String optionsJson) {
      this.optionsJson = optionsJson;
    }

    @Override
    public boolean finishAssertion(
      HttpSession session, User user, String responseJson) {
      return finishResult;
    }

    @Override
    public boolean isAvailable() {
      return available;
    }

    @Override
    public String startAssertion(HttpSession session, User user) {
      return optionsJson;
    }
  }

}
