package io.jenkins.plugins.openmfa;

import static io.jenkins.plugins.openmfa.WebAuthnTestSupport.findById;
import static io.jenkins.plugins.openmfa.WebAuthnTestSupport.postWithCrumb;
import static io.jenkins.plugins.openmfa.WebAuthnTestSupport.testCredential;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import hudson.model.User;
import hudson.util.Secret;
import io.jenkins.plugins.openmfa.WebAuthnTestSupport.FakeWebAuthnService;
import io.jenkins.plugins.openmfa.base.MFAContext;
import io.jenkins.plugins.openmfa.constant.PluginConstants;
import io.jenkins.plugins.openmfa.service.RememberMFAService;
import io.jenkins.plugins.openmfa.service.TOTPService;
import io.jenkins.plugins.openmfa.service.WebAuthnService;
import io.jenkins.plugins.openmfa.service.model.WebAuthnCredential;
import java.io.IOException;
import java.net.URL;
import java.util.List;
import jenkins.model.Jenkins;
import org.htmlunit.HttpMethod;
import org.htmlunit.Page;
import org.htmlunit.WebRequest;
import org.htmlunit.html.HtmlPage;
import org.htmlunit.util.NameValuePair;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.MockAuthorizationStrategy;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

/**
 * Integration tests for the setup page's security-key endpoints, mostly what
 * they refuse (the page is reachable by a password-only session).
 */
@WithJenkins
class MFASetupActionWebAuthnTest {

  private static final long ONE_DAY_MS = 24L * 60 * 60 * 1000;

  private final RememberMFAService rememberMFAService =
    MFAContext.i().getService(RememberMFAService.class);

  private final TOTPService totpService =
    MFAContext.i().getService(TOTPService.class);

  /**
   * Restore the real WebAuthnService after any test that stubbed it, so the
   * stub never leaks into an unrelated test.
   */
  @AfterEach
  void restoreRealWebAuthnService() {
    MFAContext.i().removeService(WebAuthnService.class);
  }

  /**
   * Disabling TOTP also deletes every registered security key (TOTP is the
   * enrollment anchor), and rotates the epoch along the way.
   */
  @Test
  void testDisableClearsWebAuthnCredentials(JenkinsRule j) throws Exception {
    j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
    Secret secret = enrollUser("disableclearsuser", 1);
    User user = User.getById("disableclearsuser", false);
    String epochBefore = MFAUserProperty.forUser(user).getOrCreateMfaEpoch();

    try (var wc = j.createWebClient()) {
      wc.setThrowExceptionOnFailingStatusCode(false);
      loginAndVerify(j, wc, "disableclearsuser", secret);

      Page page =
        postWithCrumb(j, wc, "user/disableclearsuser/mfa-setup/disable", null);
      assertTrue(
        page.getWebResponse().getStatusCode() < 400,
        "Disable should succeed, got: " + page.getWebResponse().getStatusCode()
      );
    }

    MFAUserProperty property = MFAUserProperty.forUser(user);
    assertFalse(property.isEnabled(), "TOTP should be disabled");
    assertFalse(
      property.hasWebAuthn(),
      "Disabling TOTP must also remove every registered security key"
    );
    assertNotEquals(
      epochBefore, property.getOrCreateMfaEpoch(),
      "Disabling TOTP must rotate the MFA epoch"
    );
  }

  /**
   * The happy path: the endpoint hands the user-supplied name to the service
   * and the credential shows up on the user, trimmed.
   */
  @Test
  void testRegisterFinishAppendsNamedCredential(JenkinsRule j)
    throws Exception {
    j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
    MFAContext.i()
      .registerService(WebAuthnService.class, new FakeWebAuthnService("{}"));
    Secret secret = enrollUser("registerfinishuser", 0);

    try (var wc = j.createWebClient()) {
      wc.setThrowExceptionOnFailingStatusCode(false);
      loginAndVerify(j, wc, "registerfinishuser", secret);

      Page page =
        postWithCrumb(
          j, wc,
          "user/registerfinishuser/mfa-setup/webauthn-register-finish",
          "{\"name\":\"  YubiKey work  \",\"response\":{\"id\":\"abc\"}}"
        );
      assertEquals(
        200, page.getWebResponse().getStatusCode(),
        "Registration should succeed for a verified self-service session"
      );
    }

    List<WebAuthnCredential> credentials =
      MFAUserProperty.forUser(User.getById("registerfinishuser", false))
        .getWebAuthnCredentials();
    assertEquals(1, credentials.size(), "One credential should be registered");
    assertEquals(
      "YubiKey work", credentials.get(0).getName(),
      "The user-supplied name should be stored, trimmed"
    );
  }

  /**
   * Registration is self-service only: an administrator cannot plant a key
   * on somebody else's account.
   */
  @Test
  void testRegisterFinishForbiddenForAdminOnAnotherUser(JenkinsRule j)
    throws Exception {
    j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
    j.jenkins.setAuthorizationStrategy(
      new MockAuthorizationStrategy()
        .grant(Jenkins.ADMINISTER).everywhere().to("finishadmin")
        .grant(Jenkins.READ).everywhere().to("finishvictim")
    );
    MFAContext.i()
      .registerService(WebAuthnService.class, new FakeWebAuthnService("{}"));
    Secret adminSecret = enrollUser("finishadmin", 0);
    enrollUser("finishvictim", 0);

    try (var wc = j.createWebClient()) {
      wc.setThrowExceptionOnFailingStatusCode(false);
      loginAndVerify(j, wc, "finishadmin", adminSecret);

      Page page =
        postWithCrumb(
          j, wc,
          "user/finishvictim/mfa-setup/webauthn-register-finish",
          "{\"name\":\"Planted\",\"response\":{}}"
        );
      assertEquals(
        403, page.getWebResponse().getStatusCode(),
        "An admin must not be able to register a key for another user"
      );
      assertFalse(
        MFAUserProperty.forUser(User.getById("finishvictim", false))
          .hasWebAuthn(),
        "No credential should have been planted on the victim"
      );
    }
  }

  /** register-finish refuses an unverified session on its own. */
  @Test
  void testRegisterFinishForbiddenWhenSessionNotVerified(JenkinsRule j)
    throws Exception {
    j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
    MFAContext.i()
      .registerService(WebAuthnService.class, new FakeWebAuthnService("{}"));
    enrollUser("unverifiedfinishuser", 0);

    try (var wc = j.createWebClient()) {
      wc.setThrowExceptionOnFailingStatusCode(false);
      // Logged in with the password only - MFA never passed.
      wc.login("unverifiedfinishuser");

      Page page =
        postWithCrumb(
          j, wc,
          "user/unverifiedfinishuser/mfa-setup/webauthn-register-finish",
          "{\"name\":\"Planted\",\"response\":{\"id\":\"abc\"}}"
        );
      assertEquals(
        403, page.getWebResponse().getStatusCode(),
        "Finishing a registration must require an MFA-verified session"
      );
    }

    assertFalse(
      MFAUserProperty.forUser(User.getById("unverifiedfinishuser", false))
        .hasWebAuthn(),
      "No credential should have been planted from an unverified session"
    );
  }

  /**
   * An envelope that is not even JSON is rejected as client error, never a
   * server error.
   */
  @Test
  void testRegisterFinishGarbageBodyIsClientError(JenkinsRule j)
    throws Exception {
    j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
    MFAContext.i()
      .registerService(WebAuthnService.class, new FakeWebAuthnService("{}"));
    Secret secret = enrollUser("registergarbageuser", 0);

    try (var wc = j.createWebClient()) {
      wc.setThrowExceptionOnFailingStatusCode(false);
      loginAndVerify(j, wc, "registergarbageuser", secret);

      Page page =
        postWithCrumb(
          j, wc,
          "user/registergarbageuser/mfa-setup/webauthn-register-finish",
          "not valid json{{{"
        );
      assertEquals(
        400, page.getWebResponse().getStatusCode(),
        "A garbage registration body should be a client error"
      );
    }
  }

  /**
   * A well-formed envelope carrying an unusable attestation response is a
   * client error, not a 500, against the real WebAuthnService.
   */
  @Test
  void testRegisterFinishInvalidAttestationIsClientError(JenkinsRule j)
    throws Exception {
    j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
    Secret secret = enrollUser("registerbadattestationuser", 0);

    try (var wc = j.createWebClient()) {
      wc.setThrowExceptionOnFailingStatusCode(false);
      loginAndVerify(j, wc, "registerbadattestationuser", secret);
      // Start a real ceremony so there is something pending to fail.
      postWithCrumb(
        j, wc,
        "user/registerbadattestationuser/mfa-setup/webauthn-register-start",
        null
      );

      Page page =
        postWithCrumb(
          j, wc,
          "user/registerbadattestationuser/mfa-setup/webauthn-register-finish",
          "{\"name\":\"Key\",\"response\":{\"id\":\"nope\"}}"
        );
      assertEquals(
        400, page.getWebResponse().getStatusCode(),
        "An invalid attestation should be a client error, never a 500"
      );
    }
  }

  /**
   * A blank credential name is rejected rather than silently defaulted.
   */
  @Test
  void testRegisterFinishRejectsBlankName(JenkinsRule j) throws Exception {
    j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
    MFAContext.i()
      .registerService(WebAuthnService.class, new FakeWebAuthnService("{}"));
    Secret secret = enrollUser("registerblanknameuser", 0);

    try (var wc = j.createWebClient()) {
      wc.setThrowExceptionOnFailingStatusCode(false);
      loginAndVerify(j, wc, "registerblanknameuser", secret);

      Page page =
        postWithCrumb(
          j, wc,
          "user/registerblanknameuser/mfa-setup/webauthn-register-finish",
          "{\"name\":\"   \",\"response\":{}}"
        );
      assertEquals(
        400, page.getWebResponse().getStatusCode(),
        "A blank credential name should be rejected"
      );
    }

    assertFalse(
      MFAUserProperty.forUser(User.getById("registerblanknameuser", false))
        .hasWebAuthn(),
      "No credential should be stored when the name is rejected"
    );
  }

  /**
   * A credential name past the configured cap is rejected.
   */
  @Test
  void testRegisterFinishRejectsOverlongName(JenkinsRule j) throws Exception {
    j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
    MFAContext.i()
      .registerService(WebAuthnService.class, new FakeWebAuthnService("{}"));
    Secret secret = enrollUser("registerlongnameuser", 0);

    try (var wc = j.createWebClient()) {
      wc.setThrowExceptionOnFailingStatusCode(false);
      loginAndVerify(j, wc, "registerlongnameuser", secret);

      String tooLong =
        "n".repeat(PluginConstants.WebAuthn.MAX_CREDENTIAL_NAME_LENGTH + 1);
      Page page =
        postWithCrumb(
          j, wc,
          "user/registerlongnameuser/mfa-setup/webauthn-register-finish",
          "{\"name\":\"" + tooLong + "\",\"response\":{}}"
        );
      assertEquals(
        400, page.getWebResponse().getStatusCode(),
        "A credential name past the cap should be rejected"
      );
    }

    assertFalse(
      MFAUserProperty.forUser(User.getById("registerlongnameuser", false))
        .hasWebAuthn(),
      "No credential should be stored when the name is rejected"
    );
  }

  /**
   * Registration is self-service only: an administrator with a verified
   * session cannot start a ceremony against another user's account.
   */
  @Test
  void testRegisterStartForbiddenForAdminOnAnotherUser(JenkinsRule j)
    throws Exception {
    j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
    j.jenkins.setAuthorizationStrategy(
      new MockAuthorizationStrategy()
        .grant(Jenkins.ADMINISTER).everywhere().to("startadmin")
        .grant(Jenkins.READ).everywhere().to("startvictim")
    );
    MFAContext.i()
      .registerService(WebAuthnService.class, new FakeWebAuthnService("{}"));
    Secret adminSecret = enrollUser("startadmin", 0);
    enrollUser("startvictim", 0);

    try (var wc = j.createWebClient()) {
      wc.setThrowExceptionOnFailingStatusCode(false);
      loginAndVerify(j, wc, "startadmin", adminSecret);

      Page page =
        postWithCrumb(
          j, wc, "user/startvictim/mfa-setup/webauthn-register-start", null
        );
      assertEquals(
        403, page.getWebResponse().getStatusCode(),
        "An admin must not be able to start a registration for another user"
      );
    }
  }

  /** A password-only session must not be able to enrol a key. */
  @Test
  void testRegisterStartForbiddenWhenSessionNotVerified(JenkinsRule j)
    throws Exception {
    j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
    MFAContext.i()
      .registerService(WebAuthnService.class, new FakeWebAuthnService("{}"));
    enrollUser("unverifiedstartuser", 0);

    try (var wc = j.createWebClient()) {
      wc.setThrowExceptionOnFailingStatusCode(false);
      // Logged in with the password only - MFA never passed.
      wc.login("unverifiedstartuser");

      Page page =
        postWithCrumb(
          j, wc,
          "user/unverifiedstartuser/mfa-setup/webauthn-register-start", null
        );
      assertEquals(
        403, page.getWebResponse().getStatusCode(),
        "Registration must require an MFA-verified session"
      );
    }
  }

  /**
   * The registration endpoint is refused outright when the feature is
   * switched off globally.
   */
  @Test
  void testRegisterStartForbiddenWhenWebAuthnDisabled(JenkinsRule j)
    throws Exception {
    j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
    MFAGlobalConfiguration.get().setAllowWebAuthn(false);
    Secret secret = enrollUser("webauthnoffuser", 0);

    try (var wc = j.createWebClient()) {
      wc.setThrowExceptionOnFailingStatusCode(false);
      loginAndVerify(j, wc, "webauthnoffuser", secret);

      Page page =
        postWithCrumb(
          j, wc, "user/webauthnoffuser/mfa-setup/webauthn-register-start", null
        );
      assertEquals(
        403, page.getWebResponse().getStatusCode(),
        "Registration should be forbidden when WebAuthn is disabled globally"
      );
    }
  }

  /**
   * Without an active TOTP second factor there is nothing to anchor a
   * security key to, so registration is refused.
   */
  @Test
  void testRegisterStartForbiddenWithoutActiveTotp(JenkinsRule j)
    throws Exception {
    j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
    MFAContext.i()
      .registerService(WebAuthnService.class, new FakeWebAuthnService("{}"));
    Secret secret = enrollUser("nototpuser", 0);

    try (var wc = j.createWebClient()) {
      wc.setThrowExceptionOnFailingStatusCode(false);
      // Verify the session first, then drop the TOTP factor, so the only
      // gate left to fail is the active-TOTP one.
      loginAndVerify(j, wc, "nototpuser", secret);
      User user = User.getById("nototpuser", false);
      MFAUserProperty.forUser(user).setSecret(null);
      user.save();

      Page page =
        postWithCrumb(
          j, wc, "user/nototpuser/mfa-setup/webauthn-register-start", null
        );
      assertEquals(
        403, page.getWebResponse().getStatusCode(),
        "Registration should be refused without an active TOTP factor"
      );
    }
  }

  /**
   * A user who already holds the maximum number of credentials is refused a
   * new ceremony.
   */
  @Test
  void testRegisterStartRejectedWhenCredentialLimitReached(JenkinsRule j)
    throws Exception {
    j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
    MFAContext.i()
      .registerService(WebAuthnService.class, new FakeWebAuthnService("{}"));
    Secret secret =
      enrollUser(
        "registerlimituser", PluginConstants.WebAuthn.MAX_CREDENTIALS_PER_USER
      );

    try (var wc = j.createWebClient()) {
      wc.setThrowExceptionOnFailingStatusCode(false);
      loginAndVerify(j, wc, "registerlimituser", secret);

      Page page =
        postWithCrumb(
          j, wc, "user/registerlimituser/mfa-setup/webauthn-register-start",
          null
        );
      assertEquals(
        400, page.getWebResponse().getStatusCode(),
        "Registration should be refused once the per-user cap is reached"
      );
    }
  }

  /**
   * The happy path for starting a ceremony: the service's options JSON is
   * returned verbatim to the browser.
   */
  @Test
  void testRegisterStartReturnsOptionsForVerifiedSelf(JenkinsRule j)
    throws Exception {
    j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
    String canned = "{\"publicKey\":{\"challenge\":\"abc123\"}}";
    MFAContext.i()
      .registerService(WebAuthnService.class, new FakeWebAuthnService(canned));
    Secret secret = enrollUser("registerstartuser", 0);

    try (var wc = j.createWebClient()) {
      wc.setThrowExceptionOnFailingStatusCode(false);
      loginAndVerify(j, wc, "registerstartuser", secret);

      Page page =
        postWithCrumb(
          j, wc, "user/registerstartuser/mfa-setup/webauthn-register-start",
          null
        );
      assertEquals(
        200, page.getWebResponse().getStatusCode(),
        "Registration start should succeed for a verified self-service session"
      );
      assertEquals(
        canned, page.getWebResponse().getContentAsString(),
        "The service's creation options should be returned verbatim"
      );
    }
  }

  /**
   * Unlike registration, removal is allowed for an administrator acting on
   * another user's account.
   */
  @Test
  void testRemoveAllowedForAdminOnAnotherUser(JenkinsRule j) throws Exception {
    j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
    j.jenkins.setAuthorizationStrategy(
      new MockAuthorizationStrategy()
        .grant(Jenkins.ADMINISTER).everywhere().to("removeadmin")
        .grant(Jenkins.READ).everywhere().to("removevictim")
    );
    Secret adminSecret = enrollUser("removeadmin", 0);
    enrollUser("removevictim", 1);

    try (var wc = j.createWebClient()) {
      wc.setThrowExceptionOnFailingStatusCode(false);
      loginAndVerify(j, wc, "removeadmin", adminSecret);

      Page page = postRemove(j, wc, "removevictim", "cred-removevictim-0");
      assertTrue(
        page.getWebResponse().getStatusCode() < 400,
        "Removal should redirect back to the setup page, got: "
          + page.getWebResponse().getStatusCode()
      );
    }

    assertFalse(
      MFAUserProperty.forUser(User.getById("removevictim", false)).hasWebAuthn(),
      "An admin should be able to remove another user's security key"
    );
  }

  /**
   * Removal is gated on an MFA-verified session too, so a password-only
   * session cannot strip a victim's second factor.
   */
  @Test
  void testRemoveForbiddenWhenSessionNotVerified(JenkinsRule j)
    throws Exception {
    j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
    enrollUser("unverifiedremoveuser", 1);

    try (var wc = j.createWebClient()) {
      wc.setThrowExceptionOnFailingStatusCode(false);
      wc.login("unverifiedremoveuser");

      Page page =
        postRemove(j, wc, "unverifiedremoveuser", "cred-unverifiedremoveuser-0");
      assertEquals(
        403, page.getWebResponse().getStatusCode(),
        "Removal must require an MFA-verified session"
      );
    }

    assertTrue(
      MFAUserProperty.forUser(User.getById("unverifiedremoveuser", false))
        .hasWebAuthn(),
      "The credential should still be there after a refused removal"
    );
  }

  /**
   * Self-service removal is refused while the feature is off (keys are inert;
   * admins can still remove them from the management page).
   */
  @Test
  void testRemoveForbiddenWhenWebAuthnDisabled(JenkinsRule j) throws Exception {
    j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
    Secret secret = enrollUser("removewebauthnoffuser", 1);

    try (var wc = j.createWebClient()) {
      wc.setThrowExceptionOnFailingStatusCode(false);
      loginAndVerify(j, wc, "removewebauthnoffuser", secret);
      MFAGlobalConfiguration.get().setAllowWebAuthn(false);

      Page page =
        postRemove(j, wc, "removewebauthnoffuser", "cred-removewebauthnoffuser-0");
      assertEquals(
        403, page.getWebResponse().getStatusCode(),
        "Removal should be forbidden while WebAuthn is disabled globally"
      );
    }

    assertTrue(
      MFAUserProperty.forUser(User.getById("removewebauthnoffuser", false))
        .hasWebAuthn(),
      "The credential should survive a refused removal"
    );
  }

  /**
   * Removing a key rotates the MFA epoch, which invalidates any remember-MFA
   * token issued before the removal.
   */
  @Test
  void testRemoveRotatesEpochAndInvalidatesRememberToken(JenkinsRule j)
    throws Exception {
    j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
    Secret secret = enrollUser("removeepochuser", 1);
    User user = User.getById("removeepochuser", false);
    String epochBefore = MFAUserProperty.forUser(user).getOrCreateMfaEpoch();
    long now = System.currentTimeMillis();
    String token =
      rememberMFAService
        .createTokenValue("removeepochuser", epochBefore, now + ONE_DAY_MS);
    assertTrue(
      rememberMFAService
        .isValidTokenValue(token, "removeepochuser", epochBefore, now),
      "The token should be valid under the epoch it was issued against"
    );

    try (var wc = j.createWebClient()) {
      wc.setThrowExceptionOnFailingStatusCode(false);
      loginAndVerify(j, wc, "removeepochuser", secret);

      Page page = postRemove(j, wc, "removeepochuser", "cred-removeepochuser-0");
      assertTrue(
        page.getWebResponse().getStatusCode() < 400,
        "Removal should redirect back to the setup page, got: "
          + page.getWebResponse().getStatusCode()
      );
    }

    MFAUserProperty property = MFAUserProperty.forUser(user);
    assertFalse(property.hasWebAuthn(), "The credential should be gone");
    String epochAfter = property.getOrCreateMfaEpoch();
    assertNotEquals(
      epochBefore, epochAfter, "Removing a key should rotate the MFA epoch"
    );
    assertFalse(
      rememberMFAService
        .isValidTokenValue(token, "removeepochuser", epochAfter, now),
      "A remember-MFA token issued before the removal must stop validating"
    );
  }

  /**
   * With a verified session the setup page lists the registered keys and
   * offers the "add security key" form.
   */
  @Test
  void testSetupPageListsCredentialsWhenSessionVerified(JenkinsRule j)
    throws Exception {
    j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
    Secret secret = enrollUser("setuppageverifieduser", 1);

    try (var wc = j.createWebClient()) {
      wc.setThrowExceptionOnFailingStatusCode(false);
      wc.getOptions().setJavaScriptEnabled(false);
      loginAndVerify(j, wc, "setuppageverifieduser", secret);

      HtmlPage page = wc.goTo("user/setuppageverifieduser/mfa-setup");
      assertNotNull(
        findById(page, "mfa-webauthn-add"),
        "The add-security-key form should be offered to a verified session"
      );
      assertNull(
        findById(page, "mfa-webauthn-verify-first"),
        "No verify-first notice should be shown to a verified session"
      );
      assertTrue(
        page.asNormalizedText().contains("Test key setuppageverifieduser-0"),
        "The registered key's name should be listed"
      );
    }
  }

  /**
   * An unverified session sees the key-management section replaced by a
   * notice pointing at the MFA challenge.
   */
  @Test
  void testSetupPageShowsVerifyFirstNoticeWhenSessionNotVerified(JenkinsRule j)
    throws Exception {
    j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
    enrollUser("setuppageunverifieduser", 1);

    try (var wc = j.createWebClient()) {
      wc.setThrowExceptionOnFailingStatusCode(false);
      wc.getOptions().setJavaScriptEnabled(false);
      wc.login("setuppageunverifieduser");

      HtmlPage page = wc.goTo("user/setuppageunverifieduser/mfa-setup");
      assertNotNull(
        findById(page, "mfa-webauthn-verify-first"),
        "An unverified session should see the verify-first notice"
      );
      assertNull(
        findById(page, "mfa-webauthn-add"),
        "An unverified session must not be offered the add-key form"
      );
    }
  }

  /**
   * Creates a user with an active TOTP secret plus the requested number of
   * registered WebAuthn credentials, returning the TOTP secret.
   */
  private Secret enrollUser(String username, int credentialCount)
    throws IOException {
    User user = User.getById(username, true);
    MFAUserProperty property = MFAUserProperty.getOrCreate(user);
    Secret secret = totpService.generateSecret();
    property.setSecret(secret);
    for (int i = 0; i < credentialCount; i++) {
      property.addWebAuthnCredential(testCredential(username + "-" + i));
    }
    user.save();
    return secret;
  }

  /**
   * Logs in and passes the TOTP challenge, leaving the web client with an
   * MFA-verified session.
   */
  private void loginAndVerify(
    JenkinsRule j, JenkinsRule.WebClient wc, String username, Secret secret)
    throws Exception {
    wc.login(username);
    WebRequest request =
      new WebRequest(new URL(j.getURL(), "mfa-login/verify"), HttpMethod.POST);
    request.setRequestParameters(
      List.of(
        new NameValuePair(
          PluginConstants.FormParameters.TOTP_CODE,
          totpService.generateTOTP(secret)
        )
      )
    );
    wc.getPage(wc.addCrumb(request));
  }

  /**
   * POSTs a credential removal for the given user.
   */
  private Page postRemove(
    JenkinsRule j, JenkinsRule.WebClient wc, String username,
    String credentialId) throws Exception {
    WebRequest request =
      new WebRequest(
        new URL(j.getURL(), "user/" + username + "/mfa-setup/webauthn-remove"),
        HttpMethod.POST
      );
    request.setRequestParameters(
      List.of(
        new NameValuePair(
          PluginConstants.FormParameters.CREDENTIAL_ID, credentialId
        )
      )
    );
    return wc.getPage(wc.addCrumb(request));
  }

}
