package io.jenkins.plugins.openmfa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import hudson.model.User;
import hudson.util.Secret;
import io.jenkins.plugins.openmfa.base.MFAContext;
import io.jenkins.plugins.openmfa.constant.PluginConstants;
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
 * Guards the factor-mutation endpoints of the MFA setup page: changing or
 * removing an existing factor needs a session that has passed MFA, while
 * first-time enrolment stays open.
 */
@WithJenkins
class MFASetupActionGateTest {

  private final TOTPService totpService =
    MFAContext.i().getService(TOTPService.class);

  /**
   * A user who has not enrolled yet is unaffected by the gate: enrolment is
   * how they get a second factor in the first place.
   */
  @Test
  void testFirstEnrollmentNeedsNoVerifiedSession(JenkinsRule j)
    throws Exception {
    j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
    User.getById("firsttimer", true);

    try (var wc = j.createWebClient()) {
      wc.setThrowExceptionOnFailingStatusCode(false);
      wc.login("firsttimer");

      Secret secret = totpService.generateSecret();
      Page page = postEnable(j, wc, "firsttimer", secret);

      assertEquals(
        200,
        page.getWebResponse().getStatusCode(),
        "First-time enrolment must not require an MFA-verified session"
      );
      assertTrue(
        MFAUserProperty.forUser(User.getById("firsttimer", false)).isEnabled(),
        "First-time enrolment must enable MFA"
      );
    }
  }

  /**
   * Once the session has passed the MFA challenge, re-enrollment goes through.
   */
  @Test
  void testReEnrollmentAllowedAfterPassingMFA(JenkinsRule j) throws Exception {
    j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
    Secret original = enroll("verifieduser");

    try (var wc = j.createWebClient()) {
      wc.setThrowExceptionOnFailingStatusCode(false);
      wc.login("verifieduser");
      postVerify(j, wc, totpService.generateTOTP(original));

      Secret replacement = totpService.generateSecret();
      Page page = postEnable(j, wc, "verifieduser", replacement);

      assertEquals(
        200,
        page.getWebResponse().getStatusCode(),
        "A session that passed MFA may re-enroll"
      );
      assertEquals(
        replacement.getPlainText(),
        storedSecret("verifieduser").getPlainText(),
        "The new TOTP secret must be stored"
      );
    }
  }

  /**
   * A password-only session cannot replace the enrolled TOTP secret, which
   * would otherwise let the holder of a password defeat MFA outright.
   */
  @Test
  void testReEnrollmentRejectedWithoutVerifiedSession(JenkinsRule j)
    throws Exception {
    j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
    Secret original = enroll("blockeduser");

    try (var wc = j.createWebClient()) {
      wc.setThrowExceptionOnFailingStatusCode(false);
      wc.login("blockeduser");

      Page page = postEnable(j, wc, "blockeduser");

      assertEquals(
        403,
        page.getWebResponse().getStatusCode(),
        "Re-enrolling an existing factor must be refused before the session passes MFA"
      );
      assertEquals(
        original.getPlainText(),
        storedSecret("blockeduser").getPlainText(),
        "The stored TOTP secret must be left untouched"
      );
    }
  }

  /**
   * Creates a user with MFA already enabled and returns their TOTP secret.
   */
  private Secret enroll(String username) throws Exception {
    User user = User.getById(username, true);
    MFAUserProperty property = MFAUserProperty.getOrCreate(user);
    Secret secret = totpService.generateSecret();
    property.setSecret(secret);
    user.save();
    return secret;
  }

  /**
   * Submits a fresh secret and its current code to the setup page.
   */
  private Page postEnable(
    JenkinsRule j, JenkinsRule.WebClient wc, String username)
    throws Exception {
    return postEnable(j, wc, username, totpService.generateSecret());
  }

  /**
   * Submits the given secret and its current code to the setup page.
   */
  private Page postEnable(
    JenkinsRule j, JenkinsRule.WebClient wc, String username, Secret secret)
    throws Exception {
    WebRequest request =
      new WebRequest(
        new URL(j.getURL(), "user/" + username + "/mfa-setup/enable"),
        HttpMethod.POST
      );
    request.setRequestParameters(
      List.of(
        new NameValuePair(
          PluginConstants.FormParameters.SECRET, secret.getEncryptedValue()
        ),
        new NameValuePair(
          PluginConstants.FormParameters.CODE, totpService.generateTOTP(secret)
        )
      )
    );
    return wc.getPage(wc.addCrumb(request));
  }

  /**
   * Submits a TOTP code to the MFA challenge endpoint.
   */
  private Page postVerify(JenkinsRule j, JenkinsRule.WebClient wc, String code)
    throws Exception {
    WebRequest request =
      new WebRequest(new URL(j.getURL(), "mfa-login/verify"), HttpMethod.POST);
    request.setRequestParameters(
      List.of(
        new NameValuePair(PluginConstants.FormParameters.TOTP_CODE, code)
      )
    );
    return wc.getPage(wc.addCrumb(request));
  }

  /**
   * The TOTP secret currently stored for the user.
   */
  private Secret storedSecret(String username) {
    return MFAUserProperty
      .forUser(User.getById(username, false))
      .getSecret();
  }
}
