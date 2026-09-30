package io.jenkins.plugins.openmfa.service;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import hudson.util.Secret;
import io.jenkins.plugins.openmfa.MFAGlobalConfiguration;
import io.jenkins.plugins.openmfa.base.MFAContext;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

/**
 * Unit tests for RememberMFAService token creation and validation.
 */
@WithJenkins
class RememberMFAServiceTest {

  private static final long ONE_DAY_MS = 24L * 60 * 60 * 1000;

  private final RememberMFAService rememberMFAService =
    MFAContext.i().getService(RememberMFAService.class);

  private final Secret totpSecret = Secret.fromString("JBSWY3DPEHPK3PXP");

  /**
   * Changing the TOTP secret invalidates previously issued tokens.
   */
  @Test
  void testChangedTotpSecretRejected(JenkinsRule j) {
    long now = System.currentTimeMillis();
    String token =
      rememberMFAService.createTokenValue("alice", totpSecret, now + ONE_DAY_MS);

    Secret newSecret = Secret.fromString("KRSXG5CTMVRXEZLU");
    assertFalse(
      rememberMFAService.isValidTokenValue(token, "alice", newSecret, now),
      "Token bound to old TOTP secret should be rejected after secret change"
    );
  }

  /**
   * An expired token does not validate even with a matching signature.
   */
  @Test
  void testExpiredTokenRejected(JenkinsRule j) {
    long now = System.currentTimeMillis();
    String token =
      rememberMFAService.createTokenValue("alice", totpSecret, now - 1);

    assertFalse(
      rememberMFAService.isValidTokenValue(token, "alice", totpSecret, now),
      "Expired token should be rejected"
    );
  }

  /**
   * The feature is enabled by default (24 hours) and disabled when hours is 0.
   */
  @Test
  void testIsEnabledFollowsConfiguredHours(JenkinsRule j) {
    MFAGlobalConfiguration config = MFAGlobalConfiguration.get();

    assertTrue(
      rememberMFAService.isEnabled(),
      "Remember-MFA should be enabled with the default duration"
    );

    config.setRememberMfaHours(0);
    assertFalse(
      rememberMFAService.isEnabled(),
      "Remember-MFA should be disabled when configured hours is 0"
    );
  }

  /**
   * Malformed token values are rejected without throwing.
   */
  @Test
  void testMalformedTokensRejected(JenkinsRule j) {
    long now = System.currentTimeMillis();

    assertFalse(
      rememberMFAService.isValidTokenValue(null, "alice", totpSecret, now),
      "Null token should be rejected"
    );
    assertFalse(
      rememberMFAService.isValidTokenValue("", "alice", totpSecret, now),
      "Empty token should be rejected"
    );
    assertFalse(
      rememberMFAService.isValidTokenValue("garbage", "alice", totpSecret, now),
      "Token without separators should be rejected"
    );
    assertFalse(
      rememberMFAService
        .isValidTokenValue("a:notanumber:c", "alice", totpSecret, now),
      "Token with non-numeric expiry should be rejected"
    );
  }

  /**
   * A token with a tampered expiry does not validate (expiry is signed).
   */
  @Test
  void testTamperedExpiryRejected(JenkinsRule j) {
    long now = System.currentTimeMillis();
    String token =
      rememberMFAService.createTokenValue("alice", totpSecret, now + 1);

    // Extend the expiry field without re-signing
    String[] parts = token.split(":");
    parts[1] = String.valueOf(now + ONE_DAY_MS);
    String tampered = String.join(":", parts);

    assertFalse(
      rememberMFAService.isValidTokenValue(tampered, "alice", totpSecret, now),
      "Token with tampered expiry should be rejected"
    );
  }

  /**
   * A token with a tampered signature does not validate.
   */
  @Test
  void testTamperedTokenRejected(JenkinsRule j) {
    long now = System.currentTimeMillis();
    String token =
      rememberMFAService.createTokenValue("alice", totpSecret, now + ONE_DAY_MS);

    // Flip the last character of the signature
    char last = token.charAt(token.length() - 1);
    String tampered =
      token.substring(0, token.length() - 1) + (last == 'A' ? 'B' : 'A');

    assertFalse(
      rememberMFAService.isValidTokenValue(tampered, "alice", totpSecret, now),
      "Token with tampered signature should be rejected"
    );
  }

  /**
   * Usernames containing the separator character are handled safely.
   */
  @Test
  void testUsernameWithSeparator(JenkinsRule j) {
    long now = System.currentTimeMillis();
    String token =
      rememberMFAService
        .createTokenValue("alice:admin", totpSecret, now + ONE_DAY_MS);

    assertTrue(
      rememberMFAService
        .isValidTokenValue(token, "alice:admin", totpSecret, now),
      "Username containing separator should round-trip"
    );
    assertFalse(
      rememberMFAService.isValidTokenValue(token, "alice", totpSecret, now),
      "Token for alice:admin should not validate for alice"
    );
  }

  /**
   * A freshly created token for the same user and secret validates.
   */
  @Test
  void testValidTokenValidates(JenkinsRule j) {
    long now = System.currentTimeMillis();
    String token =
      rememberMFAService.createTokenValue("alice", totpSecret, now + ONE_DAY_MS);

    assertTrue(
      rememberMFAService.isValidTokenValue(token, "alice", totpSecret, now),
      "Fresh token for same user and secret should validate"
    );
  }

  /**
   * A token issued for one user does not validate for another user.
   */
  @Test
  void testWrongUserRejected(JenkinsRule j) {
    long now = System.currentTimeMillis();
    String token =
      rememberMFAService.createTokenValue("alice", totpSecret, now + ONE_DAY_MS);

    assertFalse(
      rememberMFAService.isValidTokenValue(token, "bob", totpSecret, now),
      "Token issued for alice should not validate for bob"
    );
  }
}
