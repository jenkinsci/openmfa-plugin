package io.jenkins.plugins.openmfa.service;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

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

  private final String mfaEpoch = "epoch-aaaaaaaaaaaaaaaa";

  private final RememberMFAService rememberMFAService =
    MFAContext.i().getService(RememberMFAService.class);

  /**
   * Changing the MFA epoch (e.g. because the user rotated or reconfigured
   * their MFA method) invalidates previously issued tokens.
   */
  @Test
  void testEpochChangeInvalidatesToken(JenkinsRule j) {
    long now = System.currentTimeMillis();
    String token =
      rememberMFAService.createTokenValue("alice", mfaEpoch, now + ONE_DAY_MS);

    String newEpoch = "epoch-bbbbbbbbbbbbbbbb";
    assertFalse(
      rememberMFAService.isValidTokenValue(token, "alice", newEpoch, now),
      "Token bound to old MFA epoch should be rejected after the epoch changes"
    );
  }

  /**
   * An expired token does not validate even with a matching signature.
   */
  @Test
  void testExpiredTokenRejected(JenkinsRule j) {
    long now = System.currentTimeMillis();
    String token =
      rememberMFAService.createTokenValue("alice", mfaEpoch, now - 1);

    assertFalse(
      rememberMFAService.isValidTokenValue(token, "alice", mfaEpoch, now),
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
      rememberMFAService.isValidTokenValue(null, "alice", mfaEpoch, now),
      "Null token should be rejected"
    );
    assertFalse(
      rememberMFAService.isValidTokenValue("", "alice", mfaEpoch, now),
      "Empty token should be rejected"
    );
    assertFalse(
      rememberMFAService.isValidTokenValue("garbage", "alice", mfaEpoch, now),
      "Token without separators should be rejected"
    );
    assertFalse(
      rememberMFAService
        .isValidTokenValue("a:notanumber:c", "alice", mfaEpoch, now),
      "Token with non-numeric expiry should be rejected"
    );
  }

  /**
   * A null epoch (e.g. property not yet created) is rejected.
   */
  @Test
  void testNullEpochRejected(JenkinsRule j) {
    long now = System.currentTimeMillis();
    String token =
      rememberMFAService.createTokenValue("alice", mfaEpoch, now + ONE_DAY_MS);

    assertFalse(
      rememberMFAService.isValidTokenValue(token, "alice", null, now),
      "Null MFA epoch should be rejected"
    );
  }

  /**
   * A token with a tampered expiry does not validate (expiry is signed).
   */
  @Test
  void testTamperedExpiryRejected(JenkinsRule j) {
    long now = System.currentTimeMillis();
    String token =
      rememberMFAService.createTokenValue("alice", mfaEpoch, now + 1);

    // Extend the expiry field without re-signing
    String[] parts = token.split(":");
    parts[1] = String.valueOf(now + ONE_DAY_MS);
    String tampered = String.join(":", parts);

    assertFalse(
      rememberMFAService.isValidTokenValue(tampered, "alice", mfaEpoch, now),
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
      rememberMFAService.createTokenValue("alice", mfaEpoch, now + ONE_DAY_MS);

    // Flip a character in the middle of the signature (the final
    // colon-separated component), not the last character of the token: the
    // final base64url character of an unpadded HMAC-SHA256 signature
    // encodes a few bits that fall outside the decoded MAC bytes, so
    // flipping between 'A' and 'B' there can -- roughly 1 in 16 times --
    // decode to the exact same signature bytes and make this assertion
    // flaky. A character in the middle of the signature always sits inside
    // a complete 4-character base64 group, so altering it always changes
    // the decoded bytes.
    int lastColon = token.lastIndexOf(':');
    String signature = token.substring(lastColon + 1);
    int middle = lastColon + 1 + signature.length() / 2;
    char original = token.charAt(middle);
    char replacement = original == 'A' ? 'B' : 'A';
    String tampered =
      token.substring(0, middle) + replacement + token.substring(middle + 1);

    assertFalse(
      rememberMFAService.isValidTokenValue(tampered, "alice", mfaEpoch, now),
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
        .createTokenValue("alice:admin", mfaEpoch, now + ONE_DAY_MS);

    assertTrue(
      rememberMFAService
        .isValidTokenValue(token, "alice:admin", mfaEpoch, now),
      "Username containing separator should round-trip"
    );
    assertFalse(
      rememberMFAService.isValidTokenValue(token, "alice", mfaEpoch, now),
      "Token for alice:admin should not validate for alice"
    );
  }

  /**
   * A freshly created token for the same user and epoch validates.
   */
  @Test
  void testValidTokenValidates(JenkinsRule j) {
    long now = System.currentTimeMillis();
    String token =
      rememberMFAService.createTokenValue("alice", mfaEpoch, now + ONE_DAY_MS);

    assertTrue(
      rememberMFAService.isValidTokenValue(token, "alice", mfaEpoch, now),
      "Fresh token for same user and epoch should validate"
    );
  }

  /**
   * A token issued for one user does not validate for another user.
   */
  @Test
  void testWrongUserRejected(JenkinsRule j) {
    long now = System.currentTimeMillis();
    String token =
      rememberMFAService.createTokenValue("alice", mfaEpoch, now + ONE_DAY_MS);

    assertFalse(
      rememberMFAService.isValidTokenValue(token, "bob", mfaEpoch, now),
      "Token issued for alice should not validate for bob"
    );
  }
}
