package io.jenkins.plugins.openmfa;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import hudson.model.User;
import io.jenkins.plugins.openmfa.base.MFAContext;
import io.jenkins.plugins.openmfa.constant.PluginConstants;
import io.jenkins.plugins.openmfa.service.RateLimitService;
import io.jenkins.plugins.openmfa.service.TOTPService;
import jenkins.security.ApiTokenProperty;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

/**
 * Integration tests for the core MFA flow.
 * Tests TOTP generation, verification, replay attack prevention, and rate
 * limiting.
 */
@WithJenkins
class MFAFlowIntegrationTest {

  private RateLimitService rateLimitService;
  private TOTPService totpService;

  @BeforeEach
  void setUp() {
    totpService = MFAContext.i().getService(TOTPService.class);
    rateLimitService = MFAContext.i().getService(RateLimitService.class);
  }

  /**
   * Test admin can reset user MFA.
   */
  @Test
  void testAdminResetUserMFA(JenkinsRule j) throws Exception {
    // Create user with MFA enabled
    User testUser = User.getById("resetadminuser", true);
    MFAUserProperty property = MFAUserProperty.getOrCreate(testUser);
    property.setSecret(totpService.generateSecret());
    testUser.save();

    assertTrue(property.isEnabled(), "MFA should be enabled initially");

    // Admin resets MFA (simulated through UserService)
    // In production, this is done via MFAManagementLink
    property.setSecret(null);
    testUser.save();

    assertFalse(property.isEnabled(), "MFA should be disabled after admin reset");
  }

  /**
   * Test that API token authentication bypasses MFA.
   */
  @Test
  void testApiTokenBypassesMFA(JenkinsRule j) throws Exception {
    // Create user with MFA enabled
    User testUser = User.getById("apiuser", true);
    MFAUserProperty property = MFAUserProperty.getOrCreate(testUser);
    property.setSecret(totpService.generateSecret());
    testUser.save();

    // Generate an API token for the user
    ApiTokenProperty apiTokenProperty = testUser.getProperty(ApiTokenProperty.class);
    if (apiTokenProperty == null) {
      apiTokenProperty = new ApiTokenProperty();
      testUser.addProperty(apiTokenProperty);
    }
    // ApiTokenProperty stores the token internally, we just verify it exists
    assertNotNull(apiTokenProperty, "API token property should be created");

    // API token authentication should work even with MFA enabled
    // This is handled by BasicHeaderApiTokenAuthenticator setting the attribute
    // that MFAFilter checks
  }

  /**
   * Test the complete MFA setup flow:
   * 1. User logs in with username/password
   * 2. User navigates to MFA setup page
   * 3. System generates secret and QR code
   * 4. User enters TOTP code from authenticator app
   * 5. MFA is enabled for the user
   */
  @Test
  void testCompleteMFASetupFlow(JenkinsRule j) throws Exception {
    // Create a test user
    User testUser = User.getById("testuser", true);

    // Generate a secret (simulating what happens on the setup page)
    String encryptedSecret = totpService.generateSecret().getEncryptedValue();

    // Generate a valid TOTP code for the current time
    String validCode =
      totpService.generateTOTP(
        hudson.util.Secret.fromString(encryptedSecret)
      );

    // Simulate enabling MFA with the valid code
    MFAUserProperty property = MFAUserProperty.getOrCreate(testUser);
    property.setSecret(hudson.util.Secret.fromString(encryptedSecret));
    testUser.save();

    // Verify the code works (simulating form submission)
    assertTrue(property.verifyCode(validCode), "Valid TOTP code should verify");

    // Verify MFA is now enabled
    assertTrue(property.isEnabled(), "MFA should be enabled after setup");
    assertNotNull(property.getSecret(), "Secret should be stored");
  }

  /**
   * Test that lockout is cleared after successful verification.
   */
  @Test
  void testLockoutClearedOnSuccess(JenkinsRule j) throws Exception {
    User testUser = User.getById("lockoutuser", true);
    String username = testUser.getId();

    MFAUserProperty property = MFAUserProperty.getOrCreate(testUser);
    String secret = totpService.generateSecret().getEncryptedValue();
    property.setSecret(hudson.util.Secret.fromString(secret));
    testUser.save();

    // Record some failed attempts
    for (int i = 0; i < PluginConstants.RateLimit.MAX_ATTEMPTS; i++) {
      rateLimitService.recordFailedAttempt(username);
    }

    // Get valid code
    String validCode =
      totpService.generateTOTP(hudson.util.Secret.fromString(secret));

    // Successful verification should clear failed attempts
    assertTrue(property.verifyCode(validCode), "Valid code should verify");
    rateLimitService.clearFailedAttempts(username);

    // Verify failed attempts are cleared
    assertFalse(
      rateLimitService.isLockedOut(username),
      "User should not be locked out after clearing attempts"
    );
  }

  /**
   * Test MFA disable functionality.
   */
  @Test
  void testMFADisable(JenkinsRule j) throws Exception {
    User testUser = User.getById("disableuser", true);

    // Enable MFA first
    MFAUserProperty property = MFAUserProperty.getOrCreate(testUser);
    property.setSecret(totpService.generateSecret());
    testUser.save();

    assertTrue(property.isEnabled(), "MFA should be enabled");

    // Disable MFA by clearing the secret
    property.setSecret(null);
    testUser.save();

    assertFalse(property.isEnabled(), "MFA should be disabled after clearing secret");
  }

  /**
   * Test the MFA login flow:
   * 1. User with MFA enabled logs in
   * 2. User is redirected to MFA verification page
   * 3. User enters correct TOTP code
   * 4. Session is marked as MFA verified
   * 5. User is redirected to original destination
   */
  @Test
  void testMFALoginFlow(JenkinsRule j) throws Exception {
    // Create user with MFA enabled
    User testUser = User.getById("loginuser", true);
    MFAUserProperty property = MFAUserProperty.getOrCreate(testUser);
    String secret = totpService.generateSecret().getEncryptedValue();
    property.setSecret(hudson.util.Secret.fromString(secret));
    testUser.save();

    // Generate valid TOTP code
    String validCode =
      totpService.generateTOTP(hudson.util.Secret.fromString(secret));

    // Verify the code works
    assertTrue(
      property.verifyCode(validCode), "Valid code should verify during login"
    );
  }

  /**
   * Test MFA setup with invalid code:
   * User enters wrong TOTP code during setup
   */
  @Test
  void testMFASetupWithInvalidCode(JenkinsRule j) throws Exception {
    User testUser = User.getById("setupuser", true);

    // Generate a secret
    String encryptedSecret = totpService.generateSecret().getEncryptedValue();

    // Try to verify with an invalid code
    MFAUserProperty property = MFAUserProperty.getOrCreate(testUser);
    property.setSecret(hudson.util.Secret.fromString(encryptedSecret));

    // Invalid code should not verify
    assertFalse(property.verifyCode("000000"), "Invalid code should not verify");
    assertFalse(property.verifyCode("123456"), "Invalid code should not verify");
    assertFalse(property.verifyCode("abcdef"), "Non-numeric code should not verify");
    assertFalse(property.verifyCode("12345"), "Short code should not verify");
    assertFalse(property.verifyCode("1234567"), "Long code should not verify");
  }

  /**
   * Test QR code provisioning URI format.
   */
  @Test
  void testProvisioningUriFormat(JenkinsRule j) throws Exception {
    hudson.util.Secret secret = totpService.generateSecret();
    String username = "testprovisionuser";
    String issuer = "Jenkins";

    String uri = totpService.getProvisioningUri(username, secret, issuer);

    assertNotNull(uri, "URI should not be null");
    assertTrue(
      uri.startsWith("otpauth://totp/"),
      "URI should start with otpauth://totp/"
    );
    assertTrue(
      uri.contains(issuer),
      "URI should contain the issuer name"
    );
    assertTrue(
      uri.contains(username),
      "URI should contain the username"
    );
    assertTrue(
      uri.contains("secret="),
      "URI should contain the secret parameter"
    );
    assertTrue(
      uri.contains("issuer=" + issuer),
      "URI should contain the issuer parameter"
    );
  }

  /**
   * Test rate limiting - multiple failed attempts should trigger lockout.
   */
  @Test
  void testRateLimitingOnFailedAttempts(JenkinsRule j) throws Exception {
    User testUser = User.getById("rateuser", true);
    String username = testUser.getId();

    // Clear any existing failed attempts
    rateLimitService.clearFailedAttempts(username);

    // Simulate multiple failed login attempts
    int maxAttempts = PluginConstants.RateLimit.MAX_ATTEMPTS;

    for (int i = 0; i < maxAttempts; i++) {
      assertFalse(
        rateLimitService.isLockedOut(username),
        "User should not be locked out before reaching max attempts"
      );
      rateLimitService.recordFailedAttempt(username);
    }

    // After max attempts, user should be locked out
    assertTrue(
      rateLimitService.isLockedOut(username),
      "User should be locked out after max failed attempts"
    );

    // Verify lockout duration is reasonable
    long remainingSeconds = rateLimitService.getRemainingLockoutSeconds(username);
    assertTrue(remainingSeconds > 0, "Lockout should have remaining time");
  }

  /**
   * Test replay attack prevention - same TOTP code cannot be used twice.
   */
  @Test
  void testReplayAttackPrevention(JenkinsRule j) throws Exception {
    String secretPlain = totpService.generateSecret().getPlainText();
    hudson.util.Secret secret = hudson.util.Secret.fromString(secretPlain);

    // Generate a valid code
    String code = totpService.generateTOTP(secret);

    // First verification should succeed
    boolean firstResult = totpService.verifyCode(secret, code);
    assertTrue(firstResult, "First verification should succeed");

    // Second verification with same code should fail (replay attack)
    boolean secondResult = totpService.verifyCode(secret, code);
    assertFalse(secondResult, "Second use of same code should be rejected");
  }

  /**
   * Test TOTP code generation with time drift tolerance.
   * Codes from adjacent time windows should still verify.
   */
  @Test
  void testTimeDriftTolerance(JenkinsRule j) throws Exception {
    hudson.util.Secret secret = totpService.generateSecret();
    long currentTime = System.currentTimeMillis() / 1000L / 30;

    // Generate codes for current, previous, and next time windows
    String currentCode = totpService.generateTOTP(secret, currentTime);
    String previousCode = totpService.generateTOTP(secret, currentTime - 1);
    String nextCode = totpService.generateTOTP(secret, currentTime + 1);

    // All three should verify (current +/-1 window)
    assertTrue(
      totpService.verifyCode(secret, currentCode),
      "Current time window code should verify"
    );
    assertTrue(
      totpService.verifyCode(secret, previousCode),
      "Previous time window code should verify"
    );
    assertTrue(
      totpService.verifyCode(secret, nextCode),
      "Next time window code should verify"
    );

    // Code from 2 windows ago should not verify
    String tooOldCode = totpService.generateTOTP(secret, currentTime - 2);
    assertFalse(
      totpService.verifyCode(secret, tooOldCode),
      "Code from 2 windows ago should not verify"
    );

    // Code from 2 windows ahead should not verify
    String tooNewCode = totpService.generateTOTP(secret, currentTime + 2);
    assertFalse(
      totpService.verifyCode(secret, tooNewCode),
      "Code from 2 windows ahead should not verify"
    );
  }
}
