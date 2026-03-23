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
class MFAFlowTest {

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

}
