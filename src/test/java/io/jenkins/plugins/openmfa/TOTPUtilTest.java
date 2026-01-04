package io.jenkins.plugins.openmfa;

import static org.junit.jupiter.api.Assertions.*;

import io.jenkins.plugins.openmfa.base.MFAContext;
import io.jenkins.plugins.openmfa.service.TOTPService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class TOTPUtilTest {

  private TOTPService totpService;

  @BeforeEach
  void setUp() {
    totpService = MFAContext.i().getService(TOTPService.class);
  }

  @Test
  void testGenerateSecret() {
    String secret = totpService.generateSecret();
    assertNotNull(secret);
    assertTrue(!secret.isEmpty());
  }

  @Test
  void testGenerateTOTP() {
    String secret = totpService.generateSecret();
    String code = totpService.generateTOTP(secret);
    assertNotNull(code);
    assertEquals(6, code.length());
    assertTrue(code.matches("\\d{6}"));
  }

  @Test
  void testVerifyCode() {
    String secret = totpService.generateSecret();
    String code = totpService.generateTOTP(secret);

    // Should verify current code
    assertTrue(totpService.verifyCode(secret, code));

    // Should not verify invalid code
    assertFalse(totpService.verifyCode(secret, "000000"));
  }

  @Test
  void testVerifyCodeWithInvalidInput() {
    String secret = totpService.generateSecret();

    // Should not verify null code
    assertFalse(totpService.verifyCode(secret, null));

    // Should not verify short code
    assertFalse(totpService.verifyCode(secret, "123"));

    // Should not verify long code
    assertFalse(totpService.verifyCode(secret, "1234567"));

    // Should not verify non-numeric code
    assertFalse(totpService.verifyCode(secret, "abcdef"));
  }

  @Test
  void testGetProvisioningUri() {
    String secret = totpService.generateSecret();
    String uri = totpService.getProvisioningUri("testuser", secret, "Jenkins");

    assertNotNull(uri);
    assertTrue(uri.startsWith("otpauth://totp/"));
    assertTrue(uri.contains("testuser"));
    assertTrue(uri.contains("secret=" + secret.replace("=", "")));
    assertTrue(uri.contains("issuer=Jenkins"));
  }

  @Test
  void testCodeChangesOverTime() {
    String secret = totpService.generateSecret();

    // Generate code for different time windows
    long currentTime = System.currentTimeMillis() / 1000L / 30;
    String code1 = totpService.generateTOTP(secret, currentTime);
    String code2 = totpService.generateTOTP(secret, currentTime + 1);

    // Codes should be different for different time windows
    assertNotEquals(code1, code2);
  }

  @Test
  void testTimeDriftTolerance() {
    String secret = totpService.generateSecret();
    long currentTime = System.currentTimeMillis() / 1000L / 30;

    // Generate codes for current, previous, and next time windows
    String currentCode = totpService.generateTOTP(secret, currentTime);
    String previousCode = totpService.generateTOTP(secret, currentTime - 1);
    String nextCode = totpService.generateTOTP(secret, currentTime + 1);

    // All three should verify (current ±1 window)
    assertTrue(totpService.verifyCode(secret, currentCode));
    assertTrue(totpService.verifyCode(secret, previousCode));
    assertTrue(totpService.verifyCode(secret, nextCode));

    // Code from 2 windows ago should not verify
    String tooOldCode = totpService.generateTOTP(secret, currentTime - 2);
    assertFalse(totpService.verifyCode(secret, tooOldCode));
  }

  @Test
  void testValidateTOTP() {
    String secret = totpService.generateSecret();
    String code = totpService.generateTOTP(secret);

    // Should validate current code
    assertTrue(totpService.validateTOTP(secret, code));

    // Should not validate invalid code
    assertFalse(totpService.validateTOTP(secret, "000000"));
  }
}
