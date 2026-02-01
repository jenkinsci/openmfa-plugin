package io.jenkins.plugins.openmfa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

import hudson.model.User;
import hudson.util.Secret;
import io.jenkins.plugins.openmfa.base.MFAContext;
import io.jenkins.plugins.openmfa.service.TOTPService;

@WithJenkins
class MFAUserPropertyTest {

  private TOTPService totpService;

  @BeforeEach
  void setUp() {
    totpService = MFAContext.i().getService(TOTPService.class);
  }

  @Test
  void testDefaultState(JenkinsRule j) {
    MFAUserProperty property = new MFAUserProperty();

    assertFalse(property.isEnabled());
    assertNull(property.getSecret());
  }

  @Test
  void testEnableMFA(JenkinsRule j) {
    MFAUserProperty property = new MFAUserProperty();

    Secret secret = totpService.generateSecret();
    property.setSecret(secret);

    assertTrue(property.isEnabled());
    assertTrue(property.isEnabled());
    assertEquals(Secret.toString(secret), Secret.toString(property.getSecret()));
  }

  @Test
  void testVerifyCode(JenkinsRule j) {
    MFAUserProperty property = new MFAUserProperty();

    Secret secret = totpService.generateSecret();
    property.setSecret(secret);

    String code = totpService.generateTOTP(secret);
    assertTrue(property.verifyCode(code));
    assertFalse(property.verifyCode("000000"));
  }

  @Test
  void testVerifyCodeWhenDisabled(JenkinsRule j) {
    MFAUserProperty property = new MFAUserProperty();

    Secret secret = totpService.generateSecret();
    property.setSecret(secret);

    String code = totpService.generateTOTP(secret);
    assertFalse(property.verifyCode(code)); // Should fail when disabled
  }

  @Test
  void testVerifyCodeWhenNotConfigured(JenkinsRule j) {
    MFAUserProperty property = new MFAUserProperty();

    // No secret set

    assertFalse(property.verifyCode("123456")); // Should fail when not configured
  }

  @Test
  void testGetOrCreate(JenkinsRule j) throws Exception {
    User user = User.getById("testuser2", true);

    // Should create new property
    MFAUserProperty property1 = MFAUserProperty.getOrCreate(user);
    assertNotNull(property1);

    // Should return existing property
    MFAUserProperty property2 = MFAUserProperty.getOrCreate(user);
    assertNotNull(property2);
    assertEquals(property1, property2);
  }
}
