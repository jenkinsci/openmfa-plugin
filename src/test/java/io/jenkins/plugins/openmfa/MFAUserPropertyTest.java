package io.jenkins.plugins.openmfa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import hudson.model.User;
import hudson.util.Secret;
import io.jenkins.plugins.openmfa.base.MFAContext;
import io.jenkins.plugins.openmfa.service.TOTPService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

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
    assertEquals(secret.getPlainText(), property.getSecret().getPlainText());
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

  @Test
  void testNullUserRejected() {
    MFAUserProperty property = MFAUserProperty.forUser(null);
    assertNull(property, "Null user should return null property");
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
  void testVerifyCodeWhenNotConfigured(JenkinsRule j) {
    MFAUserProperty property = new MFAUserProperty();

    // No secret set

    assertFalse(property.verifyCode("123456")); // Should fail when not configured
  }
}
