package io.jenkins.plugins.openmfa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
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
  void testMfaEpochLazyAndStable(JenkinsRule j) {
    MFAUserProperty property = new MFAUserProperty();

    String epoch1 = property.getOrCreateMfaEpoch();
    assertNotNull(epoch1, "Epoch should be lazily generated");
    assertFalse(epoch1.isEmpty(), "Epoch should not be empty");

    String epoch2 = property.getOrCreateMfaEpoch();
    assertEquals(epoch1, epoch2, "Repeated calls should return the same epoch");
  }

  @Test
  void testNullUserRejected() {
    MFAUserProperty property = MFAUserProperty.forUser(null);
    assertNull(property, "Null user should return null property");
  }

  /**
   * A property that predates the mfaEpoch field (i.e. loaded from old XML
   * containing only {@code <secret>}) has {@code mfaEpoch == null}; lazy
   * generation must still work transparently.
   */
  @Test
  void testOldXmlWithoutEpochLoads(JenkinsRule j) {
    MFAUserProperty property = new MFAUserProperty();
    property.setSecret(totpService.generateSecret());

    String epoch = property.getOrCreateMfaEpoch();
    assertNotNull(epoch, "Epoch should be generated even without a persisted value");
    assertFalse(epoch.isEmpty(), "Epoch should not be empty");
  }

  @Test
  void testRotateMfaEpochChangesValue(JenkinsRule j) {
    MFAUserProperty property = new MFAUserProperty();

    String epoch1 = property.getOrCreateMfaEpoch();
    property.rotateMfaEpoch();
    String epoch2 = property.getOrCreateMfaEpoch();

    assertNotEquals(epoch1, epoch2, "Rotating the epoch should change its value");
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
