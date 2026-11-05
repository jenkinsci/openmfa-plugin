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
import io.jenkins.plugins.openmfa.service.model.WebAuthnCredential;
import java.util.List;
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
  void testAddListRemoveWebAuthnCredentialRoundTrip(JenkinsRule j) {
    MFAUserProperty property = new MFAUserProperty();
    assertFalse(property.hasWebAuthn());
    assertTrue(property.getWebAuthnCredentials().isEmpty());

    WebAuthnCredential first =
      new WebAuthnCredential(
        "cred-1", "pk-1", 0L, "Laptop", "2026-01-01T00:00:00Z", null
      );
    WebAuthnCredential second =
      new WebAuthnCredential(
        "cred-2", "pk-2", 0L, "Phone", "2026-01-02T00:00:00Z", null
      );

    property.addWebAuthnCredential(first);
    property.addWebAuthnCredential(second);

    List<WebAuthnCredential> credentials = property.getWebAuthnCredentials();
    assertEquals(2, credentials.size());
    assertTrue(property.hasWebAuthn());

    assertTrue(property.removeWebAuthnCredential("cred-1"));
    credentials = property.getWebAuthnCredentials();
    assertEquals(1, credentials.size());
    assertEquals("cred-2", credentials.get(0).getCredentialId());
    assertTrue(property.hasWebAuthn());

    assertTrue(property.removeWebAuthnCredential("cred-2"));
    assertFalse(property.hasWebAuthn());
    assertTrue(property.getWebAuthnCredentials().isEmpty());
  }

  @Test
  void testAddWebAuthnCredentialDoesNotRotateEpoch(JenkinsRule j) {
    MFAUserProperty property = new MFAUserProperty();
    String epochBefore = property.getOrCreateMfaEpoch();

    property.addWebAuthnCredential(
      new WebAuthnCredential(
        "cred-1", "pk-1", 0L, "Laptop", "2026-01-01T00:00:00Z", null
      )
    );

    String epochAfter = property.getOrCreateMfaEpoch();
    assertEquals(
      epochBefore, epochAfter, "Adding a credential must not rotate the MFA epoch"
    );
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
  void testGetWebAuthnCredentialsReturnsDefensiveCopy(JenkinsRule j) {
    MFAUserProperty property = new MFAUserProperty();
    property.addWebAuthnCredential(
      new WebAuthnCredential(
        "cred-1", "pk-1", 0L, "Laptop", "2026-01-01T00:00:00Z", null
      )
    );

    List<WebAuthnCredential> credentials = property.getWebAuthnCredentials();
    credentials.clear();

    assertTrue(
      property.hasWebAuthn(),
      "Mutating the returned list must not affect stored state"
    );
    assertEquals(1, property.getWebAuthnCredentials().size());
  }

  @Test
  void testLastUsedMethodDefaultsToNull(JenkinsRule j) {
    MFAUserProperty property = new MFAUserProperty();

    assertNull(property.getLastUsedMethod());
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

  /** Legacy XML without webAuthnCredentials yields an empty list, not null. */
  @Test
  void testOldXmlWithoutCredentialListLoads(JenkinsRule j) {
    MFAUserProperty property = new MFAUserProperty();

    List<WebAuthnCredential> credentials = property.getWebAuthnCredentials();
    assertNotNull(credentials, "Credential list should never be null");
    assertTrue(
      credentials.isEmpty(), "Credential list should be empty when never populated"
    );
  }

  /** Legacy XML without mfaEpoch still generates one lazily. */
  @Test
  void testOldXmlWithoutEpochLoads(JenkinsRule j) {
    MFAUserProperty property = new MFAUserProperty();
    property.setSecret(totpService.generateSecret());

    String epoch = property.getOrCreateMfaEpoch();
    assertNotNull(epoch, "Epoch should be generated even without a persisted value");
    assertFalse(epoch.isEmpty(), "Epoch should not be empty");
  }

  @Test
  void testRemoveWebAuthnCredentialReturnsFalseWhenNotFound(JenkinsRule j) {
    MFAUserProperty property = new MFAUserProperty();

    assertFalse(property.removeWebAuthnCredential("does-not-exist"));
  }

  @Test
  void testRemoveWebAuthnCredentialRotatesEpoch(JenkinsRule j) {
    MFAUserProperty property = new MFAUserProperty();
    property.addWebAuthnCredential(
      new WebAuthnCredential(
        "cred-1", "pk-1", 0L, "Laptop", "2026-01-01T00:00:00Z", null
      )
    );
    String epochBefore = property.getOrCreateMfaEpoch();

    property.removeWebAuthnCredential("cred-1");

    String epochAfter = property.getOrCreateMfaEpoch();
    assertNotEquals(
      epochBefore, epochAfter, "Removing a credential must rotate the MFA epoch"
    );
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
  void testSetLastUsedMethodAndSave(JenkinsRule j) {
    MFAUserProperty property = new MFAUserProperty();

    property.setLastUsedMethodAndSave("totp");
    assertEquals("totp", property.getLastUsedMethod());

    property.setLastUsedMethodAndSave("webauthn");
    assertEquals("webauthn", property.getLastUsedMethod());
  }

  /** Signature counter updates go through the property, not the copy. */
  @Test
  void testUpdateWebAuthnCredentialPersistsCounterAndLastUsed(JenkinsRule j) {
    MFAUserProperty property = new MFAUserProperty();
    property.addWebAuthnCredential(
      new WebAuthnCredential(
        "cred-1", "pk-1", 0L, "Laptop", "2026-01-01T00:00:00Z", null
      )
    );
    property.addWebAuthnCredential(
      new WebAuthnCredential(
        "cred-2", "pk-2", 7L, "Phone", "2026-01-02T00:00:00Z", null
      )
    );

    property.updateWebAuthnCredential("cred-1", 42L, "2026-02-03T04:05:06Z");

    WebAuthnCredential updated = property.getWebAuthnCredentials().get(0);
    assertEquals("cred-1", updated.getCredentialId());
    assertEquals(42L, updated.getSignatureCount());
    assertEquals("2026-02-03T04:05:06Z", updated.getLastUsedAt());

    WebAuthnCredential untouched = property.getWebAuthnCredentials().get(1);
    assertEquals(7L, untouched.getSignatureCount());
    assertNull(untouched.getLastUsedAt());
  }

  /**
   * Updating an unknown credential id is a no-op rather than an error.
   */
  @Test
  void testUpdateWebAuthnCredentialUnknownIdIsNoOp(JenkinsRule j) {
    MFAUserProperty property = new MFAUserProperty();
    property.addWebAuthnCredential(
      new WebAuthnCredential(
        "cred-1", "pk-1", 3L, "Laptop", "2026-01-01T00:00:00Z", null
      )
    );

    property.updateWebAuthnCredential("nope", 99L, "2026-02-03T04:05:06Z");

    assertEquals(3L, property.getWebAuthnCredentials().get(0).getSignatureCount());
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
