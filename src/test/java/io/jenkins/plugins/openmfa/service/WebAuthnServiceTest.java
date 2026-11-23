package io.jenkins.plugins.openmfa.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import hudson.model.User;
import io.jenkins.plugins.openmfa.MFAGlobalConfiguration;
import io.jenkins.plugins.openmfa.MFAUserProperty;
import io.jenkins.plugins.openmfa.base.MFAContext;
import io.jenkins.plugins.openmfa.base.MFAException;
import io.jenkins.plugins.openmfa.constant.PluginConstants;
import io.jenkins.plugins.openmfa.service.model.WebAuthnCredential;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.List;
import jenkins.model.JenkinsLocationConfiguration;
import net.sf.json.JSONObject;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.springframework.mock.web.MockHttpSession;

/**
 * Unit tests for WebAuthnService, with round trips driven by a
 * {@link SoftwareAuthenticator} through the real library verification path.
 */
@WithJenkins
class WebAuthnServiceTest {

  private static final String GARBAGE_RESPONSE = "{\"not\":\"a credential\"}";

  private static final String ORIGIN = "https://jenkins.example.com";

  private static final String ROOT_URL = ORIGIN + "/";

  private static String expectedUserHandle(String userId) throws Exception {
    byte[] digest =
      MessageDigest.getInstance("SHA-256")
        .digest(userId.getBytes(StandardCharsets.UTF_8));
    return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
  }

  private final WebAuthnService webAuthnService =
    MFAContext.i().getService(WebAuthnService.class);

  /**
   * A counter that goes backwards is the signature of a cloned authenticator:
   * the assertion is refused and the stored credential is left untouched.
   */
  @Test
  void testAssertionRejectsSignatureCounterRegression(JenkinsRule j)
    throws Exception {
    User user = configuredUser("clonedkey");
    SoftwareAuthenticator authenticator = register(user);

    assertTrue(
      assertWith(user, authenticator, 5),
      "The first assertion should advance the counter to 5"
    );
    assertEquals(5L, storedCredential(user).getSignatureCount());

    assertFalse(
      assertWith(user, authenticator, 3),
      "A counter that goes backwards must be rejected"
    );
    WebAuthnCredential unchanged = storedCredential(user);
    assertEquals(
      5L, unchanged.getSignatureCount(),
      "A rejected assertion must not move the stored counter"
    );
  }

  /**
   * A response signed for an origin that is neither the Jenkins root URL nor
   * a configured extra origin is rejected.
   */
  @Test
  void testAssertionRejectsUnlistedOrigin(JenkinsRule j) throws Exception {
    User user = configuredUser("foreignorigin");
    SoftwareAuthenticator authenticator = register(user);

    MockHttpSession session = new MockHttpSession();
    String requestJson = webAuthnService.startAssertion(session, user);

    assertFalse(
      webAuthnService.finishAssertion(
        session, user,
        authenticator.authenticate(requestJson, "https://evil.example.com", 1)
      ),
      "An assertion signed for an unlisted origin must be rejected"
    );
  }

  /**
   * A ceremony older than the configured TTL is discarded unread, even
   * though it is still in the session.
   */
  @Test
  void testCeremonyExpiresAfterTtl(JenkinsRule j) throws Exception {
    User user = configuredUser("slowuser");
    SoftwareAuthenticator authenticator = new SoftwareAuthenticator();

    MockHttpSession session = new MockHttpSession();
    String optionsJson = webAuthnService.startRegistration(session, user);
    String response = authenticator.register(optionsJson, ORIGIN);
    age(session, PluginConstants.SessionAttributes.WEBAUTHN_REGISTRATION_CEREMONY);

    MFAException thrown =
      assertThrows(
        MFAException.class,
        () -> webAuthnService.finishRegistration(session, user, response, "Key")
      );
    assertTrue(
      thrown.getMessage().contains("No WebAuthn registration in progress"),
      "An expired ceremony should read as no ceremony, got: "
        + thrown.getMessage()
    );

    MockHttpSession assertionSession = new MockHttpSession();
    String requestJson = webAuthnService.startAssertion(assertionSession, user);
    String assertionResponse =
      authenticator.authenticate(requestJson, ORIGIN, 1);
    age(
      assertionSession,
      PluginConstants.SessionAttributes.WEBAUTHN_ASSERTION_CEREMONY
    );

    assertFalse(
      webAuthnService
        .finishAssertion(assertionSession, user, assertionResponse),
      "An expired assertion ceremony must not authenticate"
    );
  }

  /**
   * Both ceremonies are single-use: the stored state is dropped by the first
   * finish attempt, so a replay against the same session finds no ceremony.
   */
  @Test
  void testCeremonyIsSingleUse(JenkinsRule j) throws Exception {
    User user = configuredUser("replayuser");

    MockHttpSession registrationSession = new MockHttpSession();
    webAuthnService.startRegistration(registrationSession, user);
    assertThrows(
      MFAException.class,
      () -> webAuthnService
        .finishRegistration(registrationSession, user, GARBAGE_RESPONSE, "Key")
    );
    MFAException replay =
      assertThrows(
        MFAException.class,
        () -> webAuthnService.finishRegistration(
          registrationSession, user, GARBAGE_RESPONSE, "Key"
        )
      );
    assertTrue(
      replay.getMessage().contains("No WebAuthn registration in progress"),
      "Replaying a consumed registration ceremony should report that no "
        + "ceremony is in progress, got: " + replay.getMessage()
    );

    MockHttpSession assertionSession = new MockHttpSession();
    webAuthnService.startAssertion(assertionSession, user);
    assertFalse(
      webAuthnService
        .finishAssertion(assertionSession, user, GARBAGE_RESPONSE),
      "Garbage assertion response should be rejected"
    );
    assertNull(
      assertionSession.getAttribute(
        PluginConstants.SessionAttributes.WEBAUTHN_ASSERTION_CEREMONY
      ),
      "A consumed assertion ceremony must be removed from the session"
    );
    assertFalse(
      webAuthnService
        .finishAssertion(assertionSession, user, GARBAGE_RESPONSE),
      "Replaying a consumed assertion ceremony should fail"
    );
  }

  /**
   * An unparseable assertion response is rejected without throwing, and the
   * ceremony state is consumed.
   */
  @Test
  void testFinishAssertionRejectsGarbage(JenkinsRule j) {
    User user = configuredUser("assertuser");
    MockHttpSession session = new MockHttpSession();

    webAuthnService.startAssertion(session, user);

    assertFalse(
      webAuthnService.finishAssertion(session, user, GARBAGE_RESPONSE),
      "Garbage assertion response should return false, not throw"
    );
    assertNull(
      session.getAttribute(
        PluginConstants.SessionAttributes.WEBAUTHN_ASSERTION_CEREMONY
      ),
      "Failed assertion must still clear the ceremony state"
    );
  }

  /**
   * Pins the browser wire shape: an assertion without
   * {@code clientExtensionResults} is rejected (not thrown), with it accepted.
   */
  @Test
  void testFinishAssertionRequiresClientExtensionResults(JenkinsRule j)
    throws Exception {
    User user = configuredUser("extresultsuser");
    SoftwareAuthenticator authenticator = register(user);

    MockHttpSession missingSession = new MockHttpSession();
    String missingRequestJson =
      webAuthnService.startAssertion(missingSession, user);
    String withExtensions =
      authenticator.authenticate(missingRequestJson, ORIGIN, 1);
    assertTrue(
      withExtensions.contains("\"clientExtensionResults\":{}"),
      "SoftwareAuthenticator should emit clientExtensionResults by default"
    );
    JSONObject withoutField = JSONObject.fromObject(withExtensions);
    withoutField.remove("clientExtensionResults");

    assertFalse(
      webAuthnService
        .finishAssertion(missingSession, user, withoutField.toString()),
      "An assertion response missing clientExtensionResults must be "
        + "rejected, not accepted or thrown as an unchecked exception"
    );

    MockHttpSession presentSession = new MockHttpSession();
    String presentRequestJson =
      webAuthnService.startAssertion(presentSession, user);
    String withField =
      authenticator.authenticate(presentRequestJson, ORIGIN, 2);

    assertTrue(
      webAuthnService.finishAssertion(presentSession, user, withField),
      "The same payload with an explicit clientExtensionResults object "
        + "must be accepted"
    );
  }

  /** A ceremony started for one user cannot be finished against another. */
  @Test
  void testFinishRegistrationRejectsCeremonyStartedForAnotherUser(JenkinsRule j)
    throws Exception {
    User alice = configuredUser("alice");
    User bob = User.getById("bob", true);
    SoftwareAuthenticator authenticator = new SoftwareAuthenticator();

    MockHttpSession session = new MockHttpSession();
    String optionsJson = webAuthnService.startRegistration(session, alice);
    String response = authenticator.register(optionsJson, ORIGIN);

    MFAException thrown =
      assertThrows(
        MFAException.class,
        () -> webAuthnService.finishRegistration(session, bob, response, "Key")
      );
    assertTrue(
      thrown.getMessage().contains("different user"),
      "Failure should say the ceremony belongs to another user, got: "
        + thrown.getMessage()
    );

    MFAUserProperty bobProperty = MFAUserProperty.forUser(bob);
    assertTrue(
      bobProperty == null || !bobProperty.hasWebAuthn(),
      "Alice's authenticator must not land on Bob's account"
    );
  }

  /**
   * An unparseable registration response raises a user-safe MFAException and
   * clears the pending ceremony.
   */
  @Test
  void testFinishRegistrationRejectsGarbage(JenkinsRule j) {
    User user = configuredUser("garbageuser");
    MockHttpSession session = new MockHttpSession();

    webAuthnService.startRegistration(session, user);
    assertNotNull(
      session.getAttribute(
        PluginConstants.SessionAttributes.WEBAUTHN_REGISTRATION_CEREMONY
      ),
      "startRegistration should record the ceremony in the session"
    );

    assertThrows(
      MFAException.class,
      () -> webAuthnService
        .finishRegistration(session, user, GARBAGE_RESPONSE, "My key")
    );
    assertNull(
      session.getAttribute(
        PluginConstants.SessionAttributes.WEBAUTHN_REGISTRATION_CEREMONY
      ),
      "Failed registration must clear the ceremony state"
    );
  }

  /**
   * The registration options carry the resolved relying-party id, a challenge,
   * and a user handle that is the SHA-256 of the Jenkins user id.
   */
  @Test
  void testRegistrationOptionsContainRpAndHashedHandle(JenkinsRule j)
    throws Exception {
    User user = configuredUser("optionsuser");
    MockHttpSession session = new MockHttpSession();

    String optionsJson = webAuthnService.startRegistration(session, user);
    JSONObject publicKey =
      JSONObject.fromObject(optionsJson).getJSONObject("publicKey");

    assertEquals(
      "jenkins.example.com",
      publicKey.getJSONObject("rp").getString("id"),
      "Options should advertise the resolved relying-party id"
    );
    assertFalse(
      publicKey.getString("challenge").isEmpty(),
      "Options should carry a challenge"
    );
    assertEquals(
      expectedUserHandle("optionsuser"),
      publicKey.getJSONObject("user").getString("id"),
      "User handle should be base64url(sha256(userId))"
    );
  }

  /**
   * With no explicit override, the relying-party id is the host of the Jenkins
   * root URL.
   */
  @Test
  void testResolveRpIdFromRootUrl(JenkinsRule j) {
    JenkinsLocationConfiguration.get().setUrl(ROOT_URL);
    MFAGlobalConfiguration.get().setWebAuthnRpId("");

    assertEquals("jenkins.example.com", webAuthnService.resolveRpId());
    assertTrue(
      webAuthnService.isAvailable(),
      "WebAuthn should be available once a relying-party id resolves"
    );
  }

  /**
   * An explicitly configured relying-party id wins over the root URL host.
   */
  @Test
  void testResolveRpIdOverride(JenkinsRule j) {
    JenkinsLocationConfiguration.get().setUrl(ROOT_URL);
    MFAGlobalConfiguration.get().setWebAuthnRpId("example.org");

    assertEquals("example.org", webAuthnService.resolveRpId());
  }

  /**
   * An rpId does not imply an origin; with no root URL or configured origin
   * the ceremony is refused.
   */
  @Test
  void testRpIdOverrideDoesNotImplyOrigin(JenkinsRule j) {
    JenkinsLocationConfiguration.get().setUrl(null);
    MFAGlobalConfiguration config = MFAGlobalConfiguration.get();
    config.setWebAuthnRpId("jenkins.example.com");
    config.setWebAuthnAllowedOrigins(List.of());

    User user = User.getById("noorigins", true);
    MockHttpSession session = new MockHttpSession();

    MFAException thrown =
      assertThrows(
        MFAException.class,
        () -> webAuthnService.startRegistration(session, user)
      );
    assertTrue(
      thrown.getMessage().contains("allowed origin"),
      "Failure should tell the administrator to configure an origin, got: "
        + thrown.getMessage()
    );
    assertNull(
      session.getAttribute(
        PluginConstants.SessionAttributes.WEBAUTHN_REGISTRATION_CEREMONY
      ),
      "A refused ceremony must not be left in the session"
    );
  }

  /**
   * A full authentication round trip advances the stored signature counter
   * and records when the key was last used.
   */
  @Test
  void testSuccessfulAssertionUpdatesCounterAndLastUsed(JenkinsRule j)
    throws Exception {
    User user = configuredUser("signin");
    SoftwareAuthenticator authenticator = register(user);

    assertNull(
      storedCredential(user).getLastUsedAt(),
      "A freshly registered credential has never been used"
    );

    assertTrue(
      assertWith(user, authenticator, 7), "A valid assertion should succeed"
    );

    WebAuthnCredential used = storedCredential(user);
    assertEquals(
      7L, used.getSignatureCount(),
      "The authenticator's counter should be persisted"
    );
    assertNotNull(
      used.getLastUsedAt(), "The last-used timestamp should be persisted"
    );
  }

  /**
   * A full registration round trip against the library's real verification
   * path stores a credential with the authenticator's id and key.
   */
  @Test
  void testSuccessfulRegistrationRoundTrip(JenkinsRule j) throws Exception {
    User user = configuredUser("roundtrip");
    SoftwareAuthenticator authenticator = new SoftwareAuthenticator();

    MockHttpSession session = new MockHttpSession();
    String optionsJson = webAuthnService.startRegistration(session, user);
    WebAuthnCredential credential =
      webAuthnService.finishRegistration(
        session, user, authenticator.register(optionsJson, ORIGIN), "Yubikey 5"
      );

    assertEquals(
      authenticator.credentialIdBase64Url(), credential.getCredentialId()
    );
    assertEquals("Yubikey 5", credential.getName());
    assertEquals(0L, credential.getSignatureCount());
    assertNotNull(credential.getCreatedAt());
    assertNull(credential.getLastUsedAt());
    assertFalse(
      credential.getPublicKeyCose().isEmpty(), "COSE public key should be stored"
    );

    MFAUserProperty property = MFAUserProperty.forUser(user);
    assertNotNull(property);
    assertTrue(property.hasWebAuthn());
    assertEquals(
      authenticator.credentialIdBase64Url(),
      property.getWebAuthnCredentials().get(0).getCredentialId(),
      "The credential should be persisted on the user"
    );
    assertNull(
      session.getAttribute(
        PluginConstants.SessionAttributes.WEBAUTHN_REGISTRATION_CEREMONY
      ),
      "A completed ceremony must be cleared"
    );
  }

  /**
   * Turning WebAuthn off globally makes it unavailable and refuses both
   * ceremonies, whatever the rest of the configuration says.
   */
  @Test
  void testUnavailableWhenWebAuthnDisabled(JenkinsRule j) {
    User user = configuredUser("disableduser");
    MFAGlobalConfiguration.get().setAllowWebAuthn(false);

    assertFalse(
      webAuthnService.isAvailable(),
      "WebAuthn must be unavailable when disabled globally"
    );

    MockHttpSession session = new MockHttpSession();
    assertTrue(
      assertThrows(
        MFAException.class,
        () -> webAuthnService.startRegistration(session, user)
      ).getMessage().contains("disabled"),
      "Registration should refuse with a 'disabled' message"
    );
    assertTrue(
      assertThrows(
        MFAException.class,
        () -> webAuthnService.startAssertion(session, user)
      ).getMessage().contains("disabled"),
      "Sign-in should refuse with a 'disabled' message"
    );
  }

  /** Without a root URL or rpId override, WebAuthn is unavailable. */
  @Test
  void testUnavailableWithoutRootUrl(JenkinsRule j) {
    JenkinsLocationConfiguration.get().setUrl(null);
    MFAGlobalConfiguration.get().setWebAuthnRpId("");

    assertNull(webAuthnService.resolveRpId());
    assertFalse(
      webAuthnService.isAvailable(),
      "WebAuthn cannot be available without a relying-party id"
    );

    User user = User.getById("norooturluser", true);
    MockHttpSession session = new MockHttpSession();
    MFAException thrown =
      assertThrows(
        MFAException.class,
        () -> webAuthnService.startAssertion(session, user)
      );
    assertTrue(
      thrown.getMessage().contains("Jenkins URL"),
      "Failure should point the administrator at the Jenkins URL, got: "
        + thrown.getMessage()
    );
  }

  /** Rewinds a pending ceremony past its TTL. */
  private void age(MockHttpSession session, String attribute) {
    String stored = (String) session.getAttribute(attribute);
    assertNotNull(stored, "There should be a ceremony to age");
    String json =
      stored.substring(stored.indexOf(WebAuthnService.CEREMONY_SEPARATOR) + 1);
    long expired =
      System.currentTimeMillis()
        - PluginConstants.WebAuthn.CEREMONY_TTL_MS - 1000;
    session.setAttribute(attribute, WebAuthnService.encodeCeremony(expired, json));
  }

  /**
   * Runs one complete authentication ceremony with the given counter value.
   */
  private boolean assertWith(
    User user, SoftwareAuthenticator authenticator, long signatureCount)
    throws Exception {
    MockHttpSession session = new MockHttpSession();
    String requestJson = webAuthnService.startAssertion(session, user);
    return webAuthnService.finishAssertion(
      session, user, authenticator.authenticate(requestJson, ORIGIN, signatureCount)
    );
  }

  /**
   * A user on a Jenkins whose root URL, relying-party id and origins are all
   * in their default, working configuration.
   */
  private User configuredUser(String id) {
    JenkinsLocationConfiguration.get().setUrl(ROOT_URL);
    MFAGlobalConfiguration config = MFAGlobalConfiguration.get();
    config.setAllowWebAuthn(true);
    config.setWebAuthnRpId("");
    config.setWebAuthnAllowedOrigins(List.of());
    return User.getById(id, true);
  }

  /**
   * Registers a fresh software authenticator for the user and returns it.
   */
  private SoftwareAuthenticator register(User user) throws Exception {
    SoftwareAuthenticator authenticator = new SoftwareAuthenticator();
    MockHttpSession session = new MockHttpSession();
    String optionsJson = webAuthnService.startRegistration(session, user);
    webAuthnService.finishRegistration(
      session, user, authenticator.register(optionsJson, ORIGIN), "Test key"
    );
    return authenticator;
  }

  /**
   * The user's single stored credential.
   */
  private WebAuthnCredential storedCredential(User user) {
    MFAUserProperty property = MFAUserProperty.forUser(user);
    assertNotNull(property, "User should have an MFA property");
    List<WebAuthnCredential> credentials = property.getWebAuthnCredentials();
    assertEquals(1, credentials.size(), "Expected exactly one credential");
    return credentials.get(0);
  }
}
