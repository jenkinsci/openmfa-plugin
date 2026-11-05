package io.jenkins.plugins.openmfa.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import hudson.model.User;
import io.jenkins.plugins.openmfa.MFAUserProperty;
import io.jenkins.plugins.openmfa.service.model.WebAuthnCredential;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

/**
 * Unit tests for the adapter that exposes credentials stored on
 * {@link MFAUserProperty} to java-webauthn-server.
 */
@WithJenkins
class UserPropertyCredentialRepositoryTest {

  private static final String PUBLIC_KEY = encode("not-a-real-cose-key");

  private static String encode(String value) {
    return Base64.getUrlEncoder()
      .withoutPadding()
      .encodeToString(value.getBytes(StandardCharsets.UTF_8));
  }

  private static ByteArray sha256(String value) throws Exception {
    return new ByteArray(
      MessageDigest.getInstance("SHA-256")
        .digest(value.getBytes(StandardCharsets.UTF_8))
    );
  }

  /**
   * The descriptors feeding {@code excludeCredentials} (registration) and
   * {@code allowCredentials} (authentication) cover every stored credential.
   */
  @Test
  void testGetCredentialIdsForUsernameListsEveryCredential(JenkinsRule j)
    throws Exception {
    User user = userWith("multikey", "cred-a", "cred-b");
    UserPropertyCredentialRepository repository =
      new UserPropertyCredentialRepository(user);

    Set<String> ids =
      repository.getCredentialIdsForUsername("multikey").stream()
        .map(PublicKeyCredentialDescriptor::getId)
        .map(ByteArray::getBase64Url)
        .collect(Collectors.toSet());

    assertEquals(Set.of(encode("cred-a"), encode("cred-b")), ids);
  }

  /**
   * A user with no credentials yields no descriptors, and an unknown user
   * does not blow up.
   */
  @Test
  void testGetCredentialIdsForUsernameWithoutCredentials(JenkinsRule j) {
    User.getById("bare", true);
    UserPropertyCredentialRepository repository =
      new UserPropertyCredentialRepository(null);

    assertTrue(repository.getCredentialIdsForUsername("bare").isEmpty());
    assertTrue(repository.getCredentialIdsForUsername("ghost").isEmpty());
  }

  /**
   * {@code lookupAll} spans users, so registration can see that a credential
   * id is already taken by somebody else.
   */
  @Test
  void testLookupAllSpansUsers(JenkinsRule j) throws Exception {
    userWith("owner", "shared-cred");
    UserPropertyCredentialRepository repository =
      new UserPropertyCredentialRepository(User.getById("newcomer", true));

    Set<RegisteredCredential> matches =
      repository.lookupAll(ByteArray.fromBase64Url(encode("shared-cred")));

    assertEquals(1, matches.size());
    assertEquals(
      sha256("owner"), matches.iterator().next().getUserHandle(),
      "The match should point back at the owning user"
    );
    assertTrue(
      repository.lookupAll(ByteArray.fromBase64Url(encode("free-cred")))
        .isEmpty()
    );
  }

  /**
   * {@code lookup} finds a stored credential by id and handle, and carries
   * across the stored signature counter and public key.
   */
  @Test
  void testLookupFindsStoredCredential(JenkinsRule j) throws Exception {
    User user = userWith("lookupuser", "cred-a");
    MFAUserProperty.forUser(user)
      .updateWebAuthnCredential(encode("cred-a"), 42L, "2026-01-01T00:00:00Z");
    UserPropertyCredentialRepository repository =
      new UserPropertyCredentialRepository(user);

    Optional<RegisteredCredential> found =
      repository.lookup(
        ByteArray.fromBase64Url(encode("cred-a")), sha256("lookupuser")
      );

    assertTrue(found.isPresent());
    assertEquals(42L, found.get().getSignatureCount());
    assertEquals(PUBLIC_KEY, found.get().getPublicKeyCose().getBase64Url());
    assertEquals(sha256("lookupuser"), found.get().getUserHandle());
  }

  /**
   * {@code lookup} rejects a credential id that is not registered to the
   * handle's user.
   */
  @Test
  void testLookupRejectsUnknownCredential(JenkinsRule j) throws Exception {
    User user = userWith("lookupmiss", "cred-a");
    UserPropertyCredentialRepository repository =
      new UserPropertyCredentialRepository(user);

    assertTrue(
      repository.lookup(
        ByteArray.fromBase64Url(encode("cred-z")), sha256("lookupmiss")
      ).isEmpty()
    );
  }

  /**
   * A credential whose stored id is not valid base64url is skipped rather
   * than failing the whole ceremony.
   */
  @Test
  void testUnreadableCredentialIsSkipped(JenkinsRule j) throws Exception {
    User user = User.getById("corrupt", true);
    MFAUserProperty property = MFAUserProperty.getOrCreate(user);
    property.addWebAuthnCredential(
      new WebAuthnCredential(
        "not valid base64url!!", PUBLIC_KEY, 0L, "Broken",
        "2026-01-01T00:00:00Z", null
      )
    );
    UserPropertyCredentialRepository repository =
      new UserPropertyCredentialRepository(user);

    assertTrue(repository.getCredentialIdsForUsername("corrupt").isEmpty());
    assertFalse(
      repository.lookupAll(ByteArray.fromBase64Url(encode("anything")))
        .stream()
        .findAny()
        .isPresent()
    );
  }

  /**
   * The user handle is the SHA-256 of the Jenkins user id, and resolves back
   * to that user.
   */
  @Test
  void testUserHandleRoundTrip(JenkinsRule j) throws Exception {
    User user = User.getById("handleuser", true);
    UserPropertyCredentialRepository repository =
      new UserPropertyCredentialRepository(user);

    Optional<ByteArray> handle =
      repository.getUserHandleForUsername("handleuser");
    assertEquals(Optional.of(sha256("handleuser")), handle);

    assertEquals(
      Optional.of("handleuser"),
      repository.getUsernameForUserHandle(sha256("handleuser")),
      "The ceremony's own user should resolve from its handle"
    );
  }

  /**
   * A handle belonging to a user other than the ceremony's still resolves,
   * via the fallback scan.
   */
  @Test
  void testUsernameForUserHandleFallsBackToScan(JenkinsRule j)
    throws Exception {
    User.getById("scanned", true);
    UserPropertyCredentialRepository repository =
      new UserPropertyCredentialRepository(User.getById("someoneelse", true));

    assertEquals(
      Optional.of("scanned"),
      repository.getUsernameForUserHandle(sha256("scanned"))
    );
  }

  /**
   * An unknown handle resolves to nothing rather than throwing.
   */
  @Test
  void testUsernameForUserHandleUnknown(JenkinsRule j) throws Exception {
    UserPropertyCredentialRepository repository =
      new UserPropertyCredentialRepository(null);

    assertTrue(
      repository.getUsernameForUserHandle(sha256("nobody-at-all")).isEmpty()
    );
  }

  private User userWith(String id, String... credentialIds)
    throws IOException {
    User user = User.getById(id, true);
    MFAUserProperty property = MFAUserProperty.getOrCreate(user);
    for (String credentialId : credentialIds) {
      property.addWebAuthnCredential(
        new WebAuthnCredential(
          encode(credentialId), PUBLIC_KEY, 0L, credentialId,
          "2026-01-01T00:00:00Z", null
        )
      );
    }
    return user;
  }
}
