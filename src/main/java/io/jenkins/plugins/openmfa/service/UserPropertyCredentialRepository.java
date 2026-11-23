package io.jenkins.plugins.openmfa.service;

import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.exception.Base64UrlException;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import hudson.model.User;
import io.jenkins.plugins.openmfa.MFAUserProperty;
import io.jenkins.plugins.openmfa.base.MFAException;
import io.jenkins.plugins.openmfa.service.model.WebAuthnCredential;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import lombok.extern.java.Log;

/**
 * Lets java-webauthn-server read credentials stored on {@link MFAUserProperty}.
 * User handles are {@code sha256(userId)} so authenticators do not leak
 * account names; reverse lookup tries the ceremony's user before a full scan.
 */
@Log
class UserPropertyCredentialRepository implements CredentialRepository {

  private static final String DIGEST_ALGORITHM = "SHA-256";

  /** WebAuthn user handle for a user id: SHA-256 of the id. */
  @NonNull
  static ByteArray userHandle(@NonNull String userId) {
    try {
      return new ByteArray(
        MessageDigest.getInstance(DIGEST_ALGORITHM)
          .digest(userId.getBytes(StandardCharsets.UTF_8))
      );
    } catch (NoSuchAlgorithmException e) {
      throw new MFAException("SHA-256 is unavailable in this JVM", e);
    }
  }

  @CheckForNull
  private static ByteArray decode(@Nullable String base64Url) {
    if (base64Url == null || base64Url.isEmpty()) {
      return null;
    }
    try {
      return ByteArray.fromBase64Url(base64Url);
    } catch (Base64UrlException e) {
      log.warning("Ignoring WebAuthn credential with unreadable base64url: " + e);
      return null;
    }
  }

  @NonNull
  private static List<WebAuthnCredential> storedCredentials(@Nullable User user) {
    MFAUserProperty property = MFAUserProperty.forUser(user);
    return property == null ? List.of() : property.getWebAuthnCredentials();
  }

  @CheckForNull
  private static RegisteredCredential toRegisteredCredential(
    WebAuthnCredential credential, ByteArray handle) {
    ByteArray credentialId = decode(credential.getCredentialId());
    ByteArray publicKey = decode(credential.getPublicKeyCose());
    if (credentialId == null || publicKey == null) {
      return null;
    }
    return RegisteredCredential.builder()
      .credentialId(credentialId)
      .userHandle(handle)
      .publicKeyCose(publicKey)
      .signatureCount(credential.getSignatureCount())
      .build();
  }

  /** The ceremony's user, tried before scanning all users. */
  @CheckForNull
  private final User scopedUser;

  UserPropertyCredentialRepository(@Nullable User scopedUser) {
    this.scopedUser = scopedUser;
  }

  @Override
  public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(
    String username) {
    Set<PublicKeyCredentialDescriptor> descriptors = new LinkedHashSet<>();
    for (WebAuthnCredential credential : storedCredentials(
      User.getById(username, false)
    )) {
      ByteArray credentialId = decode(credential.getCredentialId());
      if (credentialId != null) {
        descriptors
          .add(PublicKeyCredentialDescriptor.builder().id(credentialId).build());
      }
    }
    return descriptors;
  }

  @Override
  public Optional<ByteArray> getUserHandleForUsername(String username) {
    return Optional.of(userHandle(username));
  }

  @Override
  public Optional<String> getUsernameForUserHandle(ByteArray userHandle) {
    if (scopedUser != null && userHandle(scopedUser.getId()).equals(userHandle)) {
      return Optional.of(scopedUser.getId());
    }
    for (User user : User.getAll()) {
      if (userHandle(user.getId()).equals(userHandle)) {
        return Optional.of(user.getId());
      }
    }
    return Optional.empty();
  }

  @Override
  public Optional<RegisteredCredential> lookup(
    ByteArray credentialId, ByteArray userHandle) {
    // Stored ids come from getBase64Url(), so compare as text.
    String wanted = credentialId.getBase64Url();
    return getUsernameForUserHandle(userHandle)
      .flatMap(
        username -> storedCredentials(User.getById(username, false)).stream()
          .filter(c -> wanted.equals(c.getCredentialId()))
          .findFirst()
          .map(c -> toRegisteredCredential(c, userHandle))
      );
  }

  @Override
  public Set<RegisteredCredential> lookupAll(ByteArray credentialId) {
    Set<RegisteredCredential> matches = new LinkedHashSet<>();
    String wanted = credentialId.getBase64Url();
    for (User user : User.getAll()) {
      ByteArray handle = userHandle(user.getId());
      for (WebAuthnCredential credential : storedCredentials(user)) {
        if (wanted.equals(credential.getCredentialId())) {
          RegisteredCredential registered =
            toRegisteredCredential(credential, handle);
          if (registered != null) {
            matches.add(registered);
          }
        }
      }
    }
    return matches;
  }
}
