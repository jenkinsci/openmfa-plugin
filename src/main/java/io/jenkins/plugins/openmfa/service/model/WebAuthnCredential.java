package io.jenkins.plugins.openmfa.service.model;

import lombok.Getter;
import lombok.Setter;

/**
 * A single WebAuthn credential registered by a user as an MFA second
 * factor. {@code credentialId} and {@code publicKeyCose} are base64url
 * encoded; {@code createdAt} and {@code lastUsedAt} are ISO-8601 strings.
 *
 * <p>
 * Only {@code signatureCount} and {@code lastUsedAt} are mutable after
 * registration: the signature counter advances and the last-used timestamp
 * updates on every authentication, while the remaining fields are fixed at
 * registration time.
 */
@Getter
public class WebAuthnCredential {

  private final String createdAt;

  private final String credentialId;

  @Setter
  private String lastUsedAt;

  private final String name;

  private final String publicKeyCose;

  @Setter
  private long signatureCount;

  public WebAuthnCredential(String credentialId, String publicKeyCose,
    long signatureCount, String name, String createdAt, String lastUsedAt) {
    this.credentialId = credentialId;
    this.publicKeyCose = publicKeyCose;
    this.signatureCount = signatureCount;
    this.name = name;
    this.createdAt = createdAt;
    this.lastUsedAt = lastUsedAt;
  }
}
