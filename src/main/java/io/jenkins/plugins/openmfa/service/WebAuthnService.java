package io.jenkins.plugins.openmfa.service;

import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.AssertionResult;
import com.yubico.webauthn.FinishAssertionOptions;
import com.yubico.webauthn.FinishRegistrationOptions;
import com.yubico.webauthn.RegistrationResult;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartAssertionOptions;
import com.yubico.webauthn.StartRegistrationOptions;
import com.yubico.webauthn.data.AttestationConveyancePreference;
import com.yubico.webauthn.data.AuthenticatorAssertionResponse;
import com.yubico.webauthn.data.AuthenticatorAttestationResponse;
import com.yubico.webauthn.data.AuthenticatorSelectionCriteria;
import com.yubico.webauthn.data.ClientAssertionExtensionOutputs;
import com.yubico.webauthn.data.ClientRegistrationExtensionOutputs;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import com.yubico.webauthn.data.UserIdentity;
import com.yubico.webauthn.data.UserVerificationRequirement;
import com.yubico.webauthn.exception.AssertionFailedException;
import com.yubico.webauthn.exception.RegistrationFailedException;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.model.User;
import io.jenkins.plugins.openmfa.MFAGlobalConfiguration;
import io.jenkins.plugins.openmfa.MFAUserProperty;
import io.jenkins.plugins.openmfa.base.MFAException;
import io.jenkins.plugins.openmfa.base.Service;
import io.jenkins.plugins.openmfa.constant.PluginConstants;
import io.jenkins.plugins.openmfa.service.model.WebAuthnCredential;
import io.jenkins.plugins.openmfa.util.JenkinsUtil;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.logging.Level;
import lombok.extern.java.Log;

/**
 * WebAuthn registration and authentication ceremonies on top of Yubico
 * java-webauthn-server. The {@link RelyingParty} is rebuilt per call because
 * its configuration is editable at runtime. Ceremony state lives in the
 * session, timestamped, single-use (no replay) and TTL-bound.
 */
@Log
@Service
public class WebAuthnService {

  /** Separates issue time from ceremony JSON; package-private for tests. */
  static final String CEREMONY_SEPARATOR = ":";

  private static final String DEFAULT_CREDENTIAL_NAME = "Security key";

  private static final String NO_ORIGINS_MESSAGE =
    "WebAuthn has no accepted origins: set the Jenkins URL under "
      + "Manage Jenkins > System, or list at least one allowed origin in "
      + "the OpenMFA configuration. A Relying Party ID on its own does not "
      + "imply an origin.";

  private static final String UNAVAILABLE_MESSAGE =
    "WebAuthn is not configured: set the Jenkins URL under "
      + "Manage Jenkins > System, or configure an explicit WebAuthn "
      + "Relying Party ID.";

  /** Formats a stored ceremony; package-private so tests can age one. */
  @NonNull
  static String encodeCeremony(long issuedAtMillis, String json) {
    return issuedAtMillis + CEREMONY_SEPARATOR + json;
  }

  /**
   * URL to browser-style origin ({@code scheme://host[:port]}, default port
   * omitted).
   */
  @NonNull
  private static Optional<String> originOf(@CheckForNull String url) {
    if (url == null || url.isBlank()) {
      return Optional.empty();
    }
    try {
      URI uri = new URI(url.trim());
      String scheme = uri.getScheme();
      String host = uri.getHost();
      if (scheme == null || host == null) {
        return Optional.empty();
      }
      scheme = scheme.toLowerCase(Locale.ROOT);
      int port = uri.getPort();
      boolean defaultPort =
        port == -1
          || ("https".equals(scheme) && port == 443)
          || ("http".equals(scheme) && port == 80);
      return Optional
        .of(scheme + "://" + host + (defaultPort ? "" : ":" + port));
    } catch (URISyntaxException e) {
      log.warning("Ignoring unparseable URL while deriving WebAuthn origin: " + url);
      return Optional.empty();
    }
  }

  /**
   * Completes an authentication ceremony. Never throws: every failure
   * (including a signature-counter regression, i.e. a cloned authenticator)
   * is logged and returns {@code false}. On success the counter is persisted.
   *
   * @return whether the assertion was valid for this user
   */
  public boolean finishAssertion(
    HttpSession session, User user, String responseJson) {
    String stored =
      consume(
        session, PluginConstants.SessionAttributes.WEBAUTHN_ASSERTION_CEREMONY
      );
    if (stored == null) {
      log.warning(
        "No live WebAuthn assertion in progress for user: " + user.getId()
      );
      return false;
    }

    try {
      AssertionRequest request = AssertionRequest.fromJson(stored);
      PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> response =
        PublicKeyCredential.parseAssertionResponseJson(responseJson);

      AssertionResult result =
        relyingParty(user).finishAssertion(
          FinishAssertionOptions.builder()
            .request(request)
            .response(response)
            .build()
        );

      if (!result.isSuccess()) {
        log.warning("WebAuthn assertion rejected for user: " + user.getId());
        return false;
      }
      if (!user.getId().equals(result.getUsername())) {
        log.warning(
          "WebAuthn assertion resolved to '"
            + result.getUsername()
            + "' but was presented for '" + user.getId() + "'"
        );
        return false;
      }
      if (!result.isSignatureCounterValid()) {
        log.warning(
          "WebAuthn signature counter regressed for user: "
            + user.getId()
            + " - possible cloned authenticator; rejecting the assertion"
        );
        return false;
      }

      MFAUserProperty property = MFAUserProperty.forUser(user);
      if (property != null) {
        property.updateWebAuthnCredential(
          result.getCredential().getCredentialId().getBase64Url(),
          result.getSignatureCount(),
          Instant.now().toString()
        );
      }
      return true;
    } catch (IOException | AssertionFailedException | RuntimeException e) {
      // Never throws: a misconfigured RP is a failed login, not a 500.
      log.log(
        Level.WARNING,
        "WebAuthn assertion failed for user: " + user.getId(), e
      );
      return false;
    }
  }

  /**
   * Completes a registration ceremony and stores the new credential.
   *
   * @throws MFAException
   *           if no live ceremony is pending, it belongs to another
   *           user, the response is invalid, or the user is at the cap
   */
  @NonNull
  public WebAuthnCredential finishRegistration(
    HttpSession session, User user, String responseJson, String name) {
    String stored =
      consume(
        session, PluginConstants.SessionAttributes.WEBAUTHN_REGISTRATION_CEREMONY
      );
    if (stored == null) {
      throw new MFAException(
        "No WebAuthn registration in progress. Please start over."
      );
    }

    PublicKeyCredentialCreationOptions request;
    PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> response;
    try {
      request = PublicKeyCredentialCreationOptions.fromJson(stored);
      response = PublicKeyCredential.parseRegistrationResponseJson(responseJson);
    } catch (IOException | IllegalArgumentException e) {
      log.log(
        Level.FINE, "Unreadable WebAuthn registration response for user: "
          + user.getId(),
        e
      );
      throw new MFAException(
        "The security key registration response could not be read. "
          + "Please try again."
      );
    }

    // Session ceremony and target user come from different sources; tie them
    // so a ceremony cannot plant a key on another account.
    requireCeremonyBelongsTo(request, user);

    RegistrationResult result;
    try {
      result =
        relyingParty(user).finishRegistration(
          FinishRegistrationOptions.builder()
            .request(request)
            .response(response)
            .build()
        );
    } catch (RegistrationFailedException | IllegalArgumentException e) {
      log.log(
        Level.FINE, "WebAuthn registration failed for user: " + user.getId(), e
      );
      throw new MFAException(
        "The security key could not be registered. Please try again."
      );
    }

    WebAuthnCredential credential =
      new WebAuthnCredential(
        result.getKeyId().getId().getBase64Url(),
        result.getPublicKeyCose().getBase64Url(),
        result.getSignatureCount(),
        name == null || name.isBlank() ? DEFAULT_CREDENTIAL_NAME : name.trim(),
        Instant.now().toString(),
        null
      );

    boolean appended;
    try {
      appended = MFAUserProperty.getOrCreate(user).addWebAuthnCredential(credential);
    } catch (IOException e) {
      throw new MFAException(
        "The security key was verified but could not be saved.", e
      );
    }
    if (!appended) {
      // At the cap: report rather than silently drop the key.
      throw new MFAException(
        "The security key was verified but not saved: this account already "
          + "holds the maximum number of security keys."
      );
    }
    return credential;
  }

  /** Whether WebAuthn is enabled and a relying-party id resolves. */
  public boolean isAvailable() {
    return MFAGlobalConfiguration.get().isAllowWebAuthn()
      && resolveRpId() != null;
  }

  /** Configured Relying Party ID, else the Jenkins root URL host, else null. */
  @CheckForNull
  public String resolveRpId() {
    String configured = MFAGlobalConfiguration.get().getWebAuthnRpId();
    if (configured != null && !configured.isBlank()) {
      return configured.trim();
    }
    String rootUrl = JenkinsUtil.getJenkinsRootUrl().orElse(null);
    if (rootUrl == null || rootUrl.isBlank()) {
      return null;
    }
    try {
      String host = new URI(rootUrl.trim()).getHost();
      return host == null || host.isBlank() ? null : host;
    } catch (URISyntaxException e) {
      log.warning("Jenkins root URL is not a valid URI: " + rootUrl);
      return null;
    }
  }

  /**
   * Starts an authentication ceremony, storing its state in the session.
   *
   * @return JSON for {@code navigator.credentials.get()}
   */
  @NonNull
  public String startAssertion(HttpSession session, User user) {
    AssertionRequest request =
      relyingParty(user).startAssertion(
        StartAssertionOptions.builder()
          .username(user.getId())
          .userVerification(UserVerificationRequirement.PREFERRED)
          .timeout(PluginConstants.WebAuthn.CEREMONY_TTL_MS)
          .build()
      );
    try {
      store(
        session,
        PluginConstants.SessionAttributes.WEBAUTHN_ASSERTION_CEREMONY,
        request.toJson()
      );
      return request.toCredentialsGetJson();
    } catch (IOException e) {
      throw new MFAException("Could not prepare the WebAuthn sign-in request", e);
    }
  }

  /**
   * Starts a registration ceremony, storing its state in the session.
   *
   * @return JSON for {@code navigator.credentials.create()}
   */
  @NonNull
  public String startRegistration(HttpSession session, User user) {
    PublicKeyCredentialCreationOptions options =
      relyingParty(user).startRegistration(
        StartRegistrationOptions.builder()
          .user(
            UserIdentity.builder()
              .name(user.getId())
              .displayName(user.getDisplayName())
              .id(UserPropertyCredentialRepository.userHandle(user.getId()))
              .build()
          )
          .authenticatorSelection(
            AuthenticatorSelectionCriteria.builder()
              .userVerification(UserVerificationRequirement.PREFERRED)
              .build()
          )
          .timeout(PluginConstants.WebAuthn.CEREMONY_TTL_MS)
          .build()
      );
    try {
      store(
        session,
        PluginConstants.SessionAttributes.WEBAUTHN_REGISTRATION_CEREMONY,
        options.toJson()
      );
      return options.toCredentialsCreateJson();
    } catch (IOException e) {
      throw new MFAException(
        "Could not prepare the WebAuthn registration request", e
      );
    }
  }

  /**
   * Reads and removes a ceremony (single-use), discarding it past its TTL.
   *
   * @return the ceremony JSON, or {@code null} if absent, unreadable or expired
   */
  @CheckForNull
  private String consume(HttpSession session, String attribute) {
    Object value;
    // Two concurrent finish attempts must not both see the ceremony.
    synchronized (session) {
      value = session.getAttribute(attribute);
      session.removeAttribute(attribute);
    }
    if (!(value instanceof String ceremony)) {
      return null;
    }
    int separator = ceremony.indexOf(CEREMONY_SEPARATOR);
    if (separator < 0) {
      return null;
    }
    long issuedAt;
    try {
      issuedAt = Long.parseLong(ceremony.substring(0, separator));
    } catch (NumberFormatException e) {
      return null;
    }
    if (
      System.currentTimeMillis()
        - issuedAt > PluginConstants.WebAuthn.CEREMONY_TTL_MS
    ) {
      log.fine("Discarding WebAuthn ceremony that outlived its TTL");
      return null;
    }
    return ceremony.substring(separator + 1);
  }

  /**
   * Builds a relying party for the current configuration.
   *
   * @throws MFAException
   *           if disabled, or no rpId or origin resolves
   */
  @NonNull
  private RelyingParty relyingParty(User user) {
    MFAGlobalConfiguration config = MFAGlobalConfiguration.get();
    if (!config.isAllowWebAuthn()) {
      throw new MFAException(
        "WebAuthn security keys are disabled in the OpenMFA configuration."
      );
    }
    String rpId = resolveRpId();
    if (rpId == null) {
      throw new MFAException(UNAVAILABLE_MESSAGE);
    }

    return RelyingParty.builder()
      .identity(
        RelyingPartyIdentity.builder().id(rpId).name(config.getIssuer()).build()
      )
      .credentialRepository(new UserPropertyCredentialRepository(user))
      .origins(resolveOrigins())
      .attestationConveyancePreference(AttestationConveyancePreference.NONE)
      // Checked via isSignatureCounterValid() so the rejection is logged.
      .validateSignatureCounter(false)
      .build();
  }

  /**
   * Fails unless the pending ceremony was started for the given user.
   */
  private void requireCeremonyBelongsTo(
    PublicKeyCredentialCreationOptions request, User user) {
    UserIdentity ceremonyUser = request.getUser();
    boolean sameUser =
      user.getId().equals(ceremonyUser.getName())
        && UserPropertyCredentialRepository.userHandle(user.getId())
          .equals(ceremonyUser.getId());
    if (!sameUser) {
      log.warning(
        "Refusing to finish a WebAuthn registration started for '"
          + ceremonyUser.getName() + "' against user '" + user.getId() + "'"
      );
      throw new MFAException(
        "This registration was started for a different user. "
          + "Please start over."
      );
    }
  }

  /**
   * Accepted origins: the root URL's origin plus configured extras. An rpId
   * override deliberately adds no origin (that would widen acceptance).
   *
   * @throws MFAException
   *           if no origin can be determined
   */
  @NonNull
  private Set<String> resolveOrigins() {
    Set<String> origins = new LinkedHashSet<>();
    originOf(JenkinsUtil.getJenkinsRootUrl().orElse(null)).ifPresent(origins::add);
    for (String configured : MFAGlobalConfiguration.get()
      .getWebAuthnAllowedOrigins()) {
      originOf(configured).ifPresent(origins::add);
    }
    if (origins.isEmpty()) {
      throw new MFAException(NO_ORIGINS_MESSAGE);
    }
    return origins;
  }

  /** Stores a new ceremony stamped with the current time. */
  private void store(HttpSession session, String attribute, String json) {
    synchronized (session) {
      session
        .setAttribute(attribute, encodeCeremony(System.currentTimeMillis(), json));
    }
  }
}
