package io.jenkins.plugins.openmfa;

import static io.jenkins.plugins.openmfa.util.JenkinsUtil.isAdmin;

import com.fasterxml.jackson.databind.JsonNode;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.model.InvisibleAction;
import hudson.model.User;
import hudson.util.Secret;
import io.jenkins.plugins.openmfa.base.MFAContext;
import io.jenkins.plugins.openmfa.base.MFAException;
import io.jenkins.plugins.openmfa.constant.PluginConstants;
import io.jenkins.plugins.openmfa.constant.TOTPConstants;
import io.jenkins.plugins.openmfa.constant.UIConstants;
import io.jenkins.plugins.openmfa.service.SessionService;
import io.jenkins.plugins.openmfa.service.TOTPService;
import io.jenkins.plugins.openmfa.service.WebAuthnService;
import io.jenkins.plugins.openmfa.service.model.WebAuthnCredential;
import io.jenkins.plugins.openmfa.util.SecurityUtil;
import io.jenkins.plugins.openmfa.util.WebAuthnHttpUtil;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import lombok.extern.java.Log;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.HttpResponses;
import org.kohsuke.stapler.HttpResponses.HttpResponseException;
import org.kohsuke.stapler.Stapler;
import org.kohsuke.stapler.StaplerRequest2;
import org.kohsuke.stapler.WebMethod;
import org.kohsuke.stapler.interceptor.RequirePOST;

/**
 * Action that provides MFA setup interface for users.
 */
@Log
public class MFASetupAction extends InvisibleAction {

  /**
   * Registration error codes sent as {@code {"error": "<code>"}}; the page
   * script localizes them, unknown codes render as the generic message.
   */
  private static final String ERROR_CREDENTIAL_LIMIT = "credential_limit";

  private static final String ERROR_INVALID_REQUEST = "invalid_request";

  private static final String ERROR_NAME_REQUIRED = "name_required";

  private static final String ERROR_NAME_TOO_LONG = "name_too_long";

  private static final String ERROR_REGISTRATION_FAILED = "registration_failed";

  private final User targetUser;

  public MFASetupAction(User targetUser) {
    this.targetUser = targetUser;
  }

  /**
   * Disables MFA for the current user.
   */
  @RequirePOST
  public HttpResponse doDisable() throws IOException {
    requireCanConfigureTargetUser();
    if (MFAGlobalConfiguration.get().isRequireMFA()) {
      return HttpResponses.redirectTo("?error=require_mfa");
    }

    MFAUserProperty property = MFAUserProperty.forUser(targetUser);
    if (property != null) {
      // TOTP anchors security keys: keys left behind would revive on
      // re-enrollment. Also rotates the MFA epoch.
      property.clearAllFactors();
      log.info(String.format("MFA disabled for user: %s", targetUser.getId()));
    }

    return HttpResponses.redirectTo("?success=disabled");
  }

  /**
   * Enables MFA for the current user.
   */
  @RequirePOST
  public HttpResponse doEnable() throws IOException {
    requireCanConfigureTargetUser();

    var req = Stapler.getCurrentRequest2();
    String secretParam = req.getParameter(PluginConstants.FormParameters.SECRET);
    String code = req.getParameter(PluginConstants.FormParameters.CODE);

    // Convert to Secret for secure handling
    Secret secret = Secret.fromString(secretParam);

    // Verify the code before enabling
    TOTPService totpService = MFAContext.i().getService(TOTPService.class);
    if (!totpService.verifyCode(secret, code)) {
      return HttpResponses.redirectTo("?error=invalid_code");
    }

    MFAUserProperty.getOrCreate(targetUser).enrollSecret(secret);

    log.info(String.format("MFA enabled for user: %s", targetUser.getId()));

    // Mark the user doesn't need to re-verify
    MFAContext.i()
      .getService(SessionService.class)
      .verifySession(req);

    return HttpResponses.redirectTo("?success=enabled");
  }

  /**
   * Completes a WebAuthn registration from a {@code {"name", "response"}}
   * JSON body (name kept out of the query string so it stays out of logs).
   */
  @RequirePOST
  @WebMethod(name = "webauthn-register-finish")
  public HttpResponse doWebauthnRegisterFinish() {
    MFAUserProperty property = requireWebAuthnManagement(true);
    // Re-checked: parallel ceremonies; the property enforces it again on add.
    if (property.isAtWebAuthnLimit()) {
      return WebAuthnHttpUtil
        .jsonError(UIConstants.HttpStatus.BAD_REQUEST, ERROR_CREDENTIAL_LIMIT);
    }

    var req = Stapler.getCurrentRequest2();
    String body = WebAuthnHttpUtil.readCeremonyBody(req);
    JsonNode envelope = body == null ? null : WebAuthnHttpUtil.parseJsonObject(body);
    if (envelope == null) {
      log.fine(
        "Unreadable WebAuthn registration envelope for user: "
          + targetUser.getId()
      );
      return WebAuthnHttpUtil
        .jsonError(UIConstants.HttpStatus.BAD_REQUEST, ERROR_INVALID_REQUEST);
    }

    JsonNode responseNode = envelope.get("response");
    if (responseNode == null || !responseNode.isObject()) {
      return WebAuthnHttpUtil
        .jsonError(UIConstants.HttpStatus.BAD_REQUEST, ERROR_INVALID_REQUEST);
    }

    JsonNode nameNode = envelope.get("name");
    String name =
      nameNode == null || !nameNode.isTextual() ? "" : nameNode.asText().trim();
    if (name.isEmpty()) {
      return WebAuthnHttpUtil
        .jsonError(UIConstants.HttpStatus.BAD_REQUEST, ERROR_NAME_REQUIRED);
    }
    if (name.length() > PluginConstants.WebAuthn.MAX_CREDENTIAL_NAME_LENGTH) {
      return WebAuthnHttpUtil
        .jsonError(UIConstants.HttpStatus.BAD_REQUEST, ERROR_NAME_TOO_LONG);
    }

    try {
      WebAuthnCredential credential =
        webAuthnService().finishRegistration(
          req.getSession(true), targetUser, responseNode.toString(), name
        );
      log.info(
        String.format(
          "Registered a WebAuthn credential for user: %s", targetUser.getId()
        )
      );
      Map<String, String> payload = new LinkedHashMap<>();
      payload.put("credentialId", credential.getCredentialId());
      payload.put("name", credential.getName());
      return WebAuthnHttpUtil.json(payload);
    } catch (MFAException e) {
      // Admin-facing message stays in the log; the browser gets a code.
      log.warning(
        "WebAuthn registration refused for user "
          + targetUser.getId() + ": "
          + e.getMessage()
      );
      return WebAuthnHttpUtil.jsonError(
        UIConstants.HttpStatus.BAD_REQUEST,
        property.isAtWebAuthnLimit()
          ? ERROR_CREDENTIAL_LIMIT
          : ERROR_REGISTRATION_FAILED
      );
    }
  }

  /**
   * Starts a WebAuthn registration (self-service, MFA-verified session only)
   * and returns the {@code navigator.credentials.create()} options as JSON.
   */
  @RequirePOST
  @WebMethod(name = "webauthn-register-start")
  public HttpResponse doWebauthnRegisterStart() {
    MFAUserProperty property = requireWebAuthnManagement(true);
    if (property.isAtWebAuthnLimit()) {
      return WebAuthnHttpUtil
        .jsonError(UIConstants.HttpStatus.BAD_REQUEST, ERROR_CREDENTIAL_LIMIT);
    }

    var req = Stapler.getCurrentRequest2();
    try {
      return WebAuthnHttpUtil.json(
        webAuthnService().startRegistration(req.getSession(true), targetUser)
      );
    } catch (MFAException e) {
      log.warning(
        "Could not start WebAuthn registration for user "
          + targetUser.getId() + ": " + e.getMessage()
      );
      return HttpResponses.forbidden();
    }
  }

  /** Removes a WebAuthn credential; admins may act on other users. */
  @RequirePOST
  @WebMethod(name = "webauthn-remove")
  public HttpResponse doWebauthnRemove() {
    MFAUserProperty property = requireWebAuthnManagement(false);

    var req = Stapler.getCurrentRequest2();
    String credentialId =
      req.getParameter(PluginConstants.FormParameters.CREDENTIAL_ID);
    boolean removed =
      credentialId != null
        && !credentialId.isBlank()
        && property.removeWebAuthnCredential(credentialId);

    if (!removed) {
      return redirectToSetupPage(req, "error=key_not_found");
    }
    log.info(
      String.format(
        "Removed a WebAuthn credential from user: %s", targetUser.getId()
      )
    );
    return redirectToSetupPage(req, "success=key_removed");
  }

  /**
   * Generates a QR code for the given secret.
   */
  public String generateQRCode(String username, String encryptedSecret) {
    try {
      Secret secret = Secret.fromString(encryptedSecret);
      String issuer = MFAGlobalConfiguration.get().getIssuer();

      TOTPService totpService = MFAContext.i().getService(TOTPService.class);
      String uri = totpService.getProvisioningUri(username, secret, issuer);

      QRCodeWriter qrCodeWriter = new QRCodeWriter();
      BitMatrix bitMatrix =
        qrCodeWriter.encode(
          uri,
          BarcodeFormat.QR_CODE,
          UIConstants.QRCode.WIDTH,
          UIConstants.QRCode.HEIGHT
        );

      BufferedImage image = MatrixToImageWriter.toBufferedImage(bitMatrix);

      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      javax.imageio.ImageIO.write(image, UIConstants.QRCode.IMAGE_FORMAT, baos);
      byte[] imageBytes = baos.toByteArray();

      return UIConstants.QRCode.DATA_URI_PREFIX
        + Base64.getEncoder().encodeToString(imageBytes);
    } catch (WriterException | IOException e) {
      log.log(Level.SEVERE, "Error generating QR code", e);
      return null;
    }
  }

  /**
   * Generates a new secret for the current user.
   * Returns the Secret object for secure handling.
   */
  public String generateSecret() {
    TOTPService totpService = MFAContext.i().getService(TOTPService.class);
    return totpService.generateSecret().getEncryptedValue();
  }

  /**
   * Get the placeholder for verification code input (for Jelly views).
   */
  public String getCodePlaceholder() {
    StringBuilder placeholder = new StringBuilder();
    for (int i = 0; i < TOTPConstants.TOTP_CODE_DIGITS; i++) {
      placeholder.append("0");
    }
    return placeholder.toString();
  }

  /**
   * Gets the user this setup page targets.
   */
  public User getCurrentUser() {
    return getTargetUser();
  }

  /**
   * Get the form parameter name for verification code (for Jelly views).
   */
  public String getFormParamCode() {
    return PluginConstants.FormParameters.CODE;
  }

  /**
   * Get the form parameter name for a credential id (for Jelly views).
   */
  public String getFormParamCredentialId() {
    return PluginConstants.FormParameters.CREDENTIAL_ID;
  }

  /**
   * Get the form parameter name for secret (for Jelly views).
   */
  public String getFormParamSecret() {
    return PluginConstants.FormParameters.SECRET;
  }

  /**
   * Path of the MFA challenge page, for the "verify MFA first" notice.
   */
  @NonNull
  public String getLoginPath() {
    var req = Stapler.getCurrentRequest2();
    String contextPath = req != null ? req.getContextPath() : "";
    return contextPath + "/" + PluginConstants.Urls.LOGIN_ACTION_URL;
  }

  /**
   * Gets the MFA property for the current user.
   */
  public MFAUserProperty getMFAProperty() throws IOException {
    requireCanConfigureTargetUser();
    if (targetUser == null) {
      return null;
    }
    return MFAUserProperty.getOrCreate(targetUser);
  }

  /**
   * The most security keys this user may register (for Jelly views).
   */
  public int getMaxWebAuthnCredentials() {
    return PluginConstants.WebAuthn.MAX_CREDENTIALS_PER_USER;
  }

  /** The user whose page this action is mounted under. */
  public User getTargetUser() {
    return targetUser;
  }

  /**
   * Get the TOTP code digit count (for Jelly views).
   */
  public int getTotpCodeDigits() {
    return TOTPConstants.TOTP_CODE_DIGITS;
  }

  @Override
  public String getUrlName() {
    return PluginConstants.Urls.SETUP_ACTION_URL;
  }

  /** The target user's security keys; empty if the caller lacks access. */
  @NonNull
  public List<WebAuthnCredential> getWebAuthnCredentials() {
    if (!canConfigureTargetUser()) {
      return List.of();
    }
    MFAUserProperty property = MFAUserProperty.forUser(targetUser);
    return property == null ? List.of() : property.getWebAuthnCredentials();
  }

  /**
   * Longest accepted security key name (for Jelly views).
   */
  public int getWebAuthnNameMaxLength() {
    return PluginConstants.WebAuthn.MAX_CREDENTIAL_NAME_LENGTH;
  }

  /**
   * Absolute (context-path rooted) URL of the register-finish endpoint.
   */
  @NonNull
  public String getWebAuthnRegisterFinishUrl() {
    return setupUrl() + "/webauthn-register-finish";
  }

  /**
   * Absolute (context-path rooted) URL of the register-start endpoint.
   */
  @NonNull
  public String getWebAuthnRegisterStartUrl() {
    return setupUrl() + "/webauthn-register-start";
  }

  /**
   * Absolute URL of the remove endpoint (page is reachable with and without a
   * trailing slash).
   */
  @NonNull
  public String getWebAuthnRemoveUrl() {
    return setupUrl() + "/webauthn-remove";
  }

  /** Whether the page is viewed by its owner (registration is owner-only). */
  public boolean isSelfService() {
    User current = User.current();
    return targetUser != null
      && current != null
      && current.getId() != null
      && current.getId().equals(targetUser.getId());
  }

  /**
   * Whether the session passed MFA; not implied by reaching this page, which
   * is on the MFA filter allow-list.
   */
  public boolean isSessionMFAVerified() {
    var req = Stapler.getCurrentRequest2();
    if (req == null) {
      return false;
    }
    return MFAContext.i()
      .getService(SessionService.class)
      .isVerifiedSession(req.getSession(false));
  }

  /** Whether WebAuthn is enabled and a relying-party id resolves. */
  public boolean isWebAuthnAvailable() {
    return webAuthnService().isAvailable();
  }

  /** Whether the target user is at the security key limit. */
  public boolean isWebAuthnLimitReached() {
    if (!canConfigureTargetUser()) {
      return false;
    }
    MFAUserProperty property = MFAUserProperty.forUser(targetUser);
    return property != null && property.isAtWebAuthnLimit();
  }

  private boolean canConfigureTargetUser() {
    return isSelfService() || (targetUser != null && isAdmin());
  }

  /**
   * Absolute redirect to the setup page with a status query, so the browser
   * never lands on the POST-only endpoint.
   */
  private HttpResponse redirectToSetupPage(StaplerRequest2 req, String query) {
    return HttpResponses.redirectTo(
      SecurityUtil.buildSetupURI(req.getContextPath(), targetUser.getId())
        + "?" + query
    );
  }

  private void requireCanConfigureTargetUser() throws HttpResponseException {
    if (!canConfigureTargetUser()) {
      throw HttpResponses.forbidden();
    }
  }

  /**
   * Gate for every security-key endpoint: self-or-admin; self-only when
   * {@code selfOnly} (admins must not enrol their own key on another account);
   * an MFA-verified session (the page is allow-listed, so a stolen password
   * alone must not be able to register a key); active TOTP (the enrollment
   * anchor); and the feature available.
   *
   * @throws HttpResponseException
   *           403 if any gate fails
   */
  @NonNull
  private MFAUserProperty requireWebAuthnManagement(boolean selfOnly) {
    requireCanConfigureTargetUser();
    if (selfOnly && !isSelfService()) {
      log.warning(
        "Refusing WebAuthn registration for '"
          + targetUser.getId()
          + "' requested by another user: registration is self-service only"
      );
      throw HttpResponses.forbidden();
    }
    if (!isSessionMFAVerified()) {
      log.warning(
        "Refusing security key management for '"
          + targetUser.getId()
          + "': the session has not passed MFA verification"
      );
      throw HttpResponses.forbidden();
    }
    MFAUserProperty property = MFAUserProperty.forUser(targetUser);
    if (property == null || !property.isEnabled()) {
      throw HttpResponses.forbidden();
    }
    if (!webAuthnService().isAvailable()) {
      throw HttpResponses.forbidden();
    }
    return property;
  }

  /** This page's URL, rooted at the context path. */
  @NonNull
  private String setupUrl() {
    var req = Stapler.getCurrentRequest2();
    return SecurityUtil.buildSetupURI(
      req != null ? req.getContextPath() : "",
      targetUser != null ? targetUser.getId() : ""
    );
  }

  /** Looked up per call so services stubbed after startup are seen. */
  private WebAuthnService webAuthnService() {
    return MFAContext.i().getService(WebAuthnService.class);
  }
}
