package io.jenkins.plugins.openmfa;

import static io.jenkins.plugins.openmfa.util.JenkinsUtil.isAdmin;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import hudson.model.Action;
import hudson.model.User;
import hudson.util.Secret;
import io.jenkins.plugins.openmfa.base.MFAContext;
import io.jenkins.plugins.openmfa.constant.PluginConstants;
import io.jenkins.plugins.openmfa.constant.TOTPConstants;
import io.jenkins.plugins.openmfa.constant.UIConstants;
import io.jenkins.plugins.openmfa.service.SessionService;
import io.jenkins.plugins.openmfa.service.TOTPService;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Base64;
import java.util.logging.Level;
import jenkins.model.Jenkins;
import lombok.extern.java.Log;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.HttpResponses;
import org.kohsuke.stapler.HttpResponses.HttpResponseException;
import org.kohsuke.stapler.Stapler;
import org.kohsuke.stapler.interceptor.RequirePOST;

/**
 * Action that provides MFA setup interface for users.
 */
@Log
public class MFASetupAction implements Action {

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
      property.setSecret(null);
      targetUser.save();
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

    MFAUserProperty property = MFAUserProperty.getOrCreate(targetUser);
    property.setSecret(secret);
    targetUser.save();

    log.info(String.format("MFA enabled for user: %s", targetUser.getId()));

    // Mark the user doesn't need to re-verify
    MFAContext.i()
      .getService(SessionService.class)
      .verifySession(req);

    return HttpResponses.redirectTo("?success=enabled");
  }

  /**
   * Generates a QR code for the given secret.
   */
  public String generateQRCode(String username, String encryptedSecret) {
    try {
      Secret secret = Secret.fromString(encryptedSecret);

      String issuer = UIConstants.Defaults.DEFAULT_ISSUER;
      Jenkins jenkins = Jenkins.get();
      if (jenkins.getSecurityRealm() instanceof MFASecurityRealm) {
        MFASecurityRealm realm = (MFASecurityRealm) jenkins.getSecurityRealm();
        issuer = realm.getIssuer();
      }

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

  @Override
  public String getDisplayName() {
    return UIConstants.DisplayNames.CONFIGURE_MFA;
  }

  /**
   * Get the form parameter name for verification code (for Jelly views).
   */
  public String getFormParamCode() {
    return PluginConstants.FormParameters.CODE;
  }

  /**
   * Get the form parameter name for secret (for Jelly views).
   */
  public String getFormParamSecret() {
    return PluginConstants.FormParameters.SECRET;
  }

  @Override
  public String getIconFileName() {
    return null;
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
   * The user whose page this action is mounted under (e.g.
   * /user/<id>/mfa-setup).
   */
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

  private boolean canConfigureTargetUser() {
    if (targetUser == null) {
      return false;
    }
    User current = User.current();
    if (
      current != null
        && current.getId() != null
        && current.getId().equals(targetUser.getId())
    ) {
      return true;
    }
    return isAdmin();
  }

  private void requireCanConfigureTargetUser() throws HttpResponseException {
    if (!canConfigureTargetUser()) {
      throw HttpResponses.forbidden();
    }
  }
}
