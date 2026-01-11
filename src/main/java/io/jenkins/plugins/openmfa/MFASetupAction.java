package io.jenkins.plugins.openmfa;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import hudson.Extension;
import hudson.model.User;
import hudson.util.Secret;
import io.jenkins.plugins.openmfa.base.MFAContext;
import io.jenkins.plugins.openmfa.constant.PluginConstants;
import io.jenkins.plugins.openmfa.constant.TOTPConstants;
import io.jenkins.plugins.openmfa.constant.UIConstants;
import io.jenkins.plugins.openmfa.service.TOTPService;
import jenkins.model.Jenkins;
import lombok.extern.java.Log;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.HttpResponses;
import org.kohsuke.stapler.Stapler;
import org.kohsuke.stapler.interceptor.RequirePOST;

import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Base64;
import java.util.logging.Level;

/**
 * Action that provides MFA setup interface for users.
 */
@Log
@Extension
public class MFASetupAction implements hudson.model.Action {

  @Override
  public String getIconFileName() {
    return UIConstants.Icons.SECURE;
  }

  @Override
  public String getDisplayName() {
    return UIConstants.DisplayNames.CONFIGURE_MFA;
  }

  @Override
  public String getUrlName() {
    return PluginConstants.Urls.SETUP_ACTION_URL;
  }

  /**
   * Gets the current user.
   */
  public User getCurrentUser() {
    return User.current();
  }

  /**
   * Gets the MFA property for the current user.
   */
  public MFAUserProperty getMFAProperty() throws IOException {
    User user = getCurrentUser();
    if (user == null) {
      return null;
    }
    return MFAUserProperty.getOrCreate(user);
  }

  /**
   * Generates a new secret for the current user.
   */
  public String generateSecret() {
    TOTPService totpService = MFAContext.i().getService(TOTPService.class);
    return totpService.generateSecret();
  }

  /**
   * Generates a QR code for the given secret.
   */
  public String generateQRCode(String username, String secret) {
    try {
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
          uri, BarcodeFormat.QR_CODE, UIConstants.QRCode.WIDTH,
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
   * Enables MFA for the current user.
   */
  @RequirePOST
  public HttpResponse doEnable() throws IOException {
    User user = getCurrentUser();
    if (user == null) {
      return HttpResponses.forbidden();
    }

    var req = Stapler.getCurrentRequest2();
    String secret = req.getParameter(PluginConstants.FormParameters.SECRET);
    String code = req.getParameter(PluginConstants.FormParameters.CODE);

    // Verify the code before enabling
    TOTPService totpService = MFAContext.i().getService(TOTPService.class);
    if (!totpService.verifyCode(secret, code)) {
      return HttpResponses
        .error(UIConstants.HttpStatus.BAD_REQUEST, "Invalid verification code");
    }

    MFAUserProperty property = MFAUserProperty.getOrCreate(user);
    property.setSecret(Secret.fromString(secret));
    property.setEnabled(true);
    user.save();

    log.info(String.format("MFA enabled for user: %s", user.getId()));

    return HttpResponses.redirectToDot();
  }

  /**
   * Disables MFA for the current user.
   */
  @RequirePOST
  public HttpResponse doDisable() throws IOException {
    User user = getCurrentUser();
    if (user == null) {
      return HttpResponses.forbidden();
    }

    MFAUserProperty property = MFAUserProperty.forUser(user);
    if (property != null) {
      property.setEnabled(false);
      user.save();
      log.info(String.format("MFA disabled for user: %s", user.getId()));
    }

    return HttpResponses.redirectToDot();
  }

  /**
   * Resets MFA for the current user (generates new secret).
   */
  @RequirePOST
  public HttpResponse doReset() throws IOException {
    User user = getCurrentUser();
    if (user == null) {
      return HttpResponses.forbidden();
    }

    MFAUserProperty property = MFAUserProperty.getOrCreate(user);
    property.setSecret(null);
    property.setEnabled(false);
    user.save();

    log.info(String.format("MFA reset for user: %s", user.getId()));

    return HttpResponses.redirectToDot();
  }

  /**
   * Get the form parameter name for secret (for Jelly views).
   */
  public String getFormParamSecret() {
    return PluginConstants.FormParameters.SECRET;
  }

  /**
   * Get the form parameter name for verification code (for Jelly views).
   */
  public String getFormParamCode() {
    return PluginConstants.FormParameters.CODE;
  }

  /**
   * Get the TOTP code digit count (for Jelly views).
   */
  public int getTotpCodeDigits() {
    return TOTPConstants.TOTP_CODE_DIGITS;
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
}
