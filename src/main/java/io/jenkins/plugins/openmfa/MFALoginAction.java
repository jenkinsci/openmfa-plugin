package io.jenkins.plugins.openmfa;

import hudson.Extension;
import hudson.model.InvisibleAction;
import hudson.model.RootAction;
import hudson.model.User;
import io.jenkins.plugins.openmfa.base.MFAContext;
import io.jenkins.plugins.openmfa.constant.PluginConstants;
import io.jenkins.plugins.openmfa.service.RateLimitService;
import io.jenkins.plugins.openmfa.service.SessionService;
import io.jenkins.plugins.openmfa.util.JenkinsUtil;
import io.jenkins.plugins.openmfa.util.SecurityUtil;
import io.jenkins.plugins.openmfa.util.TOTPUtil;
import jakarta.servlet.http.HttpSession;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import lombok.extern.java.Log;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.HttpResponses;
import org.kohsuke.stapler.Stapler;
import org.kohsuke.stapler.interceptor.RequirePOST;

/**
 * Action that provides the MFA login page where users enter their TOTP code.
 */
@Log
@Extension
public class MFALoginAction extends InvisibleAction implements RootAction {

  /**
   * Validates that the redirect target is safe (no open redirect).
   * The path must be relative (start with /) and must not be a full URL.
   */
  private static boolean isSafeRedirectTarget(String target) {
    if (target == null || target.isEmpty()) {
      return false;
    }
    // Must start with / and not //
    if (!target.startsWith("/") || target.startsWith("//")) {
      return false;
    }
    // Must not contain protocol (open redirect). Allow query params like ?foo:bar,
    // but reject protocol-like prefixes in the path.
    String beforeQuery = target.split("\\?", 2)[0];
    if (beforeQuery.contains(":")) {
      return false;
    }
    return true;
  }

  private final RateLimitService rateLimitService =
    MFAContext.i().getService(RateLimitService.class);

  private final SessionService sessionService =
    MFAContext.i().getService(SessionService.class);

  /**
   * Handles TOTP code verification via POST.
   */
  @RequirePOST
  @SuppressWarnings("lgtm[jenkins/no-permission-check]")
  public HttpResponse doVerify() {
    User user = User.current();
    if (user == null) {
      return HttpResponses.forbidden();
    }

    var req = Stapler.getCurrentRequest2();
    String totpCode = req.getParameter(PluginConstants.FormParameters.TOTP_CODE);
    String fromParam = req.getParameter(PluginConstants.FROM_PARAM);

    // Check if user is not null
    MFAUserProperty mfaProperty = MFAUserProperty.forUser(user);
    if (mfaProperty == null) {
      log.warning(
        String.format(
          "MFA property not found for user: %s",
          user.getId()
        )
      );
      return HttpResponses.forbidden();
    }

    String username = mfaProperty.getUser().getId();

    // Check if user is locked out due to too many failed attempts
    if (rateLimitService.isLockedOut(username)) {
      long remainingSeconds = rateLimitService.getRemainingLockoutSeconds(username);
      log.warning(
        String.format(
          "User %s is locked out, %d seconds remaining", username, remainingSeconds
        )
      );
      String mfaLoginUrl =
        "/"
          + PluginConstants.Urls.LOGIN_ACTION_URL
          + "?error=locked"
          + (fromParam != null && !fromParam.isEmpty()
            ? "&"
              + PluginConstants.FROM_PARAM
              + "="
              + URLEncoder.encode(fromParam, StandardCharsets.UTF_8)
            : "");
      return HttpResponses.redirectViaContextPath(mfaLoginUrl);
    }

    // Verify the TOTP code
    if (!mfaProperty.verifyCode(totpCode)) {
      // Record failed attempt for rate limiting
      rateLimitService.recordFailedAttempt(username);
      log.warning(String.format("Invalid MFA code for user: %s", username));

      String redirectUrl =
        "/"
          + PluginConstants.Urls.LOGIN_ACTION_URL
          + "?error="
          + (rateLimitService.isLockedOut(username) ? "locked" : "invalid")
          + (fromParam != null && !fromParam.isEmpty()
            ? "&"
              + PluginConstants.FROM_PARAM
              + "="
              + URLEncoder.encode(fromParam, StandardCharsets.UTF_8)
            : "");
      return HttpResponses.redirectViaContextPath(redirectUrl);
    } else {
      log.info(String.format("MFA verification successful for user: %s", username));
      // Clear any failed attempts on success
      rateLimitService.clearFailedAttempts(username);
      // Mark MFA as verified in the new session
      sessionService.verifySession(req);

      // Redirect to original requested page, or root if none
      String from = req.getParameter(PluginConstants.FROM_PARAM);
      if (from != null && !from.isEmpty() && isSafeRedirectTarget(from)) {
        return HttpResponses.redirectViaContextPath(from);
      }
      return HttpResponses.redirectViaContextPath("/");
    }
  }

  /**
   * Get the form parameter name for TOTP code (for Jelly views).
   */
  public String getFormParamTotpCode() {
    return PluginConstants.FormParameters.TOTP_CODE;
  }

  /**
   * Returns the post-MFA redirect target from the current request.
   * Used to preserve the originally requested URL when the form is submitted.
   */
  public String getFromParam() {
    var req = Stapler.getCurrentRequest2();
    if (req == null) {
      return null;
    }
    return req.getParameter(PluginConstants.FROM_PARAM);
  }

  /**
   * Returns the current user's MFA setup path.
   */
  public String getMFASetupPath() {
    var req = Stapler.getCurrentRequest2();
    return JenkinsUtil.getCurrentUser()
      .map(User::getId)
      .map(
        userId -> SecurityUtil
          .buildSetupURI(req != null ? req.getContextPath() : "", userId)
      )
      .orElse(null);
  }

  /**
   * Gets the username from the current user.
   */
  public String getPendingUsername() {
    return JenkinsUtil.getCurrentUser().map(User::getId).orElse(null);
  }

  public Long getRemainingLockoutSeconds() {
    User user = User.current();
    if (user == null) {
      return 0L;
    }
    return rateLimitService.getRemainingLockoutSeconds(user.getId());
  }

  /**
   * Returns the post-MFA redirect target only if it passes security validation.
   * Use for links (e.g. "already verified" continue button).
   */
  public String getSafeFromParam() {
    String from = getFromParam();
    return (from != null && isSafeRedirectTarget(from)) ? from : null;
  }

  /**
   * Get the security check endpoint (for Jelly views).
   */
  public String getSecurityCheckEndpoint() {
    return PluginConstants.Urls.SECURITY_CHECK_ENDPOINT;
  }

  @Override
  public String getUrlName() {
    return PluginConstants.Urls.LOGIN_ACTION_URL;
  }

  /**
   * Check if there's a pending MFA authentication.
   */
  public boolean hasPendingAuth() {
    return getPendingUsername() != null;
  }

  /**
   * Check if MFA is enabled for the current user.
   *
   * @return true if MFA is enabled, false otherwise
   */
  public boolean isMFAEnabled() {
    return TOTPUtil.isMFAEnabled();
  }

  /**
   * Check if MFA is required for the current user.
   *
   * @return true if MFA is required for the current user, false otherwise
   */
  public boolean isMFARequired() {
    return TOTPUtil.isMFARequired();
  }

  /**
   * Check if the current session has already passed MFA verification.
   *
   * @return true if the current session has already passed MFA verification,
   *         false otherwise
   */
  public boolean isSessionMFAVerified() {
    var req = Stapler.getCurrentRequest2();
    if (req == null) {
      return false;
    }

    HttpSession session = req.getSession(false);
    return session != null
      && MFAContext.i()
        .getService(SessionService.class)
        .isVerifiedSession(session);
  }

  /**
   * Returns true when the user is logged in, MFA is disabled, and MFA is not
   * globally required.
   */
  public boolean shouldShowMFAOptionalNotice() {
    return JenkinsUtil.getCurrentUser().isPresent()
      && !isMFAEnabled()
      && !isMFARequired();
  }

}
