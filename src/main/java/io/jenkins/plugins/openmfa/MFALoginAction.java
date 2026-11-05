package io.jenkins.plugins.openmfa;

import hudson.Extension;
import hudson.model.InvisibleAction;
import hudson.model.RootAction;
import hudson.model.User;
import io.jenkins.plugins.openmfa.base.MFAContext;
import io.jenkins.plugins.openmfa.base.MFAException;
import io.jenkins.plugins.openmfa.constant.PluginConstants;
import io.jenkins.plugins.openmfa.service.RateLimitService;
import io.jenkins.plugins.openmfa.service.RememberMFAService;
import io.jenkins.plugins.openmfa.service.SessionService;
import io.jenkins.plugins.openmfa.service.WebAuthnService;
import io.jenkins.plugins.openmfa.util.JenkinsUtil;
import io.jenkins.plugins.openmfa.util.SecurityUtil;
import io.jenkins.plugins.openmfa.util.TOTPUtil;
import io.jenkins.plugins.openmfa.util.WebAuthnHttpUtil;
import jakarta.servlet.http.HttpSession;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import lombok.extern.java.Log;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.HttpResponses;
import org.kohsuke.stapler.Stapler;
import org.kohsuke.stapler.StaplerRequest2;
import org.kohsuke.stapler.WebMethod;
import org.kohsuke.stapler.interceptor.RequirePOST;

/**
 * Action that provides the MFA login page where users enter their TOTP code.
 */
@Log
@Extension
public class MFALoginAction extends InvisibleAction implements RootAction {

  /** Login-page error redirect, preserving {@code from} if present. */
  private static String buildErrorRedirectUrl(String error, String fromParam) {
    return "/"
      + PluginConstants.Urls.LOGIN_ACTION_URL
      + "?error="
      + error
      + (fromParam != null && !fromParam.isEmpty()
        ? "&"
          + PluginConstants.FROM_PARAM
          + "="
          + URLEncoder.encode(fromParam, StandardCharsets.UTF_8)
        : "");
  }

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

  private final RememberMFAService rememberMFAService =
    MFAContext.i().getService(RememberMFAService.class);

  private final SessionService sessionService =
    MFAContext.i().getService(SessionService.class);

  /**
   * Handles TOTP code verification via POST.
   */
  @RequirePOST
  @SuppressWarnings("lgtm[jenkins/no-permission-check]")
  public HttpResponse doVerify() {
    return verifyChallenge(
      PluginConstants.MFAMethods.TOTP,
      (req, user, mfaProperty) -> mfaProperty
        .verifyCode(req.getParameter(PluginConstants.FormParameters.TOTP_CODE))
    );
  }

  /**
   * Starts a WebAuthn assertion and returns the
   * {@code navigator.credentials.get()} options as JSON.
   */
  @RequirePOST
  @SuppressWarnings("lgtm[jenkins/no-permission-check]")
  @WebMethod(name = "webauthn-challenge")
  public HttpResponse doWebauthnChallenge() {
    // Same gate as the challenge page.
    if (!isWebAuthnAvailableForUser()) {
      return HttpResponses.forbidden();
    }
    User user = User.current();
    if (user == null) {
      // Unreachable; keeps the dereferences below provably non-null.
      return HttpResponses.forbidden();
    }

    var req = Stapler.getCurrentRequest2();
    try {
      String optionsJson =
        webAuthnService().startAssertion(req.getSession(true), user);
      return WebAuthnHttpUtil.json(optionsJson);
    } catch (MFAException e) {
      log.warning(
        "Could not start WebAuthn assertion for user "
          + user.getId() + ": "
          + e.getMessage()
      );
      return HttpResponses.forbidden();
    }
  }

  /**
   * Completes a WebAuthn assertion; same lockout, rate limit and success
   * handling as {@link #doVerify()}.
   */
  @RequirePOST
  @SuppressWarnings("lgtm[jenkins/no-permission-check]")
  @WebMethod(name = "webauthn-verify")
  public HttpResponse doWebauthnVerify() {
    return verifyChallenge(
      PluginConstants.MFAMethods.WEBAUTHN,
      (req, user, mfaProperty) -> {
        String responseJson = WebAuthnHttpUtil.readCeremonyBody(req);
        return responseJson != null
          && webAuthnService()
            .finishAssertion(req.getSession(true), user, responseJson);
      }
    );
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

  /** Default challenge method: the last used one if still usable, else TOTP. */
  public String getPreferredMethod() {
    User user = User.current();
    MFAUserProperty mfaProperty = MFAUserProperty.forUser(user);
    String lastUsedMethod =
      mfaProperty != null ? mfaProperty.getLastUsedMethod() : null;
    if (
      PluginConstants.MFAMethods.WEBAUTHN.equals(lastUsedMethod)
        && isWebAuthnAvailableForUser()
    ) {
      return PluginConstants.MFAMethods.WEBAUTHN;
    }
    return PluginConstants.MFAMethods.TOTP;
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

  /** Whether WebAuthn is enabled and the current user has a credential. */
  public boolean isWebAuthnAvailableForUser() {
    User user = User.current();
    MFAUserProperty mfaProperty = MFAUserProperty.forUser(user);
    if (mfaProperty == null || !mfaProperty.hasWebAuthn()) {
      return false;
    }
    return webAuthnService().isAvailable();
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

  /** Success path shared by both challenge endpoints. */
  private HttpResponse completeVerifiedLogin(
    StaplerRequest2 req, MFAUserProperty mfaProperty, String username,
    String method, String fromParam) {
    log.info(
      String.format("MFA verification successful for user: %s (%s)", username, method)
    );
    // Clear any failed attempts on success
    rateLimitService.clearFailedAttempts(username);
    // Mark MFA as verified in the new session
    sessionService.verifySession(req);
    // Record which MFA method was used most recently
    mfaProperty.setLastUsedMethodAndSave(method);

    // Remember this verification if the user chose "Keep me signed in"
    if (rememberMFAService.isEnabled() && rememberMFAService.shouldRemember(req)) {
      rememberMFAService.issueCookie(
        req,
        Stapler.getCurrentResponse2(),
        username,
        mfaProperty.getOrCreateMfaEpoch()
      );
    }

    // Redirect to original requested page, or root if none
    if (
      fromParam != null && !fromParam.isEmpty() && isSafeRedirectTarget(fromParam)
    ) {
      return HttpResponses.redirectViaContextPath(fromParam);
    }
    return HttpResponses.redirectViaContextPath("/");
  }

  /**
   * Shared challenge flow: lockout is checked before the proof is read and
   * failures count toward the rate limit; {@code verifier} checks the proof.
   */
  private HttpResponse verifyChallenge(String method, ChallengeVerifier verifier) {
    User user = User.current();
    if (user == null) {
      return HttpResponses.forbidden();
    }

    var req = Stapler.getCurrentRequest2();
    String fromParam = req.getParameter(PluginConstants.FROM_PARAM);

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
      return HttpResponses
        .redirectViaContextPath(buildErrorRedirectUrl("locked", fromParam));
    }

    if (!verifier.verify(req, user, mfaProperty)) {
      // Record failed attempt for rate limiting
      rateLimitService.recordFailedAttempt(username);
      log.warning(
        String.format("Invalid MFA proof (%s) for user: %s", method, username)
      );

      return HttpResponses.redirectViaContextPath(
        buildErrorRedirectUrl(
          rateLimitService.isLockedOut(username) ? "locked" : "invalid", fromParam
        )
      );
    }
    return completeVerifiedLogin(req, mfaProperty, username, method, fromParam);
  }

  /** Looked up per call so services stubbed after startup are seen. */
  private WebAuthnService webAuthnService() {
    return MFAContext.i().getService(WebAuthnService.class);
  }

  /** Checks the method-specific proof in the request. */
  @FunctionalInterface
  private interface ChallengeVerifier {

    boolean verify(StaplerRequest2 req, User user, MFAUserProperty property);
  }
}
