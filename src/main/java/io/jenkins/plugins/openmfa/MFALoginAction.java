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
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpSession;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import lombok.extern.java.Log;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.HttpResponses;
import org.kohsuke.stapler.Stapler;
import org.kohsuke.stapler.StaplerRequest2;
import org.kohsuke.stapler.StaplerResponse2;
import org.kohsuke.stapler.WebMethod;
import org.kohsuke.stapler.interceptor.RequirePOST;

/**
 * Action that provides the MFA login page where users enter their TOTP code.
 */
@Log
@Extension
public class MFALoginAction extends InvisibleAction implements RootAction {

  /**
   * Upper bound on the size of a WebAuthn assertion response body read by
   * {@link #doWebauthnVerify()}. A body past this size is treated as
   * invalid input rather than being buffered in full.
   */
  private static final int MAX_WEBAUTHN_RESPONSE_BYTES = 64 * 1024;

  /**
   * Builds the standard MFA-login error redirect: back to the login page
   * with {@code ?error=<error>}, preserving the {@code from} parameter if
   * present.
   */
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

  /**
   * Wraps a pre-rendered JSON string as an {@code application/json}
   * response, used to hand WebAuthn ceremony options to the browser.
   */
  private static HttpResponse jsonResponse(String json) {
    return new HttpResponse() {

      @Override
      public void generateResponse(
        StaplerRequest2 req, StaplerResponse2 rsp, Object node)
        throws IOException, ServletException {
        rsp.setContentType("application/json;charset=UTF-8");
        PrintWriter writer = rsp.getWriter();
        writer.print(json);
        writer.flush();
      }
    };
  }

  /**
   * Reads the request body as the WebAuthn assertion response JSON,
   * enforcing {@link #MAX_WEBAUTHN_RESPONSE_BYTES}. Returns {@code null}
   * (never throws) if the body is unreadable or exceeds the cap, so an
   * oversized or broken body is handled as ordinary invalid input rather
   * than a server error.
   */
  private static String readWebauthnResponseBody(StaplerRequest2 req) {
    try (ServletInputStream in = req.getInputStream()) {
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      byte[] buffer = new byte[8192];
      int total = 0;
      int read;
      while ((read = in.read(buffer)) != -1) {
        total += read;
        if (total > MAX_WEBAUTHN_RESPONSE_BYTES) {
          log.warning("Rejecting oversized WebAuthn assertion response body");
          return null;
        }
        out.write(buffer, 0, read);
      }
      return out.toString(StandardCharsets.UTF_8);
    } catch (IOException e) {
      log.warning(
        "Failed to read WebAuthn assertion response body: " + e.getMessage()
      );
      return null;
    }
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
      return HttpResponses
        .redirectViaContextPath(buildErrorRedirectUrl("locked", fromParam));
    }

    // Verify the TOTP code
    if (!mfaProperty.verifyCode(totpCode)) {
      // Record failed attempt for rate limiting
      rateLimitService.recordFailedAttempt(username);
      log.warning(String.format("Invalid MFA code for user: %s", username));

      return HttpResponses.redirectViaContextPath(
        buildErrorRedirectUrl(
          rateLimitService.isLockedOut(username) ? "locked" : "invalid", fromParam
        )
      );
    } else {
      return completeVerifiedLogin(
        req, mfaProperty, username, PluginConstants.MFAMethods.TOTP, fromParam
      );
    }
  }

  /**
   * Starts a WebAuthn authentication ceremony for the current user and
   * returns the {@code navigator.credentials.get()} options as JSON.
   *
   * <p>
   * Forbidden when there is no pending MFA authentication, WebAuthn is
   * unavailable (disabled, or no relying-party id resolves), or the user has
   * no registered credential to challenge.
   */
  @RequirePOST
  @SuppressWarnings("lgtm[jenkins/no-permission-check]")
  @WebMethod(name = "webauthn-challenge")
  public HttpResponse doWebauthnChallenge() {
    User user = User.current();
    if (user == null) {
      return HttpResponses.forbidden();
    }

    MFAUserProperty mfaProperty = MFAUserProperty.forUser(user);
    if (mfaProperty == null || !mfaProperty.hasWebAuthn()) {
      return HttpResponses.forbidden();
    }

    // Looked up per call rather than cached in a field: tests stub this
    // service via MFAContext.i().registerService(...) after this extension
    // singleton already exists, so a cached field would never see the stub.
    WebAuthnService webAuthnService =
      MFAContext.i().getService(WebAuthnService.class);
    if (!webAuthnService.isAvailable()) {
      return HttpResponses.forbidden();
    }

    var req = Stapler.getCurrentRequest2();
    try {
      String optionsJson = webAuthnService.startAssertion(req.getSession(true), user);
      return jsonResponse(optionsJson);
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
   * Completes a WebAuthn authentication ceremony via POST, the body being
   * the browser's {@code navigator.credentials.get()} response as JSON.
   *
   * <p>
   * Mirrors {@link #doVerify()}: lockout is honored before the response is
   * even read, a failed assertion counts toward the same rate limit, and a
   * successful one verifies the session, records {@code "webauthn"} as the
   * last used method, optionally issues the remember-MFA cookie, and
   * redirects via {@code from}.
   */
  @RequirePOST
  @SuppressWarnings("lgtm[jenkins/no-permission-check]")
  @WebMethod(name = "webauthn-verify")
  public HttpResponse doWebauthnVerify() {
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

    String responseJson = readWebauthnResponseBody(req);
    // Looked up per call rather than cached in a field: tests stub this
    // service via MFAContext.i().registerService(...) after this extension
    // singleton already exists, so a cached field would never see the stub.
    WebAuthnService webAuthnService =
      MFAContext.i().getService(WebAuthnService.class);
    boolean success =
      responseJson != null
        && webAuthnService.finishAssertion(req.getSession(true), user, responseJson);

    if (!success) {
      // Record failed attempt for rate limiting
      rateLimitService.recordFailedAttempt(username);
      log.warning(String.format("Invalid WebAuthn assertion for user: %s", username));

      return HttpResponses.redirectViaContextPath(
        buildErrorRedirectUrl(
          rateLimitService.isLockedOut(username) ? "locked" : "invalid", fromParam
        )
      );
    } else {
      return completeVerifiedLogin(
        req, mfaProperty, username, PluginConstants.MFAMethods.WEBAUTHN, fromParam
      );
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

  /**
   * Returns the MFA method the challenge page should present by default:
   * the method last used, if it is still usable for this user, otherwise
   * {@code "totp"}.
   */
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

  /**
   * Returns whether WebAuthn can be offered to the current user on the
   * challenge page: the feature is enabled globally and the user has at
   * least one registered credential.
   */
  public boolean isWebAuthnAvailableForUser() {
    User user = User.current();
    MFAUserProperty mfaProperty = MFAUserProperty.forUser(user);
    if (mfaProperty == null || !mfaProperty.hasWebAuthn()) {
      return false;
    }
    // Looked up per call rather than cached in a field: tests stub this
    // service via MFAContext.i().registerService(...) after this extension
    // singleton already exists, so a cached field would never see the stub.
    return MFAContext.i().getService(WebAuthnService.class).isAvailable();
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

  /**
   * Finishes a successful MFA challenge, shared by {@link #doVerify()} and
   * {@link #doWebauthnVerify()}: clears the rate limit, marks the session
   * verified, records which method satisfied the challenge, optionally
   * issues the remember-MFA cookie, and redirects to the originally
   * requested page (or root if there wasn't one / it isn't safe).
   *
   * @param method
   *          {@code "totp"} or {@code "webauthn"}
   */
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

}
