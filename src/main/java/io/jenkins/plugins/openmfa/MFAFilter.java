package io.jenkins.plugins.openmfa;

import hudson.Extension;
import hudson.model.User;
import io.jenkins.plugins.openmfa.base.MFAContext;
import io.jenkins.plugins.openmfa.constant.PluginConstants;
import io.jenkins.plugins.openmfa.service.RateLimitService;
import io.jenkins.plugins.openmfa.service.SessionService;
import io.jenkins.plugins.openmfa.util.JenkinsUtil;
import io.jenkins.plugins.openmfa.util.TOTPUtil;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import lombok.extern.java.Log;

/**
 * Filter that intercepts requests to handle MFA verification after standard
 * authentication.
 * This filter ensures that users who have passed username/password
 * authentication
 * must also complete MFA verification before accessing protected resources.
 */
@Log
@Extension
public class MFAFilter implements Filter {

  /**
   * URLs that should be accessible without MFA verification.
   * These include login pages, MFA-related pages, and public resources.
   */
  @SuppressWarnings("java:S1075") // URIs should not be hardcoded - these are URL
                                  // paths, not file paths
  private static final List<String> ALLOWED_PATHS =
    Arrays.asList(
      "/login",
      "/loginError",
      "/logout",
      "/securityRealm",
      "/adjuncts/",
      "/assets/",
      "/static/",
      "/images/",
      "/css/",
      "/scripts/",
      "/" + PluginConstants.Urls.LOGIN_ACTION_URL,
      "/" + PluginConstants.Urls.SETUP_ACTION_URL,
      PluginConstants.Urls.SECURITY_CHECK_ENDPOINT
    );

  private SessionService sessionService =
    MFAContext.i().getService(SessionService.class);

  @Override
  public void destroy() {
    // No cleanup needed
  }

  @Override
  public void doFilter(
    ServletRequest request, ServletResponse response, FilterChain chain)
    throws IOException, ServletException {

    if (
      !(request instanceof HttpServletRequest)
        || !(response instanceof HttpServletResponse)
    ) {
      chain.doFilter(request, response);
      return;
    }

    HttpServletRequest req = (HttpServletRequest) request;
    HttpServletResponse resp = (HttpServletResponse) response;

    Optional<User> user = JenkinsUtil.getCurrentUser();
    log.fine("Current user: " + user.map(User::getId).orElse("<anonymous>"));

    if (user.isEmpty() || shouldAllowPath(req)) {
      log.fine("Allowing path without MFA check: " + req.getRequestURI());
      chain.doFilter(req, resp);
      return;
    }

    if (sessionService.isVerifiedSession(req.getSession(false))) {
      log.fine("Session already verified, allowing access");
      chain.doFilter(req, resp);
      return;
    }

    // User is authenticated, check if MFA verification is required
    if (!handleMFAVerification(req, resp, user.get())) {
      // MFA verification failed or pending, don't continue the chain
      return;
    }

    // MFA verified or not required, continue with the request
    chain.doFilter(req, resp);
  }

  @Override
  public void init(FilterConfig filterConfig) throws ServletException {
    // No initialization needed
  }

  /**
   * Handles MFA verification for authenticated users.
   *
   * @return true if the request should continue, false if it was
   *         redirected/blocked
   */
  private boolean handleMFAVerification(
    HttpServletRequest req, HttpServletResponse resp, User user)
    throws IOException {

    String username = user.getId();
    MFAUserProperty mfaProperty = MFAUserProperty.forUser(user);
    if (!TOTPUtil.isMFAEnabled()) {
      if (TOTPUtil.isMFARequired()) {
        resp.sendRedirect(
          req.getContextPath()
            + "/user/" + URLEncoder.encode(username, StandardCharsets.UTF_8)
            + "/" + PluginConstants.Urls.SETUP_ACTION_URL
        );
        // MFA is required but not enabled, redirect to MFA setup page
        return false;
      } else {
        // MFA is not required, allow access
        return true;
      }
    }

    HttpSession session = req.getSession(true);

    // Check if MFA is already verified in this session
    if (
      MFAContext.i()
        .getService(SessionService.class)
        .isVerifiedSession(session)
    ) {
      log.fine(String.format("MFA already verified for user: %s", username));
      return true;
    }

    // Check if TOTP code is provided in the request
    String totpCode = req.getParameter(PluginConstants.FormParameters.TOTP_CODE);

    if (totpCode != null && !totpCode.isEmpty()) {
      RateLimitService rateLimitService =
        MFAContext.i().getService(RateLimitService.class);

      // Check if user is locked out due to too many failed attempts
      if (rateLimitService.isLockedOut(username)) {
        long remainingSeconds = rateLimitService.getRemainingLockoutSeconds(username);
        log.warning(
          String.format(
            "User %s is locked out, %d seconds remaining", username, remainingSeconds
          )
        );
        resp.sendRedirect(
          req.getContextPath()
            + "/" + PluginConstants.Urls.LOGIN_ACTION_URL
            + "?error=locked&remaining=" + remainingSeconds
        );
        return false;
      }

      // Verify the TOTP code
      if (mfaProperty.verifyCode(totpCode)) {
        log.info(String.format("MFA verification successful for user: %s", username));
        // Clear any failed attempts on success
        rateLimitService.clearFailedAttempts(username);
        // Mark MFA as verified in the new session
        sessionService.verifySession(req);

        return true;
      } else {
        // Record failed attempt for rate limiting
        rateLimitService.recordFailedAttempt(username);
        log.warning(String.format("Invalid MFA code for user: %s", username));
        // Redirect back to MFA page with error
        resp.sendRedirect(
          req.getContextPath()
            + "/" + PluginConstants.Urls.LOGIN_ACTION_URL
            + "?error=invalid"
        );

        return false;
      }
    }

    // MFA is required but not yet verified, redirect to MFA page
    log.fine(
      String.format(
        "MFA required for user: %s, current path: %s, redirecting to MFA page",
        username,
        req.getRequestURI()
      )
    );

    // Store pending authentication state
    session.setAttribute(PluginConstants.SessionAttributes.PENDING_AUTH, username);

    // Redirect to MFA input page (only if response is not already committed)
    resp.sendRedirect(
      req.getContextPath() + "/" + PluginConstants.Urls.LOGIN_ACTION_URL
    );
    return false;
  }

  /**
   * Checks if the request path should be allowed without MFA verification.
   */
  private boolean shouldAllowPath(HttpServletRequest req) {
    String uri = req.getRequestURI();
    String contextPath = req.getContextPath();

    // Remove context path to get the relative path
    String relativePath = uri;
    if (
      contextPath != null && !contextPath.isEmpty() && uri.startsWith(contextPath)
    ) {
      relativePath = uri.substring(contextPath.length());
    }

    // Check if path matches any allowed pattern
    // Use strict matching to prevent path bypass attacks (e.g., /loginEvil matching
    // /login)
    for (String allowedPath : ALLOWED_PATHS) {
      if (relativePath.equals(allowedPath)) {
        return true;
      }
      // Only allow prefix matching for directory-style paths (ending with /)
      if (allowedPath.endsWith("/") && relativePath.startsWith(allowedPath)) {
        return true;
      }
      // For non-directory paths, also allow if followed by / or ? (subpaths/query
      // strings)
      if (
        !allowedPath.endsWith("/")
          && (relativePath.startsWith(allowedPath + "/")
            || relativePath.startsWith(allowedPath + "?"))
      ) {
        return true;
      }
    }

    // Allow user-scoped setup page (/user/<id>/mfa-setup and subpaths) without MFA,
    // otherwise users can get locked out when trying to configure/disable MFA.
    if (
      relativePath.matches(
        "^/user/[^/]+/" + PluginConstants.Urls.SETUP_ACTION_URL + "($|/.*)"
      )
    ) {
      return true;
    }

    return false;
  }
}
