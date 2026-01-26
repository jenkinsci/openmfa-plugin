package io.jenkins.plugins.openmfa;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import hudson.Extension;
import hudson.model.User;
import io.jenkins.plugins.openmfa.constant.PluginConstants;
import io.jenkins.plugins.openmfa.util.JenkinsUtil;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
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

  @Override
  public void init(FilterConfig filterConfig) throws ServletException {
    // No initialization needed
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

    // User is authenticated, check if MFA verification is required
    if (!handleMFAVerification(req, resp, user.get())) {
      // MFA verification failed or pending, don't continue the chain
      return;
    }

    // MFA verified or not required, continue with the request
    chain.doFilter(req, resp);
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
    for (String allowedPath : ALLOWED_PATHS) {
      if (relativePath.equals(allowedPath) || relativePath.startsWith(allowedPath)) {
        return true;
      }
    }

    Optional<User> user = JenkinsUtil.getCurrentUser();
    if (user.isPresent()) {
      MFAUserProperty mfaProperty = MFAUserProperty.forUser(user.get());
      if (
        MFAGlobalConfiguration.get().isRequireMFA()
          || (mfaProperty != null
            && mfaProperty.isEnabled()
            && mfaProperty.isConfigured())
      ) {
        // MFA is required or user has MFA configured, block access
        return false;
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

    // Allow user-scoped security page (/user/<id>/security and subpaths) without
    // MFA,
    // otherwise users cannot access their security configuration page.
    if (relativePath.matches("^/user/[^/]+/security($|/.*)")) {
      return true;
    }

    return false;
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
    if (
      mfaProperty == null || !mfaProperty.isEnabled() || !mfaProperty.isConfigured()
    ) {
      MFAGlobalConfiguration globalConfig = MFAGlobalConfiguration.get();
      if (globalConfig.isRequireMFA()) {
        resp.sendRedirect(
          req.getContextPath()
            + "/user/" + username + "/" + PluginConstants.Urls.SETUP_ACTION_URL
        );
        // MFA is required but not enabled or configured, redirect to MFA setup page
        return false;
      } else {
        // MFA is not required, allow access
        return true;
      }
    }

    HttpSession session = req.getSession(true);
    Boolean mfaVerified =
      (Boolean) session.getAttribute(
        PluginConstants.SessionAttributes.MFA_VERIFIED
      );

    // Check if MFA is already verified in this session
    if (Boolean.TRUE.equals(mfaVerified)) {
      log.fine(String.format("MFA already verified for user: %s", username));
      return true;
    }

    // Check if TOTP code is provided in the request
    String totpCode = req.getParameter(PluginConstants.FormParameters.TOTP_CODE);

    if (totpCode != null && !totpCode.isEmpty()) {
      // Verify the TOTP code
      if (mfaProperty.verifyCode(totpCode)) {
        log.info(String.format("MFA verification successful for user: %s", username));
        // Mark MFA as verified in the session
        session.setAttribute(PluginConstants.SessionAttributes.MFA_VERIFIED, true);
        return true;
      } else {
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
    log.info(
      String.format("MFA required for user: %s, redirecting to MFA page", username)
    );

    // Store pending authentication state
    session.setAttribute(PluginConstants.SessionAttributes.PENDING_AUTH, username);

    // Redirect to MFA input page (only if response is not already committed)
    resp.sendRedirect(
      req.getContextPath() + "/" + PluginConstants.Urls.LOGIN_ACTION_URL
    );
    return false;
  }

  @Override
  public void destroy() {
    // No cleanup needed
  }
}
