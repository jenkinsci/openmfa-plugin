package io.jenkins.plugins.openmfa;

import hudson.Extension;
import hudson.model.User;
import io.jenkins.plugins.openmfa.base.MFAContext;
import io.jenkins.plugins.openmfa.constant.PluginConstants;
import io.jenkins.plugins.openmfa.service.SessionService;
import io.jenkins.plugins.openmfa.util.JenkinsUtil;
import io.jenkins.plugins.openmfa.util.SecurityUtil;
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
   * Builds the {@code from} query parameter with the originally requested URI
   * so the user can be redirected there after MFA verification.
   *
   * @return the from param as "&from=encoded" for appending to URLs that
   *         already have query params, or empty string if there is no target
   */
  private String buildFromParam(HttpServletRequest req) {
    String uri = req.getRequestURI();
    String contextPath = req.getContextPath();
    String relativePath = uri;
    if (
      contextPath != null && !contextPath.isEmpty() && uri.startsWith(contextPath)
    ) {
      relativePath = uri.substring(contextPath.length());
    }
    if (relativePath.isEmpty()) {
      relativePath = "/";
    }
    String query = req.getQueryString();
    if (query != null && !query.isEmpty()) {
      relativePath = relativePath + "?" + query;
    }
    try {
      return "&"
        + PluginConstants.FROM_PARAM
        + "="
        + URLEncoder.encode(
          relativePath, java.nio.charset.StandardCharsets.UTF_8
        );
    } catch (Exception e) {
      return "";
    }
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
    if (!TOTPUtil.isMFAEnabled()) {
      if (TOTPUtil.isMFARequired()) {
        resp.sendRedirect(
          SecurityUtil.buildSetupURI(
            req.getContextPath(),
            username
          )
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

    // Redirect to MFA input page, preserving the originally requested URL
    String fromParam = buildFromParam(req);
    String mfaLoginUrl =
      req.getContextPath()
        + "/"
        + PluginConstants.Urls.LOGIN_ACTION_URL
        + (fromParam.isEmpty() ? "" : "?" + fromParam.substring(1));
    resp.sendRedirect(mfaLoginUrl);
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
