package io.jenkins.plugins.openmfa;

import hudson.Extension;
import hudson.model.User;
import io.jenkins.plugins.openmfa.constant.PluginConstants;
import io.jenkins.plugins.openmfa.util.JenkinsUtil;
import java.io.IOException;
import java.util.Optional;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.extern.java.Log;

/**
 * Filter that intercepts login requests to handle MFA verification.
 */
@Log
@Extension
public class MFAFilter implements Filter {

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

    if (
      user.isEmpty()
        || !req.getRequestURI().endsWith(PluginConstants.Urls.SECURITY_CHECK_ENDPOINT)
    ) {
      log.fine("User is anonymous, continuing with normal authentication.");
      chain.doFilter(req, resp);
      return;
    }

    // Handle login request.
    handleLoginRequest(req, resp, user.get());
    // Continue with normal authentication
    chain.doFilter(req, resp);
  }

  private void handleLoginRequest(
    HttpServletRequest req, HttpServletResponse resp, User user)
    throws IOException, ServletException {

    String username = user.getId();
    MFAUserProperty mfaProperty = MFAUserProperty.forUser(user);

    if (
      mfaProperty != null && mfaProperty.isEnabled() && mfaProperty.isConfigured()
    ) {
      // MFA is required, verify TOTP code
      String totpCode = req.getParameter(PluginConstants.FormParameters.TOTP_CODE);
      // MFA is required
      if (totpCode == null || totpCode.isEmpty()) {
        // First stage: password only, redirect to MFA page
        log.info(
          String
            .format("MFA required for user: %s, redirecting to MFA page", username)
        );

        // Redirect to MFA input page
        resp.sendRedirect(
          req.getContextPath() + "/" + PluginConstants.Urls.LOGIN_ACTION_URL
        );
        return;
      }

      log.info(String.format("Verifying TOTP code for user: %s", username));
    }
  }

  @Override
  public void destroy() {
    // No cleanup needed
  }
}
