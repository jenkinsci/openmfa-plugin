package io.jenkins.plugins.openmfa.service;

import static io.jenkins.plugins.openmfa.constant.PluginConstants.SessionAttributes.MFA_VERIFIED;

import io.jenkins.plugins.openmfa.base.Service;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import lombok.extern.java.Log;

/**
 * Service for MFA session verification state.
 */
@Log
@Service
public class SessionService {

  /**
   * Returns whether the current session has passed MFA verification.
   *
   * @param session
   *          the HTTP session
   * @return true if MFA is verified in this session, false otherwise
   */
  public boolean isVerifiedSession(HttpSession session) {
    if (session == null) {
      return false;
    }
    Object attr = session.getAttribute(MFA_VERIFIED);
    return Boolean.TRUE.equals(attr);
  }

  /**
   * Marks the session as MFA-verified.
   *
   * @param request
   *          the HTTP request
   */
  public void verifySession(HttpServletRequest request) {
    // Regenerate session to prevent session fixation attacks
    HttpSession session = regenerateSession(request);
    if (session != null) {
      session.setAttribute(MFA_VERIFIED, true);
    }
  }

  /**
   * Regenerates the session to prevent session fixation attacks.
   * Copies all existing session attributes to the new session.
   *
   * @param request
   *          the HTTP request
   * @return the new session, or null if no session existed
   */
  private HttpSession regenerateSession(HttpServletRequest request) {
    HttpSession oldSession = request.getSession(false);
    Map<String, Object> attrs = new HashMap<>();

    if (oldSession != null) {
      Enumeration<String> names = oldSession.getAttributeNames();
      while (names.hasMoreElements()) {
        String name = names.nextElement();
        attrs.put(name, oldSession.getAttribute(name));
      }
      oldSession.invalidate();
    }

    HttpSession newSession = request.getSession(true);
    attrs.forEach(newSession::setAttribute);
    log.fine("Session regenerated for security");
    return newSession;
  }
}
