package io.jenkins.plugins.openmfa.service;

import static io.jenkins.plugins.openmfa.constant.PluginConstants.SessionAttributes.MFA_VERIFIED;

import io.jenkins.plugins.openmfa.base.Service;
import jakarta.servlet.http.HttpSession;
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
   * @param session the HTTP session
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
   * @param session the HTTP session
   */
  public void verifySession(HttpSession session) {
    if (session != null) {
      session.setAttribute(MFA_VERIFIED, true);
    }
  }
}
