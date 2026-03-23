package io.jenkins.plugins.openmfa.service;

import static io.jenkins.plugins.openmfa.constant.PluginConstants.SessionAttributes.MFA_VERIFIED;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.jenkins.plugins.openmfa.base.MFAContext;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpSession;

/**
 * Unit tests for SessionService.
 * Tests session verification behavior.
 */
class SessionServiceTest {

  private final SessionService sessionService =
    MFAContext.i().getService(SessionService.class);

  /**
   * Test isVerifiedSession returns false when MFA_VERIFIED attribute is false.
   */
  @Test
  void testIsVerifiedSessionWithFalseAttribute() {
    MockHttpSession session = new MockHttpSession();
    session.setAttribute(MFA_VERIFIED, false);

    assertFalse(
      sessionService.isVerifiedSession(session),
      "Session with MFA_VERIFIED=false should not be verified"
    );
  }

  /**
   * Test isVerifiedSession returns false for new session without MFA verified
   * attribute.
   */
  @Test
  void testIsVerifiedSessionWithNewSession() {
    MockHttpSession session = new MockHttpSession();
    assertFalse(
      sessionService.isVerifiedSession(session),
      "New session without MFA verified attribute should not be verified"
    );
  }

  /**
   * Test isVerifiedSession returns false for null session.
   */
  @Test
  void testIsVerifiedSessionWithNullSession() {
    assertFalse(
      sessionService.isVerifiedSession(null),
      "Null session should not be verified"
    );
  }

  /**
   * Test isVerifiedSession returns true when MFA_VERIFIED attribute is set.
   */
  @Test
  void testIsVerifiedSessionWithVerifiedAttribute() {
    MockHttpSession session = new MockHttpSession();
    session.setAttribute(MFA_VERIFIED, true);

    assertTrue(
      sessionService.isVerifiedSession(session),
      "Session with MFA_VERIFIED=true should be verified"
    );
  }
}
