package io.jenkins.plugins.openmfa.constant;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

/**
 * Constants used throughout the OpenMFA plugin. This includes URL paths,
 * session attributes, and form parameter names.
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class PluginConstants {

  /**
   * URL path constants
   */
  public static final class Urls {

    public static final String LOGIN_ACTION_URL = "openmfa-login";
    public static final String SETUP_ACTION_URL = "openmfa-setup";
    public static final String SECURITY_CHECK_ENDPOINT = "/openmfa/security-check";

    private Urls() {
    }
  }

  /**
   * Session attribute constants
   */
  public static final class SessionAttributes {

    public static final String PENDING_AUTH = "openmfa-pending-auth";

    private SessionAttributes() {
    }
  }

  /**
   * Form parameter constants
   */
  public static final class FormParameters {

    public static final String TOTP_CODE = "openmfa_totp";
    public static final String SECRET = "secret";
    public static final String CODE = "code";

    private FormParameters() {
    }
  }
}
