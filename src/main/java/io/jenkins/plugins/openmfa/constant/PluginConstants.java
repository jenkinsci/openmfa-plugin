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

    public static final String LOGIN_ACTION_URL = "mfa-login";
    public static final String SETUP_ACTION_URL = "mfa-setup";
    public static final String MANAGEMENT_ACTION_URL = "mfa-management";
    public static final String SECURITY_CHECK_ENDPOINT =
      "/" + LOGIN_ACTION_URL + "/verify";

    private Urls() {
    }
  }

  /**
   * Session attribute constants
   */
  public static final class SessionAttributes {

    public static final String PENDING_AUTH = "X-Plugin-OpenMFA-Pending-Auth";
    public static final String MFA_VERIFIED = "X-Plugin-OpenMFA-Verified";

    private SessionAttributes() {
    }
  }

  /**
   * Form parameter constants
   */
  public static final class FormParameters {

    public static final String TOTP_CODE = "x-plugin-openmfa-totp";
    public static final String SECRET = "x-plugin-openmfa-secret";
    public static final String CODE = "x-plugin-openmfa-code";

    private FormParameters() {
    }
  }
}
