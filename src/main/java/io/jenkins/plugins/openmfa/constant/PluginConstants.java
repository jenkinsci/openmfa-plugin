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
   * Query/form parameter for post-MFA redirect target.
   * Used to preserve the originally requested URL across the MFA flow.
   */
  public static final String FROM_PARAM = "from";

  /**
   * Form parameter constants
   */
  public static final class FormParameters {

    public static final String CODE = "x-plugin-openmfa-code";
    public static final String SECRET = "x-plugin-openmfa-secret";
    public static final String TOTP_CODE = "x-plugin-openmfa-totp";

    private FormParameters() {
    }
  }

  /**
   * Rate limiting constants
   */
  public static final class RateLimit {

    /** Time window for counting attempts in milliseconds (5 minutes) */
    public static final long ATTEMPT_WINDOW_MS = 5 * 60 * 1000L;

    /** Lockout duration in milliseconds (5 minutes) */
    public static final long LOCKOUT_DURATION_MS = 5 * 60 * 1000L;

    /** Maximum failed TOTP attempts before lockout */
    public static final int MAX_ATTEMPTS = 5;

    private RateLimit() {
    }
  }

  /**
   * Remember-MFA cookie constants
   */
  public static final class RememberMFA {

    /** Name of the long-lived remember-MFA cookie issued by this plugin */
    public static final String COOKIE_NAME = "openmfa-remember";

    /** One hour in milliseconds */
    public static final long HOUR_MS = 60L * 60 * 1000;

    /** Name of the Jenkins "Keep me signed in" (remember-me) cookie */
    public static final String JENKINS_REMEMBER_ME_COOKIE = "remember-me";

    private RememberMFA() {
    }
  }

  /**
   * Session attribute constants
   */
  public static final class SessionAttributes {

    public static final String MFA_VERIFIED = "X-Plugin-OpenMFA-Verified";
    public static final String PENDING_AUTH = "X-Plugin-OpenMFA-Pending-Auth";

    private SessionAttributes() {
    }
  }

  /**
   * URL path constants
   */
  public static final class Urls {

    public static final String LOGIN_ACTION_URL = "mfa-login";
    public static final String MANAGEMENT_ACTION_URL = "mfa-management";
    public static final String SECURITY_CHECK_ENDPOINT =
      "/" + LOGIN_ACTION_URL + "/verify";
    public static final String SETUP_ACTION_URL = "mfa-setup";

    private Urls() {
    }
  }
}
