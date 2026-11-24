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
    public static final String CREDENTIAL_ID = "x-plugin-openmfa-credential-id";
    public static final String SECRET = "x-plugin-openmfa-secret";
    public static final String TOTP_CODE = "x-plugin-openmfa-totp";

    private FormParameters() {
    }
  }

  /**
   * Identifiers of the MFA methods a user can satisfy a challenge with, as
   * persisted in {@code MFAUserProperty.lastUsedMethod}.
   */
  public static final class MFAMethods {

    public static final String TOTP = "totp";
    public static final String WEBAUTHN = "webauthn";

    private MFAMethods() {
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

    /**
     * Serialized WebAuthn assertion request for the in-flight login ceremony.
     * Single-use: removed as soon as a finish is attempted.
     */
    public static final String WEBAUTHN_ASSERTION_CEREMONY =
      "X-Plugin-OpenMFA-WebAuthn-Assertion";

    /**
     * Serialized WebAuthn credential creation options for the in-flight
     * registration ceremony. Single-use: removed as soon as a finish is
     * attempted.
     */
    public static final String WEBAUTHN_REGISTRATION_CEREMONY =
      "X-Plugin-OpenMFA-WebAuthn-Registration";

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

  /**
   * WebAuthn ceremony constants
   */
  public static final class WebAuthn {

    /**
     * How long a started registration or authentication ceremony stays
     * valid, in milliseconds (5 minutes). Enforced server-side when a
     * ceremony is finished, and advertised to the browser as the ceremony
     * timeout.
     */
    public static final long CEREMONY_TTL_MS = 5 * 60 * 1000L;

    /**
     * Most credentials a single user may register. Keeps a verified session
     * from being used to grow a user's record without limit, and keeps the
     * allow-credentials list of a login ceremony small.
     */
    public static final int MAX_CREDENTIALS_PER_USER = 10;

    /**
     * Longest accepted user-chosen label for a registered credential, in
     * characters. The label is only ever shown back to its owner, but it is
     * attacker-controlled free text that gets persisted in the user's
     * {@code config.xml}, so it is capped rather than stored unbounded.
     */
    public static final int MAX_CREDENTIAL_NAME_LENGTH = 64;

    /**
     * Upper bound on the size of a WebAuthn ceremony request body accepted
     * by the login and setup endpoints. A body past this size is treated as
     * invalid input rather than being buffered in full.
     */
    public static final int MAX_RESPONSE_BYTES = 64 * 1024;

    private WebAuthn() {
    }
  }
}
