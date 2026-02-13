package io.jenkins.plugins.openmfa.constant;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

/**
 * Constants related to UI components, including QR codes, icons, and display
 * names.
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class UIConstants {

  /**
   * Default values
   */
  public static final class Defaults {

    public static final String DEFAULT_ISSUER = "Jenkins";
    public static final boolean DEFAULT_MFA_ENABLED = false;
    public static final boolean DEFAULT_REQUIRE_MFA = false;

    private Defaults() {
    }
  }

  /**
   * Display names for UI components
   */
  public static final class DisplayNames {

    public static final String CONFIGURE_MFA = "Configure MFA";
    public static final String MFA_LOGIN = "MFA Login";
    public static final String MFA_USER_MANAGEMENT = "MFA User Management";
    public static final String MFA_SECURITY_REALM =
      "MFA Security Realm (wraps existing realm)";
    public static final String MULTI_FACTOR_AUTHENTICATION =
      "Multi-Factor Authentication (MFA)";
    public static final String OPENMFA_GLOBAL_CONFIGURATION = "OpenMFA";

    private DisplayNames() {
    }
  }

  /**
   * HTTP response codes
   */
  public static final class HttpStatus {

    public static final int BAD_REQUEST = 400;
    public static final int INTERNAL_SERVER_ERROR = 500;
    public static final int NOT_FOUND = 404;

    private HttpStatus() {
    }
  }

  /**
   * Icon file names
   */
  public static final class Icons {

    public static final String SECURE = "secure.png";

    private Icons() {
    }
  }

  /**
   * QR code configuration
   */
  public static final class QRCode {

    public static final String DATA_URI_PREFIX = "data:image/png;base64,";
    public static final int HEIGHT = 300;
    public static final String IMAGE_FORMAT = "PNG";
    public static final int WIDTH = 300;

    private QRCode() {
    }
  }
}
