package io.jenkins.plugins.openmfa.constant;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

/**
 * Constants related to TOTP (Time-based One-Time Password) generation and
 * verification.
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class TOTPConstants {

  /**
   * Time step in seconds (30 seconds as per RFC 6238)
   */
  public static final int TIME_STEP_SECONDS = 30;

  /**
   * Number of digits in TOTP code (6 digits)
   */
  public static final int TOTP_CODE_DIGITS = 6;

  /**
   * HMAC algorithm used for TOTP generation (HmacSHA1 as per RFC 6238)
   */
  public static final String HMAC_ALGORITHM = "HmacSHA1";

  /**
   * Secret key size in bytes (160 bits = 20 bytes)
   */
  public static final int SECRET_KEY_SIZE_BYTES = 20;

  /**
   * Number of time windows to check for time drift tolerance -1, 0, +1 means ±30
   * seconds
   */
  public static final int TIME_WINDOW_TOLERANCE = 1;

  /**
   * Hex string padding length for time counter
   */
  public static final int HEX_TIME_PADDING_LENGTH = 16;

  /**
   * HMAC key spec algorithm name
   */
  public static final String MAC_KEY_ALGORITHM = "RAW";

  /**
   * Radix for hexadecimal conversion
   */
  public static final int HEX_RADIX = 16;

  /**
   * TOTP URI scheme
   */
  public static final String TOTP_URI_SCHEME = "otpauth://totp/";

  /**
   * URI format string for TOTP provisioning Format:
   * otpauth://totp/issuer:username?secret=secret&issuer=issuer
   */
  public static final String TOTP_URI_FORMAT =
    "otpauth://totp/%s:%s?secret=%s&issuer=%s";

  /**
   * Number conversion base for power calculation
   */
  public static final int DECIMAL_BASE = 10;

  /**
   * Mask for extracting offset from hash (0xf)
   */
  public static final int OFFSET_MASK = 0xf;

  /**
   * Mask for first byte in binary conversion (0x7f)
   */
  public static final int BINARY_FIRST_BYTE_MASK = 0x7f;

  /**
   * Mask for other bytes in binary conversion (0xff)
   */
  public static final int BINARY_OTHER_BYTE_MASK = 0xff;

  /**
   * Bit shift for first byte (24 bits)
   */
  public static final int SHIFT_24_BITS = 24;

  /**
   * Bit shift for second byte (16 bits)
   */
  public static final int SHIFT_16_BITS = 16;

  /**
   * Bit shift for third byte (8 bits)
   */
  public static final int SHIFT_8_BITS = 8;

  /**
   * Digits power array
   * 10^1, 10^2, 10^3, 10^4, 10^5, 10^6, 10^7, 10^8
   *
   * @see <a href="https://tools.ietf.org/html/rfc4226#section-5.3">RFC 4226</a>
   */
  public static final int[] DIGITS_POWER =
    { 1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000 };

  /**
   * Divisor for calculating time counter from milliseconds
   */
  public static final long MILLIS_TO_SECONDS = 1000L;

  /**
   * String formatting for hex bytes
   */
  public static final String HEX_FORMAT = "%02x";

  /**
   * Padding character for hex and digit strings
   */
  public static final String PADDING_ZERO = "0";

  /**
   * Characters per hex byte
   */
  public static final int HEX_CHARS_PER_BYTE = 2;

}
