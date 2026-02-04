package io.jenkins.plugins.openmfa.service;

import static io.jenkins.plugins.openmfa.constant.TOTPConstants.BINARY_FIRST_BYTE_MASK;
import static io.jenkins.plugins.openmfa.constant.TOTPConstants.BINARY_OTHER_BYTE_MASK;
import static io.jenkins.plugins.openmfa.constant.TOTPConstants.DIGITS_POWER;
import static io.jenkins.plugins.openmfa.constant.TOTPConstants.HEX_CHARS_PER_BYTE;
import static io.jenkins.plugins.openmfa.constant.TOTPConstants.HEX_RADIX;
import static io.jenkins.plugins.openmfa.constant.TOTPConstants.HEX_TIME_PADDING_LENGTH;
import static io.jenkins.plugins.openmfa.constant.TOTPConstants.HMAC_ALGORITHM;
import static io.jenkins.plugins.openmfa.constant.TOTPConstants.MAC_KEY_ALGORITHM;
import static io.jenkins.plugins.openmfa.constant.TOTPConstants.MILLIS_TO_SECONDS;
import static io.jenkins.plugins.openmfa.constant.TOTPConstants.OFFSET_MASK;
import static io.jenkins.plugins.openmfa.constant.TOTPConstants.PADDING_ZERO;
import static io.jenkins.plugins.openmfa.constant.TOTPConstants.SHIFT_16_BITS;
import static io.jenkins.plugins.openmfa.constant.TOTPConstants.SHIFT_24_BITS;
import static io.jenkins.plugins.openmfa.constant.TOTPConstants.SHIFT_8_BITS;
import static io.jenkins.plugins.openmfa.constant.TOTPConstants.TIME_STEP_SECONDS;
import static io.jenkins.plugins.openmfa.constant.TOTPConstants.TIME_WINDOW_TOLERANCE;
import static io.jenkins.plugins.openmfa.constant.TOTPConstants.TOTP_CODE_DIGITS;

import hudson.util.Secret;
import io.jenkins.plugins.openmfa.base.MFAException;
import io.jenkins.plugins.openmfa.base.Service;
import io.jenkins.plugins.openmfa.constant.TOTPConstants;
import java.security.SecureRandom;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import lombok.extern.java.Log;
import org.apache.commons.codec.binary.Base32;

/**
 * Service for handling Time-based One-Time Password (TOTP) operations.
 * This service is automatically registered and managed by MFAContext.
 */
@Log
@Service
public class TOTPService {

  /** Cleanup interval - run cleanup every 100 verifications */
  private static final int CLEANUP_INTERVAL = 100;

  /**
   * Cache of used TOTP codes to prevent replay attacks.
   * Key: secret hash + code, Value: expiry timestamp (when code becomes invalid)
   */
  private final Map<String, Long> usedCodes = new ConcurrentHashMap<>();

  /** Counter for triggering periodic cleanup */
  private int verificationCount = 0;

  public TOTPService() {
    // Default constructor for service instantiation
  }

  /**
   * Generates a random secret key for TOTP.
   *
   * @return Secret containing Base32-encoded secret key
   */
  public Secret generateSecret() {
    SecureRandom random = new SecureRandom();
    byte[] bytes = new byte[TOTPConstants.SECRET_KEY_SIZE_BYTES];
    random.nextBytes(bytes);
    Base32 base32 = new Base32();
    return Secret.fromString(base32.encodeToString(bytes));
  }

  /**
   * Generates a TOTP code for the given secret at the current time.
   *
   * @param secret
   *          Secret containing Base32-encoded secret key
   * @return 6-digit TOTP code
   */
  public String generateTOTP(Secret secret) {
    return generateTOTP(
      secret,
      System.currentTimeMillis()
        / MILLIS_TO_SECONDS
        / TIME_STEP_SECONDS
    );
  }

  /**
   * Generates a TOTP code for the given secret and step.
   *
   * @param secret
   *          Secret containing Base32-encoded secret key
   * @param step
   *          step (usually current time / 30)
   * @return 6-digit TOTP code
   */
  public String generateTOTP(Secret secret, long step) {
    Base32 base32 = new Base32();
    byte[] bytes = base32.decode(Secret.toString(secret));
    String hexKey = bytesToHex(bytes);
    String hexTime = Long.toHexString(step);

    return generateTOTP(hexKey, hexTime, TOTP_CODE_DIGITS);
  }

  /**
   * Generates the provisioning URI for QR code generation.
   *
   * @param username
   *          Jenkins username
   * @param secret
   *          Secret containing Base32-encoded secret key
   * @param issuer
   *          Issuer name (e.g., "Jenkins")
   * @return otpauth:// URI
   */
  public String getProvisioningUri(String username, Secret secret, String issuer) {
    String secretPlainText = Secret.toString(secret);
    return String.format(
      TOTPConstants.TOTP_URI_FORMAT,
      issuer,
      username,
      secretPlainText.replace("=", ""),
      issuer
    );
  }

  /**
   * Validates a TOTP code against the given secret.
   *
   * @param secret
   *          Secret containing the secret key
   * @param code
   *          the code to validate
   * @return true if valid, false otherwise
   */
  public boolean validateTOTP(Secret secret, String code) {
    return verifyCode(secret, code);
  }

  /**
   * Verifies a TOTP code against the secret, allowing for time drift.
   * Includes replay protection to prevent the same code from being used twice.
   *
   * @param secret
   *          Secret containing Base32-encoded secret key
   * @param code
   *          6-digit code to verify
   * @return true if the code is valid and has not been used before
   */
  public boolean verifyCode(Secret secret, String code) {
    if (code == null || code.length() != TOTP_CODE_DIGITS) {
      return false;
    }

    // Periodic cleanup of expired codes
    if (++verificationCount % CLEANUP_INTERVAL == 0) {
      cleanupExpiredCodes();
    }

    try {
      long currentStep =
        System.currentTimeMillis() / MILLIS_TO_SECONDS / TIME_STEP_SECONDS;

      // Check current time window and ±1 window (90 seconds total)
      for (int i = -TIME_WINDOW_TOLERANCE; i <= TIME_WINDOW_TOLERANCE; i++) {
        String generatedCode = generateTOTP(secret, currentStep + i);
        if (generatedCode.equals(code)) {
          // Check for replay attack - has this code been used before?
          String cacheKey = generateCacheKey(secret, code);
          Long existingExpiry = usedCodes.get(cacheKey);

          if (existingExpiry != null && System.currentTimeMillis() < existingExpiry) {
            log.warning("TOTP replay attack detected - code already used");
            return false;
          }

          // Mark code as used - expires after the time window passes
          // Code is valid for current step ± tolerance, so expire after (tolerance +
          // 1) steps
          long expiryTime =
            (currentStep + TIME_WINDOW_TOLERANCE + 1)
              * TIME_STEP_SECONDS
              * MILLIS_TO_SECONDS;
          usedCodes.put(cacheKey, expiryTime);

          log.fine("TOTP code verified and marked as used");
          return true;
        }
      }
    } catch (Exception e) {
      return false;
    }

    return false;
  }

  private String bytesToHex(byte[] bytes) {
    StringBuilder sb = new StringBuilder();
    for (byte b : bytes) {
      sb.append(String.format(TOTPConstants.HEX_FORMAT, b));
    }
    return sb.toString();
  }

  /**
   * Removes expired entries from the used codes cache.
   */
  private void cleanupExpiredCodes() {
    long now = System.currentTimeMillis();
    Iterator<Map.Entry<String, Long>> iterator = usedCodes.entrySet().iterator();
    while (iterator.hasNext()) {
      Map.Entry<String, Long> entry = iterator.next();
      if (entry.getValue() < now) {
        iterator.remove();
      }
    }
    log.fine(
      String.format("Cleaned up expired TOTP codes, remaining: %d", usedCodes.size())
    );
  }

  /**
   * Generates a cache key for tracking used codes.
   * Uses a hash of the secret to avoid storing the actual secret.
   */
  private String generateCacheKey(Secret secret, String code) {
    return Secret.toString(secret).hashCode() + ":" + code;
  }

  private String generateTOTP(String key, String step, int len) {
    try {
      // First 8 bytes are for the movingFactor
      // Compliant with base RFC 4226 (HOTP)
      StringBuilder paddedStep = new StringBuilder(step);
      while (paddedStep.length() < HEX_TIME_PADDING_LENGTH) {
        paddedStep.insert(0, PADDING_ZERO);
      }

      log.fine("Padded step: " + paddedStep.toString());

      byte[] msg = hexStringToByteArray(paddedStep.toString());
      byte[] k = hexStringToByteArray(key);

      byte[] hash = hmacSha(HMAC_ALGORITHM, k, msg);

      int offset = hash[hash.length - 1] & OFFSET_MASK;

      int binary =
        ((hash[offset] & BINARY_FIRST_BYTE_MASK) << SHIFT_24_BITS)
          | ((hash[offset + 1] & BINARY_OTHER_BYTE_MASK) << SHIFT_16_BITS)
          | ((hash[offset + 2] & BINARY_OTHER_BYTE_MASK) << SHIFT_8_BITS)
          | (hash[offset + 3] & BINARY_OTHER_BYTE_MASK);

      int otp = binary % DIGITS_POWER[len];

      StringBuilder result = new StringBuilder(Integer.toString(otp));
      while (result.length() < len) {
        result.insert(0, PADDING_ZERO);
      }
      return result.toString();
    } catch (Exception e) {
      throw new MFAException("Error generating TOTP", e);
    }
  }

  private byte[] hexStringToByteArray(String s) {
    // Ensure even length by padding with leading zero if needed
    String hexString = s;
    if (s.length() % HEX_CHARS_PER_BYTE != 0) {
      hexString = PADDING_ZERO + s;
    }

    int len = hexString.length();
    byte[] data = new byte[len / HEX_CHARS_PER_BYTE];
    for (int i = 0; i < len; i += HEX_CHARS_PER_BYTE) {
      data[i / HEX_CHARS_PER_BYTE] =
        (byte) ((Character.digit(hexString.charAt(i), HEX_RADIX) << 4)
          + Character.digit(hexString.charAt(i + 1), HEX_RADIX));
    }
    return data;
  }

  private byte[] hmacSha(String crypto, byte[] keyBytes, byte[] text) {
    try {
      Mac hmac = Mac.getInstance(crypto);
      SecretKeySpec macKey = new SecretKeySpec(keyBytes, MAC_KEY_ALGORITHM);
      hmac.init(macKey);
      return hmac.doFinal(text);
    } catch (Exception e) {
      throw new MFAException("Error generating HMAC", e);
    }
  }
}
