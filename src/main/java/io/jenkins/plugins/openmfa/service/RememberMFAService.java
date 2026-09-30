package io.jenkins.plugins.openmfa.service;

import hudson.model.User;
import hudson.util.Secret;
import io.jenkins.plugins.openmfa.MFAGlobalConfiguration;
import io.jenkins.plugins.openmfa.MFAUserProperty;
import io.jenkins.plugins.openmfa.base.MFAException;
import io.jenkins.plugins.openmfa.base.Service;
import io.jenkins.plugins.openmfa.constant.PluginConstants;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Optional;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import lombok.extern.java.Log;
import org.springframework.security.authentication.RememberMeAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Service for long-lived "remember MFA" tokens. Issues and validates
 * stateless HMAC-signed tokens so users who chose "Keep me signed in"
 * are not asked for MFA on every new HTTP session.
 *
 * Token format: {@code base64url(username):expiryEpochMillis:base64url(hmac)}
 * where the HMAC covers the username, the expiry, and a hash of the user's
 * TOTP secret — so changing or disabling MFA invalidates all issued tokens.
 */
@Log
@Service
public class RememberMFAService {

  private static final String HASH_ALGORITHM = "SHA-256";
  private static final String HMAC_ALGORITHM = "HmacSHA256";
  private static final String SEPARATOR = ":";
  private static final int TOKEN_PARTS = 3;

  /**
   * Clears the remember-MFA cookie (e.g. on logout).
   *
   * @param request
   *          the HTTP request (for the context path)
   * @param response
   *          the HTTP response to add the expired cookie to
   */
  public void clearCookie(
    HttpServletRequest request, HttpServletResponse response) {
    Cookie cookie = new Cookie(PluginConstants.RememberMFA.COOKIE_NAME, "");
    cookie.setHttpOnly(true);
    cookie.setSecure(request.isSecure());
    cookie.setPath(cookiePath(request));
    cookie.setMaxAge(0);
    response.addCookie(cookie);
  }

  /**
   * Creates a signed token value for the given user.
   *
   * @param username
   *          the Jenkins user id the token is issued for
   * @param totpSecret
   *          the user's current TOTP secret (binds the token to it)
   * @param expiryEpochMillis
   *          absolute expiry time in epoch milliseconds
   * @return the token value suitable for a cookie
   */
  public String createTokenValue(
    String username, Secret totpSecret, long expiryEpochMillis) {
    String payload =
      encode(username.getBytes(StandardCharsets.UTF_8))
        + SEPARATOR
        + expiryEpochMillis;
    return payload + SEPARATOR + encode(sign(payload, totpSecret));
  }

  /**
   * Returns whether the remember-MFA feature is enabled in global
   * configuration.
   *
   * @return true if the configured duration is greater than zero days
   */
  public boolean isEnabled() {
    return MFAGlobalConfiguration.get().getRememberMfaHours() > 0;
  }

  /**
   * Validates a token value against the expected user and current TOTP
   * secret. Rejects malformed, expired, tampered, or foreign tokens without
   * throwing.
   *
   * @param tokenValue
   *          the raw cookie value
   * @param username
   *          the currently authenticated user id
   * @param totpSecret
   *          the user's current TOTP secret
   * @param nowMillis
   *          current time in epoch milliseconds
   * @return true if the token is valid for this user
   */
  public boolean isValidTokenValue(
    String tokenValue, String username, Secret totpSecret, long nowMillis) {
    if (tokenValue == null || tokenValue.isEmpty() || totpSecret == null) {
      return false;
    }

    String[] parts = tokenValue.split(SEPARATOR, -1);
    if (parts.length != TOKEN_PARTS) {
      return false;
    }

    long expiry;
    try {
      expiry = Long.parseLong(parts[1]);
    } catch (NumberFormatException e) {
      return false;
    }
    if (expiry <= nowMillis) {
      log.fine("Remember-MFA token expired for user: " + username);
      return false;
    }

    if (
      !parts[0].equals(encode(username.getBytes(StandardCharsets.UTF_8)))
    ) {
      return false;
    }

    byte[] expectedMac = sign(parts[0] + SEPARATOR + parts[1], totpSecret);
    byte[] actualMac;
    try {
      actualMac = Base64.getUrlDecoder().decode(parts[2]);
    } catch (IllegalArgumentException e) {
      return false;
    }
    return MessageDigest.isEqual(expectedMac, actualMac);
  }

  /**
   * Checks whether the request carries a valid remember-MFA cookie for the
   * given user.
   *
   * @param request
   *          the HTTP request
   * @param user
   *          the currently authenticated user
   * @return true if a valid cookie is present and the feature is enabled
   */
  public boolean isVerifiedByCookie(HttpServletRequest request, User user) {
    if (!isEnabled()) {
      return false;
    }
    MFAUserProperty property = MFAUserProperty.forUser(user);
    if (property == null || property.getSecret() == null) {
      return false;
    }
    return findCookie(request)
      .map(
        value -> isValidTokenValue(
          value, user.getId(), property.getSecret(), System.currentTimeMillis()
        )
      )
      .orElse(false);
  }

  /**
   * Issues a remember-MFA cookie for the user with the configured lifetime.
   *
   * @param request
   *          the HTTP request (for the context path and secure flag)
   * @param response
   *          the HTTP response to add the cookie to
   * @param username
   *          the Jenkins user id
   * @param totpSecret
   *          the user's current TOTP secret
   */
  public void issueCookie(
    HttpServletRequest request,
    HttpServletResponse response,
    String username,
    Secret totpSecret) {
    int hours = MFAGlobalConfiguration.get().getRememberMfaHours();
    long expiry =
      System.currentTimeMillis() + hours * PluginConstants.RememberMFA.HOUR_MS;

    Cookie cookie =
      new Cookie(
        PluginConstants.RememberMFA.COOKIE_NAME,
        createTokenValue(username, totpSecret, expiry)
      );
    cookie.setHttpOnly(true);
    cookie.setSecure(request.isSecure());
    cookie.setPath(cookiePath(request));
    cookie.setMaxAge(hours * 60 * 60);
    response.addCookie(cookie);
    log.fine("Issued remember-MFA cookie for user: " + username);
  }

  /**
   * Returns whether the user chose "Keep me signed in": either the current
   * authentication came from the Jenkins remember-me cookie, or the request
   * carries that cookie (the case right after an interactive login).
   *
   * @param request
   *          the HTTP request
   * @return true if the session should be remembered
   */
  public boolean shouldRemember(HttpServletRequest request) {
    Authentication auth =
      SecurityContextHolder.getContext().getAuthentication();
    if (auth instanceof RememberMeAuthenticationToken) {
      return true;
    }
    Cookie[] cookies = request.getCookies();
    if (cookies == null) {
      return false;
    }
    for (Cookie cookie : cookies) {
      if (
        PluginConstants.RememberMFA.JENKINS_REMEMBER_ME_COOKIE
          .equals(cookie.getName())
      ) {
        return true;
      }
    }
    return false;
  }

  private String cookiePath(HttpServletRequest request) {
    String contextPath = request.getContextPath();
    return contextPath == null || contextPath.isEmpty() ? "/" : contextPath;
  }

  private String encode(byte[] bytes) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }

  private Optional<String> findCookie(HttpServletRequest request) {
    Cookie[] cookies = request.getCookies();
    if (cookies == null) {
      return Optional.empty();
    }
    for (Cookie cookie : cookies) {
      if (PluginConstants.RememberMFA.COOKIE_NAME.equals(cookie.getName())) {
        return Optional.ofNullable(cookie.getValue());
      }
    }
    return Optional.empty();
  }

  /**
   * Computes the HMAC over the payload and a hash of the TOTP secret using
   * the plugin's signing key.
   */
  private byte[] sign(String payload, Secret totpSecret) {
    try {
      String message = payload + SEPARATOR + totpSecretHash(totpSecret);
      Secret key = MFAGlobalConfiguration.get().getOrCreateRememberMfaKey();
      Mac mac = Mac.getInstance(HMAC_ALGORITHM);
      mac.init(
        new SecretKeySpec(
          key.getPlainText().getBytes(StandardCharsets.UTF_8), HMAC_ALGORITHM
        )
      );
      return mac.doFinal(message.getBytes(StandardCharsets.UTF_8));
    } catch (Exception e) {
      throw new MFAException("Error signing remember-MFA token", e);
    }
  }

  private String totpSecretHash(Secret totpSecret)
    throws NoSuchAlgorithmException {
    byte[] hash =
      MessageDigest.getInstance(HASH_ALGORITHM)
        .digest(totpSecret.getPlainText().getBytes(StandardCharsets.UTF_8));
    return encode(hash);
  }
}
