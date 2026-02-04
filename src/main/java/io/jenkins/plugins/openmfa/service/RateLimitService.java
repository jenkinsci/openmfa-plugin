package io.jenkins.plugins.openmfa.service;

import static io.jenkins.plugins.openmfa.constant.PluginConstants.RateLimit.ATTEMPT_WINDOW_MS;
import static io.jenkins.plugins.openmfa.constant.PluginConstants.RateLimit.LOCKOUT_DURATION_MS;
import static io.jenkins.plugins.openmfa.constant.PluginConstants.RateLimit.MAX_ATTEMPTS;

import io.jenkins.plugins.openmfa.base.Service;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import lombok.extern.java.Log;

/**
 * Service to rate-limit TOTP verification attempts and prevent brute-force
 * attacks.
 */
@Log
@Service
public class RateLimitService {

  /** Stores timestamps of failed attempts per username */
  private final Map<String, CopyOnWriteArrayList<Long>> failedAttempts =
    new ConcurrentHashMap<>();

  /** Stores lockout expiry time per username */
  private final Map<String, Long> lockouts = new ConcurrentHashMap<>();

  /**
   * Clears failed attempts for a user after successful verification.
   *
   * @param username
   *          the username to clear
   */
  public void clearFailedAttempts(String username) {
    failedAttempts.remove(username);
    lockouts.remove(username);
    log.fine(String.format("Failed attempts cleared for user: %s", username));
  }

  /**
   * Gets the remaining lockout time in seconds for a user.
   *
   * @param username
   *          the username to check
   * @return remaining lockout time in seconds, or 0 if not locked out
   */
  public long getRemainingLockoutSeconds(String username) {
    Long lockoutExpiry = lockouts.get(username);
    if (lockoutExpiry == null) {
      return 0;
    }

    long remaining = lockoutExpiry - System.currentTimeMillis();
    return remaining > 0 ? remaining / 1000 : 0;
  }

  /**
   * Checks if a user is currently locked out due to too many failed attempts.
   *
   * @param username
   *          the username to check
   * @return true if the user is locked out, false otherwise
   */
  public boolean isLockedOut(String username) {
    Long lockoutExpiry = lockouts.get(username);
    if (lockoutExpiry == null) {
      return false;
    }

    if (System.currentTimeMillis() > lockoutExpiry) {
      // Lockout expired, clear it
      lockouts.remove(username);
      failedAttempts.remove(username);
      log.fine(String.format("Lockout expired for user: %s", username));
      return false;
    }

    return true;
  }

  /**
   * Records a failed TOTP verification attempt for a user.
   * If the user exceeds the maximum attempts within the time window,
   * they will be locked out.
   *
   * @param username
   *          the username that failed verification
   */
  public void recordFailedAttempt(String username) {
    long now = System.currentTimeMillis();

    CopyOnWriteArrayList<Long> attempts =
      failedAttempts.computeIfAbsent(username, k -> new CopyOnWriteArrayList<>());

    // Remove expired attempts
    cleanupExpiredAttempts(attempts, now);

    // Add new attempt
    attempts.add(now);

    log.fine(
      String.format(
        "Failed attempt recorded for user: %s, total attempts: %d",
        username, attempts.size()
      )
    );

    // Check if max attempts exceeded
    if (attempts.size() >= MAX_ATTEMPTS) {
      lockouts.put(username, now + LOCKOUT_DURATION_MS);
      log.warning(
        String.format(
          "User %s locked out for %d seconds due to too many failed MFA attempts",
          username, LOCKOUT_DURATION_MS / 1000
        )
      );
    }
  }

  /**
   * Removes attempts that are older than the attempt window.
   */
  private void cleanupExpiredAttempts(CopyOnWriteArrayList<Long> attempts, long now) {
    long cutoff = now - ATTEMPT_WINDOW_MS;
    Iterator<Long> iterator = attempts.iterator();
    while (iterator.hasNext()) {
      if (iterator.next() < cutoff) {
        attempts.remove(iterator.next());
      }
    }
    // Use removeIf for thread-safe removal
    attempts.removeIf(timestamp -> timestamp < cutoff);
  }
}
