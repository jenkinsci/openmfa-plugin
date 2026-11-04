package io.jenkins.plugins.openmfa;

import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import hudson.model.User;
import hudson.model.UserProperty;
import hudson.util.Secret;
import io.jenkins.plugins.openmfa.base.MFAContext;
import io.jenkins.plugins.openmfa.service.TOTPService;
import io.jenkins.plugins.openmfa.util.SecurityUtil;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.logging.Level;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.java.Log;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.Stapler;

/**
 * User property to store MFA secret and status. Factor mutations go through
 * methods that own epoch rotation and persistence; the raw
 * {@link #setSecret(Secret)} is a test fixture setter.
 */
@Log
@Getter
@Setter
public class MFAUserProperty extends UserProperty {

  private static final int MFA_EPOCH_BYTES = 16;

  private static final SecureRandom RANDOM = new SecureRandom();

  /**
   * Gets the MFA property for a user.
   *
   * @param user
   *          The user to get the property for.
   * @return The MFA property for the user, or null if not found.
   */
  @CheckForNull
  public static MFAUserProperty forUser(@Nullable User user) {
    if (user == null) {
      return null;
    }
    return user.getProperty(MFAUserProperty.class);
  }

  /**
   * Gets or creates the MFA property for a user.
   */
  @NonNull
  public static MFAUserProperty getOrCreate(User user) throws IOException {
    MFAUserProperty property = forUser(user);
    if (property == null) {
      property = new MFAUserProperty();
      property.setUser(user);
      user.addProperty(property);
    }
    return property;
  }

  /**
   * MFA "generation"; rotating it invalidates remember-MFA tokens issued
   * before. No Lombok accessors: they would bypass randomness, persistence
   * and synchronization.
   */
  @CheckForNull
  @Getter(AccessLevel.NONE)
  @Setter(AccessLevel.NONE)
  private String mfaEpoch;

  @CheckForNull
  @DataBoundSetter
  private Secret secret;

  @DataBoundConstructor
  public MFAUserProperty() {
  }

  public MFAUserProperty(Secret secret) {
    this.secret = secret;
  }

  /**
   * Removes the TOTP secret and rotates the epoch, in a single save.
   *
   * @throws IOException
   *           if persisting fails; propagated so the user can retry
   */
  public synchronized void clearAllFactors() throws IOException {
    secret = null;
    mfaEpoch = generateMfaEpoch();
    saveUser();
  }

  /**
   * Enrolls a TOTP secret, rotating the epoch on re-enrollment (invalidating
   * the old secret's remember-MFA cookies), in a single save.
   *
   * @throws IOException
   *           if persisting fails; propagated so the user can retry
   */
  public synchronized void enrollSecret(Secret newSecret) throws IOException {
    boolean reEnrollment = isEnabled();
    secret = newSecret;
    if (reEnrollment) {
      mfaEpoch = generateMfaEpoch();
    }
    saveUser();
  }

  /** Returns the MFA epoch, lazily generating and persisting one. */
  @NonNull
  public synchronized String getOrCreateMfaEpoch() {
    // Local variable lets SpotBugs prove the @NonNull contract.
    String epoch = mfaEpoch;
    if (epoch == null || epoch.isEmpty()) {
      epoch = generateMfaEpoch();
      mfaEpoch = epoch;
      saveUserQuietly();
    }
    return epoch;
  }

  @NonNull
  public String getSetupActionUrl() {
    return SecurityUtil.buildSetupURI(
      Stapler.getCurrentRequest2().getContextPath(),
      getUser().getId()
    );
  }

  public User getUser() {
    return super.user;
  }

  /**
   * Check if MFA is enabled for this user.
   */
  public boolean isEnabled() {
    return secret != null && !secret.getPlainText().isEmpty();
  }

  /** Rotates the MFA epoch, invalidating existing remember-MFA tokens. */
  public synchronized void rotateMfaEpoch() {
    mfaEpoch = generateMfaEpoch();
    saveUserQuietly();
  }

  /**
   * Verify a TOTP code for this user.
   */
  public boolean verifyCode(String code) {
    if (!isEnabled()) {
      return false;
    }
    return MFAContext.i()
      .getService(TOTPService.class)
      .verifyCode(secret, code);
  }

  private String generateMfaEpoch() {
    byte[] bytes = new byte[MFA_EPOCH_BYTES];
    RANDOM.nextBytes(bytes);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }

  /** Persists the owning user (if attached), propagating failures. */
  private void saveUser() throws IOException {
    User owner = getUser();
    if (owner != null) {
      owner.save();
    }
  }

  /**
   * Persists the owning user (if attached), logging failures; for background
   * bookkeeping where a lost write beats a broken request.
   */
  private void saveUserQuietly() {
    User owner = getUser();
    if (owner == null) {
      return;
    }
    try {
      owner.save();
    } catch (IOException e) {
      log.log(
        Level.SEVERE,
        "Failed to persist MFA epoch for user: " + owner.getId(),
        e
      );
    }
  }
}
