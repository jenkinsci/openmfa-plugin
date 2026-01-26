package io.jenkins.plugins.openmfa;

import java.util.ArrayList;
import java.util.List;

import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.model.Descriptor;
import hudson.model.User;
import hudson.security.SecurityRealm;
import io.jenkins.plugins.openmfa.constant.UIConstants;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.java.Log;

/**
 * Security realm that wraps another realm (like LDAP) and adds MFA support.
 */
@Getter
@Setter
public class MFASecurityRealm extends SecurityRealm {

  @DataBoundSetter
  private SecurityRealm delegate;

  @DataBoundSetter
  private boolean requireMFA = UIConstants.Defaults.DEFAULT_REQUIRE_MFA;

  @DataBoundSetter
  private String issuer = UIConstants.Defaults.DEFAULT_ISSUER;

  @DataBoundConstructor
  public MFASecurityRealm(SecurityRealm delegate) {
    this.delegate = delegate;
    this.requireMFA = UIConstants.Defaults.DEFAULT_REQUIRE_MFA;
    this.issuer = UIConstants.Defaults.DEFAULT_ISSUER;
  }

  @Override
  public SecurityComponents createSecurityComponents() {
    SecurityComponents delegateComponents = delegate.createSecurityComponents();

    AuthenticationManager authManager =
      new MFAAuthenticationManager(delegateComponents.manager2, requireMFA);

    return new SecurityComponents(authManager, delegateComponents.userDetails2);
  }

  @Override
  public UserDetails loadUserByUsername2(String username)
    throws UsernameNotFoundException {
    return delegate.loadUserByUsername2(username);
  }

  @Override
  public hudson.security.GroupDetails loadGroupByGroupname2(
    String groupname, boolean includeChildren)
    throws UsernameNotFoundException {
    return delegate.loadGroupByGroupname2(groupname, true);
  }

  /**
   * Custom authentication manager that verifies MFA after successful primary
   * authentication.
   */
  @Log
  private static class MFAAuthenticationManager implements AuthenticationManager {

    private final AuthenticationManager delegate;
    private final boolean requireMFA;

    MFAAuthenticationManager(AuthenticationManager delegate, boolean requireMFA) {
      this.delegate = delegate;
      this.requireMFA = requireMFA;
    }

    @Override
    public Authentication authenticate(Authentication authentication)
      throws AuthenticationException {
      // First, authenticate with the underlying realm (e.g., LDAP)
      Authentication delegateAuth = delegate.authenticate(authentication);

      if (delegateAuth == null || !delegateAuth.isAuthenticated()) {
        return delegateAuth;
      }

      // Check if MFA token is provided
      if (authentication instanceof MFAAuthenticationToken) {
        MFAAuthenticationToken mfaToken = (MFAAuthenticationToken) authentication;
        String totpCode = mfaToken.getTotpCode();

        // Get user and check MFA
        User user = User.getById(delegateAuth.getName(), false);
        if (user != null) {
          MFAUserProperty mfaProperty = MFAUserProperty.forUser(user);

          if (
            mfaProperty != null
              && mfaProperty.isEnabled()
              && mfaProperty.isConfigured()
          ) {
            // MFA is enabled, verify code
            if (totpCode == null || totpCode.isEmpty()) {
              log.warning(
                String.format(
                  "MFA required but no TOTP code provided for user: %s", user.getId()
                )
              );
              throw new BadCredentialsException("MFA code required");
            }

            if (!mfaProperty.verifyCode(totpCode)) {
              log.warning(
                String.format("Invalid MFA code for user: %s", user.getId())
              );
              throw new BadCredentialsException("Invalid MFA code");
            }

            log.info(
              String.format("MFA verification successful for user: %s", user.getId())
            );
          } else if (requireMFA) {
            // MFA is required but not configured
            log.warning(
              String.format(
                "MFA required but not configured for user: %s", user.getId()
              )
            );
            throw new BadCredentialsException("MFA must be configured");
          }
        }
      } else {
        // Not an MFA token, check if MFA is required
        User user = User.getById(delegateAuth.getName(), false);
        if (user != null) {
          MFAUserProperty mfaProperty = MFAUserProperty.forUser(user);
          if (
            (mfaProperty != null && mfaProperty.isEnabled()
              && mfaProperty.isConfigured()) || requireMFA
          ) {
            throw new BadCredentialsException("MFA code required");
          }
        }
      }

      return delegateAuth;
    }
  }

  @Extension
  public static class DescriptorImpl extends Descriptor<SecurityRealm> {

    @NonNull
    @Override
    public String getDisplayName() {
      return UIConstants.DisplayNames.MFA_SECURITY_REALM;
    }

    /**
     * Get the default issuer name (for Jelly views).
     */
    public String getDefaultIssuer() {
      return UIConstants.Defaults.DEFAULT_ISSUER;
    }

    /**
     * Get all available security realm descriptors except this one.
     */
    public List<Descriptor<SecurityRealm>> getAllDescriptors() {
      List<Descriptor<SecurityRealm>> descriptors = new ArrayList<>();
      for (Descriptor<SecurityRealm> d : SecurityRealm.all()) {
        if (d != this) {
          descriptors.add(d);
        }
      }
      return descriptors;
    }
  }
}
