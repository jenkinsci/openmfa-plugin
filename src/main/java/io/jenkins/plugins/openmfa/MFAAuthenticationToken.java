package io.jenkins.plugins.openmfa;

import java.util.Collection;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

/**
 * Authentication token that includes TOTP code for MFA.
 */
@Getter
@EqualsAndHashCode(callSuper = true)
public class MFAAuthenticationToken extends UsernamePasswordAuthenticationToken {

  private final String totpCode;

  public MFAAuthenticationToken(String username, String password, String totpCode) {
    super(username, password);
    this.totpCode = totpCode;
  }

  public MFAAuthenticationToken(
    Object principal, Object credentials, String totpCode,
    Collection<? extends GrantedAuthority> authorities) {
    super(principal, credentials, authorities);
    this.totpCode = totpCode;
  }
}
