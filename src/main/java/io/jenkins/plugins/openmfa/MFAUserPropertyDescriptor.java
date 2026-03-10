package io.jenkins.plugins.openmfa;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.model.User;
import hudson.model.UserPropertyDescriptor;
import hudson.model.userproperty.UserPropertyCategory;

/**
 * Descriptor for {@link MFAUserProperty}.
 */
@Extension
public class MFAUserPropertyDescriptor extends UserPropertyDescriptor {

  public MFAUserPropertyDescriptor() {
    super(MFAUserProperty.class);
  }

  @NonNull
  @Override
  public String getDisplayName() {
    return Messages.DisplayNames_MULTI_FACTOR_AUTHENTICATION();
  }

  @NonNull
  @Override
  public UserPropertyCategory getUserPropertyCategory() {
    return UserPropertyCategory.get(UserPropertyCategory.Security.class);
  }

  @Override
  public boolean isEnabled() {
    // This property is always available but configured through the user's security
    // page.
    return true;
  }

  @Override
  public MFAUserProperty newInstance(User user) {
    return new MFAUserProperty();
  }
}
