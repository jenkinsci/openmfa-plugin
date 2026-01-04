package io.jenkins.plugins.openmfa;

import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.model.User;
import hudson.model.UserProperty;
import hudson.model.UserPropertyDescriptor;
import hudson.util.Secret;
import io.jenkins.plugins.openmfa.base.MFAContext;
import io.jenkins.plugins.openmfa.constant.UIConstants;
import io.jenkins.plugins.openmfa.service.TOTPService;
import java.io.IOException;
import lombok.Getter;
import lombok.Setter;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;

/**
 * User property to store MFA secret and status.
 */
@Getter
@Setter
public class MFAUserProperty extends UserProperty {

    @CheckForNull
    @DataBoundSetter
    private Secret secret;

    @DataBoundSetter
    private boolean enabled = UIConstants.Defaults.DEFAULT_MFA_ENABLED;

    @DataBoundConstructor
    public MFAUserProperty() {
        this.enabled = UIConstants.Defaults.DEFAULT_MFA_ENABLED;
    }

    public MFAUserProperty(Secret secret, boolean enabled) {
        this.secret = secret;
        this.enabled = enabled;
    }

    /**
     * Check if MFA is configured for this user.
     */
    public boolean isConfigured() {
        return secret != null && !Secret.toString(secret).isEmpty();
    }

    /**
     * Verify a TOTP code for this user.
     */
    public boolean verifyCode(String code) {
        if (!isConfigured() || !enabled) {
            return false;
        }
        TOTPService totpService = MFAContext.i().getService(TOTPService.class);
        return totpService.verifyCode(Secret.toString(secret), code);
    }

    /**
     * Gets the MFA property for a user, or null if not found.
     */
    @CheckForNull
    public static MFAUserProperty forUser(User user) {
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
            user.addProperty(property);
        }
        return property;
    }

    @Extension
    public static class DescriptorImpl extends UserPropertyDescriptor {

        @NonNull
        @Override
        public String getDisplayName() {
            return UIConstants.DisplayNames.MULTI_FACTOR_AUTHENTICATION;
        }

        @Override
        public boolean isEnabled() {
            // This property is always available but configured through the user's security
            // page
            return true;
        }

        @Override
        public MFAUserProperty newInstance(User user) {
            return new MFAUserProperty();
        }
    }
}
