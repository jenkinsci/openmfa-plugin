package io.jenkins.plugins.openmfa.service;

import io.jenkins.plugins.openmfa.base.Inject;
import io.jenkins.plugins.openmfa.base.Service;

/**
 * Example service that demonstrates dependency injection.
 * This service depends on TOTPService which will be automatically injected.
 */
@Service
public class VerificationService {

    @Inject
    private TOTPService totpService;

    public VerificationService() {
        // Default constructor for service instantiation
    }

    /**
     * Verifies a user's MFA code.
     *
     * @param username the username
     * @param secret the user's secret key
     * @param code the code to verify
     * @return true if verification succeeds, false otherwise
     */
    public boolean verifyUser(String username, String secret, String code) {
        if (username == null || secret == null || code == null) {
            return false;
        }

        // Use the injected TOTPService
        return totpService.validateTOTP(secret, code);
    }

    /**
     * Gets the TOTP service (for testing or direct access).
     *
     * @return the injected TOTP service
     */
    public TOTPService getTotpService() {
        return totpService;
    }
}
