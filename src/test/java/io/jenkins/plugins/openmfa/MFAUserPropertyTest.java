package io.jenkins.plugins.openmfa;

import static org.junit.jupiter.api.Assertions.*;

import hudson.model.User;
import hudson.util.Secret;
import io.jenkins.plugins.openmfa.base.MFAContext;
import io.jenkins.plugins.openmfa.service.TOTPService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

@WithJenkins
class MFAUserPropertyTest {

    private TOTPService totpService;

    @BeforeEach
    void setUp() {
        totpService = MFAContext.i().getService(TOTPService.class);
    }

    @Test
    void testDefaultState(JenkinsRule j) {
        MFAUserProperty property = new MFAUserProperty();

        assertFalse(property.isEnabled());
        assertFalse(property.isConfigured());
        assertNull(property.getSecret());
    }

    @Test
    void testEnableMFA(JenkinsRule j) {
        MFAUserProperty property = new MFAUserProperty();

        Secret secret = totpService.generateSecret();
        property.setSecret(secret);
        property.setEnabled(true);

        assertTrue(property.isEnabled());
        assertTrue(property.isConfigured());
        assertEquals(Secret.toString(secret), Secret.toString(property.getSecret()));
    }

    @Test
    void testVerifyCode(JenkinsRule j) {
        MFAUserProperty property = new MFAUserProperty();

        Secret secret = totpService.generateSecret();
        property.setSecret(secret);
        property.setEnabled(true);

        String code = totpService.generateTOTP(secret);
        assertTrue(property.verifyCode(code));
        assertFalse(property.verifyCode("000000"));
    }

    @Test
    void testVerifyCodeWhenDisabled(JenkinsRule j) {
        MFAUserProperty property = new MFAUserProperty();

        Secret secret = totpService.generateSecret();
        property.setSecret(secret);
        property.setEnabled(false); // MFA is disabled

        String code = totpService.generateTOTP(secret);
        assertFalse(property.verifyCode(code)); // Should fail when disabled
    }

    @Test
    void testVerifyCodeWhenNotConfigured(JenkinsRule j) {
        MFAUserProperty property = new MFAUserProperty();

        property.setEnabled(true);
        // No secret set

        assertFalse(property.verifyCode("123456")); // Should fail when not configured
    }

    @Test
    void testGetOrCreate(JenkinsRule j) throws Exception {
        User user = User.getById("testuser2", true);

        // Should create new property
        MFAUserProperty property1 = MFAUserProperty.getOrCreate(user);
        assertNotNull(property1);

        // Should return existing property
        MFAUserProperty property2 = MFAUserProperty.getOrCreate(user);
        assertNotNull(property2);
        assertEquals(property1, property2);
    }
}
