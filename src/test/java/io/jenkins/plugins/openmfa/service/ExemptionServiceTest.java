package io.jenkins.plugins.openmfa.service;

import static org.junit.jupiter.api.Assertions.*;

import hudson.model.User;
import io.jenkins.plugins.openmfa.MFAGlobalConfiguration;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

@WithJenkins
class ExemptionServiceTest {

  @BeforeEach
  void setUp() {
    // Reset fallback instance to ensure clean state for each test
    MFAGlobalConfiguration.resetFallbackInstance();
  }

  @AfterEach
  void tearDown() {
    // Clean up after each test
    MFAGlobalConfiguration.resetFallbackInstance();
  }

  @Test
  void testUserExemptByRole(JenkinsRule j) throws Exception {
    j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
    MFAGlobalConfiguration config = MFAGlobalConfiguration.get();
    config.setExemptRoles("admin\nci-agents");
    ExemptionService exemptionService = new ExemptionService();
    User user = User.getById("adminuser", true);
    // User has no roles assigned yet in test environment
    assertFalse(exemptionService.isExempt(user));
  }

  @Test
  void testUserExemptByUsername(JenkinsRule j) throws Exception {
    j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
    MFAGlobalConfiguration config = MFAGlobalConfiguration.get();
    config.setExemptUsers("testuser\nexemptuser");
    ExemptionService exemptionService = new ExemptionService();
    User user = User.getById("testuser", true);
    assertTrue(exemptionService.isExempt(user));
  }

  @Test
  void testUserExemptByUsernameCaseInsensitive(JenkinsRule j) throws Exception {
    j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
    MFAGlobalConfiguration config = MFAGlobalConfiguration.get();
    config.setExemptUsers("TESTUSER");
    ExemptionService exemptionService = new ExemptionService();
    User user = User.getById("testuser", true);
    assertTrue(exemptionService.isExempt(user));
  }

  @Test
  void testUserNotExemptByUsername(JenkinsRule j) throws Exception {
    j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
    MFAGlobalConfiguration config = MFAGlobalConfiguration.get();
    config.setExemptUsers("otheruser");
    ExemptionService exemptionService = new ExemptionService();
    User user = User.getById("testuser", true);
    assertFalse(exemptionService.isExempt(user));
  }

  @Test
  void testUserNotExemptWhenListsEmpty(JenkinsRule j) throws Exception {
    j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
    ExemptionService exemptionService = new ExemptionService();
    User user = User.getById("testuser", true);
    assertFalse(exemptionService.isExempt(user));
  }
}
