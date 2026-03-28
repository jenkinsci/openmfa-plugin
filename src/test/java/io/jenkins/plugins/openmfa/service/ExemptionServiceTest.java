package io.jenkins.plugins.openmfa.service;

import static org.junit.jupiter.api.Assertions.*;

import hudson.model.User;
import io.jenkins.plugins.openmfa.MFAGlobalConfiguration;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

@WithJenkins
class ExemptionServiceTest {

  private MFAGlobalConfiguration config;
  private ExemptionService exemptionService;

  @BeforeEach
  void setUp(JenkinsRule j) {
    exemptionService = new ExemptionService();
    config = MFAGlobalConfiguration.get();
  }

  @Test
  void testUserExemptByRole(JenkinsRule j) throws Exception {
    config.setExemptRoles("admin\nci-agents");
    User user = User.getById("adminuser", true);
    // User has no roles assigned yet in test environment
    assertFalse(exemptionService.isExempt(user));
  }

  @Test
  void testUserExemptByUsername(JenkinsRule j) throws Exception {
    config.setExemptUsers("testuser\nexemptuser");
    User user = User.getById("testuser", true);
    assertTrue(exemptionService.isExempt(user));
  }

  @Test
  void testUserExemptByUsernameCaseInsensitive(JenkinsRule j) throws Exception {
    config.setExemptUsers("TESTUSER");
    User user = User.getById("testuser", true);
    assertTrue(exemptionService.isExempt(user));
  }

  @Test
  void testUserNotExemptByUsername(JenkinsRule j) throws Exception {
    config.setExemptUsers("otheruser");
    User user = User.getById("testuser", true);
    assertFalse(exemptionService.isExempt(user));
  }

  @Test
  void testUserNotExemptWhenListsEmpty(JenkinsRule j) throws Exception {
    User user = User.getById("testuser", true);
    assertFalse(exemptionService.isExempt(user));
  }
}
