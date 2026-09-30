package io.jenkins.plugins.openmfa;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

@WithJenkins
class MFAGlobalConfigurationTest {

  @Test
  void testExemptionConfigurationDefaults(JenkinsRule j) throws Exception {
    MFAGlobalConfiguration config = MFAGlobalConfiguration.get();

    assertTrue(config.getExemptUsers().isEmpty());
    assertTrue(config.getExemptRoles().isEmpty());
  }

  @Test
  void testExemptionConfigurationPersistence(JenkinsRule j) throws Exception {
    MFAGlobalConfiguration config = MFAGlobalConfiguration.get();

    // Configure exemptions
    config.setExemptUsers(List.of("svc-account1", "svc-account2"));
    config.setExemptRoles(List.of("ci-agents", "service-accounts"));
    config.save();

    // Reload and verify
    MFAGlobalConfiguration loaded = MFAGlobalConfiguration.get();
    assertEquals(
      List.of("svc-account1", "svc-account2"), loaded.getExemptUsers()
    );
    assertEquals(
      List.of("ci-agents", "service-accounts"), loaded.getExemptRoles()
    );
  }

  @Test
  void testExemptionTextFormForUI(JenkinsRule j) throws Exception {
    MFAGlobalConfiguration config = MFAGlobalConfiguration.get();

    config.setExemptUsers(List.of("svc-account1", "svc-account2"));

    assertEquals(
      "svc-account1\nsvc-account2",
      config.getExemptUsersText(),
      "UI textarea should see one entry per line"
    );
  }

  @Test
  void testRememberMfaHoursDefault(JenkinsRule j) throws Exception {
    MFAGlobalConfiguration config = MFAGlobalConfiguration.get();

    assertEquals(
      24, config.getRememberMfaHours(), "Default remember-MFA should be 24h"
    );
  }
}
