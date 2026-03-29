package io.jenkins.plugins.openmfa;

import static org.junit.jupiter.api.Assertions.*;

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
    config.setExemptUsers("svc-account1\nsvc-account2");
    config.setExemptRoles("ci-agents\nservice-accounts");
    config.save();

    // Reload and verify
    MFAGlobalConfiguration loaded = MFAGlobalConfiguration.get();
    assertEquals("svc-account1\nsvc-account2", loaded.getExemptUsers());
    assertEquals("ci-agents\nservice-accounts", loaded.getExemptRoles());
  }
}
