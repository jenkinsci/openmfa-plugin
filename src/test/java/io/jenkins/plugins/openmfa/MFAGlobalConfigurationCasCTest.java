package io.jenkins.plugins.openmfa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.jenkins.plugins.casc.ConfigurationAsCode;
import io.jenkins.plugins.casc.ConfiguratorException;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

/**
 * Tests that the plugin's global configuration binds correctly from
 * JCasC yaml, using the upstream-compatible shape (list-valued
 * exemptions).
 */
@WithJenkins
class MFAGlobalConfigurationCasCTest {

  /**
   * The deployment yaml (upstream-style lists for exemptions, remember-MFA
   * settings included) applies cleanly and lands in the configuration.
   */
  @Test
  void testAppliesConfiguration(JenkinsRule j) throws Exception {
    applyCasC("casc-openmfa.yaml");

    MFAGlobalConfiguration config = MFAGlobalConfiguration.get();
    assertEquals("Jenkins", config.getIssuer());
    assertTrue(config.isRequireMFA(), "requireMFA should bind");
    assertEquals(
      5, config.getRememberMfaHours(), "rememberMfaHours should bind"
    );
    assertEquals(
      "test-signing-key",
      config.getRememberMfaKey().getPlainText(),
      "rememberMfaKey should bind as a Secret"
    );
    assertEquals(
      List.of("svc-deploy", "break-glass"),
      config.getExemptUsers(),
      "exemptUsers should bind as a list"
    );
    assertEquals(
      List.of("ci-agents", "service-accounts"),
      config.getExemptRoles(),
      "exemptRoles should bind as a list"
    );
  }

  private void applyCasC(String resource) throws ConfiguratorException {
    ConfigurationAsCode.get()
      .configure(getClass().getResource(resource).toExternalForm());
  }
}
