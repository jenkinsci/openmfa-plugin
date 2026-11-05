package io.jenkins.plugins.openmfa;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import org.htmlunit.html.HtmlCheckBoxInput;
import org.htmlunit.html.HtmlForm;
import org.htmlunit.html.HtmlPage;
import org.htmlunit.html.HtmlTextArea;
import org.htmlunit.html.HtmlTextInput;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

@WithJenkins
class MFAGlobalConfigurationTest {

  @Test
  void testConfigureRoundtripViaSecurityForm(JenkinsRule j) throws Exception {
    // Start from known defaults, distinct from what the form will submit,
    // so the assertions below can only pass if the jelly fields actually
    // exist and bind back to the configuration object.
    MFAGlobalConfiguration config = MFAGlobalConfiguration.get();
    config.setAllowWebAuthn(true);
    config.setWebAuthnRpId("");
    config.setWebAuthnAllowedOrigins(List.of());
    config.save();

    try (var wc = j.createWebClient()) {
      HtmlPage page = wc.goTo("configureSecurity");
      HtmlForm form = page.getFormByName("config");

      HtmlCheckBoxInput allowWebAuthnCheckbox =
        form.getInputByName("_.allowWebAuthn");
      allowWebAuthnCheckbox.setChecked(false);

      HtmlTextInput rpIdInput = form.getInputByName("_.webAuthnRpId");
      rpIdInput.setText("jenkins.example.com");

      HtmlTextArea originsTextArea =
        form.getTextAreaByName("_.webAuthnAllowedOrigins");
      originsTextArea.setText("https://jenkins.example.com");

      j.submit(form);
    }

    MFAGlobalConfiguration reloaded = MFAGlobalConfiguration.get();
    assertFalse(
      reloaded.isAllowWebAuthn(),
      "allowWebAuthn checkbox state should bind from the rendered form"
    );
    assertEquals(
      "jenkins.example.com",
      reloaded.getWebAuthnRpId(),
      "webAuthnRpId should bind from the rendered form"
    );
    assertEquals(
      List.of("https://jenkins.example.com"),
      reloaded.getWebAuthnAllowedOrigins(),
      "webAuthnAllowedOrigins should bind from the rendered form"
    );
  }

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
  void testIssuerConfigurationPersistence(JenkinsRule j) throws Exception {
    MFAGlobalConfiguration config = MFAGlobalConfiguration.get();
    assertEquals("Jenkins", config.getIssuer());

    config.setIssuer("  Prod Jenkins  ");
    assertEquals("Prod Jenkins", config.getIssuer());
    config.save();

    config.setIssuer("Temporary");
    config.load();
    assertEquals("Prod Jenkins", config.getIssuer());

    config.setIssuer("   ");
    assertEquals("Jenkins", config.getIssuer());
  }

  @Test
  void testRememberMfaHoursDefault(JenkinsRule j) throws Exception {
    MFAGlobalConfiguration config = MFAGlobalConfiguration.get();

    assertEquals(
      24, config.getRememberMfaHours(), "Default remember-MFA should be 24h"
    );
  }

  @Test
  void testWebAuthnConfigurationDefaults(JenkinsRule j) throws Exception {
    MFAGlobalConfiguration config = MFAGlobalConfiguration.get();

    assertTrue(config.isAllowWebAuthn(), "WebAuthn should be allowed by default");
    assertEquals("", config.getWebAuthnRpId(), "Default rpId should be unset");
    assertTrue(
      config.getWebAuthnAllowedOrigins().isEmpty(),
      "Default allowed origins should be empty"
    );
  }
}
