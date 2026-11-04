package io.jenkins.plugins.openmfa;

import hudson.model.User;
import hudson.security.csrf.CrumbIssuer;
import io.jenkins.plugins.openmfa.base.MFAException;
import io.jenkins.plugins.openmfa.service.WebAuthnService;
import io.jenkins.plugins.openmfa.service.model.WebAuthnCredential;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.net.URL;
import java.time.Instant;
import org.htmlunit.HttpMethod;
import org.htmlunit.Page;
import org.htmlunit.WebRequest;
import org.htmlunit.html.HtmlElement;
import org.htmlunit.html.HtmlPage;
import org.jvnet.hudson.test.JenkinsRule;

/** Shared WebAuthn test scaffolding: stub service, POST helper, fixtures. */
final class WebAuthnTestSupport {

  /**
   * Finds an element by id via XPath, returning {@code null} instead of
   * throwing when it is not present (unlike {@link HtmlPage#getElementById}).
   */
  static HtmlElement findById(HtmlPage page, String id) {
    return page.getFirstByXPath("//*[@id='" + id + "']");
  }

  /**
   * POSTs a crumb-protected request to the given path, optionally with a raw
   * JSON body.
   */
  static Page postWithCrumb(
    JenkinsRule j, JenkinsRule.WebClient wc, String path, String body)
    throws Exception {
    WebRequest request = new WebRequest(new URL(j.getURL(), path), HttpMethod.POST);
    CrumbIssuer crumbIssuer = j.jenkins.getCrumbIssuer();
    if (crumbIssuer != null) {
      request
        .setAdditionalHeader(
          crumbIssuer.getCrumbRequestField(),
          crumbIssuer.getCrumb((ServletRequest) null)
        );
    }
    if (body != null) {
      request.setAdditionalHeader("Content-Type", "application/json");
      request.setRequestBody(body);
    }
    return wc.getPage(request);
  }

  /**
   * A registered credential fixture: {@code cred-<name>} /
   * {@code cose-<name>}, labelled {@code Test key <name>}, never used yet.
   */
  static WebAuthnCredential testCredential(String name) {
    return new WebAuthnCredential(
      "cred-" + name,
      "cose-" + name,
      0,
      "Test key " + name,
      Instant.now().toString(),
      null
    );
  }

  private WebAuthnTestSupport() {
  }

  /**
   * Stub {@link WebAuthnService}: canned start options, real-like registration
   * persistence (cap included), configurable assertion outcome. Always
   * available; tests disable WebAuthn globally instead.
   */
  static final class FakeWebAuthnService extends WebAuthnService {

    private boolean assertionResult = true;

    private final String optionsJson;

    FakeWebAuthnService(String optionsJson) {
      this.optionsJson = optionsJson;
    }

    @Override
    public boolean finishAssertion(
      HttpSession session, User user, String responseJson) {
      return assertionResult;
    }

    @Override
    public WebAuthnCredential finishRegistration(
      HttpSession session, User user, String responseJson, String name) {
      WebAuthnCredential credential =
        new WebAuthnCredential(
          "fake-cred-" + user.getId(),
          "fake-cose",
          0,
          name,
          Instant.now().toString(),
          null
        );
      boolean stored;
      try {
        stored = MFAUserProperty.getOrCreate(user).addWebAuthnCredential(credential);
      } catch (IOException e) {
        throw new IllegalStateException(e);
      }
      if (!stored) {
        throw new MFAException(
          "The security key was verified but not saved: this account already "
            + "holds the maximum number of security keys."
        );
      }
      return credential;
    }

    @Override
    public boolean isAvailable() {
      return true;
    }

    @Override
    public String startAssertion(HttpSession session, User user) {
      return optionsJson;
    }

    @Override
    public String startRegistration(HttpSession session, User user) {
      return optionsJson;
    }

    /**
     * Makes {@code finishAssertion} report a failed assertion.
     */
    FakeWebAuthnService assertionResult(boolean result) {
      this.assertionResult = result;
      return this;
    }
  }
}
