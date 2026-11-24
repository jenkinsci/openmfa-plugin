package io.jenkins.plugins.openmfa.util;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import io.jenkins.plugins.openmfa.constant.PluginConstants;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletResponse;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.java.Log;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.StaplerRequest2;
import org.kohsuke.stapler.StaplerResponse2;

/**
 * HTTP plumbing for the WebAuthn endpoints: size-capped body reading (one cap
 * for all attacker-reachable endpoints) and JSON responses.
 */
@Log
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class WebAuthnHttpUtil {

  private static final String CONTENT_TYPE_JSON = "application/json;charset=UTF-8";

  private static final ObjectMapper MAPPER = new ObjectMapper();

  /** {@code 200 application/json} with the given fields. */
  @NonNull
  public static HttpResponse json(Map<String, String> body) {
    return respond(HttpServletResponse.SC_OK, serialize(body, "{}"));
  }

  /** {@code 200 application/json} with a pre-rendered JSON string. */
  @NonNull
  public static HttpResponse json(String json) {
    return respond(HttpServletResponse.SC_OK, json);
  }

  /**
   * {@code {"error": "<code>"}} with the given status. Codes are fixed
   * machine-readable values: never prose, user input, or configuration detail.
   */
  @NonNull
  public static HttpResponse jsonError(int status, String code) {
    return respond(
      status, serialize(Map.of("error", code), "{\"error\":\"refused\"}")
    );
  }

  /** Parses a JSON object body; {@code null} (never throws) if it is not one. */
  @CheckForNull
  public static JsonNode parseJsonObject(String body) {
    try {
      JsonNode parsed = MAPPER.readTree(body);
      return parsed != null && parsed.isObject() ? parsed : null;
    } catch (IOException e) {
      return null;
    }
  }

  /**
   * Reads a ceremony body, enforcing
   * {@link PluginConstants.WebAuthn#MAX_RESPONSE_BYTES} while streaming.
   *
   * @return the UTF-8 body, or {@code null} (never throws) if unreadable or
   *         over the cap
   */
  @CheckForNull
  public static String readCeremonyBody(StaplerRequest2 req) {
    try (ServletInputStream in = req.getInputStream()) {
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      byte[] buffer = new byte[8192];
      int total = 0;
      int read;
      while ((read = in.read(buffer)) != -1) {
        total += read;
        if (total > PluginConstants.WebAuthn.MAX_RESPONSE_BYTES) {
          log.warning("Rejecting oversized WebAuthn ceremony request body");
          return null;
        }
        out.write(buffer, 0, read);
      }
      return out.toString(StandardCharsets.UTF_8);
    } catch (IOException e) {
      log.warning(
        "Failed to read WebAuthn ceremony request body: " + e.getMessage()
      );
      return null;
    }
  }

  /** Writes a JSON response with the given status. */
  @NonNull
  private static HttpResponse respond(int status, String body) {
    return new HttpResponse() {

      @Override
      public void generateResponse(
        StaplerRequest2 req, StaplerResponse2 rsp, Object node)
        throws IOException, ServletException {
        rsp.setStatus(status);
        rsp.setContentType(CONTENT_TYPE_JSON);
        PrintWriter writer = rsp.getWriter();
        writer.print(body);
        writer.flush();
      }
    };
  }

  /** Serializes to JSON, using {@code fallback} on (impossible) failure. */
  @NonNull
  private static String serialize(Map<String, String> body, String fallback) {
    try {
      return MAPPER.writeValueAsString(body);
    } catch (IOException e) {
      return fallback;
    }
  }
}
