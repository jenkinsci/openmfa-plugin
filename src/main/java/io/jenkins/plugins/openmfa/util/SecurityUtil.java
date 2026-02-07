package io.jenkins.plugins.openmfa.util;

import io.jenkins.plugins.openmfa.constant.PluginConstants;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class SecurityUtil {

  /**
   * Builds the setup URI for a user.
   *
   * @param context
   *          The Jenkins context.
   * @param userId
   *          The user ID.
   * @return The setup URI.
   */
  public static String buildSetupURI(String context, String userId) {
    return String.format(
      "%s/user/%s/%s",
      context,
      URLEncoder.encode(userId, StandardCharsets.UTF_8),
      PluginConstants.Urls.SETUP_ACTION_URL
    );
  }

}
