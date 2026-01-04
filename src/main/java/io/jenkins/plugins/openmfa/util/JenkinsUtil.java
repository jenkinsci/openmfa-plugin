package io.jenkins.plugins.openmfa.util;

import hudson.model.User;
import hudson.util.VersionNumber;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import jenkins.model.Jenkins;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class JenkinsUtil {

    private static final List<String> JENKINS_ROOT_URL_IGNORE_PATHS = Arrays.asList(
            "/logout",
            "/login",
            "/adjuncts",
            "/static",
            ".css",
            ".js",
            "PopupContent",
            "/ajaxBuildQueue",
            "/ajaxExecutors",
            "/descriptorByName",
            "/checkPluginUrl",
            "/log",
            "/theme-dark",
            "/resourceBundle",
            "/favicon.ico");

    public static Optional<Jenkins> getJenkins() {
        return Optional.ofNullable(Jenkins.getInstanceOrNull());
    }

    public static Optional<VersionNumber> getJenkinsVersion() {
        return getJenkins().map(j -> Jenkins.getVersion());
    }

    public static Optional<String> getJenkinsRootUrl() {
        return getJenkins().map(Jenkins::getRootUrl);
    }

    /**
     * Gets the {@link User} object representing the currently logged-in user, or
     * null if the current user is anonymous.
     */
    public static Optional<User> getCurrentUser() {
        return Optional.ofNullable(User.current());
    }
}
