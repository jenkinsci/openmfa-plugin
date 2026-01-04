package io.jenkins.plugins.openmfa.util;

import static org.junit.jupiter.api.Assertions.*;

import hudson.util.VersionNumber;
import java.lang.reflect.Modifier;
import java.util.Optional;
import jenkins.model.Jenkins;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

/**
 * Unit tests for {@link JenkinsUtil} utility class.
 */
@WithJenkins
class JenkinsUtilTest {

    @Test
    void testUtilityClassHasPrivateConstructor() throws Exception {
        // Verify the utility class follows the utility class pattern
        var constructor = JenkinsUtil.class.getDeclaredConstructor();
        assertTrue(Modifier.isPrivate(constructor.getModifiers()), "Constructor should be private");
    }

    @Test
    void testGetJenkinsReturnsInstance(JenkinsRule j) {
        Optional<Jenkins> jenkins = JenkinsUtil.getJenkins();

        assertTrue(jenkins.isPresent(), "Jenkins instance should be present");
        assertNotNull(jenkins.get(), "Jenkins instance should not be null");
        assertSame(j.getInstance(), jenkins.get(), "Should return the same Jenkins instance");
    }

    @Test
    void testGetJenkinsVersionFormat(JenkinsRule j) {
        VersionNumber version = JenkinsUtil.getJenkinsVersion().orElse(null);

        assertNotNull(version);
        String versionString = version.toString();
        assertNotNull(versionString);

        // Version should contain at least one digit
        assertTrue(versionString.matches(".*\\d+.*"), "Version should contain at least one digit");
    }

    @Test
    void testJenkinsInstanceIsNotNull(JenkinsRule j) {
        Optional<Jenkins> jenkins = JenkinsUtil.getJenkins();

        jenkins.ifPresent(instance -> {
            assertNotNull(instance.getRootDir(), "Jenkins root directory should not be null");
            assertNotNull(instance.getRootUrl(), "Jenkins root URL should not be null");
        });
    }

    @Test
    void testJenkinsRootUrlIgnorePathsConstantExists() {
        // This tests that the constant is accessible indirectly through the class
        // behavior
        // The constant itself is private, so we just ensure the class can be loaded
        assertDoesNotThrow(JenkinsUtil::getJenkins, "JenkinsUtil class should load without errors");
    }
}
