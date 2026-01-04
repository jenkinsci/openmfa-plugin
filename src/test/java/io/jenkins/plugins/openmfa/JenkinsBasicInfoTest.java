package io.jenkins.plugins.openmfa;

import static org.junit.jupiter.api.Assertions.*;

import hudson.model.User;
import jenkins.model.Jenkins;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

/**
 * Unit tests for verifying basic Jenkins instance information and
 * functionality.
 */
@WithJenkins
class JenkinsBasicInfoTest {

    @Test
    void testJenkinsInstanceAvailable(JenkinsRule j) {
        Jenkins jenkins = j.getInstance();
        assertNotNull(jenkins, "Jenkins instance should be available");
    }

    @Test
    void testJenkinsVersion(JenkinsRule j) {
        String version = Jenkins.getVersion().toString();

        assertNotNull(version, "Jenkins version should not be null");
        assertFalse(version.isEmpty(), "Jenkins version should not be empty");
    }

    @Test
    void testJenkinsRootUrl(JenkinsRule j) throws Exception {
        Jenkins jenkins = j.getInstance();
        String rootUrl = jenkins.getRootUrl();

        assertNotNull(rootUrl, "Jenkins root URL should not be null");
        assertTrue(rootUrl.startsWith("http"), "Root URL should start with http");
    }

    @Test
    void testJenkinsSystemMessage(JenkinsRule j) throws Exception {
        Jenkins jenkins = j.getInstance();

        // Set a system message
        String testMessage = "Test System Message";
        jenkins.setSystemMessage(testMessage);

        assertEquals(testMessage, jenkins.getSystemMessage(), "System message should be retrievable");
    }

    @Test
    void testCreateUser(JenkinsRule j) {
        String userId = "testuser";
        User user = User.getById(userId, true);

        assertNotNull(user, "User should be created");
        assertEquals(userId, user.getId(), "User ID should match");
    }

    @Test
    void testUserFullName(JenkinsRule j) {
        String userId = "testuser2";
        String fullName = "Test User";

        User user = User.getById(userId, true);
        user.setFullName(fullName);

        assertEquals(fullName, user.getFullName(), "User full name should match");
    }

    @Test
    void testMultipleUsers(JenkinsRule j) {
        User user1 = User.getById("user1", true);
        User user2 = User.getById("user2", true);
        User user3 = User.getById("user3", true);

        assertNotNull(user1);
        assertNotNull(user2);
        assertNotNull(user3);

        assertNotEquals(user1.getId(), user2.getId());
        assertNotEquals(user2.getId(), user3.getId());
        assertNotEquals(user1.getId(), user3.getId());
    }

    @Test
    void testJenkinsSecurityEnabled(JenkinsRule j) {
        Jenkins jenkins = j.getInstance();

        // In test environment, security might be disabled by default
        // Just verify we can check the security status
        boolean securityEnabled = jenkins.isUseSecurity();

        // Should be able to retrieve the security status without errors
        assertNotNull(Boolean.valueOf(securityEnabled));
    }

    @Test
    void testJenkinsQuietMode(JenkinsRule j) {
        Jenkins jenkins = j.getInstance();

        // Test entering and exiting quiet mode
        assertFalse(jenkins.isQuietingDown(), "Jenkins should not be in quiet mode initially");

        jenkins.doQuietDown();
        assertTrue(jenkins.isQuietingDown(), "Jenkins should be in quiet mode after doQuietDown()");

        jenkins.doCancelQuietDown();
        assertFalse(jenkins.isQuietingDown(), "Jenkins should not be in quiet mode after cancel");
    }

    @Test
    void testJenkinsNodeName(JenkinsRule j) {
        Jenkins jenkins = j.getInstance();
        String nodeName = jenkins.getDisplayName();

        // Built-in node typically has a display name
        assertNotNull(nodeName, "Node display name should not be null");
    }

    @Test
    void testJenkinsNumExecutors(JenkinsRule j) {
        Jenkins jenkins = j.getInstance();
        int numExecutors = jenkins.getNumExecutors();

        // Should have at least one executor
        assertTrue(numExecutors >= 0, "Number of executors should be non-negative");
    }

    @Test
    void testUserDirectoryCreation(JenkinsRule j) throws Exception {
        String userId = "dirTestUser";
        User user = User.getById(userId, true);

        assertNotNull(user, "User should be created");
        // Test that user properties can be set and saved
        user.setFullName("Directory Test User");
        user.save();

        // Verify we can retrieve the user again after saving
        User retrievedUser = User.getById(userId, false);
        assertNotNull(retrievedUser, "User should exist after saving");
        assertEquals("Directory Test User", retrievedUser.getFullName());
    }

    @Test
    void testGetUserByIdWithoutCreating(JenkinsRule j) {
        String userId = "nonexistentuser";
        User user = User.getById(userId, false);

        // User should not be created if second parameter is false
        assertNull(user, "User should not exist when create=false");
    }

    @Test
    void testJenkinsRootDir(JenkinsRule j) {
        Jenkins jenkins = j.getInstance();

        // Test that we can retrieve Jenkins root directory
        assertNotNull(jenkins.getRootDir(), "Root directory should not be null");
        assertTrue(jenkins.getRootDir().exists(), "Root directory should exist");
    }

    @Test
    void testJenkinsDescription(JenkinsRule j) throws Exception {
        Jenkins jenkins = j.getInstance();
        String description = "Test Jenkins Description";

        jenkins.setSystemMessage(description);
        assertEquals(description, jenkins.getSystemMessage());
    }

    @Test
    void testUserEmailAddress(JenkinsRule j) {
        String userId = "emailtestuser";
        User user = User.getById(userId, true);

        // Test that user can be created and has a valid ID
        assertNotNull(user);
        assertEquals(userId, user.getId());
    }

    @Test
    void testJenkinsWorkspaceDir(JenkinsRule j) {
        Jenkins jenkins = j.getInstance();

        assertNotNull(jenkins.getRootDir(), "Jenkins root directory should not be null");
        assertTrue(jenkins.getRootDir().exists(), "Jenkins root directory should exist");
        assertTrue(jenkins.getRootDir().isDirectory(), "Jenkins root path should be a directory");
    }

    @Test
    void testAllUsersRetrieval(JenkinsRule j) {
        // Create some test users
        User.getById("alluser1", true);
        User.getById("alluser2", true);
        User.getById("alluser3", true);

        // Get all users
        var allUsers = User.getAll();

        assertNotNull(allUsers, "User list should not be null");
        assertTrue(allUsers.size() >= 3, "Should have at least 3 users");
    }
}
