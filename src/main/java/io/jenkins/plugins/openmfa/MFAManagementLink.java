package io.jenkins.plugins.openmfa;

import hudson.Extension;
import hudson.model.ManagementLink;
import hudson.model.User;
import hudson.security.Permission;
import io.jenkins.plugins.openmfa.base.MFAContext;
import io.jenkins.plugins.openmfa.constant.PluginConstants;
import io.jenkins.plugins.openmfa.constant.UIConstants;
import io.jenkins.plugins.openmfa.service.UserService;
import io.jenkins.plugins.openmfa.service.model.UserInfo;
import io.jenkins.plugins.openmfa.util.JenkinsUtil;
import io.jenkins.plugins.openmfa.util.SecurityUtil;
import java.io.IOException;
import java.util.Collection;
import jenkins.model.Jenkins;
import lombok.extern.java.Log;
import org.kohsuke.stapler.Header;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.HttpResponses;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.Stapler;
import org.kohsuke.stapler.interceptor.RequirePOST;

/**
 * Management link providing the MFA Management dashboard on the Manage Jenkins
 * page.
 * Allows admins to view all users' MFA status and reset MFA for users.
 */
@Log
@Extension
public class MFAManagementLink extends ManagementLink {

  /**
   * Resets MFA for a specific user.
   *
   * @param userId
   *          The ID of the user to reset MFA for
   * @return HTTP response indicating success or failure
   */
  @RequirePOST
  public HttpResponse doResetMFA(
    @QueryParameter String userId,
    @Header("X-Requested-With") String requestedWith) {
    checkAdminPermission();

    if (userId == null || userId.trim().isEmpty()) {
      return HttpResponses.error(
        UIConstants.HttpStatus.BAD_REQUEST,
        "User ID is required"
      );
    }

    User user = User.getById(userId, false);
    if (user == null) {
      return HttpResponses.error(
        UIConstants.HttpStatus.NOT_FOUND,
        "User not found: " + userId
      );
    }

    try {
      UserService userService = MFAContext.i().getService(UserService.class);
      userService.resetMFA(user);
      log.info(String.format("Admin reset MFA for user: %s", userId));

      if ("XMLHttpRequest".equals(requestedWith)) {
        return HttpResponses.ok();
      }
      return HttpResponses.redirectTo(".?success=reset_mfa&user_id=" + userId);
    } catch (IOException e) {
      log.severe(
        String.format("Failed to reset MFA for user %s: %s", userId, e.getMessage())
      );
      return HttpResponses.error(
        UIConstants.HttpStatus.INTERNAL_SERVER_ERROR,
        "Failed to reset MFA: " + e.getMessage()
      );
    }
  }

  /**
   * Redirects to the user's MFA setup page.
   *
   * @param userId
   *          The ID of the user to modify MFA for
   * @return HTTP response to redirect to user's MFA setup page
   */
  @RequirePOST
  public HttpResponse doSetMFA(@QueryParameter String userId) {
    checkAdminPermission();

    if (userId == null || userId.trim().isEmpty()) {
      return HttpResponses.error(
        UIConstants.HttpStatus.BAD_REQUEST,
        "User ID is required"
      );
    }

    User user = User.getById(userId, false);
    if (user == null) {
      return HttpResponses.error(
        UIConstants.HttpStatus.NOT_FOUND,
        "User not found: " + userId
      );
    }

    // Redirect to the user's MFA setup page
    return HttpResponses.redirectTo(
      SecurityUtil.buildSetupURI(
        Stapler.getCurrentRequest2().getContextPath(),
        userId
      )
    );
  }

  /**
   * Gets all users with their MFA status.
   * Called from Jelly view.
   *
   * @return Collection of UserMFAInfo objects
   */
  public Collection<UserInfo> getAllUsers() {
    checkAdminPermission();
    UserService userService = MFAContext.i().getService(UserService.class);
    return userService.getAllUsersWithMFAStatus();
  }

  @Override
  public Category getCategory() {
    return Category.SECURITY;
  }

  @Override
  public String getDescription() {
    return Messages.MFAManagementLink_description();
  }

  @Override
  public String getDisplayName() {
    return Messages.DisplayNames_MFA_USER_MANAGEMENT();
  }

  /**
   * Gets the count of users with MFA enabled.
   *
   * @return Number of users with MFA enabled
   */
  public long getEnabledCount() {
    checkAdminPermission();
    UserService userService = MFAContext.i().getService(UserService.class);
    return userService.getEnabledMFACount();
  }

  @Override
  public String getIconFileName() {
    return "symbol-id-card";
  }

  @Override
  public Permission getRequiredPermission() {
    return Jenkins.ADMINISTER;
  }

  /**
   * Builds the MFA setup URI for a user.
   *
   * @param userId
   *          The user ID.
   * @return The setup URI for the user.
   */
  public String getSetupUri(String userId) {
    return SecurityUtil.buildSetupURI(
      Stapler.getCurrentRequest2().getContextPath(),
      userId
    );
  }

  /**
   * Gets the total number of users.
   *
   * @return Total user count
   */
  public long getTotalCount() {
    checkAdminPermission();
    UserService userService = MFAContext.i().getService(UserService.class);
    return userService.getTotalUserCount();
  }

  @Override
  public String getUrlName() {
    return PluginConstants.Urls.MANAGEMENT_ACTION_URL;
  }

  /**
   * Checks if the current user has admin permission.
   * Throws AccessDeniedException if not.
   */
  private void checkAdminPermission() {
    JenkinsUtil.checkAdminPermission();
  }
}
