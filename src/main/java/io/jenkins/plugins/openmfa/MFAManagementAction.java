package io.jenkins.plugins.openmfa;

import java.io.IOException;
import java.util.Collection;

import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.HttpResponses;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.interceptor.RequirePOST;

import hudson.Extension;
import hudson.model.RootAction;
import hudson.model.User;
import io.jenkins.plugins.openmfa.base.MFAContext;
import io.jenkins.plugins.openmfa.constant.PluginConstants;
import io.jenkins.plugins.openmfa.constant.UIConstants;
import io.jenkins.plugins.openmfa.service.MFAUserService;
import io.jenkins.plugins.openmfa.service.model.UserMFAInfo;
import jenkins.model.Jenkins;
import lombok.extern.java.Log;

/**
 * Root action providing the MFA Management dashboard for administrators.
 * Allows admins to view all users' MFA status and reset MFA for users.
 */
@Log
@Extension
public class MFAManagementAction implements RootAction {

  @Override
  public String getIconFileName() {
    // Only show in sidebar for admins
    // if (Jenkins.get().hasPermission(Jenkins.ADMINISTER)) {
    //   return "symbol-lock-closed";
    // }
    return null;
  }

  @Override
  public String getDisplayName() {
    return UIConstants.DisplayNames.MFA_MANAGEMENT;
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
    Jenkins.get().checkPermission(Jenkins.ADMINISTER);
  }

  /**
   * Gets all users with their MFA status.
   * Called from Jelly view.
   *
   * @return Collection of UserMFAInfo objects
   */
  public Collection<UserMFAInfo> getAllUsers() {
    checkAdminPermission();
    MFAUserService userService = MFAContext.i().getService(MFAUserService.class);
    return userService.getAllUsersWithMFAStatus();
  }

  /**
   * Gets the count of users with MFA enabled.
   *
   * @return Number of users with MFA enabled
   */
  public long getEnabledCount() {
    checkAdminPermission();
    MFAUserService userService = MFAContext.i().getService(MFAUserService.class);
    return userService.getEnabledMFACount();
  }

  /**
   * Gets the total number of users.
   *
   * @return Total user count
   */
  public long getTotalCount() {
    checkAdminPermission();
    MFAUserService userService = MFAContext.i().getService(MFAUserService.class);
    return userService.getTotalUserCount();
  }

  /**
   * Resets MFA for a specific user.
   *
   * @param userId The ID of the user to reset MFA for
   * @return HTTP response indicating success or failure
   */
  @RequirePOST
  public HttpResponse doResetMFA(@QueryParameter String userId) {
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
      MFAUserService userService = MFAContext.i().getService(MFAUserService.class);
      userService.resetMFA(user);
      log.info(String.format("Admin reset MFA for user: %s", userId));
      return HttpResponses.redirectToDot();
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
}
