/**
 * MFA Login Script
 * Handles TOTP code input, notificationBar feedback, and lockout countdown.
 * Stores remaining lockout in localStorage; blocks form submit and shows banner when lockout > 0.
 */
(function () {
  'use strict';

  /**
   * Starts countdown and redirect when already verified (continue link present).
   */
  function initAlreadyVerifiedRedirect() {
    const link = document.getElementById('mfa-continue-link');
    const msg = document.getElementById('mfa-redirect-msg');
    if (!link || !msg) return;

    const redirectUrl =
      link.getAttribute('href') ||
      (window.Jenkins && window.Jenkins.rootURL
        ? window.Jenkins.rootURL + '/'
        : '/');
    const template = msg.getAttribute('data-redirect-template');
    let seconds = 5;

    function tick() {
      if (seconds <= 0) {
        window.location.href = redirectUrl;
        return;
      }
      msg.textContent = template.replace('{0}', String(seconds));
      seconds--;
      setTimeout(tick, 1000);
    }
    tick();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initAlreadyVerifiedRedirect);
  } else {
    initAlreadyVerifiedRedirect();
  }
})();
