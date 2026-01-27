/**
 * MFA Management Dashboard Scripts
 */

/**
 * Confirmation dialog before resetting MFA for a user.
 * @param {string} userId - The ID of the user to reset
 * @returns {boolean} - Whether to proceed with the reset
 */
function confirmReset(userId) {
  return confirm(
    'Are you sure you want to reset MFA for user "' + userId + '"?\n\n' +
    'This will remove their current MFA configuration and they will need to set up MFA again.'
  );
}

/**
 * Shows a toast notification with the given message.
 * @param {string} message - The message to display
 * @param {string} type - The type of toast ('success' or 'error')
 */
function showToast(message, type) {
  var toast = document.getElementById('mfa-toast');
  if (!toast) return;

  var messageSpan = toast.querySelector('.mfa-toast-message');
  if (messageSpan) {
    messageSpan.textContent = message;
  }

  // Update toast styling based on type
  if (type === 'error') {
    toast.style.background = 'var(--mfa-danger)';
  } else {
    toast.style.background = 'var(--mfa-success)';
  }

  toast.classList.remove('mfa-toast-hidden');
  toast.classList.add('mfa-toast-visible');

  setTimeout(function() {
    toast.classList.remove('mfa-toast-visible');
    toast.classList.add('mfa-toast-hidden');
  }, 4000);
}

/**
 * Initialize page functionality on load.
 */
(function() {
  // Check URL for success parameter
  var urlParams = new URLSearchParams(window.location.search);
  if (urlParams.get('reset') === 'success') {
    showToast('MFA has been reset successfully', 'success');
    // Clean up URL
    if (window.history.replaceState) {
      var cleanUrl = window.location.pathname;
      window.history.replaceState({}, document.title, cleanUrl);
    }
  }
})();
