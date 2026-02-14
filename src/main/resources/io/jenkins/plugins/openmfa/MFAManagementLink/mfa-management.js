/**
 * MFA Management Dashboard Scripts
 */

let _pendingResetForm = null;

/**
 * Get localized labels and messages for the reset dialog from the DOM.
 */
function _getResetDialogLabels() {
  const el = document.getElementById('mfa-reset-dialog-messages');
  if (!el) return null;
  return {
    title: el.getAttribute('data-title') || '',
    messagePrefix: el.getAttribute('data-message-prefix') || '',
    messageSuffix: el.getAttribute('data-message-suffix') || '',
    okText: el.getAttribute('data-ok-text') || '',
    cancelText: el.getAttribute('data-cancel-text') || '',
  };
}

/**
 * Shows the reset MFA confirmation dialog using Jenkins Design Library dialogs.
 * Falls back to the browser confirm() if the dialog API is unavailable.
 * @param {string} userId - The ID of the user to reset
 * @param {HTMLFormElement} form - The form to submit on confirm
 */
function showResetConfirm(userId, username, form) {
  const labels = _getResetDialogLabels();
  const message =
    (labels ? labels.messagePrefix : '') +
    ' ' +
    username +
    '(' +
    userId +
    ')' +
    (labels ? labels.messageSuffix : '');

  // Fallback if the Design Library dialog API is not available
  if (typeof dialog === 'undefined') {
    if (window.confirm(message)) {
      form.submit();
    }
    return;
  }

  _pendingResetForm = form;

  dialog
    .confirm(labels ? labels.title : '', {
      message: message,
      okText: labels ? labels.okText : undefined,
      cancelText: labels ? labels.cancelText : undefined,
      type: 'destructive',
    })
    .then(function (confirmed) {
      if (confirmed && _pendingResetForm) {
        _pendingResetForm.submit();
      }
      _pendingResetForm = null;
    });
}

/**
 * Show notificationBar if server rendered notification data is present.
 */
function initNotification() {
  const el = document.getElementById('mfa-notification-data');
  if (!el || typeof notificationBar === 'undefined') return;
  const msg = el.getAttribute('data-msg');
  const type = el.getAttribute('data-type');
  if (!msg) return;
  const barType =
    type === 'error' ? notificationBar.ERROR : notificationBar.SUCCESS;
  notificationBar.show(msg, barType);
}

/**
 * Initialize page functionality on load.
 * Wires up event handlers without using inline JavaScript.
 */
(function () {
  function init() {
    initNotification();

    const resetForms = document.querySelectorAll('.mfa-mgmt-reset-form');
    for (let j = 0; j < resetForms.length; j++) {
      (function (form) {
        const resetBtn = form.querySelector('button');
        if (resetBtn) {
          resetBtn.addEventListener('click', function () {
            const userIdInput = form.querySelector('input[name="userId"]');
            const userNameInput = form.querySelector('input[name="fullName"]');
            if (userIdInput) {
              showResetConfirm(userIdInput.value, userNameInput.value, form);
            }
          });
        }
      })(resetForms[j]);
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
