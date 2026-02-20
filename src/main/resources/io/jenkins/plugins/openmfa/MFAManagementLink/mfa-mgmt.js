/**
 * MFA Management Dashboard Scripts
 */

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
    toastUserPrefix: el.getAttribute('data-toast-user-prefix') || '',
    toastUserSuffix: el.getAttribute('data-toast-user-suffix') || '',
    toastSuccess: el.getAttribute('data-toast-success') || '',
    toastErrorDefault: el.getAttribute('data-toast-error-default') || '',
    disabledStatus: el.getAttribute('data-status-disabled') || '',
    setButtonText: el.getAttribute('data-set-button-text') || '',
  };
}

/**
 * Display a Jenkins notification if the notification bar is available.
 */
function showToast(message, type) {
  if (!message || typeof notificationBar === 'undefined') return;
  const toastType =
    type === 'error' ? notificationBar.ERROR : notificationBar.SUCCESS;
  notificationBar.show(message, toastType);
}

/**
 * Updates the current row to reflect that MFA is no longer enabled.
 */
function updateRowAfterReset(form, labels) {
  const row = form.closest('tr');
  if (!row) return;

  const statusBadge = row.querySelector('.mfa-mgmt-status');
  if (statusBadge && labels.disabledStatus) {
    statusBadge.classList.remove('jenkins-alert-success');
    statusBadge.classList.add('jenkins-alert-warning');
    statusBadge.textContent = labels.disabledStatus;
  }

  const actionsCell = row.querySelector('.mfa-mgmt-actions-cell');
  const setupLink = row.querySelector('.mfa-mgmt-user-cell a');
  if (!actionsCell || !setupLink) return;

  actionsCell.innerHTML = '';
  const setBtn = document.createElement('a');
  setBtn.href = setupLink.href;
  setBtn.className = 'jenkins-button jenkins-button--primary';
  setBtn.textContent = labels.setButtonText;
  actionsCell.appendChild(setBtn);
}

/**
 * Submits the reset form through fetch to avoid page reload and URL params.
 */
function submitResetMFA(form, userId, username) {
  const labels = _getResetDialogLabels() || {};
  const btn = form.querySelector('button');
  if (btn) btn.disabled = true;

  const crumb = getJenkinsCrumb(form);

  fetch(form.action, {
    method: 'POST',
    body: new FormData(form),
    credentials: 'same-origin',
    headers: {
      'X-Requested-With': 'XMLHttpRequest',
      [crumb.header]: crumb.value,
    },
  })
    .then(function (response) {
      if (!response.ok) {
        return response.text().then(function (text) {
          throw new Error(text || labels.toastErrorDefault);
        });
      }

      const displayName = username ? username + '(' + userId + ')' : userId;
      const successMessage =
        labels.toastUserPrefix +
        ' ' +
        displayName +
        labels.toastUserSuffix +
        ' ' +
        labels.toastSuccess;
      showToast(successMessage.trim(), 'success');
      updateRowAfterReset(form, labels);
    })
    .catch(function (err) {
      showToast(
        err && err.message ? err.message : labels.toastErrorDefault,
        'error',
      );
      if (btn) btn.disabled = false;
    });
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
      submitResetMFA(form, userId, username);
    }
    return;
  }

  dialog
    .confirm(labels ? labels.title : '', {
      message: message,
      okText: labels ? labels.okText : undefined,
      cancelText: labels ? labels.cancelText : undefined,
      type: 'destructive',
    })
    .then(function (confirmed) {
      if (confirmed) {
        submitResetMFA(form, userId, username);
      }
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
  showToast(msg, type);
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
