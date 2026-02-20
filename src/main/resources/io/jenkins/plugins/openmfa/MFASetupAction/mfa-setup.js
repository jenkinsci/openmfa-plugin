let _pendingDisableForm = null;

/**
 * Get localized labels and messages for the disable dialog from the DOM.
 */
function _getDisableDialogLabels() {
  const el = document.getElementById('mfa-disable-dialog-messages');
  if (!el) return null;
  return {
    title: el.getAttribute('data-title') || '',
    message: el.getAttribute('data-message') || '',
    okText: el.getAttribute('data-ok-text') || '',
    cancelText: el.getAttribute('data-cancel-text') || '',
  };
}

/**
 * Shows the disable MFA confirmation dialog using Jenkins Design Library dialogs.
 * Falls back to the browser confirm() if the dialog API is unavailable.
 * @param {HTMLFormElement} form - The form to submit on confirm
 */
function showDisableConfirm(form) {
  const labels = _getDisableDialogLabels();
  const message = labels
    ? labels.message
    : 'Are you sure you want to disable MFA?';

  // Fallback if the Design Library dialog API is not available
  if (typeof dialog === 'undefined') {
    if (window.confirm(message)) {
      form.submit();
    }
    return;
  }

  _pendingDisableForm = form;

  dialog
    .confirm(labels ? labels.title : '', {
      message: message,
      okText: labels ? labels.okText : undefined,
      cancelText: labels ? labels.cancelText : undefined,
      type: 'destructive',
    })
    .then(function (confirmed) {
      if (confirmed && _pendingDisableForm) {
        _pendingDisableForm.submit();
      }
      _pendingDisableForm = null;
    });
}

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

function copySecret(button) {
  const input = button.previousElementSibling;
  const secret = input.value;
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard
      .writeText(secret)
      .then(function () {
        const originalText = button.textContent;
        button.textContent = 'Copied!';
        button.classList.add('copied');
        setTimeout(function () {
          button.textContent = originalText;
          button.classList.remove('copied');
        }, 2000);
      })
      .catch(function (err) {
        console.error('Failed to copy:', err);
        fallbackCopy(secret, button);
      });
  } else {
    fallbackCopy(secret, button);
  }
}

function fallbackCopy(text, button) {
  const textArea = document.createElement('textarea');
  textArea.value = text;
  textArea.style.position = 'fixed';
  textArea.style.opacity = '0';
  document.body.appendChild(textArea);
  textArea.select();
  try {
    document.execCommand('copy');
    const originalText = button.textContent;
    button.textContent = 'Copied!';
    button.classList.add('copied');
    setTimeout(function () {
      button.textContent = originalText;
      button.classList.remove('copied');
    }, 2000);
  } catch (err) {
    console.error('Failed to copy:', err);
  }
  document.body.removeChild(textArea);
}

/**
 * Initialize page functionality on load.
 */
function init() {
  initNotification();

  const disableForms = document.querySelectorAll('.mfa-disable-form');
  for (let j = 0; j < disableForms.length; j++) {
    (function (form) {
      const disableBtn = form.querySelector('button[type="button"]');
      if (disableBtn) {
        disableBtn.addEventListener('click', function () {
          showDisableConfirm(form);
        });
      }
    })(disableForms[j]);
  }
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
