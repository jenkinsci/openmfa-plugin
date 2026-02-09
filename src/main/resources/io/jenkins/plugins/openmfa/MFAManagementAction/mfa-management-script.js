/**
 * MFA Management Dashboard Scripts
 */

var _pendingResetForm = null;

/**
 * Shows the reset MFA confirmation dialog.
 * @param {string} userId - The ID of the user to reset
 * @param {HTMLFormElement} form - The form to submit on confirm
 */
function showResetConfirm(userId, form) {
  var dialog = document.getElementById('mfa-reset-confirm-dialog');
  var userEl = document.getElementById('mfa-reset-confirm-user');
  if (!dialog || !userEl) return;

  userEl.textContent = userId;
  _pendingResetForm = form;
  dialog.setAttribute('aria-hidden', 'false');

  var confirmBtn = document.getElementById('mfa-reset-confirm-submit');
  if (confirmBtn && !confirmBtn._bound) {
    confirmBtn._bound = true;
    confirmBtn.addEventListener('click', function() {
      if (_pendingResetForm) {
        _pendingResetForm.submit();
        _pendingResetForm = null;
      }
      closeResetConfirm();
    });
  }

  document.addEventListener('keydown', _resetConfirmEscape);
}

/**
 * Closes the reset MFA confirmation dialog.
 */
function closeResetConfirm() {
  var dialog = document.getElementById('mfa-reset-confirm-dialog');
  if (dialog) {
    dialog.setAttribute('aria-hidden', 'true');
  }
  _pendingResetForm = null;
  document.removeEventListener('keydown', _resetConfirmEscape);
}

function _resetConfirmEscape(e) {
  if (e.key === 'Escape') {
    closeResetConfirm();
  }
}

/**
 * Dismisses the toast (used when success=reset_mfa is shown server-side).
 * @param {HTMLElement} button - The close button element
 */
function dismissToast(button) {
  var toast = button.closest('.mfa-toast');
  if (toast) {
    toast.classList.add('mfa-toast-hiding');
    setTimeout(function() {
      toast.remove();
      if (window.history && window.history.replaceState) {
        var url = new URL(window.location.href);
        url.searchParams.delete('success');
        window.history.replaceState({}, document.title, url.pathname + (url.search || ''));
      }
    }, 300);
  }
}

/**
 * Initialize page functionality on load.
 * Wires up event handlers without using inline JavaScript.
 */
(function() {
  // Wire up toast close buttons
  var closeButtons = document.querySelectorAll('.mfa-toast-close');
  for (var i = 0; i < closeButtons.length; i++) {
    (function(button) {
      button.addEventListener('click', function() {
        dismissToast(button);
      });
    })(closeButtons[i]);
  }

  // Auto-dismiss the first toast after 5 seconds, if present
  setTimeout(function() {
    var toast = document.querySelector('.mfa-toast');
    if (toast && toast.parentNode) {
      var closeBtn = toast.querySelector('.mfa-toast-close');
      if (closeBtn) {
        dismissToast(closeBtn);
      }
    }
  }, 5000);

  // Wire up reset confirmation modal buttons and reset buttons
  var cancelBtn = document.querySelector('.mfa-mgmt-modal-btn-cancel');
  if (cancelBtn) {
    cancelBtn.addEventListener('click', function() {
      closeResetConfirm();
    });
  }

  // Attach click handlers to all reset buttons to show confirm dialog
  var resetForms = document.querySelectorAll('.mfa-mgmt-reset-form');
  for (var j = 0; j < resetForms.length; j++) {
    (function(form) {
      var resetBtn = form.querySelector('.mfa-mgmt-btn-reset');
      if (resetBtn) {
        resetBtn.addEventListener('click', function() {
          var userIdInput = form.querySelector('input[name="userId"]');
          if (userIdInput) {
            showResetConfirm(userIdInput.value, form);
          }
        });
      }
    })(resetForms[j]);
  }
})();
