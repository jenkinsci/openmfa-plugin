/**
 * MFA Login Script
 * Handles TOTP code input, notificationBar feedback, and lockout countdown.
 */
(function () {
  'use strict';

  const digits = document.querySelectorAll('.mfa-login-digit');
  const hidden = document.getElementById('mfa-login-code-hidden');
  const form = document.querySelector('.mfa-login-container form');
  const submitBtn = form ? form.querySelector('button[type="submit"]') : null;

  /**
   * Updates the hidden input with the combined digit values.
   */
  function updateHidden() {
    let code = '';
    digits.forEach(function (d) {
      code += d.value;
    });
    if (hidden) {
      hidden.value = code;
    }
  }

  /**
   * Sets up event listeners for each digit input.
   */
  function initDigitInputs() {
    digits.forEach(function (input, idx) {
      input.addEventListener('input', function (e) {
        const val = e.target.value.replace(/[^0-9]/g, '');
        e.target.value = val.slice(-1);
        updateHidden();
        if (val && idx < 5) {
          digits[idx + 1].focus();
        }
      });

      input.addEventListener('keydown', function (e) {
        if (e.key === 'Backspace' && !e.target.value && idx > 0) {
          digits[idx - 1].focus();
        }
      });

      input.addEventListener('paste', function (e) {
        e.preventDefault();
        const paste = (e.clipboardData || window.clipboardData)
          .getData('text')
          .replace(/[^0-9]/g, '')
          .slice(0, 6);
        for (let i = 0; i < paste.length; i++) {
          if (digits[i]) {
            digits[i].value = paste[i];
          }
        }
        updateHidden();
        if (digits[Math.min(paste.length, 5)]) {
          digits[Math.min(paste.length, 5)].focus();
        }
      });
    });

    // Focus first digit on load
    if (digits[0]) {
      digits[0].focus();
    }
  }

  /**
   * Formats seconds into a human-readable string (MM:SS or just seconds).
   * @param {number} seconds - The number of seconds
   * @returns {string} Formatted time string
   */
  function formatTime(seconds) {
    if (seconds < 60) {
      return seconds + 's';
    }
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return mins + ':' + (secs < 10 ? '0' : '') + secs;
  }

  /**
   * Disables the form inputs and submit button.
   */
  function disableForm() {
    digits.forEach(function (d) {
      d.disabled = true;
      d.classList.add('mfa-login-digit-disabled');
    });
    if (submitBtn) {
      submitBtn.disabled = true;
    }
  }

  /**
   * Enables the form inputs and submit button.
   */
  function enableForm() {
    digits.forEach(function (d) {
      d.disabled = false;
      d.classList.remove('mfa-login-digit-disabled');
    });
    if (submitBtn) {
      submitBtn.disabled = false;
    }
    if (digits[0]) {
      digits[0].focus();
    }
  }

  /**
   * Handles the lockout countdown.
   * @param {number} remainingSeconds - Seconds remaining in lockout
   */
  function handleLockout(remainingSeconds) {
    const lockoutBanner = document.getElementById('mfa-lockout-banner');
    const countdownEl = document.getElementById('mfa-lockout-countdown');

    if (!lockoutBanner || !countdownEl) return;

    disableForm();
    lockoutBanner.classList.remove('mfa-lockout-hidden');
    lockoutBanner.classList.add('mfa-lockout-visible');

    let remaining = remainingSeconds;

    function updateCountdown() {
      countdownEl.textContent = formatTime(remaining);

      if (remaining <= 0) {
        lockoutBanner.classList.remove('mfa-lockout-visible');
        lockoutBanner.classList.add('mfa-lockout-hidden');
        enableForm();
        // Remove error params from URL without reload
        const url = new URL(window.location.href);
        url.searchParams.delete('error');
        url.searchParams.delete('remaining');
        window.history.replaceState(
          {},
          document.title,
          url.pathname + url.search,
        );
        return;
      }

      remaining--;
      setTimeout(updateCountdown, 1000);
    }

    updateCountdown();
  }

  /**
   * Initializes error handling based on URL parameters.
   */
  function initErrorHandling() {
    const urlParams = new URLSearchParams(window.location.search);
    const error = urlParams.get('error');

    if (error === 'invalid' && typeof notificationBar !== 'undefined') {
      const msgEl = document.getElementById('mfa-invalid-code-msg');
      const msg = msgEl ? msgEl.textContent : 'Invalid verification code.';
      notificationBar.show(msg, notificationBar.ERROR);
    } else if (error === 'locked') {
      const remaining = parseInt(urlParams.get('remaining'), 10);
      if (!isNaN(remaining) && remaining > 0) {
        handleLockout(remaining);
      }
    }
  }

  // Initialize when DOM is ready
  if (digits.length > 0) {
    initDigitInputs();
  }
  initErrorHandling();
})();
