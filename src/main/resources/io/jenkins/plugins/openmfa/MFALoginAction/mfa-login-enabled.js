/**
 * MFA Login Script
 * Handles TOTP code input, notificationBar feedback, and lockout countdown.
 * Stores remaining lockout in localStorage; blocks form submit and shows banner when lockout > 0.
 */
(function () {
  'use strict';

  const LOCKOUT_STORAGE_KEY = 'openmfa.lockoutEndTime';

  function getStoredLockoutRemaining() {
    try {
      const endTime = parseInt(localStorage.getItem(LOCKOUT_STORAGE_KEY), 10);
      if (!endTime || endTime <= Date.now()) {
        localStorage.removeItem(LOCKOUT_STORAGE_KEY);
        return null;
      }
      return {
        remainingSeconds: Math.ceil((endTime - Date.now()) / 1000),
        endTime,
      };
    } catch (e) {
      return null;
    }
  }

  function setStoredLockout(remainingSeconds) {
    try {
      localStorage.setItem(
        LOCKOUT_STORAGE_KEY,
        String(Date.now() + remainingSeconds * 1000),
      );
    } catch (e) {}
  }

  function clearStoredLockout() {
    try {
      localStorage.removeItem(LOCKOUT_STORAGE_KEY);
    } catch (e) {}
  }

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
        clearStoredLockout();
        lockoutBanner.classList.remove('mfa-lockout-visible');
        lockoutBanner.classList.add('mfa-lockout-hidden');
        enableForm();
        return;
      }

      remaining--;
      setTimeout(updateCountdown, 1000);
    }

    updateCountdown();
  }

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

  /**
   * Initializes error handling and lockout from server (banner data) or stored value.
   * If lockout remaining > 0, shows banner and blocks form submit (no server request).
   */
  function initErrorHandling() {
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.get('error') === 'invalid') {
      if (typeof notificationBar !== 'undefined') {
        const msgEl = document.getElementById('mfa-invalid-code-msg');
        const msg = msgEl ? msgEl.textContent : 'Invalid verification code.';
        notificationBar.show(msg, notificationBar.ERROR);
      }
    }

    let remaining = null;
    const lockoutBanner = document.getElementById('mfa-lockout-banner');
    if (lockoutBanner) {
      const fromBanner = parseInt(
        lockoutBanner.getAttribute('data-remaining-lockout'),
        10,
      );
      if (!isNaN(fromBanner) && fromBanner > 0) {
        remaining = fromBanner;
        setStoredLockout(remaining);
      }
    }
    if (remaining == null) {
      const stored = getStoredLockoutRemaining();
      if (stored && stored.remainingSeconds > 0) {
        remaining = stored.remainingSeconds;
      }
    }
    if (remaining != null && remaining > 0) {
      handleLockout(remaining);
    }

    if (form) {
      form.addEventListener('submit', function (e) {
        const lockout = getStoredLockoutRemaining();
        if (lockout && lockout.remainingSeconds > 0) {
          e.preventDefault();
        }
      });
    }
  }

  if (digits.length > 0) {
    initDigitInputs();
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initErrorHandling);
    document.addEventListener('DOMContentLoaded', initAlreadyVerifiedRedirect);
  } else {
    initErrorHandling();
    initAlreadyVerifiedRedirect();
  }
})();
