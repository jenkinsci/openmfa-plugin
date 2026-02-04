/**
 * MFA Login Script
 * Handles TOTP code input, toast notifications, and lockout countdown.
 */
(function () {
  "use strict";

  var digits = document.querySelectorAll(".mfa-login-digit");
  var hidden = document.getElementById("mfa-login-code-hidden");
  var form = document.querySelector(".mfa-login-card form");
  var submitBtn = document.querySelector(".mfa-login-btn-primary");

  /**
   * Updates the hidden input with the combined digit values.
   */
  function updateHidden() {
    var code = "";
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
      input.addEventListener("input", function (e) {
        var val = e.target.value.replace(/[^0-9]/g, "");
        e.target.value = val.slice(-1);
        updateHidden();
        if (val && idx < 5) {
          digits[idx + 1].focus();
        }
      });

      input.addEventListener("keydown", function (e) {
        if (e.key === "Backspace" && !e.target.value && idx > 0) {
          digits[idx - 1].focus();
        }
      });

      input.addEventListener("paste", function (e) {
        e.preventDefault();
        var paste = (e.clipboardData || window.clipboardData)
          .getData("text")
          .replace(/[^0-9]/g, "")
          .slice(0, 6);
        for (var i = 0; i < paste.length; i++) {
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
   * Shows a toast notification.
   * @param {string} toastId - The ID of the toast element
   * @param {number} duration - Duration in ms before hiding (0 for persistent)
   */
  function showToast(toastId, duration) {
    var toast = document.getElementById(toastId);
    if (!toast) return;

    toast.classList.remove("mfa-toast-hidden");
    toast.classList.add("mfa-toast-visible");

    if (duration > 0) {
      setTimeout(function () {
        hideToast(toastId);
      }, duration);
    }
  }

  /**
   * Hides a toast notification.
   * @param {string} toastId - The ID of the toast element
   */
  function hideToast(toastId) {
    var toast = document.getElementById(toastId);
    if (!toast) return;

    toast.classList.remove("mfa-toast-visible");
    toast.classList.add("mfa-toast-hidden");
  }

  /**
   * Formats seconds into a human-readable string (MM:SS or just seconds).
   * @param {number} seconds - The number of seconds
   * @returns {string} Formatted time string
   */
  function formatTime(seconds) {
    if (seconds < 60) {
      return seconds + "s";
    }
    var mins = Math.floor(seconds / 60);
    var secs = seconds % 60;
    return mins + ":" + (secs < 10 ? "0" : "") + secs;
  }

  /**
   * Disables the form inputs and submit button.
   */
  function disableForm() {
    digits.forEach(function (d) {
      d.disabled = true;
      d.classList.add("mfa-login-digit-disabled");
    });
    if (submitBtn) {
      submitBtn.disabled = true;
      submitBtn.classList.add("mfa-login-btn-disabled");
    }
  }

  /**
   * Enables the form inputs and submit button.
   */
  function enableForm() {
    digits.forEach(function (d) {
      d.disabled = false;
      d.classList.remove("mfa-login-digit-disabled");
    });
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.classList.remove("mfa-login-btn-disabled");
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
    var lockoutBanner = document.getElementById("mfa-lockout-banner");
    var countdownEl = document.getElementById("mfa-lockout-countdown");

    if (!lockoutBanner || !countdownEl) return;

    disableForm();
    lockoutBanner.classList.remove("mfa-lockout-hidden");
    lockoutBanner.classList.add("mfa-lockout-visible");

    var remaining = remainingSeconds;

    function updateCountdown() {
      countdownEl.textContent = formatTime(remaining);

      if (remaining <= 0) {
        lockoutBanner.classList.remove("mfa-lockout-visible");
        lockoutBanner.classList.add("mfa-lockout-hidden");
        enableForm();
        // Remove error params from URL without reload
        var url = new URL(window.location.href);
        url.searchParams.delete("error");
        url.searchParams.delete("remaining");
        window.history.replaceState(
          {},
          document.title,
          url.pathname + url.search
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
    var urlParams = new URLSearchParams(window.location.search);
    var error = urlParams.get("error");

    if (error === "invalid") {
      showToast("mfa-toast", 4000);
    } else if (error === "locked") {
      var remaining = parseInt(urlParams.get("remaining"), 10);
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
