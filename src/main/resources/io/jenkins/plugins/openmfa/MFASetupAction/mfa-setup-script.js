function copySecret(button) {
    const input = button.previousElementSibling;
    const secret = input.value;
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(secret).then(function() {
        const originalText = button.textContent;
        button.textContent = 'Copied!';
        button.classList.add('copied');
        setTimeout(function() {
          button.textContent = originalText;
          button.classList.remove('copied');
        }, 2000);
      }).catch(function(err) {
        console.error('Failed to copy:', err);
        fallbackCopy(secret, button);
      });
    } else {
      fallbackCopy(secret, button);
    }
  }

  function dismissToast(button) {
    var toast = button.closest('.mfa-toast');
    if (toast) {
      toast.classList.add('mfa-toast-hiding');
      setTimeout(function() {
        toast.remove();
        // Clean up URL parameter
        if (window.history && window.history.replaceState) {
          var url = new URL(window.location.href);
          url.searchParams.delete('success');
          window.history.replaceState({}, document.title, url.pathname);
        }
      }, 300);
    }
  }

  function initToast() {
    // Attach click handlers to all toast close buttons
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
      if (toast && document.body.contains(toast)) {
        var closeButton = toast.querySelector('.mfa-toast-close');
        if (closeButton) {
          dismissToast(closeButton);
        }
      }
    }, 5000);
  }

  // Initialize toast on page load
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initToast);
  } else {
    initToast();
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
      setTimeout(function() {
        button.textContent = originalText;
        button.classList.remove('copied');
      }, 2000);
    } catch (err) {
      console.error('Failed to copy:', err);
    }
    document.body.removeChild(textArea);
  }
