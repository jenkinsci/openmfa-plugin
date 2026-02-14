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

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initNotification);
} else {
  initNotification();
}
