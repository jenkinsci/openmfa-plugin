/**
 * Security key registration and remove confirmation on the MFA setup page.
 * Requires webauthn-common.js.
 */
(function () {
  'use strict';

  const card = document.getElementById('mfa-webauthn-card');
  if (!card) {
    return;
  }

  const addSection = document.getElementById('mfa-webauthn-add');
  const nameInput = document.getElementById('mfa-webauthn-name');
  const addButton = document.getElementById('mfa-webauthn-add-button');
  const errorMsg = document.getElementById('mfa-webauthn-error');

  const common = window.openmfaWebAuthnCommon;
  const base64urlToArrayBuffer = common.base64urlToArrayBuffer;
  const arrayBufferToBase64url = common.arrayBufferToBase64url;
  const getCrumbHeader = common.getCrumbHeader;

  /** Decodes base64url challenge/user id/excluded ids for credentials.create(). */
  function decodeCreationOptions(publicKey) {
    publicKey.challenge = base64urlToArrayBuffer(publicKey.challenge);
    publicKey.user.id = base64urlToArrayBuffer(publicKey.user.id);
    if (Array.isArray(publicKey.excludeCredentials)) {
      publicKey.excludeCredentials = publicKey.excludeCredentials.map(
        function (cred) {
          return Object.assign({}, cred, {
            id: base64urlToArrayBuffer(cred.id),
          });
        },
      );
    }
    return publicKey;
  }

  /** Serializes an attestation into the JSON webauthn-register-finish expects. */
  function serializeAttestation(credential) {
    return {
      id: credential.id,
      rawId: arrayBufferToBase64url(credential.rawId),
      type: credential.type,
      response: {
        attestationObject: arrayBufferToBase64url(
          credential.response.attestationObject,
        ),
        clientDataJSON: arrayBufferToBase64url(
          credential.response.clientDataJSON,
        ),
      },
      clientExtensionResults: credential.getClientExtensionResults
        ? credential.getClientExtensionResults()
        : {},
    };
  }

  function showError(message) {
    if (errorMsg) {
      errorMsg.textContent = message;
      errorMsg.style.display = 'block';
    }
  }

  function hideError() {
    if (errorMsg) {
      errorMsg.style.display = 'none';
    }
  }

  /** Localized text for a server error code (data-error-<code>), else generic. */
  function messageForCode(code) {
    const localized = code
      ? addSection.getAttribute('data-error-' + code)
      : null;
    return localized || addSection.getAttribute('data-error-generic');
  }

  /** Rejects with the server's error code tagged as webauthnCode. */
  function refusalOf(response) {
    return response
      .json()
      .then(function (body) {
        return body && typeof body.error === 'string' ? body.error : '';
      })
      .catch(function () {
        return '';
      })
      .then(function (code) {
        const refusal = new Error('refused');
        refusal.webauthnCode = code;
        throw refusal;
      });
  }

  /** Runs the registration ceremony, then reloads the page. */
  function register() {
    const generic = addSection.getAttribute('data-error-generic');
    const unsupported = addSection.getAttribute('data-error-unsupported');
    const nameRequired = messageForCode('name_required');
    const startUrl = addSection.getAttribute('data-start-url');
    const finishUrl = addSection.getAttribute('data-finish-url');
    const crumbHeaders = getCrumbHeader();

    hideError();

    if (!window.navigator.credentials || !window.PublicKeyCredential) {
      showError(unsupported);
      return;
    }

    const name = (nameInput.value || '').trim();
    if (!name) {
      showError(nameRequired);
      nameInput.focus();
      return;
    }

    addButton.disabled = true;
    fetch(startUrl, {method: 'POST', headers: crumbHeaders})
      .then(function (response) {
        if (!response.ok) {
          return refusalOf(response);
        }
        return response.json();
      })
      .then(function (options) {
        const publicKey = decodeCreationOptions(options.publicKey);
        return window.navigator.credentials.create({publicKey: publicKey});
      })
      .then(function (credential) {
        return fetch(finishUrl, {
          method: 'POST',
          headers: Object.assign(
            {'Content-Type': 'application/json'},
            crumbHeaders,
          ),
          body: JSON.stringify({
            name: name,
            response: serializeAttestation(credential),
          }),
        });
      })
      .then(function (response) {
        if (!response.ok) {
          return refusalOf(response);
        }
        window.location.reload();
      })
      .catch(function (e) {
        addButton.disabled = false;
        // Browser DOMException text is not localized; show generic instead.
        showError(
          e && e.webauthnCode ? messageForCode(e.webauthnCode) : generic,
        );
      });
  }

  /** Confirms a remove (Jenkins dialog, else window.confirm). */
  function confirmRemove(form) {
    const title = card.getAttribute('data-remove-title') || '';
    const message = card.getAttribute('data-remove-message') || '';
    const okText = card.getAttribute('data-remove-ok') || undefined;
    const cancelText = card.getAttribute('data-remove-cancel') || undefined;

    if (typeof dialog === 'undefined') {
      if (window.confirm(message)) {
        form.submit();
      }
      return;
    }

    dialog
      .confirm(title, {
        message: message,
        okText: okText,
        cancelText: cancelText,
        type: 'destructive',
      })
      .then(function (confirmed) {
        if (confirmed) {
          form.submit();
        }
      });
  }

  function initWebAuthnSetup() {
    if (addSection && addButton && nameInput) {
      addButton.addEventListener('click', register);
      nameInput.addEventListener('keydown', function (e) {
        if (e.key === 'Enter') {
          e.preventDefault();
          register();
        }
      });
    }

    const removeForms = card.querySelectorAll('.mfa-webauthn-remove-form');
    for (let i = 0; i < removeForms.length; i++) {
      (function (form) {
        const button = form.querySelector('button[type="button"]');
        if (button) {
          button.addEventListener('click', function () {
            confirmRemove(form);
          });
        }
      })(removeForms[i]);
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initWebAuthnSetup);
  } else {
    initWebAuthnSetup();
  }
})();
