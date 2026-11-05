/**
 * Security-key side of the MFA challenge page: runs the assertion ceremony
 * and the TOTP/security-key switch links. Requires webauthn-common.js.
 */
(function () {
  'use strict';

  const webauthnSection = document.getElementById('mfa-webauthn-section');
  const totpSection = document.getElementById('mfa-totp-section');
  const errorMsg = document.getElementById('mfa-webauthn-error-msg');
  const useCodeLink = document.getElementById('mfa-use-code-link');
  const useWebAuthnLink = document.getElementById('mfa-use-webauthn-link');

  if (!webauthnSection) {
    return;
  }

  const common = window.openmfaWebAuthnCommon;
  const base64urlToArrayBuffer = common.base64urlToArrayBuffer;
  const arrayBufferToBase64url = common.arrayBufferToBase64url;
  const getCrumbHeader = common.getCrumbHeader;

  /** Decodes base64url challenge/credential ids for credentials.get(). */
  function decodePublicKeyOptions(publicKey) {
    publicKey.challenge = base64urlToArrayBuffer(publicKey.challenge);
    if (Array.isArray(publicKey.allowCredentials)) {
      publicKey.allowCredentials = publicKey.allowCredentials.map(
        function (cred) {
          return Object.assign({}, cred, {
            id: base64urlToArrayBuffer(cred.id),
          });
        },
      );
    }
    return publicKey;
  }

  /** Serializes an assertion into the JSON webauthn-verify expects. */
  function serializeAssertion(credential) {
    return {
      id: credential.id,
      rawId: arrayBufferToBase64url(credential.rawId),
      type: credential.type,
      response: {
        authenticatorData: arrayBufferToBase64url(
          credential.response.authenticatorData,
        ),
        clientDataJSON: arrayBufferToBase64url(
          credential.response.clientDataJSON,
        ),
        signature: arrayBufferToBase64url(credential.response.signature),
        userHandle: credential.response.userHandle
          ? arrayBufferToBase64url(credential.response.userHandle)
          : null,
      },
      // Mandatory: the server parser rejects a response without it.
      clientExtensionResults: credential.getClientExtensionResults
        ? credential.getClientExtensionResults()
        : {},
    };
  }

  function showError() {
    if (errorMsg) {
      errorMsg.style.display = 'block';
    }
  }

  function hideError() {
    if (errorMsg) {
      errorMsg.style.display = 'none';
    }
  }

  function showTotpSection() {
    if (webauthnSection) {
      webauthnSection.classList.add('mfa-section-hidden');
    }
    if (totpSection) {
      totpSection.classList.remove('mfa-section-hidden');
    }
  }

  function showWebAuthnSection() {
    if (totpSection) {
      totpSection.classList.add('mfa-section-hidden');
    }
    if (webauthnSection) {
      webauthnSection.classList.remove('mfa-section-hidden');
    }
    hideError();
    startCeremony();
  }

  /** Runs the assertion ceremony; shows the error line on failure. */
  function startCeremony() {
    if (!window.navigator.credentials || !window.PublicKeyCredential) {
      showError();
      return;
    }

    const crumbHeaders = getCrumbHeader();
    const fromParam = webauthnSection.getAttribute('data-from-param') || '';
    const challengeUrl = webauthnSection.getAttribute('data-challenge-url');
    const verifyUrl = webauthnSection.getAttribute('data-verify-url');

    fetch(challengeUrl, {
      method: 'POST',
      headers: crumbHeaders,
    })
      .then(function (response) {
        if (!response.ok) {
          throw new Error('Could not start WebAuthn challenge');
        }
        return response.json();
      })
      .then(function (options) {
        const publicKey = decodePublicKeyOptions(options.publicKey);
        return window.navigator.credentials.get({publicKey: publicKey});
      })
      .then(function (credential) {
        const body = JSON.stringify(serializeAssertion(credential));
        const url =
          verifyUrl +
          (fromParam ? '?from=' + encodeURIComponent(fromParam) : '');
        return fetch(url, {
          method: 'POST',
          redirect: 'follow',
          headers: Object.assign(
            {'Content-Type': 'application/json'},
            crumbHeaders,
          ),
          body: body,
        });
      })
      .then(function (response) {
        // Redirects are already followed; a non-ok response is the POST-only
        // endpoint itself, so show the error instead of navigating to it.
        if (!response.ok) {
          showError();
          return;
        }
        window.location = response.url;
      })
      .catch(function () {
        showError();
      });
  }

  if (useCodeLink) {
    useCodeLink.addEventListener('click', function (e) {
      e.preventDefault();
      showTotpSection();
    });
  }

  if (useWebAuthnLink) {
    useWebAuthnLink.addEventListener('click', function (e) {
      e.preventDefault();
      showWebAuthnSection();
    });
  }

  // Auto-start when WebAuthn is the preferred method.
  if (!webauthnSection.classList.contains('mfa-section-hidden')) {
    startCeremony();
  }
})();
