/**
 * Shared WebAuthn page helpers (base64url conversion, crumb header), exposed
 * as window.openmfaWebAuthnCommon.
 */
(function () {
  'use strict';

  /** Unpadded base64url string to ArrayBuffer. */
  function base64urlToArrayBuffer(value) {
    const padded = value.replace(/-/g, '+').replace(/_/g, '/');
    const padding = '='.repeat((4 - (padded.length % 4)) % 4);
    const binary = atob(padded + padding);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  /** ArrayBuffer to unpadded base64url string. */
  function arrayBufferToBase64url(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary)
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
  }

  /** Jenkins crumb header from <head> as a headers object (empty if none). */
  function getCrumbHeader() {
    const head = document.head;
    const name = head.getAttribute('data-crumb-header');
    const value = head.getAttribute('data-crumb-value');
    if (!name || !value) {
      return {};
    }
    const headers = {};
    headers[name] = value;
    return headers;
  }

  window.openmfaWebAuthnCommon = {
    arrayBufferToBase64url: arrayBufferToBase64url,
    base64urlToArrayBuffer: base64urlToArrayBuffer,
    getCrumbHeader: getCrumbHeader,
  };
})();
