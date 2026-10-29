/**
 * Application Entry Point
 * Initializes the Cryptographic Request Integrity & Authentication Framework.
 *
 * @module main
 */

import { UIController } from './ui.js';
import * as cryptoHelpers from './crypto.js';
import * as signerModule from './signer.js';
import * as verifierModule from './verifier.js';
import * as attackModule from './attacks.js';

document.addEventListener('DOMContentLoaded', () => {
  const controller = new UIController();
  controller.init();

  // Expose cryptographic utilities on window for educational inspection in DevTools
  window.__CRYPTO_FRAMEWORK__ = {
    controller,
    crypto: cryptoHelpers,
    signer: signerModule,
    verifier: verifierModule,
    attacks: attackModule
  };

  console.log(
    '%c🛡️ Cryptographic Request Integrity Framework Initialized%c\n' +
    'WebCrypto Subtle HMAC-SHA256 active.\n' +
    'Inspect window.__CRYPTO_FRAMEWORK__ for module primitives.',
    'color: #38bdf8; font-weight: bold; font-size: 14px;',
    'color: #94a3b8; font-size: 11px;'
  );
});
