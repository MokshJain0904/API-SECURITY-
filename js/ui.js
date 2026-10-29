/**
 * UI Rendering and DOM Interaction Controller
 * Manages user interface state, event handling, clipboard operations,
 * audit event logging, and attack simulations.
 *
 * Implements strict HTML escaping to ensure zero XSS risk.
 *
 * @module ui
 */

import {
  generateRandomKeyHex,
  sha256Hex,
  constantTimeEqual
} from './crypto.js';

import { signRequest } from './signer.js';
import { ApiVerifier } from './verifier.js';
import {
  simulatePayloadTampering,
  simulateReplayAttack,
  simulateExpiredTimestamp,
  simulateWrongSecretKey,
  simulatePathTampering,
  analyzeTimingComparison
} from './attacks.js';

/**
 * Escapes unsafe HTML characters to prevent XSS.
 *
 * @param {string} str - Raw string.
 * @returns {string} Safe HTML string.
 */
export function escapeHtml(str) {
  if (typeof str !== 'string') return String(str ?? '');
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * UI Controller Class
 */
export class UIController {
  constructor() {
    // Shared simulated server verifier instance
    this.verifier = new ApiVerifier({
      timestampToleranceSec: 60,
      nonceTtlSec: 300,
      serverSecretKey: ''
    });

    // In-memory state (NEVER persisted to localStorage)
    this.currentSignedRequest = null;
    this.logs = [];
    this.currentFilter = 'all';

    // Cache DOM Elements
    this.dom = {
      // Inputs
      reqMethod: document.getElementById('req-method'),
      reqPath: document.getElementById('req-path'),
      reqQuery: document.getElementById('req-query'),
      reqSecret: document.getElementById('req-secret'),
      reqKeyId: document.getElementById('req-key-id'),
      reqBody: document.getElementById('req-body'),

      // Settings
      settingTolerance: document.getElementById('setting-tolerance'),
      settingTtl: document.getElementById('setting-ttl'),
      nonceCacheCount: document.getElementById('nonce-cache-count'),
      clearCacheBtn: document.getElementById('clear-cache-btn'),

      // Buttons
      demoFillBtn: document.getElementById('demo-fill-btn'),
      formatJsonBtn: document.getElementById('format-json-btn'),
      generateKeyBtn: document.getElementById('generate-key-btn'),
      toggleSecretBtn: document.getElementById('toggle-secret-visibility-btn'),
      signRequestBtn: document.getElementById('sign-request-btn'),
      resetBuilderBtn: document.getElementById('reset-builder-btn'),
      sendToServerBtn: document.getElementById('send-to-server-btn'),
      themeToggleBtn: document.getElementById('theme-toggle-btn'),
      themeIcon: document.getElementById('theme-icon'),
      themeLabel: document.getElementById('theme-label'),

      // Displays: Canonical
      dispMethod: document.getElementById('disp-method'),
      dispPath: document.getElementById('disp-path'),
      dispQuery: document.getElementById('disp-query'),
      dispTimestamp: document.getElementById('disp-timestamp'),
      dispNonce: document.getElementById('disp-nonce'),
      dispBodyHash: document.getElementById('disp-bodyhash'),
      dispCanonicalRaw: document.getElementById('disp-canonical-raw'),
      dispSignature: document.getElementById('disp-signature'),
      dispHeadersRaw: document.getElementById('disp-headers-raw'),

      // Verifier Display
      verificationBadge: document.getElementById('verification-status-badge'),
      verificationBanner: document.getElementById('verification-outcome-banner'),
      stepCards: {
        headers: document.getElementById('step-card-headers'),
        timestamp: document.getElementById('step-card-timestamp'),
        nonce: document.getElementById('step-card-nonce'),
        canonical: document.getElementById('step-card-canonical'),
        signature: document.getElementById('step-card-signature')
      },

      // Attack Buttons
      attackPayloadBtn: document.getElementById('attack-payload-btn'),
      attackReplayBtn: document.getElementById('attack-replay-btn'),
      attackExpiredBtn: document.getElementById('attack-expired-btn'),
      attackWrongKeyBtn: document.getElementById('attack-wrongkey-btn'),
      attackPathBtn: document.getElementById('attack-path-btn'),
      attackTimingBtn: document.getElementById('attack-timing-btn'),

      // Timing Modal
      timingModal: document.getElementById('timing-attack-modal'),
      closeTimingModalBtn: document.getElementById('close-timing-modal-btn'),
      closeTimingModalBtnBottom: document.getElementById('close-timing-modal-btn-bottom'),
      runTimingBenchmarkBtn: document.getElementById('run-timing-benchmark-btn'),
      timingTargetSig: document.getElementById('timing-target-sig'),
      timingBenchmarkTbody: document.getElementById('timing-benchmark-tbody'),

      // Event Log
      eventLogList: document.getElementById('event-log-list'),
      clearLogBtn: document.getElementById('clear-log-btn'),
      filterAllBtn: document.getElementById('log-filter-all'),
      filterAcceptedBtn: document.getElementById('log-filter-accepted'),
      filterRejectedBtn: document.getElementById('log-filter-rejected'),

      // Toasts
      toastContainer: document.getElementById('toast-container')
    };
  }

  /**
   * Initializes event listeners and initial state.
   */
  init() {
    this.syncServerKey();
    this.bindEvents();
    this.updateNonceCacheBadge();
    this.loadTheme();

    // Auto-sign initial demo request
    this.handleSignRequest();

    // Support query parameter actions for automated reporting & demonstration
    const urlParams = new URLSearchParams(window.location.search);
    const action = urlParams.get('action');
    if (action) {
      setTimeout(async () => {
        if (action === 'verify') await this.handleSendToServer();
        else if (action === 'attack-payload') this.dom.attackPayloadBtn.click();
        else if (action === 'attack-replay') this.dom.attackReplayBtn.click();
        else if (action === 'attack-expired') this.dom.attackExpiredBtn.click();
        else if (action === 'attack-wrongkey') this.dom.attackWrongKeyBtn.click();
        else if (action === 'attack-path') this.dom.attackPathBtn.click();
        else if (action === 'timing') {
          this.dom.attackTimingBtn.click();
          this.dom.runTimingBenchmarkBtn.click();
        } else if (action === 'light') {
          this.toggleTheme();
        }
      }, 300);
    }
  }

  /**
   * Keeps server verifier secret key in sync with current input.
   */
  syncServerKey() {
    this.verifier.serverSecretKey = this.dom.reqSecret.value.trim();
  }

  /**
   * Displays transient toast notification.
   *
   * @param {string} message - Message text.
   * @param {'info'|'success'|'error'} [type='info'] - Notification style.
   */
  showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = 'toast';
    if (type === 'success') toast.style.borderColor = 'var(--status-pass)';
    if (type === 'error') toast.style.borderColor = 'var(--status-fail)';
    toast.textContent = message;

    this.dom.toastContainer.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = '0';
      setTimeout(() => toast.remove(), 250);
    }, 2800);
  }

  /**
   * Appends an event to the security audit event log.
   *
   * @param {Object} entry - Log entry parameters.
   * @param {'ACCEPTED'|'REJECTED'|'ATTACK'|'INFO'} entry.type - Entry category.
   * @param {string} entry.message - Description.
   * @param {string} [entry.details] - Technical detail.
   */
  logEvent({ type, message, details = '' }) {
    const timestamp = new Date().toLocaleTimeString();
    const id = Date.now() + Math.random().toString(36).substring(2, 6);
    const logItem = { id, timestamp, type, message, details };
    this.logs.unshift(logItem);
    this.renderLogs();
  }

  /**
   * Renders the event log respecting the current filter.
   */
  renderLogs() {
    const container = this.dom.eventLogList;
    container.innerHTML = '';

    const filtered = this.logs.filter((item) => {
      if (this.currentFilter === 'accepted') return item.type === 'ACCEPTED';
      if (this.currentFilter === 'rejected') return item.type === 'REJECTED' || item.type === 'ATTACK';
      return true;
    });

    if (filtered.length === 0) {
      container.innerHTML = `<div style="text-align: center; color: var(--text-dim); padding: 1.5rem;">No log entries matching filter.</div>`;
      return;
    }

    for (const item of filtered) {
      const row = document.createElement('div');
      const isAccepted = item.type === 'ACCEPTED';
      const isRejected = item.type === 'REJECTED' || item.type === 'ATTACK';

      row.className = `log-entry ${isAccepted ? 'accepted' : isRejected ? 'rejected' : ''}`;

      let badgeClass = 'badge-neutral';
      if (isAccepted) badgeClass = 'badge-pass';
      if (isRejected) badgeClass = 'badge-fail';
      if (item.type === 'INFO') badgeClass = 'badge-info';

      row.innerHTML = `
        <span class="log-time">${escapeHtml(item.timestamp)}</span>
        <span class="badge ${badgeClass}">${escapeHtml(item.type)}</span>
        <span class="log-msg">${escapeHtml(item.message)}</span>
        <span style="font-size: 0.72rem; color: var(--text-dim);">${escapeHtml(item.details)}</span>
      `;
      container.appendChild(row);
    }
  }

  /**
   * Updates the nonce cache counter in the settings strip.
   */
  updateNonceCacheBadge() {
    const stats = this.verifier.getNonceCacheStats();
    this.dom.nonceCacheCount.textContent = `${stats.size} nonce${stats.size === 1 ? '' : 's'}`;
  }

  /**
   * Resets verification checklist steps to pending state.
   */
  resetStepCards() {
    for (const [key, card] of Object.entries(this.dom.stepCards)) {
      card.className = 'step-card';
      const badge = card.querySelector('.step-badge');
      if (badge) {
        badge.className = 'badge badge-neutral step-badge';
        badge.textContent = 'Pending';
      }
      const details = card.querySelector('.step-details');
      if (details) {
        details.style.display = 'none';
        details.textContent = '';
      }
    }

    this.dom.verificationBanner.style.display = 'none';
    this.dom.verificationBadge.className = 'badge badge-neutral';
    this.dom.verificationBadge.textContent = 'Awaiting Request';
  }

  /**
   * Updates checklist UI from verification steps array.
   *
   * @param {Object} verification - Verification result object.
   */
  renderVerificationResult(verification) {
    this.resetStepCards();

    for (const step of verification.steps) {
      const card = this.dom.stepCards[step.id];
      if (!card) continue;

      const isPass = step.status === 'pass';
      card.className = `step-card ${isPass ? 'pass' : 'fail'}`;

      const badge = card.querySelector('.step-badge');
      if (badge) {
        badge.className = `badge ${isPass ? 'badge-pass' : 'badge-fail'} step-badge`;
        badge.textContent = isPass ? 'PASS' : 'FAIL';
      }

      const desc = card.querySelector('.step-desc');
      if (desc && step.message) {
        desc.textContent = step.message;
      }

      const detailsEl = card.querySelector('.step-details');
      if (detailsEl && step.detail) {
        detailsEl.style.display = 'block';
        detailsEl.textContent = typeof step.detail === 'object'
          ? JSON.stringify(step.detail, null, 2)
          : String(step.detail);
      }
    }

    // Outcome Banner
    const banner = this.dom.verificationBanner;
    banner.style.display = 'block';

    if (verification.ok) {
      banner.style.background = 'var(--status-pass-bg)';
      banner.style.border = '1px solid var(--status-pass-border)';
      banner.style.color = 'var(--status-pass)';
      banner.innerHTML = `<strong>✅ Verification Succeeded:</strong> ${escapeHtml(verification.reason)}`;

      this.dom.verificationBadge.className = 'badge badge-pass';
      this.dom.verificationBadge.textContent = 'VERIFIED & ACCEPTED';
    } else {
      banner.style.background = 'var(--status-fail-bg)';
      banner.style.border = '1px solid var(--status-fail-border)';
      banner.style.color = 'var(--status-fail)';
      banner.innerHTML = `<strong>❌ Verification Rejected:</strong> ${escapeHtml(verification.reason)}`;

      this.dom.verificationBadge.className = 'badge badge-fail';
      this.dom.verificationBadge.textContent = 'REJECTED (SECURITY VIOLATION)';
    }

    this.updateNonceCacheBadge();
  }

  /**
   * Signs the current request configured in the form.
   */
  async handleSignRequest() {
    const method = this.dom.reqMethod.value;
    const path = this.dom.reqPath.value;
    const query = this.dom.reqQuery.value;
    const secretKey = this.dom.reqSecret.value.trim();
    const keyId = this.dom.reqKeyId.value.trim();
    const body = this.dom.reqBody.value;

    if (!secretKey) {
      this.showToast('Please enter or generate a shared secret key', 'error');
      this.dom.reqSecret.focus();
      return;
    }

    try {
      this.syncServerKey();
      const signed = await signRequest({
        method,
        path,
        query,
        body,
        secretKey,
        keyId
      });

      this.currentSignedRequest = signed;

      // Update Breakdown Displays
      this.dom.dispMethod.textContent = signed.method;
      this.dom.dispPath.textContent = signed.path;
      this.dom.dispQuery.textContent = signed.query || '(empty)';
      this.dom.dispTimestamp.textContent = signed.timestamp;
      this.dom.dispNonce.textContent = signed.nonce;
      this.dom.dispBodyHash.textContent = signed.bodyHash;

      // Update Raw Displays
      this.dom.dispCanonicalRaw.textContent = signed.canonicalString;
      this.dom.dispSignature.textContent = signed.signature;

      const headerLines = Object.entries(signed.headers)
        .map(([k, v]) => `${k}: ${v}`)
        .join('\n');
      this.dom.dispHeadersRaw.textContent = `${headerLines}\nContent-Type: application/json`;

      this.showToast('Request signed with HMAC-SHA256', 'success');
      this.logEvent({
        type: 'INFO',
        message: `Signed ${signed.method} ${signed.path}`,
        details: `Nonce: ${signed.nonce.slice(0, 8)}... | Sig: ${signed.signature.slice(0, 10)}...`
      });
    } catch (err) {
      this.showToast(`Signing failed: ${err.message}`, 'error');
      console.error(err);
    }
  }

  /**
   * Dispatches the current signed request to the simulated server verifier.
   */
  async handleSendToServer() {
    if (!this.currentSignedRequest) {
      await this.handleSignRequest();
    }

    this.syncServerKey();
    const result = await this.verifier.verifyRequest(this.currentSignedRequest);
    this.renderVerificationResult(result);

    this.logEvent({
      type: result.ok ? 'ACCEPTED' : 'REJECTED',
      message: `${this.currentSignedRequest.method} ${this.currentSignedRequest.path} -> ${result.reason}`,
      details: result.ok ? 'Valid signature & fresh nonce' : `Failed at: ${result.details?.stepFailed}`
    });
  }

  /**
   * Binds UI events.
   */
  bindEvents() {
    // Generate Random 256-bit Key
    this.dom.generateKeyBtn.addEventListener('click', () => {
      const newKey = generateRandomKeyHex(256);
      this.dom.reqSecret.value = newKey;
      this.syncServerKey();
      this.showToast('Generated 256-bit cryptographic secret key', 'info');
      this.handleSignRequest();
    });

    // Toggle Secret Visibility
    this.dom.toggleSecretBtn.addEventListener('click', () => {
      const input = this.dom.reqSecret;
      const isPassword = input.type === 'password';
      input.type = isPassword ? 'text' : 'password';
      this.dom.toggleSecretBtn.textContent = isPassword ? '🔒' : '👁️';
    });

    // Format JSON Body
    this.dom.formatJsonBtn.addEventListener('click', () => {
      try {
        const parsed = JSON.parse(this.dom.reqBody.value);
        this.dom.reqBody.value = JSON.stringify(parsed, null, 2);
        this.showToast('JSON formatted', 'info');
      } catch (err) {
        this.showToast(`Invalid JSON: ${err.message}`, 'error');
      }
    });

    // Demo Fill Button
    this.dom.demoFillBtn.addEventListener('click', () => {
      this.dom.reqMethod.value = 'POST';
      this.dom.reqPath.value = '/api/v1/payments/transfer';
      this.dom.reqQuery.value = 'priority=urgent&currency=USD';
      this.dom.reqBody.value = JSON.stringify({
        senderAccountId: "ACC-99210",
        recipientAccountId: "ACC-44102",
        amount: 2500.00,
        currency: "USD",
        memo: "Vendor invoice settlement #4891"
      }, null, 2);
      this.showToast('Loaded demo transfer request', 'info');
      this.handleSignRequest();
    });

    // Reset Builder Form
    this.dom.resetBuilderBtn.addEventListener('click', () => {
      this.dom.reqMethod.value = 'GET';
      this.dom.reqPath.value = '/api/v1/profile';
      this.dom.reqQuery.value = '';
      this.dom.reqBody.value = '';
      this.handleSignRequest();
    });

    // Sign Request Button
    this.dom.signRequestBtn.addEventListener('click', () => this.handleSignRequest());

    // Send to Server Button
    this.dom.sendToServerBtn.addEventListener('click', () => this.handleSendToServer());

    // Settings
    this.dom.settingTolerance.addEventListener('change', (e) => {
      const val = parseInt(e.target.value, 10) || 60;
      this.verifier.timestampToleranceSec = val;
      this.showToast(`Timestamp tolerance set to ±${val}s`, 'info');
    });

    this.dom.settingTtl.addEventListener('change', (e) => {
      const val = parseInt(e.target.value, 10) || 300;
      this.verifier.nonceTtlSec = val;
      this.showToast(`Nonce TTL set to ${val}s`, 'info');
    });

    this.dom.clearCacheBtn.addEventListener('click', () => {
      this.verifier.clearNonceCache();
      this.updateNonceCacheBadge();
      this.showToast('Nonce cache cleared', 'info');
      this.logEvent({
        type: 'INFO',
        message: 'Administrator purged in-memory nonce cache table.'
      });
    });

    // Copy to Clipboard buttons
    document.addEventListener('click', (e) => {
      const targetBtn = e.target.closest('.copy-btn');
      if (targetBtn && targetBtn.dataset.target) {
        const targetEl = document.getElementById(targetBtn.dataset.target);
        if (targetEl) {
          const textToCopy = targetEl.textContent.trim();
          navigator.clipboard.writeText(textToCopy).then(() => {
            this.showToast('Copied to clipboard', 'info');
          }).catch(() => {
            this.showToast('Clipboard copy failed', 'error');
          });
        }
      }
    });

    // Theme Toggle
    this.dom.themeToggleBtn.addEventListener('click', () => this.toggleTheme());

    // Event Log Filter Buttons
    this.dom.filterAllBtn.addEventListener('click', () => {
      this.currentFilter = 'all';
      this.renderLogs();
    });
    this.dom.filterAcceptedBtn.addEventListener('click', () => {
      this.currentFilter = 'accepted';
      this.renderLogs();
    });
    this.dom.filterRejectedBtn.addEventListener('click', () => {
      this.currentFilter = 'rejected';
      this.renderLogs();
    });
    this.dom.clearLogBtn.addEventListener('click', () => {
      this.logs = [];
      this.renderLogs();
      this.showToast('Event log cleared', 'info');
    });

    // Attack Simulations Wiring
    this.bindAttackButtons();

    // Timing Attack Modal Wiring
    this.bindTimingModal();
  }

  /**
   * Binds attack simulation buttons.
   */
  bindAttackButtons() {
    // Attack 1: Payload Tampering
    this.dom.attackPayloadBtn.addEventListener('click', async () => {
      if (!this.currentSignedRequest) await this.handleSignRequest();
      this.syncServerKey();

      const attack = await simulatePayloadTampering(
        this.currentSignedRequest,
        this.verifier,
        this.verifier.serverSecretKey
      );

      this.renderVerificationResult(attack.result);
      this.logEvent({
        type: 'ATTACK',
        message: `[ATTACK 1] Payload Tampering detected: In-flight payload altered.`,
        details: `Expected: ${attack.expectedOutcome}`
      });
      this.showToast('Simulated Attack 1: Payload Tampering executed', 'error');
    });

    // Attack 2: Replay Attack
    this.dom.attackReplayBtn.addEventListener('click', async () => {
      if (!this.currentSignedRequest) await this.handleSignRequest();
      this.syncServerKey();

      const attack = await simulateReplayAttack(
        this.currentSignedRequest,
        this.verifier,
        this.verifier.serverSecretKey
      );

      this.renderVerificationResult(attack.result);
      this.logEvent({
        type: 'ATTACK',
        message: `[ATTACK 2] Replay Attack detected: Re-submitted nonce '${this.currentSignedRequest.nonce.slice(0, 8)}...'.`,
        details: `Expected: ${attack.expectedOutcome}`
      });
      this.showToast('Simulated Attack 2: Replay Attack intercepted', 'error');
    });

    // Attack 3: Expired Timestamp
    this.dom.attackExpiredBtn.addEventListener('click', async () => {
      this.syncServerKey();
      const clientKey = this.dom.reqSecret.value.trim();
      const tolerance = this.verifier.timestampToleranceSec;

      const attack = await simulateExpiredTimestamp(
        {
          method: this.dom.reqMethod.value,
          path: this.dom.reqPath.value,
          query: this.dom.reqQuery.value,
          body: this.dom.reqBody.value
        },
        this.verifier,
        clientKey,
        this.verifier.serverSecretKey,
        tolerance + 90 // 90 seconds beyond allowed tolerance window
      );

      this.renderVerificationResult(attack.result);
      this.logEvent({
        type: 'ATTACK',
        message: `[ATTACK 3] Stale Request detected: Timestamp outside tolerance window (age: ${attack.ageSeconds}s).`,
        details: `Expected: ${attack.expectedOutcome}`
      });
      this.showToast('Simulated Attack 3: Stale timestamp rejected', 'error');
    });

    // Attack 4: Wrong Secret Key
    this.dom.attackWrongKeyBtn.addEventListener('click', async () => {
      this.syncServerKey();

      const attack = await simulateWrongSecretKey(
        {
          method: this.dom.reqMethod.value,
          path: this.dom.reqPath.value,
          query: this.dom.reqQuery.value,
          body: this.dom.reqBody.value
        },
        this.verifier,
        this.verifier.serverSecretKey,
        'unauthorized_attacker_forged_key_0xdeadbeef'
      );

      this.renderVerificationResult(attack.result);
      this.logEvent({
        type: 'ATTACK',
        message: `[ATTACK 4] Forgery detected: Request signed with unauthorized credentials.`,
        details: `Expected: ${attack.expectedOutcome}`
      });
      this.showToast('Simulated Attack 4: Key forgery rejected', 'error');
    });

    // Attack 5: Route / Path Tampering
    this.dom.attackPathBtn.addEventListener('click', async () => {
      if (!this.currentSignedRequest) await this.handleSignRequest();
      this.syncServerKey();

      const attack = await simulatePathTampering(
        this.currentSignedRequest,
        this.verifier,
        this.verifier.serverSecretKey
      );

      this.renderVerificationResult(attack.result);
      this.logEvent({
        type: 'ATTACK',
        message: `[ATTACK 5] URI Tampering detected: Modified endpoint to '${attack.tamperedPath}'.`,
        details: `Expected: ${attack.expectedOutcome}`
      });
      this.showToast('Simulated Attack 5: Route alteration rejected', 'error');
    });
  }

  /**
   * Configures timing attack interactive analysis modal.
   */
  bindTimingModal() {
    this.dom.attackTimingBtn.addEventListener('click', () => {
      const currentSig = this.currentSignedRequest ? this.currentSignedRequest.signature : '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843';
      this.dom.timingTargetSig.textContent = currentSig;
      this.dom.timingModal.classList.remove('hidden');
    });

    const closeModal = () => this.dom.timingModal.classList.add('hidden');
    this.dom.closeTimingModalBtn.addEventListener('click', closeModal);
    this.dom.closeTimingModalBtnBottom.addEventListener('click', closeModal);

    this.dom.timingModal.addEventListener('click', (e) => {
      if (e.target === this.dom.timingModal) closeModal();
    });

    this.dom.runTimingBenchmarkBtn.addEventListener('click', () => {
      const targetSig = this.dom.timingTargetSig.textContent.trim();

      // Synthesize probes with varying prefix match lengths
      const candidates = [
        '0000000000000000000000000000000000000000000000000000000000000000', // 0 match
        targetSig.slice(0, 4) + '0'.repeat(60),                               // 4 chars match
        targetSig.slice(0, 16) + '0'.repeat(48),                              // 16 chars match
        targetSig.slice(0, 32) + '0'.repeat(32),                              // 32 chars match
        targetSig.slice(0, 60) + '0'.repeat(4),                               // 60 chars match
        targetSig                                                             // 64 chars match
      ];

      const analysis = analyzeTimingComparison(targetSig, candidates);
      const tbody = this.dom.timingBenchmarkTbody;
      tbody.innerHTML = '';

      for (const row of analysis) {
        const tr = document.createElement('tr');
        const isLeaking = row.naiveChecks < targetSig.length;

        tr.innerHTML = `
          <td class="form-control-mono">${escapeHtml(row.candidate)}</td>
          <td><span class="badge badge-info">${row.matchingPrefixLength} chars</span></td>
          <td><strong style="color: ${isLeaking ? 'var(--status-fail)' : 'var(--status-pass)'};">${row.naiveChecks} checks</strong> <span style="font-size:0.7rem; color:var(--text-dim);">(early exit)</span></td>
          <td><strong style="color: var(--status-pass);">${row.constantChecks} checks</strong> <span style="font-size:0.7rem; color:var(--text-dim);">(full scan)</span></td>
          <td>
            <span class="badge ${isLeaking ? 'badge-fail' : 'badge-pass'}">
              ${isLeaking ? '⚠️ Timing Leak' : '✓ Protected'}
            </span>
          </td>
        `;
        tbody.appendChild(tr);
      }

      this.logEvent({
        type: 'INFO',
        message: 'Executed Timing Attack Side-Channel probe analysis.',
        details: 'Compared naive loop checks vs constantTimeEqual evaluations'
      });
    });
  }

  /**
   * Theme persistence (light/dark theme toggle).
   */
  toggleTheme() {
    const isLight = document.documentElement.getAttribute('data-theme') === 'light';
    const newTheme = isLight ? 'dark' : 'light';
    document.documentElement.setAttribute('data-theme', newTheme);
    localStorage.setItem('crypto_demo_theme', newTheme);
    this.updateThemeButton(newTheme);
  }

  loadTheme() {
    const saved = localStorage.getItem('crypto_demo_theme') || 'dark';
    document.documentElement.setAttribute('data-theme', saved);
    this.updateThemeButton(saved);
  }

  updateThemeButton(theme) {
    if (theme === 'light') {
      this.dom.themeIcon.textContent = '🌙';
      this.dom.themeLabel.textContent = 'Dark Mode';
    } else {
      this.dom.themeIcon.textContent = '☀️';
      this.dom.themeLabel.textContent = 'Light Mode';
    }
  }
}
