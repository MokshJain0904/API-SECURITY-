/**
 * Simulated Server API Verifier Module
 * Enforces cryptographic request integrity, authentication, freshness, and anti-replay policies.
 *
 * Verification Sequence:
 * 1. Verify required security headers presence (X-Timestamp, X-Nonce, X-Signature).
 * 2. Validate timestamp freshness within configurable tolerance window (|server_now - timestamp| <= window).
 * 3. Validate nonce uniqueness against in-memory cache to prevent replay attacks.
 * 4. Reconstruct canonical request representation and recompute body SHA-256 digest.
 * 5. Recompute expected HMAC-SHA256 signature and compare against received signature in CONSTANT TIME.
 * 6. Mark nonce as consumed in cache ONLY after all checks succeed.
 *
 * @module verifier
 */

import {
  sha256Hex,
  computeHmacSha256,
  constantTimeEqual
} from './crypto.js';
import {
  buildCanonicalString,
  canonicalizeQuery,
  normalizePath
} from './signer.js';

/**
 * Retrieves a header value from a headers object in a case-insensitive manner.
 *
 * @param {Record<string, string>} headers - Headers map.
 * @param {string} target - Target header name (e.g., 'X-Timestamp').
 * @returns {string|undefined} Header value if found.
 */
function getHeaderCaseInsensitive(headers, target) {
  if (!headers || typeof headers !== 'object') return undefined;
  const targetLower = target.toLowerCase();
  for (const [key, val] of Object.entries(headers)) {
    if (key.toLowerCase() === targetLower) {
      return String(val);
    }
  }
  return undefined;
}

/**
 * Simulated Server API Verifier.
 */
export class ApiVerifier {
  /**
   * Initializes the Verifier with configurable freshness and nonce retention policies.
   *
   * @param {Object} [options={}] - Configuration options.
   * @param {number} [options.timestampToleranceSec=60] - Allowed timestamp drift in seconds (±).
   * @param {number} [options.nonceTtlSec=300] - Nonce cache retention time in seconds.
   * @param {string} [options.serverSecretKey=''] - Shared secret key stored on server.
   */
  constructor(options = {}) {
    this.timestampToleranceSec = Number(options.timestampToleranceSec) || 60;
    this.nonceTtlSec = Number(options.nonceTtlSec) || 300;
    this.serverSecretKey = options.serverSecretKey || '';

    /**
     * In-memory cache for anti-replay verification: Map<nonce, expiryTimestampMs>
     * @type {Map<string, number>}
     */
    this.nonceCache = new Map();
  }

  /**
   * Cleans up expired nonces from the in-memory cache.
   *
   * @returns {number} Number of nonces purged.
   */
  purgeExpiredNonces() {
    const now = Date.now();
    let purged = 0;
    for (const [nonce, expiry] of this.nonceCache.entries()) {
      if (expiry <= now) {
        this.nonceCache.delete(nonce);
        purged++;
      }
    }
    return purged;
  }

  /**
   * Clears all recorded nonces in the cache.
   */
  clearNonceCache() {
    this.nonceCache.clear();
  }

  /**
   * Returns current statistics for the verifier's nonce cache.
   *
   * @returns {{ size: number, nonces: Array<{ nonce: string, expiresAt: number, remainingSec: number }> }}
   */
  getNonceCacheStats() {
    this.purgeExpiredNonces();
    const now = Date.now();
    const nonces = [];
    for (const [nonce, expiry] of this.nonceCache.entries()) {
      nonces.push({
        nonce,
        expiresAt: expiry,
        remainingSec: Math.max(0, Math.round((expiry - now) / 1000))
      });
    }
    return {
      size: this.nonceCache.size,
      nonces
    };
  }

  /**
   * Verifies an incoming HTTP request package against security policies.
   *
   * @param {Object} request - Incoming request object.
   * @param {string} request.method - HTTP method (e.g., 'POST').
   * @param {string} request.path - Request path.
   * @param {string|Record<string, string>} [request.query=''] - Query parameters.
   * @param {string|Object} [request.body=''] - Request payload.
   * @param {Record<string, string>} request.headers - HTTP headers received.
   * @param {string} [serverSecretKeyOverride] - Optional secret key override for server simulation.
   * @param {number} [currentTimeSec] - Optional current time in seconds (for deterministic testing).
   * @returns {Promise<{ ok: boolean, reason: string, steps: Array<Object>, details: Object }>}
   */
  async verifyRequest(request, serverSecretKeyOverride, currentTimeSec) {
    this.purgeExpiredNonces();

    const serverKey = serverSecretKeyOverride !== undefined ? serverSecretKeyOverride : this.serverSecretKey;
    const nowSec = currentTimeSec !== undefined ? currentTimeSec : Math.floor(Date.now() / 1000);

    const steps = [];
    const headers = request.headers || {};

    // -------------------------------------------------------------
    // Step 1: Check Required Security Headers
    // -------------------------------------------------------------
    const rawTimestamp = getHeaderCaseInsensitive(headers, 'X-Timestamp');
    const rawNonce = getHeaderCaseInsensitive(headers, 'X-Nonce');
    const rawSignature = getHeaderCaseInsensitive(headers, 'X-Signature');
    const rawKeyId = getHeaderCaseInsensitive(headers, 'X-Key-Id') || 'unknown';

    const missingHeaders = [];
    if (!rawTimestamp) missingHeaders.push('X-Timestamp');
    if (!rawNonce) missingHeaders.push('X-Nonce');
    if (!rawSignature) missingHeaders.push('X-Signature');

    if (missingHeaders.length > 0) {
      steps.push({
        id: 'headers',
        name: '1. Required Security Headers',
        status: 'fail',
        message: `Missing mandatory headers: ${missingHeaders.join(', ')}`,
        detail: { receivedHeaders: Object.keys(headers), missing: missingHeaders }
      });

      return {
        ok: false,
        reason: `Missing mandatory headers: ${missingHeaders.join(', ')}`,
        steps,
        details: { stepFailed: 'headers' }
      };
    }

    steps.push({
      id: 'headers',
      name: '1. Required Security Headers',
      status: 'pass',
      message: 'All mandatory cryptographic headers present (X-Timestamp, X-Nonce, X-Signature)',
      detail: {
        'X-Timestamp': rawTimestamp,
        'X-Nonce': rawNonce,
        'X-Signature': `${rawSignature.slice(0, 12)}...`,
        'X-Key-Id': rawKeyId
      }
    });

    // -------------------------------------------------------------
    // Step 2: Validate Timestamp Freshness (Window Check)
    // -------------------------------------------------------------
    const requestTimestamp = parseInt(rawTimestamp, 10);
    if (Number.isNaN(requestTimestamp)) {
      steps.push({
        id: 'timestamp',
        name: '2. Timestamp Freshness Window',
        status: 'fail',
        message: 'Invalid X-Timestamp: cannot parse numeric Unix timestamp',
        detail: { rawTimestamp }
      });
      return {
        ok: false,
        reason: 'Invalid X-Timestamp header format',
        steps,
        details: { stepFailed: 'timestamp' }
      };
    }

    const timeDelta = Math.abs(nowSec - requestTimestamp);
    const isTimestampValid = timeDelta <= this.timestampToleranceSec;

    if (!isTimestampValid) {
      const isExpired = (nowSec - requestTimestamp) > this.timestampToleranceSec;
      const errorMsg = isExpired
        ? `Request timestamp has expired. Skew: ${timeDelta}s (Tolerance: ±${this.timestampToleranceSec}s)`
        : `Request timestamp is in the future. Skew: ${timeDelta}s (Tolerance: ±${this.timestampToleranceSec}s)`;

      steps.push({
        id: 'timestamp',
        name: '2. Timestamp Freshness Window',
        status: 'fail',
        message: errorMsg,
        detail: {
          serverTime: nowSec,
          requestTimestamp,
          deltaSeconds: timeDelta,
          toleranceWindow: this.timestampToleranceSec
        }
      });

      return {
        ok: false,
        reason: errorMsg,
        steps,
        details: { stepFailed: 'timestamp', timeDelta }
      };
    }

    steps.push({
      id: 'timestamp',
      name: '2. Timestamp Freshness Window',
      status: 'pass',
      message: `Timestamp is fresh. Clock delta: ${timeDelta}s (allowed: ±${this.timestampToleranceSec}s)`,
      detail: {
        serverTime: nowSec,
        requestTimestamp,
        deltaSeconds: timeDelta,
        toleranceWindow: this.timestampToleranceSec
      }
    });

    // -------------------------------------------------------------
    // Step 3: Check Nonce Cache & Replay Detection
    // -------------------------------------------------------------
    const existingNonceExpiry = this.nonceCache.get(rawNonce);
    const nowMs = nowSec * 1000;

    if (existingNonceExpiry && existingNonceExpiry > nowMs) {
      const errorMsg = `Replay attack detected: Nonce '${rawNonce}' has already been processed within the active TTL window.`;
      steps.push({
        id: 'nonce',
        name: '3. Nonce Uniqueness & Anti-Replay',
        status: 'fail',
        message: errorMsg,
        detail: {
          nonce: rawNonce,
          expiresInSec: Math.round((existingNonceExpiry - nowMs) / 1000)
        }
      });

      return {
        ok: false,
        reason: errorMsg,
        steps,
        details: { stepFailed: 'nonce', nonce: rawNonce }
      };
    }

    steps.push({
      id: 'nonce',
      name: '3. Nonce Uniqueness & Anti-Replay',
      status: 'pass',
      message: `Nonce '${rawNonce.slice(0, 8)}...' is novel and unused in the current window.`,
      detail: { nonce: rawNonce }
    });

    // -------------------------------------------------------------
    // Step 4: Recompute Canonical Representation
    // -------------------------------------------------------------
    const rawBody = typeof request.body === 'object' && request.body !== null
      ? JSON.stringify(request.body)
      : (request.body || '');

    const serverBodyHash = await sha256Hex(rawBody);
    const normMethod = (request.method || 'GET').toUpperCase().trim();
    const normPath = normalizePath(request.path);
    const sortedQuery = canonicalizeQuery(request.query);

    const serverCanonicalString = buildCanonicalString({
      method: normMethod,
      path: normPath,
      sortedQuery,
      timestamp: rawTimestamp,
      nonce: rawNonce,
      bodyHash: serverBodyHash
    });

    steps.push({
      id: 'canonical',
      name: '4. Recompute Canonical Digest',
      status: 'pass',
      message: 'Server reconstructed canonical string and recalculated SHA-256 body hash.',
      detail: {
        serverBodyHash,
        serverCanonicalString
      }
    });

    // -------------------------------------------------------------
    // Step 5: Constant-Time Signature Comparison
    // -------------------------------------------------------------
    if (!serverKey) {
      steps.push({
        id: 'signature',
        name: '5. Signature Verification',
        status: 'fail',
        message: 'Server missing shared secret key to authenticate signature.',
        detail: {}
      });
      return {
        ok: false,
        reason: 'Server does not have an active shared secret key configured.',
        steps,
        details: { stepFailed: 'signature' }
      };
    }

    const expectedSignature = await computeHmacSha256(serverKey, serverCanonicalString);
    const isSignatureMatch = constantTimeEqual(expectedSignature, rawSignature.toLowerCase().trim());

    if (!isSignatureMatch) {
      const errorMsg = 'Cryptographic signature mismatch! The request payload, URI, headers, or secret key were altered or invalid.';
      steps.push({
        id: 'signature',
        name: '5. Constant-Time Signature Comparison',
        status: 'fail',
        message: errorMsg,
        detail: {
          receivedSignature: rawSignature,
          expectedSignature,
          constantTimeEvaluated: true
        }
      });

      return {
        ok: false,
        reason: errorMsg,
        steps,
        details: {
          stepFailed: 'signature',
          receivedSignature: rawSignature,
          expectedSignature,
          serverCanonicalString
        }
      };
    }

    steps.push({
      id: 'signature',
      name: '5. Constant-Time Signature Comparison',
      status: 'pass',
      message: 'HMAC-SHA256 signature verified successfully using constant-time comparison.',
      detail: {
        matchedSignature: rawSignature,
        constantTimeEvaluated: true
      }
    });

    // -------------------------------------------------------------
    // Step 6: Mark Nonce as Consumed (ONLY on successful verification)
    // -------------------------------------------------------------
    const nonceExpiryTimeMs = Date.now() + (this.nonceTtlSec * 1000);
    this.nonceCache.set(rawNonce, nonceExpiryTimeMs);

    return {
      ok: true,
      reason: 'Request verified successfully. Authentic, intact, and within freshness window.',
      steps,
      details: {
        timestamp: rawTimestamp,
        nonce: rawNonce,
        signature: expectedSignature,
        canonicalString: serverCanonicalString,
        bodyHash: serverBodyHash
      }
    };
  }
}
