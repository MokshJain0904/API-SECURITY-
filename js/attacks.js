/**
 * Attack Simulation Module
 * Simulates real-world API security attacks to demonstrate how HMAC-SHA256 request signing,
 * timestamp tolerance windows, and nonce caches protect API endpoints against tampering,
 * replay attacks, forgery, and side-channel timing attacks.
 *
 * @module attacks
 */

import { signRequest } from './signer.js';
import { constantTimeEqual } from './crypto.js';

/**
 * Standard naive string comparison vulnerable to timing attacks (for demonstration only).
 * Terminates early on the first mismatched character.
 *
 * @param {string} a 
 * @param {string} b 
 * @returns {boolean}
 */
export function naiveCompare(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      return false; // Early exit leaks how many initial characters matched
    }
  }
  return true;
}

/**
 * Attack 1: Payload Tampering (Integrity Attack)
 * Intercepts a legitimately signed request and modifies the JSON payload in transit
 * without recalculating the HMAC signature (which the attacker cannot do without the secret key).
 *
 * Expected outcome: Rejection at Step 5 (Signature Mismatch) because the server's
 * reconstructed canonical string will have a different body SHA-256 digest.
 *
 * @param {Object} legitSignedRequest - Original signed request.
 * @param {import('./verifier.js').ApiVerifier} verifier - Verifier instance.
 * @param {string} serverKey - Server's secret key.
 * @returns {Promise<Object>} Verification outcome with attack metadata.
 */
export async function simulatePayloadTampering(legitSignedRequest, verifier, serverKey) {
  // Ensure nonce is not already consumed from a prior test so payload tampering reaches Step 5
  const rawNonce = legitSignedRequest.headers?.['X-Nonce'] || legitSignedRequest.nonce;
  if (rawNonce && verifier.nonceCache.has(rawNonce)) {
    verifier.nonceCache.delete(rawNonce);
  }

  // Parse or modify payload
  let tamperedBody;
  try {
    const parsed = JSON.parse(legitSignedRequest.body || '{}');
    parsed.amount = (parsed.amount || 100) * 1000; // Inflate transfer amount
    parsed.recipient = 'Eve_Attacker_Account_0x999';
    parsed.tampered = true;
    tamperedBody = JSON.stringify(parsed);
  } catch {
    tamperedBody = (legitSignedRequest.body || '') + '\n// TAMPERED_IN_FLIGHT_BY_ATTACKER';
  }

  // Attacker forwards original headers (with original signature) with tampered body
  const tamperedRequest = {
    method: legitSignedRequest.method,
    path: legitSignedRequest.path,
    query: legitSignedRequest.query,
    body: tamperedBody,
    headers: { ...legitSignedRequest.headers }
  };

  const verificationResult = await verifier.verifyRequest(tamperedRequest, serverKey);

  return {
    attackId: 'payload_tampering',
    attackName: 'Payload Tampering Attack',
    description: 'Modified request body in transit while preserving original cryptographic signature.',
    originalBody: legitSignedRequest.body,
    tamperedBody,
    tamperedRequest,
    result: verificationResult,
    expectedOutcome: 'Rejected (Signature Mismatch at Step 5)'
  };
}

/**
 * Attack 2: Replay Attack
 * Captures an authentic, valid request previously accepted by the server and resends
 * the identical request (with identical timestamp, nonce, and signature).
 *
 * Expected outcome: Rejection at Step 3 (Nonce Replay Detection) because the verifier
 * has cached the nonce and marks it as already processed.
 *
 * @param {Object} legitSignedRequest - Request that was already sent and accepted once.
 * @param {import('./verifier.js').ApiVerifier} verifier - Verifier instance.
 * @param {string} serverKey - Server's secret key.
 * @returns {Promise<Object>} Verification outcome with attack metadata.
 */
export async function simulateReplayAttack(legitSignedRequest, verifier, serverKey) {
  // First ensure original request has been submitted once so nonce is in cache
  const firstSubmission = await verifier.verifyRequest(legitSignedRequest, serverKey);

  // Now simulate attacker resending the identical wire request
  const replayedRequest = {
    method: legitSignedRequest.method,
    path: legitSignedRequest.path,
    query: legitSignedRequest.query,
    body: legitSignedRequest.body,
    headers: { ...legitSignedRequest.headers }
  };

  const replayResult = await verifier.verifyRequest(replayedRequest, serverKey);

  return {
    attackId: 'replay_attack',
    attackName: 'Replay Attack',
    description: 'Resending identical intercepted request packet containing previously consumed nonce.',
    firstSubmission,
    replayedRequest,
    result: replayResult,
    expectedOutcome: 'Rejected (Duplicate Nonce at Step 3)'
  };
}

/**
 * Attack 3: Expired Timestamp (Stale Request / Window Expiry)
 * Intercepts a request or delays it beyond the allowed tolerance window (e.g. 120 seconds ago).
 *
 * Expected outcome: Rejection at Step 2 (Timestamp Freshness Window) because the time delta
 * exceeds the server's configured tolerance window (default 60s).
 *
 * @param {Object} baseParams - Request parameters.
 * @param {import('./verifier.js').ApiVerifier} verifier - Verifier instance.
 * @param {string} clientKey - Client secret key.
 * @param {string} serverKey - Server secret key.
 * @param {number} [ageSeconds=150] - Number of seconds in the past to backdate.
 * @returns {Promise<Object>} Verification outcome with attack metadata.
 */
export async function simulateExpiredTimestamp(baseParams, verifier, clientKey, serverKey, ageSeconds = 150) {
  const staleTimestamp = Math.floor(Date.now() / 1000) - ageSeconds;

  // Sign request with legitimately matching key, but with a stale timestamp
  const staleSigned = await signRequest({
    method: baseParams.method || 'POST',
    path: baseParams.path || '/api/v1/transfer',
    query: baseParams.query || '',
    body: baseParams.body || '{"amount":50}',
    secretKey: clientKey,
    timestamp: staleTimestamp
  });

  const verificationResult = await verifier.verifyRequest(staleSigned, serverKey);

  return {
    attackId: 'expired_timestamp',
    attackName: 'Expired Timestamp / Stale Request',
    description: `Request timestamp is ${ageSeconds} seconds old (exceeds tolerance of ±${verifier.timestampToleranceSec}s).`,
    staleTimestamp,
    ageSeconds,
    request: staleSigned,
    result: verificationResult,
    expectedOutcome: 'Rejected (Expired Timestamp at Step 2)'
  };
}

/**
 * Attack 4: Wrong Secret Key (Forgery / Impersonation)
 * Attacker crafts a request and signs it using an unauthorized or guessed secret key.
 *
 * Expected outcome: Rejection at Step 5 (Signature Mismatch) because the server verifies
 * with the legitimate shared secret, generating an HMAC that does not match the attacker's.
 *
 * @param {Object} baseParams - Request parameters.
 * @param {import('./verifier.js').ApiVerifier} verifier - Verifier instance.
 * @param {string} serverKey - True server secret key.
 * @param {string} [attackerKey='attacker-forged-key-999999'] - Attacker's bogus key.
 * @returns {Promise<Object>} Verification outcome with attack metadata.
 */
export async function simulateWrongSecretKey(baseParams, verifier, serverKey, attackerKey = 'attacker_unauthorized_secret_key_0xdeadbeef') {
  const forgedSigned = await signRequest({
    method: baseParams.method || 'POST',
    path: baseParams.path || '/api/v1/admin/promote',
    query: baseParams.query || '',
    body: baseParams.body || '{"role":"superuser"}',
    secretKey: attackerKey,
    keyId: 'attacker-impersonator'
  });

  const verificationResult = await verifier.verifyRequest(forgedSigned, serverKey);

  return {
    attackId: 'wrong_key',
    attackName: 'Wrong Secret Key / Forgery Attack',
    description: 'Attacker signed canonical string with an unauthorized secret key.',
    attackerKey,
    serverKey,
    request: forgedSigned,
    result: verificationResult,
    expectedOutcome: 'Rejected (Signature Mismatch at Step 5)'
  };
}

/**
 * Attack 5: Header / Path / Query Tampering (Routing Tampering)
 * Intercepts a request signed for a safe endpoint (e.g. GET /api/v1/profile) and
 * redirects it to an administrative or sensitive endpoint (e.g. POST /api/v1/admin/users/delete)
 * or injects unauthorized query parameters (e.g. ?role=admin).
 *
 * Expected outcome: Rejection at Step 5 (Signature Mismatch) because the canonical string
 * binds the HTTP Method, Path, and sorted Query string into the HMAC digest.
 *
 * @param {Object} legitSignedRequest - Legitimate signed request.
 * @param {import('./verifier.js').ApiVerifier} verifier - Verifier instance.
 * @param {string} serverKey - Server secret key.
 * @returns {Promise<Object>} Verification outcome with attack metadata.
 */
export async function simulatePathTampering(legitSignedRequest, verifier, serverKey) {
  // Ensure nonce is not already consumed from a prior test so path tampering reaches Step 5
  const rawNonce = legitSignedRequest.headers?.['X-Nonce'] || legitSignedRequest.nonce;
  if (rawNonce && verifier.nonceCache.has(rawNonce)) {
    verifier.nonceCache.delete(rawNonce);
  }

  // Tamper path and add elevated query parameter
  const tamperedPath = '/api/v1/admin/system/purge';
  const tamperedQuery = 'elevated=true&role=cluster-admin';

  const tamperedRequest = {
    method: 'DELETE', // Also tamper method
    path: tamperedPath,
    query: tamperedQuery,
    body: legitSignedRequest.body,
    headers: { ...legitSignedRequest.headers }
  };

  const verificationResult = await verifier.verifyRequest(tamperedRequest, serverKey);

  return {
    attackId: 'path_tampering',
    attackName: 'URI / Method / Query Tampering',
    description: `Changed method to DELETE, path to '${tamperedPath}', and query to '${tamperedQuery}' without resigning.`,
    originalPath: legitSignedRequest.path,
    tamperedPath,
    tamperedRequest,
    result: verificationResult,
    expectedOutcome: 'Rejected (Signature Mismatch at Step 5)'
  };
}

/**
 * Demonstrates the mechanics of timing attacks comparing naive vs constant-time comparison.
 * Measures loop iterations or simulated character match evaluations to illustrate
 * how early exit leaks information about matching prefix length.
 *
 * @param {string} correctSignature - 64-character target hex signature.
 * @param {Array<string>} candidateSignatures - Array of test signatures with varying match lengths.
 * @returns {Array<Object>} Comparison data showing character checks performed.
 */
export function analyzeTimingComparison(correctSignature, candidateSignatures) {
  return candidateSignatures.map((candidate) => {
    // 1. Naive count: stops at first mismatch
    let naiveChecks = 0;
    const naiveMatch = (() => {
      if (candidate.length !== correctSignature.length) {
        naiveChecks = 1;
        return false;
      }
      for (let i = 0; i < correctSignature.length; i++) {
        naiveChecks++;
        if (candidate[i] !== correctSignature[i]) {
          return false;
        }
      }
      return true;
    })();

    // 2. Constant-time count: evaluates all characters up to max length
    let constantChecks = 0;
    const lenA = correctSignature.length;
    const lenB = candidate.length;
    let diff = lenA ^ lenB;
    const maxLen = Math.max(lenA, lenB);
    for (let i = 0; i < maxLen; i++) {
      constantChecks++;
      const charA = i < lenA ? correctSignature.charCodeAt(i) : 0;
      const charB = i < lenB ? candidate.charCodeAt(i) : 0;
      diff |= (charA ^ charB);
    }
    const constantMatch = (diff === 0);

    return {
      candidate: `${candidate.slice(0, 16)}...`,
      matchingPrefixLength: naiveChecks - (naiveMatch ? 0 : 1),
      naiveChecks,
      constantChecks,
      naiveMatch,
      constantMatch,
      leakRisk: naiveChecks < correctSignature.length ? 'LEAKS_PREFIX_LENGTH' : 'EXHAUSTIVE'
    };
  });
}
