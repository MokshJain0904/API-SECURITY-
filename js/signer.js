/**
 * Request Signer Module (Client-Side)
 * Constructs deterministic canonical request representations and computes HMAC-SHA256 signatures.
 *
 * Specification:
 * 1. Canonical String:
 *    METHOD + "\n" +
 *    PATH + "\n" +
 *    SORTED_QUERY_STRING + "\n" +
 *    TIMESTAMP + "\n" +
 *    NONCE + "\n" +
 *    BODY_SHA256_HEX
 *
 * 2. Signature:
 *    HMAC-SHA256(secretKey, canonicalString) -> 64-char lowercase hex
 *
 * 3. Output HTTP Headers:
 *    X-Timestamp: string
 *    X-Nonce: string
 *    X-Signature: string
 *    X-Key-Id: string (optional / identifier)
 *
 * @module signer
 */

import {
  sha256Hex,
  computeHmacSha256,
  generateRandomNonce
} from './crypto.js';

/**
 * Normalizes and alphabetically sorts URL query parameters to ensure deterministic representation.
 * Handles query strings with or without leading '?', as well as key-value objects.
 *
 * @param {string|Record<string, string>} [query=''] - Query string or object.
 * @returns {string} Alphabetically sorted query string (e.g., 'a=1&b=2').
 */
export function canonicalizeQuery(query = '') {
  if (!query) return '';

  /** @type {Array<[string, string]>} */
  let pairs = [];

  if (typeof query === 'string') {
    const cleanQuery = query.startsWith('?') ? query.slice(1) : query;
    if (!cleanQuery.trim()) return '';

    const searchParams = new URLSearchParams(cleanQuery);
    pairs = Array.from(searchParams.entries());
  } else if (typeof query === 'object' && query !== null) {
    pairs = Object.entries(query).map(([k, v]) => [String(k), String(v)]);
  }

  // Sort by key first, then by value if keys are identical
  pairs.sort(([keyA, valA], [keyB, valB]) => {
    if (keyA === keyB) {
      return valA.localeCompare(valB);
    }
    return keyA.localeCompare(keyB);
  });

  return pairs
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
    .join('&');
}

/**
 * Normalizes the HTTP path to ensure a leading slash and no trailing slash (unless root).
 *
 * @param {string} [path='/'] - Raw HTTP request path.
 * @returns {string} Normalized path (e.g., '/api/v1/transfers').
 */
export function normalizePath(path = '/') {
  if (!path || !path.trim()) return '/';
  let p = path.trim();
  if (!p.startsWith('/')) p = `/${p}`;
  if (p.length > 1 && p.endsWith('/')) p = p.slice(0, -1);
  return p;
}

/**
 * Builds the canonical string representation for an HTTP request according to specification.
 *
 * @param {Object} params - Canonical string parameters.
 * @param {string} params.method - HTTP method (e.g., 'POST').
 * @param {string} params.path - Normalized HTTP path.
 * @param {string} params.sortedQuery - Canonicalized query string.
 * @param {string|number} params.timestamp - Unix timestamp (seconds).
 * @param {string} params.nonce - Cryptographic nonce.
 * @param {string} params.bodyHash - Hexadecimal SHA-256 digest of body.
 * @returns {string} Raw canonical string delimited by newlines.
 */
export function buildCanonicalString({
  method,
  path,
  sortedQuery,
  timestamp,
  nonce,
  bodyHash
}) {
  const normMethod = (method || 'GET').toUpperCase().trim();
  const normPath = normalizePath(path);
  const normQuery = sortedQuery || '';
  const normTimestamp = String(timestamp).trim();
  const normNonce = String(nonce).trim();
  const normBodyHash = (bodyHash || '').toLowerCase().trim();

  return [
    normMethod,
    normPath,
    normQuery,
    normTimestamp,
    normNonce,
    normBodyHash
  ].join('\n');
}

/**
 * Signs an HTTP request payload with a shared secret key using HMAC-SHA256.
 * Generates nonce and timestamp if not explicitly supplied.
 *
 * @param {Object} options - Request signing parameters.
 * @param {string} options.method - HTTP method (GET, POST, etc.).
 * @param {string} options.path - Request path (e.g., '/api/v1/users').
 * @param {string|Record<string, string>} [options.query=''] - Query parameters.
 * @param {string|Object} [options.body=''] - Request payload (string or JSON).
 * @param {string} options.secretKey - Shared secret key.
 * @param {string} [options.keyId='key-demo-01'] - Optional Key Identifier header.
 * @param {string|number} [options.timestamp] - Unix timestamp in seconds (defaults to now).
 * @param {string} [options.nonce] - Unique nonce (defaults to random 128-bit hex).
 * @returns {Promise<Object>} Complete signed request package with metadata and headers.
 */
export async function signRequest({
  method = 'GET',
  path = '/',
  query = '',
  body = '',
  secretKey,
  keyId = 'key-demo-01',
  timestamp,
  nonce
}) {
  if (!secretKey) {
    throw new Error('A shared secret key is required to sign the request.');
  }

  // 1. Normalize body and compute body SHA-256 hash
  const rawBody = typeof body === 'object' && body !== null ? JSON.stringify(body) : (body || '');
  const bodyHash = await sha256Hex(rawBody);

  // 2. Resolve timestamp (Unix epoch in seconds) and nonce
  const resolvedTimestamp = timestamp !== undefined ? String(timestamp) : Math.floor(Date.now() / 1000).toString();
  const resolvedNonce = nonce || generateRandomNonce(16);

  // 3. Canonicalize path and query string
  const normMethod = method.toUpperCase().trim();
  const normPath = normalizePath(path);
  const sortedQuery = canonicalizeQuery(query);

  // 4. Construct canonical string
  const canonicalString = buildCanonicalString({
    method: normMethod,
    path: normPath,
    sortedQuery,
    timestamp: resolvedTimestamp,
    nonce: resolvedNonce,
    bodyHash
  });

  // 5. Compute HMAC-SHA256 signature
  const signature = await computeHmacSha256(secretKey, canonicalString);

  // 6. Assemble headers
  const headers = {
    'X-Timestamp': resolvedTimestamp,
    'X-Nonce': resolvedNonce,
    'X-Signature': signature,
    'X-Key-Id': keyId
  };

  return {
    method: normMethod,
    path: normPath,
    query: sortedQuery,
    body: rawBody,
    secretKey,
    keyId,
    timestamp: resolvedTimestamp,
    nonce: resolvedNonce,
    bodyHash,
    canonicalString,
    signature,
    headers
  };
}
