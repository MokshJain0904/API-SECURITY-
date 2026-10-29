/**
 * Cryptographic Utility Module
 * Implements pure cryptographic operations using the Web Cryptography API (window.crypto.subtle)
 * and cryptographically secure pseudorandom number generator (crypto.getRandomValues).
 *
 * No external dependencies. No DOM manipulation.
 *
 * @module crypto
 */

/**
 * Converts an ArrayBuffer or Uint8Array into a lowercase hexadecimal string.
 *
 * @param {ArrayBuffer|Uint8Array} buffer - Buffer to convert.
 * @returns {string} Hexadecimal representation.
 */
export function bufferToHex(buffer) {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
}

/**
 * Converts a hexadecimal string into a Uint8Array.
 *
 * @param {string} hex - Hexadecimal string (even length).
 * @returns {Uint8Array} Byte array representation.
 * @throws {Error} If hex string contains invalid characters or odd length.
 */
export function hexToBuffer(hex) {
  const cleanHex = hex.trim();
  if (cleanHex.length % 2 !== 0) {
    throw new Error('Hex string must have an even length');
  }
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < cleanHex.length; i += 2) {
    const byteVal = parseInt(cleanHex.substring(i, i + 2), 16);
    if (Number.isNaN(byteVal)) {
      throw new Error(`Invalid hexadecimal byte at position ${i}`);
    }
    bytes[i / 2] = byteVal;
  }
  return bytes;
}

/**
 * Encodes a string into UTF-8 byte array.
 *
 * @param {string} str - Input string.
 * @returns {Uint8Array} UTF-8 encoded bytes.
 */
export function stringToUtf8(str) {
  return new TextEncoder().encode(str || '');
}

/**
 * Decodes a UTF-8 byte array into a string.
 *
 * @param {Uint8Array|ArrayBuffer} bytes - UTF-8 encoded bytes.
 * @returns {string} Decoded string.
 */
export function utf8ToString(bytes) {
  return new TextDecoder().decode(bytes);
}

/**
 * Computes the SHA-256 digest of a string or byte array, returned as a lowercase hex string.
 *
 * @param {string|Uint8Array} data - Input string or bytes to hash.
 * @returns {Promise<string>} Hexadecimal SHA-256 hash.
 */
export async function sha256Hex(data) {
  const bytes = typeof data === 'string' ? stringToUtf8(data) : data;
  const hashBuffer = await crypto.subtle.digest('SHA-256', bytes);
  return bufferToHex(hashBuffer);
}

/**
 * Generates a cryptographically secure random hexadecimal string of given bit length.
 * Default is 256 bits (32 bytes = 64 hex characters).
 *
 * @param {number} [bitLength=256] - Desired bit length (must be multiple of 8).
 * @returns {string} Random hexadecimal string.
 */
export function generateRandomKeyHex(bitLength = 256) {
  const byteLength = Math.ceil(bitLength / 8);
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return bufferToHex(bytes);
}

/**
 * Generates a cryptographically secure random nonce string.
 * Default is 16 bytes (32 hex characters).
 *
 * @param {number} [byteLength=16] - Nonce byte length.
 * @returns {string} Random hex nonce.
 */
export function generateRandomNonce(byteLength = 16) {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return bufferToHex(bytes);
}

/**
 * Computes an HMAC-SHA256 signature for a message given a secret key.
 * Supports secret keys as UTF-8 strings or raw Uint8Array byte arrays.
 *
 * @param {string|Uint8Array} secretKey - Shared secret key.
 * @param {string|Uint8Array} message - Data to sign.
 * @returns {Promise<string>} HMAC-SHA256 signature as a lowercase hex string.
 */
export async function computeHmacSha256(secretKey, message) {
  if (!secretKey || (typeof secretKey === 'string' && secretKey.trim().length === 0)) {
    throw new Error('Secret key cannot be empty');
  }

  const keyBytes = typeof secretKey === 'string' ? stringToUtf8(secretKey) : secretKey;
  const messageBytes = typeof message === 'string' ? stringToUtf8(message) : message;

  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const signatureBuffer = await crypto.subtle.sign('HMAC', cryptoKey, messageBytes);
  return bufferToHex(signatureBuffer);
}

/**
 * Compares two strings in constant time to prevent side-channel timing attacks.
 *
 * In standard comparison (`a === b`), the engine terminates early on the first mismatched
 * character, leaking information about the matching prefix length through microsecond timing differences.
 * This implementation iterates across the maximum length without early returns,
 * accumulating bitwise differences.
 *
 * @param {string} a - First string (e.g., expected signature).
 * @param {string} b - Second string (e.g., received signature).
 * @returns {boolean} True if strings are character-identical, false otherwise.
 */
export function constantTimeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') {
    return false;
  }

  const lenA = a.length;
  const lenB = b.length;
  let diff = lenA ^ lenB;
  const maxLen = Math.max(lenA, lenB);

  for (let i = 0; i < maxLen; i++) {
    const charA = i < lenA ? a.charCodeAt(i) : 0;
    const charB = i < lenB ? b.charCodeAt(i) : 0;
    diff |= (charA ^ charB);
  }

  return diff === 0;
}
