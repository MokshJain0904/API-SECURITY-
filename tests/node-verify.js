/**
 * Node.js Test Verification Runner
 * Runs the exact same tests using Node 20+ native crypto.subtle to verify 100% correctness.
 */

import {
  sha256Hex,
  computeHmacSha256,
  constantTimeEqual,
  generateRandomKeyHex,
  generateRandomNonce
} from '../js/crypto.js';

import {
  canonicalizeQuery,
  normalizePath,
  buildCanonicalString,
  signRequest
} from '../js/signer.js';

import { ApiVerifier } from '../js/verifier.js';
import {
  simulatePayloadTampering,
  simulateReplayAttack,
  simulateExpiredTimestamp,
  simulateWrongSecretKey,
  simulatePathTampering
} from '../js/attacks.js';

function assert(condition, msg) {
  if (!condition) throw new Error(msg || 'Assertion failed');
}

function assertEqual(actual, expected, msg) {
  if (actual !== expected) throw new Error(`${msg}: Expected "${expected}", got "${actual}"`);
}

async function runTests() {
  console.log('--- RUNNING TEST SUITE VIA NODE.JS NATIVE CRYPTO ---');

  // Test 1: RFC 4231 Test Vector 2
  const rfcResult = await computeHmacSha256('Jefe', 'what do ya want for nothing?');
  assertEqual(rfcResult.toLowerCase(), '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843', 'RFC 4231 Vector 2');
  console.log('✓ Test 1: RFC 4231 Test Vector 2 passed');

  // Test 2: SHA-256 empty string
  const emptyHash = await sha256Hex('');
  assertEqual(emptyHash.toLowerCase(), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'SHA-256 empty string');
  console.log('✓ Test 2: SHA-256 Empty String passed');

  // Test 3: Constant-time comparison
  const sig1 = '5bdcc146bf60754e6a04242608957504ac33e8b15d01a99d024b1e45a8002d0f';
  const sig2 = '5bdcc146bf60754e6a04242608957504ac33e8b15d01a99d024b1e45a8002d0f';
  const sig3 = '5bdcc146bf60754e6a04242608957504ac33e8b15d01a99d024b1e45a8002d0e';
  assert(constantTimeEqual(sig1, sig2), 'Identical strings must return true');
  assert(!constantTimeEqual(sig1, sig3), 'Different strings must return false');
  assert(!constantTimeEqual(sig1, 'short'), 'Different length must return false');
  console.log('✓ Test 3: Constant-time comparison passed');

  // Test 4: Query canonicalization
  const sortedQ = canonicalizeQuery('?z=last&a=first&m=middle');
  assertEqual(sortedQ, 'a=first&m=middle&z=last', 'Query sorting');
  console.log('✓ Test 4: Query canonicalization passed');

  // Test 5: Path normalization
  assertEqual(normalizePath('api/v1/users/'), '/api/v1/users', 'Path normalization');
  console.log('✓ Test 5: Path normalization passed');

  // Test 6: Sign request
  const secretKey = 'test-secret-key-node';
  const signed = await signRequest({
    method: 'POST',
    path: '/api/v1/transfer',
    query: 'b=2&a=1',
    body: '{"amount":100}',
    secretKey
  });
  assert(signed.headers['X-Signature'].length === 64, 'Signature 64 chars');
  console.log('✓ Test 6: Request signing passed');

  // Test 7: Verifier accepts legitimate request
  const verifier = new ApiVerifier({ serverSecretKey: secretKey, timestampToleranceSec: 60 });
  const verifyRes = await verifier.verifyRequest(signed);
  assert(verifyRes.ok, `Legitimate request accepted: ${verifyRes.reason}`);
  console.log('✓ Test 7: Verifier accepts valid request passed');

  // Test 8: Attack 1 - Payload tampering
  const attack1 = await simulatePayloadTampering(signed, verifier, secretKey);
  assert(!attack1.result.ok, 'Tampered payload rejected');
  assertEqual(attack1.result.details.stepFailed, 'signature', 'Tamper failed at signature');
  console.log('✓ Test 8: Attack 1 Payload tampering rejected passed');

  // Test 9: Attack 2 - Replay attack
  const attack2 = await simulateReplayAttack(signed, verifier, secretKey);
  assert(!attack2.result.ok, 'Replay attack rejected');
  assertEqual(attack2.result.details.stepFailed, 'nonce', 'Replay failed at nonce');
  console.log('✓ Test 9: Attack 2 Replay attack rejected passed');

  // Test 10: Attack 3 - Expired timestamp
  const attack3 = await simulateExpiredTimestamp(
    { method: 'POST', path: '/api/v1/test', body: '{}' },
    verifier,
    secretKey,
    secretKey,
    150
  );
  assert(!attack3.result.ok, 'Expired timestamp rejected');
  assertEqual(attack3.result.details.stepFailed, 'timestamp', 'Expired failed at timestamp');
  console.log('✓ Test 10: Attack 3 Expired timestamp rejected passed');

  // Test 11: Attack 4 - Wrong key
  const attack4 = await simulateWrongSecretKey(
    { method: 'POST', path: '/api/v1/admin', body: '{}' },
    verifier,
    secretKey,
    'attacker-wrong-key'
  );
  assert(!attack4.result.ok, 'Wrong key rejected');
  assertEqual(attack4.result.details.stepFailed, 'signature', 'Wrong key failed at signature');
  console.log('✓ Test 11: Attack 4 Wrong secret key rejected passed');

  // Test 12: Attack 5 - Path tampering
  const attack5 = await simulatePathTampering(signed, verifier, secretKey);
  assert(!attack5.result.ok, 'Path tampering rejected');
  assertEqual(attack5.result.details.stepFailed, 'signature', 'Path tampering failed at signature');
  console.log('✓ Test 12: Attack 5 Path tampering rejected passed');

  // Test 13: Missing headers
  const missingRes = await verifier.verifyRequest({ method: 'POST', path: '/api', headers: {} });
  assert(!missingRes.ok, 'Missing headers rejected');
  assertEqual(missingRes.details.stepFailed, 'headers', 'Missing headers failed at headers');
  console.log('✓ Test 13: Missing headers rejected passed');

  // Test 14: Nonce cache purge
  verifier.clearNonceCache();
  assertEqual(verifier.getNonceCacheStats().size, 0, 'Cache empty');
  console.log('✓ Test 14: Nonce cache clear passed');

  console.log('\n=========================================');
  console.log('🎉 ALL 14 TESTS PASSED (100% SUCCESS)');
  console.log('=========================================');
}

runTests().catch(err => {
  console.error('❌ Test failed:', err);
  process.exit(1);
});
