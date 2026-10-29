import { createServer } from 'node:http';
import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const rootDir = fileURLToPath(new URL('.', import.meta.url));
const port = Number(process.env.PORT || 8000);
const toleranceSeconds = Number(process.env.TIMESTAMP_TOLERANCE_SECONDS || 60);
const nonceTtlSeconds = Number(process.env.NONCE_TTL_SECONDS || 300);
const defaultKeyId = process.env.API_KEY_ID || 'client-app-prod-01';
const defaultSecret = process.env.API_SECRET || '4f8a3d1c9b2e5f7a0d4c8e1b6f3a7d2e9c1b5a8f0e4d7c2a1b9f6e3d8c5b0a7f';
const keyRegistry = new Map([[defaultKeyId, defaultSecret]]);
const nonceCache = new Map();

const mimeTypes = {
  '.css': 'text/css; charset=utf-8',
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.md': 'text/markdown; charset=utf-8',
  '.png': 'image/png'
};

function canonicalizeQuery(url) {
  const pairs = Array.from(url.searchParams.entries());
  pairs.sort(([keyA, valueA], [keyB, valueB]) => (
    keyA === keyB ? valueA.localeCompare(valueB) : keyA.localeCompare(keyB)
  ));
  return pairs
    .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(value)}`)
    .join('&');
}

function normalizePath(path) {
  if (!path || !path.trim()) return '/';
  let normalizedPath = path.trim();
  if (!normalizedPath.startsWith('/')) normalizedPath = `/${normalizedPath}`;
  if (normalizedPath.length > 1 && normalizedPath.endsWith('/')) normalizedPath = normalizedPath.slice(0, -1);
  return normalizedPath;
}

function constantTimeEqualHex(left, right) {
  if (!/^[\da-f]{64}$/i.test(left) || !/^[\da-f]{64}$/i.test(right)) return false;
  return timingSafeEqual(Buffer.from(left, 'hex'), Buffer.from(right, 'hex'));
}

function jsonResponse(response, status, payload) {
  const body = JSON.stringify(payload);
  response.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store'
  });
  response.end(body);
}

function failResult(stepFailed, reason, detail = {}) {
  return {
    ok: false,
    reason,
    steps: [{
      id: stepFailed,
      name: `Verification failed: ${stepFailed}`,
      status: 'fail',
      message: reason,
      detail
    }],
    details: { stepFailed, ...detail }
  };
}

function purgeExpiredNonces(now = Date.now()) {
  for (const [nonce, expiry] of nonceCache) {
    if (expiry <= now) nonceCache.delete(nonce);
  }
}

function verifyRequest({ method, url, headers, rawBody }) {
  purgeExpiredNonces();
  const timestampHeader = headers['x-timestamp'];
  const nonce = headers['x-nonce'];
  const receivedSignature = headers['x-signature'];
  const keyId = headers['x-key-id'] || defaultKeyId;
  const secret = keyRegistry.get(keyId);

  if (!timestampHeader || !nonce || !receivedSignature) {
    return failResult(
      'headers',
      'Missing mandatory headers: X-Timestamp, X-Nonce, or X-Signature',
      { keyId }
    );
  }

  const timestamp = Number(timestampHeader);
  if (!Number.isInteger(timestamp)) {
    return failResult('timestamp', 'X-Timestamp must be a Unix timestamp in seconds');
  }

  const nowSeconds = Math.floor(Date.now() / 1000);
  const deltaSeconds = Math.abs(nowSeconds - timestamp);
  if (deltaSeconds > toleranceSeconds) {
    return failResult(
      'timestamp',
      `Request timestamp is outside the ±${toleranceSeconds}s freshness window`,
      { deltaSeconds, toleranceSeconds }
    );
  }

  if (nonceCache.has(nonce)) {
    return failResult('nonce', 'Replay detected: this nonce has already been accepted', { nonce });
  }

  const bodyHash = createHash('sha256').update(rawBody, 'utf8').digest('hex');
  const canonicalString = [
    method.toUpperCase(),
    normalizePath(url.pathname),
    canonicalizeQuery(url),
    timestampHeader,
    nonce,
    bodyHash
  ].join('\n');

  if (!secret) {
    return failResult('signature', `Unknown X-Key-Id: ${keyId}`, { keyId });
  }

  const expectedSignature = createHmac('sha256', secret).update(canonicalString, 'utf8').digest('hex');
  if (!constantTimeEqualHex(expectedSignature, receivedSignature.trim().toLowerCase())) {
    return failResult('signature', 'Cryptographic signature mismatch', {
      keyId,
      expectedSignature,
      receivedSignature
    });
  }

  nonceCache.set(nonce, Date.now() + nonceTtlSeconds * 1000);
  return {
    ok: true,
    reason: 'Request verified successfully by the real API server',
    steps: [
      { id: 'headers', name: 'Required security headers', status: 'pass', message: 'All required headers are present' },
      { id: 'timestamp', name: 'Timestamp freshness', status: 'pass', message: `Timestamp is within ±${toleranceSeconds}s` },
      { id: 'nonce', name: 'Nonce anti-replay check', status: 'pass', message: 'Nonce is new and has been reserved' },
      { id: 'canonical', name: 'Canonical request', status: 'pass', message: 'Server rebuilt the canonical request', detail: { bodyHash, canonicalString } },
      { id: 'signature', name: 'Constant-time HMAC comparison', status: 'pass', message: 'HMAC-SHA256 signature verified' }
    ],
    details: { keyId, nonce, bodyHash, canonicalString }
  };
}

async function readRequestBody(request) {
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > 1_048_576) throw new Error('Request body exceeds the 1 MB limit');
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString('utf8');
}

async function serveStatic(request, response, pathname) {
  const requestedPath = pathname === '/' ? '/index.html' : pathname;
  const filePath = normalize(join(rootDir, requestedPath));
  const rootPrefix = rootDir.endsWith(sep) ? rootDir : `${rootDir}${sep}`;
  if (!filePath.startsWith(rootPrefix)) {
    jsonResponse(response, 403, { error: 'Forbidden path' });
    return;
  }

  try {
    const contents = await readFile(filePath);
    response.writeHead(200, {
      'Content-Type': mimeTypes[extname(filePath)] || 'application/octet-stream',
      'Cache-Control': 'no-store'
    });
    response.end(contents);
  } catch (error) {
    if (error.code === 'ENOENT') {
      jsonResponse(response, 404, { error: 'Not found' });
      return;
    }
    jsonResponse(response, 500, { error: 'Unable to read requested resource' });
  }
}

const server = createServer(async (request, response) => {
  const url = new URL(request.url, `http://${request.headers.host || 'localhost'}`);

  if (request.method === 'OPTIONS') {
    response.writeHead(204, {
      'Access-Control-Allow-Origin': 'http://localhost:8000',
      'Access-Control-Allow-Headers': 'Content-Type, X-Key-Id, X-Timestamp, X-Nonce, X-Signature',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS'
    });
    response.end();
    return;
  }

  if (url.pathname === '/health' && request.method === 'GET') {
    jsonResponse(response, 200, { ok: true, service: 'api-security-demo', nonceCacheSize: nonceCache.size });
    return;
  }

  if (url.pathname.startsWith('/api/v1/') && request.method === 'POST') {
    try {
      const rawBody = await readRequestBody(request);
      const verification = verifyRequest({
        method: request.method,
        url,
        headers: request.headers,
        rawBody
      });

      if (!verification.ok) {
        const status = verification.details.stepFailed === 'nonce' ? 409 : 401;
        jsonResponse(response, status, verification);
        return;
      }

      let payload;
      try {
        payload = rawBody ? JSON.parse(rawBody) : {};
      } catch {
        jsonResponse(response, 400, { error: 'Request body must contain valid JSON', verification });
        return;
      }

      jsonResponse(response, 200, {
        ok: true,
        message: 'Payment request accepted by the real API',
        transaction: { status: 'approved', received: payload },
        verification
      });
    } catch (error) {
      jsonResponse(response, 400, { error: error.message });
    }
    return;
  }

  if (request.method === 'GET' || request.method === 'HEAD') {
    await serveStatic(request, response, url.pathname);
    return;
  }

  jsonResponse(response, 404, { error: 'Route not found' });
});

server.listen(port, '127.0.0.1', () => {
  console.log(`API Security server listening at http://localhost:${port}`);
  console.log(`Configured key id: ${defaultKeyId}`);
});
