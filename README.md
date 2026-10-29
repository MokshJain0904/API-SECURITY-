# Cryptographic Request Integrity and Authentication Framework for Secure APIs

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Web Cryptography API](https://img.shields.io/badge/Crypto-window.crypto.subtle-emerald.svg)](https://w3c.github.io/webcrypto/)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-0%20(Pure%20Vanilla%20ES%20Modules)-indigo.svg)](#)
[![GitHub Pages Deployable](https://img.shields.io/badge/Deploy-GitHub%20Pages%20Ready-cyan.svg)](#deploy-to-github-pages)

A client-side, zero-dependency interactive cryptographic playground and simulation laboratory developed as a college micro-project for a **Cryptography and Computer Network Security** course.

This application demonstrates how **HMAC-SHA256 request signing**, **deterministic canonicalization**, **cryptographic nonces**, and **freshness windows** safeguard RESTful APIs against tampering, payload modification, credential forgery, replay attacks, and side-channel timing vulnerabilities.

---

## 🌟 Key Features

- **Pure Web Cryptography**: Utilizes browser-native `window.crypto.subtle` (HMAC, SHA-256) and `crypto.getRandomValues`. **Zero third-party cryptographic libraries or npm dependencies**.
- **Deterministic Request Canonicalization**: Strict sorting and normalization of HTTP Methods, URIs, query parameters, timestamps, nonces, and SHA-256 payload digests (similar to AWS Signature Version 4).
- **Interactive Simulated Server Verifier**: Realistic multi-stage verification pipeline with step-by-step pass/fail checklist and detailed inspection telemetry.
- **One-Click Attack Simulation Laboratory**:
  1. **Payload Tampering**: Modifies transaction amounts in transit; caught by SHA-256 digest & HMAC mismatch.
  2. **Replay Attack**: Resends identical captured packets; caught by the in-memory nonce cache.
  3. **Expired Timestamp**: Submits stale requests outside the tolerance window; caught by freshness bounds.
  4. **Key Forgery**: Crafts requests signed with unauthorized secret keys; caught by HMAC verification.
  5. **Route / Query Tampering**: Modifies paths or query parameters in flight; caught by canonical binding.
  6. **Side-Channel Timing Attack Explorer**: Interactive probe comparison illustrating why naive early-exit comparisons (`===`) leak signature bytes, and how `constantTimeEqual()` protects systems.
- **Real-Time Security Audit Event Log**: Color-coded, filterable audit log capturing accepted and rejected transactions.
- **Dark & Light Mode**: Modern, accessible interface with high-contrast typography and glassmorphic card styling.
- **Comprehensive Browser-Based Test Runner**: Standalone unit and integration test runner (`/tests/tests.html`) verified against RFC 4231 test vectors.

---

## 📁 Repository Structure

```
crypto-project/
├── index.html              # Main interactive playground
├── css/
│   └── style.css           # Glassmorphism, dark/light theme, responsive grid
├── js/
│   ├── crypto.js           # Pure cryptographic primitives (WebCrypto subtle)
│   ├── signer.js           # Client-side request canonicalizer and HMAC signer
│   ├── verifier.js         # Simulated server verifier with nonce cache & TTL
│   ├── attacks.js          # Attack simulation threat models and timing analysis
│   ├── ui.js               # DOM wiring, rendering, audit logging, toasts
│   └── main.js             # Application entry point
├── tests/
│   └── tests.html          # Custom browser test runner with RFC 4231 vectors
├── docs/
│   ├── architecture.md     # Sequence & flowchart diagrams (Mermaid)
│   └── screenshots/        # Verified UI and attack execution screenshots
├── .nojekyll               # Disables Jekyll processing on GitHub Pages
└── README.md               # Project documentation and deployment guide
```

---

## ⚙️ Core Cryptographic Logic

### 1. Canonical String Derivation
Both the client and server construct a deterministic, newline-delimited canonical string:
```
METHOD + "\n" +
PATH + "\n" +
SORTED_QUERY_STRING + "\n" +
TIMESTAMP + "\n" +
NONCE + "\n" +
SHA256_HEX(BODY)
```

- **Query Sorting**: Parameters are sorted alphabetically by key, then value (e.g., `b=2&a=1` becomes `a=1&b=2`).
- **Body Hash**: An empty body evaluates to standard SHA-256 digest `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

### 2. Signature Calculation
$$\text{Signature} = \text{HMAC-SHA256}(\text{SecretKey}, \text{CanonicalString})$$
Output is encoded as a lowercase 64-character hexadecimal string.

### 3. Server Verification Sequence
When a request is received, the verifier executes the following steps in order:
1. **Header Validation**: Verifies that `X-Timestamp`, `X-Nonce`, and `X-Signature` headers are present.
2. **Freshness Window Check**: Ensures $|T_{\text{server}} - T_{\text{request}}| \le \text{ToleranceWindow}$ (default $\pm 60$ seconds).
3. **Anti-Replay Nonce Check**: Ensures the nonce has not been seen in the active cache.
4. **Canonical Reconstruction**: Recalculates $\text{SHA-256}(\text{Body})$ and derives the server canonical representation.
5. **Constant-Time HMAC Comparison**: Recomputes the expected HMAC and compares it with the received signature using `constantTimeEqual()`:
   ```javascript
   export function constantTimeEqual(a, b) {
     if (typeof a !== 'string' || typeof b !== 'string') return false;
     const lenA = a.length, lenB = b.length;
     let diff = lenA ^ lenB;
     const maxLen = Math.max(lenA, lenB);
     for (let i = 0; i < maxLen; i++) {
       const charA = i < lenA ? a.charCodeAt(i) : 0;
       const charB = i < lenB ? b.charCodeAt(i) : 0;
       diff |= (charA ^ charB);
     }
     return diff === 0;
   }
   ```
6. **Mark Nonce as Consumed**: The nonce is recorded in the in-memory cache with a TTL (default 300 seconds) **only after** all checks succeed.

---

## 🚀 How to Run Locally

Because the project uses standard ES modules (`import`/`export`), it should be served via any local HTTP server (browsers restrict ES module loading via raw `file://` protocol due to CORS security policies).

### Option A: Using Python (Recommended)
Open a terminal in the project directory and run:
```bash
python -m http.server 8000
```
Then navigate to: [http://localhost:8000](http://localhost:8000)

### Option B: Using Node.js
```bash
npx serve .
# or
npx http-server .
```

### Option C: Running the Test Suite
Visit [http://localhost:8000/tests/tests.html](http://localhost:8000/tests/tests.html) in your browser. All 14+ automated unit and integration tests will execute automatically with pass/fail telemetry.

---

## 🌐 Deploy to GitHub Pages

Deploying this project to GitHub Pages takes less than two minutes:

1. **Create a GitHub Repository**:
   Create a new public repository on GitHub (e.g., `api-crypto-integrity-framework`).

2. **Push Project Files**:
   ```bash
   git init
   git add .
   git commit -m "feat: initial release of API cryptographic integrity framework"
   git branch -M main
   git remote add origin https://github.com/<your-username>/api-crypto-integrity-framework.git
   git push -u origin main
   ```

3. **Enable GitHub Pages**:
   - Go to your repository on GitHub.
   - Click **Settings** ➔ **Pages** (in the left sidebar).
   - Under **Build and deployment** ➔ **Source**, select **Deploy from a branch**.
   - Select branch `main` and folder `/ (root)`.
   - Click **Save**.

4. **Verify Deployment**:
   After 30–60 seconds, your site will be live at:
   `https://<your-username>.github.io/api-crypto-integrity-framework/`

*(Note: The included `.nojekyll` file prevents GitHub Pages from skipping static folders).*

---

## 🛡️ Attack Scenarios & Expected Outcomes

| Scenario | Threat Description | Attack Vector | Expected Result |
| :--- | :--- | :--- | :--- |
| **1. Payload Tampering** | Man-in-the-Middle alters the request body in flight. | Amount changed from `$2,500` to `$2,500,000`. | **Rejected (Step 5)**: Server SHA-256 body hash does not match, causing HMAC signature mismatch. |
| **2. Replay Attack** | Adversary captures an authentic valid packet and resends it. | Replayed identical timestamp, nonce, and signature. | **Rejected (Step 3)**: Nonce found in server cache; duplicate request rejected. |
| **3. Expired Request** | Stale request submitted after transmission delay. | Timestamp backdated by 150 seconds. | **Rejected (Step 2)**: Clock skew exceeds configured $\pm 60$s freshness tolerance. |
| **4. Key Forgery** | Attacker signs a payload using an unauthorized key. | Request signed with attacker's bogus key. | **Rejected (Step 5)**: Server recomputes signature with legitimate master key, failing verification. |
| **5. Path Tampering** | Attacker modifies endpoint URI or query parameters. | Path changed from `/profile` to `/admin/purge`. | **Rejected (Step 5)**: Route and query parameters bound in canonical string do not match. |

---

## 🔒 Security Considerations & Demo Limitations

> [!IMPORTANT]
> **Educational Demonstration Context**:
> In this interactive playground, both the client signer and the server verifier execute within the same browser runtime for demonstration purposes.

In production architectures:
1. **Secret Key Segregation**: The shared secret key (`HMAC Key`) must **never** be exposed in client-side JavaScript or mobile client binaries. Secret keys should reside exclusively in secure backend microservices, Hardware Security Modules (HSM), or Key Management Services (AWS KMS, HashiCorp Vault).
2. **Transport Layer Security (TLS)**: Cryptographic request signing complements TLS; it does **not** replace it. TLS protects against eavesdropping and provides transport encryption, while HMAC signing protects against proxy tampering, non-repudiation disputes, and malicious intermediate routing.
3. **Key Rotation & Identifiers**: Real systems use the `X-Key-Id` header to support seamless key rotation with dual-key grace periods.
4. **No Storage of Secret Keys**: This application **never** writes secret keys to `localStorage` or `sessionStorage` to mitigate client-side cross-site scripting (XSS) credential theft.

---

## 🔮 Future Scope & Production Roadmap

- **Asymmetric Signatures (ECDSA with NIST P-256 or Ed25519)**:
  Transitioning from symmetric HMAC to asymmetric public-key cryptography allows clients to sign requests with private keys while servers verify using public keys, eliminating shared secret exposure.
- **Comparison with JWT & OAuth 2.0**:
  While JWTs authenticate user sessions, request signing authenticates the *entire HTTP wire payload and route*. Future versions can demonstrate combining OAuth Bearer Tokens with HMAC Request Proof-of-Possession (RFC 7800 / DPoP RFC 9449).
- **Distributed Nonce Caching with Redis**:
  In multi-node microservice clusters, the in-memory JavaScript Map is replaced with a distributed Redis cluster using atomic `SET NX EX` operations.
- **Key Rotation Protocol**:
  Interactive simulation of dual-active key transitions, allowing zero-downtime rotation of cryptographic API secrets.

---

## 📜 Academic Attribution
Developed as an engineering micro-project for academic coursework in **Cryptography, Information Security, and Computer Networks**. Complies with standard RFC 2104 (HMAC) and RFC 4231 test vectors.
