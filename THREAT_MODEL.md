# Threat Model — VanishShare

This document describes VanishShare's threat model: the assets being protected, who the adversaries are, the identified attack surfaces, and the mitigations in place for each threat.

---

## Assets Under Protection

| Asset | Sensitivity | Where It Lives |
| :--- | :--- | :--- |
| Secret plaintext (text payload) | Critical | Sender's browser only |
| Secret file (binary payload) | Critical | Sender's browser only |
| File metadata (name, MIME type) | High | Sender's browser only |
| AES-256 master key (Km) | Critical | URL fragment (#) — never on server |
| Passphrase | Critical | Sender's browser only |
| Recipient email addresses | Medium | Server: salted HMAC only |
| Secret existence & expiration | Low | Server database |
| Sender / recipient IP addresses | Medium | Server access logs |

---

## Adversary Profiles

| Adversary | Capability |
| :--- | :--- |
| **Passive Network Observer** | Can read all traffic between client and server (outside of TLS) |
| **Active Network Attacker** | Can intercept, modify, or replay traffic |
| **Compromised Server / Database** | Full read/write access to production database and storage |
| **Malicious Insider** | Employee or contractor with infrastructure access |
| **Legal / Government Compulsion** | Subpoena or court order demanding data disclosure |
| **Automated Web Crawlers / Bots** | Link preview scrapers fetching secret URLs |
| **Offline Brute-Force Attacker** | Has intercepted ciphertext and performs offline passphrase guessing |
| **Compromised CDN / Web Host** | Can serve modified JavaScript to users |
| **Malicious Browser Extension** | Extension with `<all_urls>` host permissions installed by the user |
| **Endpoint Compromise** | Keylogger or OS-level memory access on sender/recipient device |

---

## Threat-by-Threat Analysis

---

### T1 — Database / Storage Breach

**Threat:** An attacker gains full read access to the production database and/or object storage.

**Impact without mitigation:** All secrets disclosed.

**Mitigation:**
- All stored secrets are AES-256-GCM ciphertext. The server never possesses decryption keys.
- An attacker with full database access obtains only opaque ciphertext blobs.
- Recipient email addresses are stored only as salted HMAC-SHA-256 digests. Raw email addresses cannot be recovered.
- Decrypting any secret requires the AES master key, which lives exclusively in the URL fragment — a client-side construct that is never transmitted to or stored by the server.

**Residual risk:** None. Decryption of ciphertext without the key is computationally infeasible under AES-256.

---

### T2 — Passive Network Eavesdropping

**Threat:** An ISP, nation-state, or network appliance captures all traffic between the client and the VanishShare server.

**Impact without mitigation:** Ciphertext and keys exposed if sent in the clear.

**Mitigation:**
- All traffic is encrypted in transit via TLS 1.3.
- AES master keys are transported exclusively in the URL **fragment** (`#`), which per RFC 3986 §3.5 browsers **never** include in HTTP request lines, headers, or server-side logs.
- Decryption keys cannot be captured via network interception.

**Residual risk:** None for payload confidentiality. Metadata (IP addresses, timing of requests) remains visible to network observers.

---

### T3 — Legal Compulsion / Subpoena

**Threat:** Law enforcement or government entity compels VanishShare to disclose a secret's contents.

**Mitigation:**
- VanishShare genuinely cannot comply: the server possesses only ciphertext and has never had access to the decryption key.
- This is a technical guarantee, not a policy promise. There is no "backdoor" and no key escrow.
- Recipient email addresses are stored as one-way HMACs — VanishShare cannot produce a list of email addresses even if compelled.

**Residual risk:** Metadata (IP addresses, access timestamps, secret existence and expiry) can be disclosed as it is the only data VanishShare possesses. Deleted secrets leave no recoverable content beyond the standard cloud provider PITR window.

---

### T4 — Brute-Force / Dictionary Attack on Passphrase-Protected Secrets

**Threat:** An attacker intercepts the encrypted key blob (`C_master`) from the URL and performs an offline dictionary attack to recover the passphrase and decrypt `Km`.

**Mitigation:**
- Passphrase keys are derived via **PBKDF2-HMAC-SHA-256 with 600,000 iterations** and a 128-bit random salt per secret.
- 600,000 iterations at HMAC-SHA-256 requires approximately 300–600 ms per guess on a modern GPU. At $1/hour cloud GPU cost, trying 10 million passphrases costs ~$500 and takes days.
- The PBKDF2 salt is unique per secret, preventing precomputed rainbow table attacks.
- The passphrase verifier mechanism provides client-side early rejection without server interaction — but this only accelerates correct guesses, not attacker throughput.

**Residual risk:** Weak passphrases (common words, short strings) remain vulnerable to well-resourced offline attacks. Strong, random passphrases (12+ characters) are infeasible to brute-force. Users should be educated on passphrase strength.

---

### T5 — Ciphertext Size Fingerprinting

**Threat:** A passive observer notes that AES-GCM ciphertext length equals plaintext length + 28 bytes. A 2048-bit RSA key has a distinctive byte count, allowing an observer to infer the contents without decryption.

**Mitigation:**
- All payloads are padded to one of **five fixed bucket sizes** (4 KB, 16 KB, 64 KB, 128 KB, 200 KB) before encryption.
- Padding bytes are filled with cryptographically random values (not zeros), preventing differential analysis of the padding region.
- A 4-byte prefix records the original payload length for exact recovery, but this is contained within the encrypted ciphertext and is not visible to network observers.

**Residual risk:** A very small number of observables remain (which bucket was used). A 100-byte secret and a 4,000-byte secret both encrypt to the same 4 KB bucket, providing strong size anonymity within bucket ranges.

---

### T6 — Web Delivery / JavaScript Integrity (Host Compromise)

**Threat:** A compromised web host, CDN, or supply-chain attack pushes modified JavaScript that exfiltrates the key from `window.location.hash` or intercepts plaintext before encryption.

**Mitigation:**
- Strict **Content Security Policy** (`default-src 'self'`) blocks injection of inline scripts and loading of external JavaScript from untrusted origins.
- `Referrer-Policy: no-referrer` ensures the URL (including the hash fragment) is never leaked in Referer headers when users click external links from the recipient page.
- `X-Frame-Options: DENY` and CSP `frame-ancestors: none` prevent clickjacking and iframe-based hash extraction.
- All application JavaScript is served from the same first-party origin, eliminating CDN supply-chain risk for the cryptographic code.

**Residual risk:** This is a fundamental characteristic of all browser-delivered zero-knowledge systems. A fully compromised web server with the ability to modify response bodies can bypass these controls. For organizations with this threat level, the recommended approach is an audited browser extension or a native desktop/CLI client where the cryptographic code is immutable post-installation.

---

### T7 — Automated Link Scrapers / Bot Pre-Fetch (Denial of Secret)

**Threat:** Enterprise chat platforms (Slack, Teams, Discord, iMessage, Telegram) automatically fetch URL previews via automated bots. If fetching the URL consumes the one-time view slot, the intended recipient is denied access.

**Mitigation:**
- The HTTP endpoint that handles initial link loads returns **only non-sensitive metadata** (expiry time, whether a passphrase is required, download count limits). It does **not** return ciphertext and does **not** increment the download counter.
- The download counter is only incremented and the ciphertext only released after a **successful, authenticated POST request** containing a valid 6-digit OTP delivered out-of-band to the recipient's email inbox.
- An automated bot cannot access the recipient's email inbox and thus cannot complete the verification flow.
- `X-Robots-Tag: noindex, nofollow, noarchive, nosnippet` is served on all secret share routes, discouraging crawlers from following links.
- `Cache-Control: no-store` prevents caching of any response from secret routes.

**Residual risk:** None. Bot pre-fetch cannot trigger secret consumption by design.

---

### T8 — OTP Abuse / Email OTP Brute-Force

**Threat:** An attacker who knows the secret ID attempts to brute-force the 6-digit OTP, cycling through all 1,000,000 combinations.

**Mitigation:**
- A maximum of **3 failed verification attempts** is enforced per OTP code. After 3 failures, the OTP is invalidated and a new one must be requested.
- OTPs have a short expiration window, limiting the time available to guess.
- OTPs are generated using a cryptographically secure RNG, not a predictable sequence.
- Rate limiting is applied to the OTP request endpoint to prevent abuse.

**Residual risk:** None. With 3 attempts per code, the probability of a correct random guess is 3/1,000,000 = 0.0003%. Combined with OTP expiry, brute-force is infeasible.

---

### T9 — Replay Attack

**Threat:** An attacker intercepts a valid OTP verification request and replays it to retrieve the ciphertext a second time (or after the secret has been consumed).

**Mitigation:**
- On successful OTP verification, the OTP hash is **immediately cleared** from the database, making any replay of the same code fail on subsequent requests.
- Download counters are checked atomically; if the limit is reached, the record is deleted and further requests return 410 Gone.

**Residual risk:** None within the OTP flow. The URL fragment key itself can be replayed if captured, but this requires capturing the URL and is outside the server's control.

---

### T10 — Malicious Browser Extension

**Threat:** A malicious browser extension with host permissions (`<all_urls>`) installed by the sender or recipient inspects the JavaScript heap, DOM, or `window.location.hash` to steal the decryption key or plaintext.

**Mitigation:**
- Sensitive buffers (key material, plaintext ArrayBuffers, padded payload buffers) are explicitly zeroed (filled with zeros) immediately after use, reducing the window of exposure in browser memory.
- Blob URLs created during file download are revoked immediately after the download is triggered.
- VanishShare does not store keys in `localStorage`, `sessionStorage`, `IndexedDB`, or cookies — all key material lives only in JavaScript memory variables within the current page lifecycle.

**Residual risk:** Browser extension isolation is enforced by the browser, not by web applications. A sufficiently privileged extension can observe the hash fragment and in-flight memory. This is a browser platform limitation. For environments where this threat is relevant, the recommendation is to disable or audit browser extensions and use a hardened browser profile.

---

### T11 — Endpoint Device Compromise

**Threat:** The sender's or recipient's device has malware, a keylogger, or OS-level memory inspection tools.

**Mitigation:** There is no mitigation possible at the web application layer for a fully compromised endpoint. This is a universal limitation of all cryptographic software.

**Recommendation:** Organizations handling sensitive secrets should enforce endpoint security posture (EDR, device management, secure enclaves) independently of the application layer.

---

## Threat Model Summary Matrix

| ID | Threat | Residual Risk | Severity |
| :--- | :--- | :--- | :--- |
| T1 | Database / storage breach | None | ✅ Mitigated |
| T2 | Network eavesdropping | Metadata visible | ✅ Mitigated |
| T3 | Legal compulsion | Metadata disclosable | ✅ Mitigated |
| T4 | Passphrase brute-force | Weak passphrases only | ✅ Mitigated |
| T5 | Ciphertext size fingerprinting | Bucket-level observable | ✅ Mitigated |
| T6 | Host / CDN compromise | High-security environments | ⚠️ Acknowledged |
| T7 | Bot link pre-fetch DoS | None | ✅ Mitigated |
| T8 | OTP brute-force | None | ✅ Mitigated |
| T9 | Replay attack | None | ✅ Mitigated |
| T10 | Malicious browser extension | Privileged extensions only | ⚠️ Acknowledged |
| T11 | Endpoint device compromise | Full endpoint compromise only | ⚠️ Out of scope |
