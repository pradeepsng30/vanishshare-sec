# Trust Boundaries — VanishShare

This document explicitly defines the trust model for VanishShare: what the server is and is not trusted with, and where the zero-knowledge guarantees begin and end.

---

## What "Zero-Knowledge" Means in VanishShare

**Zero-knowledge**, in VanishShare's context, means:

> The VanishShare server infrastructure — including its database, object storage, web servers, CDN, logs, and staff — has zero mathematical capability to decrypt any secret payload.

This is a **data confidentiality guarantee at the persistence layer**. It is not a claim of absolute anonymity across all dimensions.

---

## Trust Boundary Map

```
╔═════════════════════════════════════════════════════════╗
║              CLIENT BROWSER (Trusted Zone)              ║
║                                                         ║
║  ┌─────────────────────────────────────────────────┐   ║
║  │ • Plaintext secret / file                       │   ║
║  │ • AES-256 master key (Km)                       │   ║
║  │ • Passphrase (if set)                           │   ║
║  │ • PBKDF2 derivation                             │   ║
║  │ • Encryption / decryption execution             │   ║
║  │ • Km lives exclusively in URL #fragment         │   ║
║  └─────────────────────────────────────────────────┘   ║
╚══════════════════════════╤══════════════════════════════╝
                           │ (Only ciphertext crosses this boundary)
                           ▼
╔═════════════════════════════════════════════════════════╗
║           SERVER INFRASTRUCTURE (Untrusted Zone)        ║
║                                                         ║
║  ┌─────────────────────────────────────────────────┐   ║
║  │ • AES-256-GCM ciphertext blob (opaque)          │   ║
║  │ • Salted HMAC digests of recipient emails       │   ║
║  │ • SHA-256 hash of OTP (not raw OTP)             │   ║
║  │ • Expiration timestamps and download counters   │   ║
║  │ • PBKDF2 salt (public; useless without key)     │   ║
║  └─────────────────────────────────────────────────┘   ║
╚═════════════════════════════════════════════════════════╝
```

---

## What the Server Knows

| Data Item | Server Visibility | Notes |
| :--- | :--- | :--- |
| Secret plaintext | ❌ Never | Encrypted before leaving the browser |
| File contents | ❌ Never | Encrypted before leaving the browser |
| File name / MIME type | ❌ Never | Encrypted as part of file metadata ciphertext |
| AES master key (Km) | ❌ Never | Exists only in URL `#` fragment |
| Sender's passphrase | ❌ Never | Never transmitted; derived client-side only |
| Recipient email (raw) | ❌ Never | Stored as salted HMAC digest only |
| Secret existence & TTL | ✅ Yes | Required for expiration enforcement |
| Download count | ✅ Yes | Required for limit enforcement |
| PBKDF2 salt | ✅ Yes | Transmitted for recipient key derivation; benign without the passphrase |
| Sender's IP address | ✅ Yes | Visible in HTTP request; used for rate limiting |
| Recipient's IP address | ✅ Yes | Visible during OTP request and verify flow |
| OTP (raw) | ❌ Never | Only SHA-256 hash stored |

---

## Zero-Knowledge Scope: What Is and Is Not Covered

### ✅ Covered by the Zero-Knowledge Guarantee

- **Payload confidentiality**: Impossible to decrypt secret content without the URL fragment key.
- **File confidentiality**: Filename, MIME type, and file bytes are all encrypted.
- **Passphrase confidentiality**: The passphrase never leaves the browser.
- **Database breach resilience**: Full database read yields only ciphertext, salted HMACs, and metadata.
- **Legal / subpoena resilience**: VanishShare cannot produce decrypted secret content because it does not possess the keys.
- **Insider threat resilience**: A malicious employee with full database and storage access cannot decrypt secrets.

### ⚠️ Not Covered (Acknowledged Limitations)

- **Web delivery trust model**: Because the application is delivered as JavaScript over HTTPS, the server theoretically could push modified JavaScript that intercepts keys before or after encryption. This is a known, fundamental boundary of all browser-based zero-knowledge systems (shared by Proton Mail Web, Bitwarden Web Vault, 1Password Web, etc.). Mitigations include: strict Content Security Policy, Referrer-Policy: no-referrer, and no cross-origin script loading.

- **Metadata anonymity**: IP addresses of senders and recipients are observable by the server infrastructure. If complete anonymity is required (not just content confidentiality), users should combine VanishShare with a VPN or Tor.

- **Malicious browser extensions**: A browser extension with broad host permissions (`<all_urls>`) can inspect the JavaScript heap and potentially extract keys or plaintext. This is outside the web application trust boundary. VanishShare mitigates this by zeroing sensitive buffers immediately after use, but memory isolation within a browser tab is not achievable without native app delivery.

- **Endpoint compromise**: If the sender's or recipient's device is compromised (keylogger, screen capture malware, OS-level memory access), VanishShare's cryptography cannot protect the secret. This is true of all cryptographic systems — security at the endpoints is a device security problem, not an application problem.

---

## Web Delivery Trust Boundary (Detailed)

The security audit finding regarding "host compromise" is a known characteristic of all browser-delivered zero-knowledge applications:

**The attack vector:**  
A compromised web host or CDN could theoretically serve modified JavaScript that reads `window.location.hash` and exfiltrates the key material before encryption or after decryption.

**Why this is not unique to VanishShare:**  
All browser-based secure applications face this model. The W3C Web Crypto API provides cryptographic isolation from the network layer but not from the JavaScript execution context itself. This is a browser platform limitation, not a VanishShare design flaw.

**What VanishShare does to reduce this risk:**
1. Strict Content Security Policy (`default-src 'self'`) prevents injection of external scripts.
2. `Referrer-Policy: no-referrer` ensures the URL hash is never leaked in Referer headers to external links.
3. `X-Frame-Options: DENY` and `frame-ancestors: none` prevent clickjacking and iframe-based extraction.
4. `X-Robots-Tag: noindex, noarchive` on secret routes prevents caching by search engines and crawlers.
5. All static assets are served from the same origin.

**For high-security environments:**  
Organizations requiring cryptographic isolation from the web delivery channel should use air-gapped environments, audited browser extensions, or purpose-built desktop clients for secret sharing operations.

---

## Secret Lifetime & Destruction

Secrets are ephemeral by design. They are permanently destroyed under any of the following conditions:

1. **Download limit reached**: When the configured maximum number of downloads is consumed (minimum 1, maximum unlimited), the database record and storage object are hard-deleted immediately after the final successful decryption event.
2. **TTL expiration**: When the configured time-to-live expires (range: 10 minutes to 30 days), the record is deleted on the next access attempt.
3. **Proactive cleanup**: Background cleanup processes delete all expired records from storage.

**What "deleted" means:** Firestore document deletion and Google Cloud Storage object deletion are permanent. Deleted data does not appear in backups beyond the point-in-time retention window of the managed service (GCP Firestore: 7 days PITR by default, can be disabled). Customers with compliance requirements regarding data retention should note this.
