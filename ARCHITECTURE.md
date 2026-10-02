# Security Architecture — VanishShare

## Overview

VanishShare is built on a **Zero-Knowledge Architecture**: the server infrastructure never possesses the mathematical capability to decrypt any secret payload. This document describes the design of that architecture and the cryptographic pipeline that enforces it.

---

## Zero-Knowledge Principle

The core design rule is:

> No decryption key or plaintext data ever touches the server, in transit or at rest.

This means that even a complete database breach, a malicious insider with full infrastructure access, or a legal subpoena to VanishShare cannot expose the contents of stored secrets. What exists on the server is exclusively:

- AES-256-GCM ciphertext (mathematically infeasible to decrypt without the key)
- Salted HMAC fingerprints of recipient email addresses (one-way; cannot be reversed)
- Expiration metadata (TTL, download count limits)

---

## Key Isolation via URI Fragment

Decryption keys are transported to recipients exclusively via the **URI fragment** (the `#` portion of a URL).

The URI fragment (defined in RFC 3986 §3.5) is a client-only construct. By specification, web browsers **never** include the fragment in HTTP request headers, request lines, or server-side access logs. This means:

- The decryption key is never sent to the VanishShare server.
- The key never appears in proxy logs, CDN access logs, or reverse proxy logs.
- Clicking the link in a browser keeps the key exclusively in the local JavaScript environment.

---

## Cryptographic Pipeline (End-to-End)

```
SENDER BROWSER
─────────────
1. Generate 256-bit AES master key (Km) via hardware-backed W3C Web Crypto API
2. Pad plaintext payload to a standard fixed bucket size (4KB / 16KB / 64KB / 128KB / 200KB)
3. Encrypt padded payload with Km using AES-256-GCM and a random 96-bit IV
4. If passphrase set:
     a. Derive passphrase key (Kp) via PBKDF2 (HMAC-SHA-256, 600,000 iterations, random salt)
     b. Encrypt Km with Kp to produce wrapped key blob (C_master)
     c. Create an AES-GCM verifier token from the constant string "VERIFIED" using Kp
     d. Embed C_master, the verifier, the IV, and the PBKDF2 salt in the URL fragment
   If no passphrase:
     a. Embed raw Km (base64) in the URL fragment as #key=...
5. Blind recipient email addresses using HMAC-SHA256 with a unique per-secret salt
6. POST encrypted ciphertext + email HMACs + TTL/limits to server
7. Share the full URL (including fragment) with intended recipient(s)

SERVER STORAGE
──────────────
  Stores: { ciphertext, email_HMACs, TTL, download_limit, download_count, expires_at }
  Does NOT store: keys, plaintext, raw email addresses

RECIPIENT BROWSER
─────────────────
1. Parse Km (or C_master + verifier) from the URL hash fragment
2. If passphrase required: derive Kp via PBKDF2 and verify locally — no server round-trip
3. Submit recipient email to server → receive 6-digit OTP via out-of-band email delivery
4. Submit OTP to server → server validates against HMAC fingerprint, returns ciphertext
5. Decrypt ciphertext locally using Km and AES-256-GCM
6. Unpad decrypted buffer to recover original plaintext
7. Wipe all sensitive intermediate buffers from browser memory
8. Secret is displayed to recipient; download count is incremented / secret is deleted server-side
```

---

## File Sharing Sub-Pipeline

When a file is attached:

1. The raw file bytes are read into browser memory as an `ArrayBuffer`.
2. The buffer is padded to a standard bucket size.
3. The padded buffer is encrypted with the same `Km` (AES-256-GCM, unique IV).
4. File metadata (original name, MIME type, byte size, and decryption IV) is serialized as JSON and **also encrypted** with `Km` as a separate ciphertext blob.
5. Both ciphertext blobs are transmitted to the server.
6. On the recipient side, file metadata is decrypted first, then used to decrypt and unpad the file payload.
7. The decrypted buffer is released as a browser download via a revocable Blob URL; the URL is revoked immediately after download triggers.

The server at no point sees the filename, MIME type, or original file contents.

---

## Payload Padding Design

AES-GCM is a stream cipher mode: the ciphertext length is `plaintext_length + 16 bytes` (authentication tag). Without padding, a passive network observer can infer the approximate type of file from its byte count — for instance, a 2048-bit RSA private key has a characteristic size distinguishable from a 4096-bit key or a certificate.

VanishShare applies **fixed-bucket padding** before encryption:

| Bucket | Usage |
| :--- | :--- |
| **4 KB** | Short secrets, tokens, passwords |
| **16 KB** | Medium text payloads, small config files |
| **64 KB** | Longer documents, structured secrets |
| **128 KB** | Large secrets, certificates, multi-key bundles |
| **200 KB** | Maximum supported file payload |

Padding is prepended with a 4-byte big-endian header encoding the original payload length, allowing exact recovery during decryption. Padding bytes are filled with cryptographically secure random values from the OS CSPRNG.

---

## Email HMAC Design

Sender-specified recipient email addresses are never stored in plaintext. The storage design is:

1. Server generates a random 16-byte `emailHmacSalt` per secret.
2. Each recipient email is normalized (trim, lowercase) and hashed as:  
   `HMAC-SHA256(serverMasterSecret + emailHmacSalt, normalizedEmail)`
3. Only the HMAC digest is stored.

When a recipient requests OTP access, they submit their email address. The server recomputes the HMAC and compares it against the stored digest. If they match, an OTP is issued.

**Properties:**
- The raw email is never stored at rest.
- Without both the `HMAC_SECRET` (a server environment variable) and the per-secret `emailHmacSalt`, the stored digests cannot be reversed.
- Even a full database read yields no email addresses.

---

## OTP Design

One-Time Passcodes are 6-digit numeric codes generated using a cryptographically secure RNG seeded by the OS. OTP storage:

- The OTP itself is never stored. Only its **SHA-256 hash** is stored in the database.
- OTPs have a short expiration window.
- A maximum of **3 failed attempts** is permitted before the OTP is invalidated and a new one must be requested.
- After the OTP is successfully verified, it is immediately cleared from the database (single-use enforcement).

---

## Memory Security

After encryption and decryption, intermediate buffers containing sensitive material (raw key bytes, plaintext payloads, padded buffers) are explicitly zeroed out by overwriting them with zeros before they are released by the JavaScript garbage collector. This reduces the window during which a malicious browser extension or JS heap inspector could extract sensitive data from browser memory.
