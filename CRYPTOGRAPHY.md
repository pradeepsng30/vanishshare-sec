# Cryptographic Specification — VanishShare

This document provides the precise cryptographic primitives and parameter choices used in VanishShare. It is intended for security researchers, cryptographers, and enterprise evaluators performing due diligence.

---

## Primitives Summary

| Purpose | Primitive | Parameters |
| :--- | :--- | :--- |
| Symmetric encryption | AES-GCM | 256-bit key, 96-bit IV, 128-bit auth tag |
| Key derivation (passphrase) | PBKDF2 | HMAC-SHA-256, 600,000 iterations, 16-byte random salt |
| Email fingerprinting | HMAC-SHA-256 | Server-held secret + per-secret random salt |
| OTP storage | SHA-256 | Raw hash; single-use; attempt-limited |
| Randomness source | W3C Web Crypto CSPRNG | `crypto.getRandomValues` (hardware-backed in modern browsers) |

---

## 1. Symmetric Encryption: AES-256-GCM

**Standard:** NIST SP 800-38D  
**Key size:** 256 bits (32 bytes)  
**IV (Initialization Vector):** 96 bits (12 bytes), generated fresh per encryption operation using a CSPRNG  
**Authentication tag:** 128 bits (16 bytes), appended to the ciphertext  
**Implementation:** W3C Web Crypto API (`SubtleCrypto.encrypt`, `SubtleCrypto.decrypt`)

### Why AES-256-GCM?

- **Authenticated encryption**: The GCM authentication tag guarantees both confidentiality and integrity. Any tampering with the ciphertext causes decryption to fail with an authentication error — no valid decryption of corrupted data is possible.
- **No padding oracle vulnerability**: Unlike CBC mode, GCM does not require block-aligned padding and is not susceptible to padding oracle attacks.
- **Hardware acceleration**: All modern CPUs include AES-NI instruction sets, and all major browser engines expose this via the Web Crypto API, providing near-native performance.

### IV Generation Policy

A fresh 96-bit IV is generated for every encryption operation using the OS-backed CSPRNG. IVs are never reused across different encryption calls, even for the same key. IV reuse with GCM would be catastrophic (allowing key and plaintext recovery), so this is a strict operational requirement.

---

## 2. Master Key Generation

**Algorithm:** AES-256 via `SubtleCrypto.generateKey`  
**Key flags:** Extractable = true (required to embed in URL hash fragment for recipient delivery)  
**Permitted operations:** encrypt, decrypt only  

The master key `Km` is generated fresh for each secret. It exists in browser memory only for the duration of the encryption operation. After the ciphertext and URL fragment are produced, the key material in the sender's browser is no longer needed and is released to the garbage collector.

---

## 3. Key Derivation: PBKDF2

When the sender sets an optional passphrase, `Km` is not placed raw into the URL fragment. Instead:

**Algorithm:** PBKDF2  
**PRF:** HMAC-SHA-256  
**Iterations:** 600,000  
**Salt:** 128 bits (16 bytes), unique per secret, generated via CSPRNG  
**Output key material:** 256 bits → used as an AES-256-GCM key `Kp`  

`Kp` is used to encrypt `Km`, producing a wrapped key blob `C_master`. The URL fragment carries `C_master`, the IV used to wrap it, the PBKDF2 salt, and a passphrase verifier (described below). The raw passphrase never leaves the browser.

### Why 600,000 Iterations?

The OWASP Password Storage Cheat Sheet (updated 2023–2026) recommends a minimum of **600,000 iterations** for PBKDF2-HMAC-SHA256. This parameter is specifically calibrated to a computational budget that makes the operation take approximately 300–600 ms on commodity server-grade GPU hardware per guess, making large-scale offline brute-force economically infeasible for strong passphrases.

Because VanishShare runs PBKDF2 in the browser via the native Web Crypto API (compiled to native AES-NI + SHA instructions via V8/JavaScriptCore), 600,000 iterations completes in approximately **40–90 ms on modern devices**, representing negligible UX latency.

### Backward Compatibility

During the transition from the legacy parameter of 100,000 iterations, the system attempts decryption at 600,000 iterations first. If that fails (indicating an older link), it falls back transparently to 100,000 iterations. All newly created links enforce 600,000 iterations.

---

## 4. Passphrase Verifier

To provide a fast client-side rejection of wrong passphrases — without requiring a server round-trip — a verifier token is included in the URL fragment:

1. The constant string `"VERIFIED"` is encrypted with `Kp` (the passphrase-derived key) using AES-256-GCM.
2. The resulting ciphertext + IV are embedded in the URL fragment as `V_pass` and `V_pass_iv`.
3. On the recipient side, the passphrase is entered, `Kp` is derived, and the verifier is decrypted.
4. If decryption succeeds and produces `"VERIFIED"`, the passphrase is correct.
5. If decryption fails (authentication tag mismatch), the passphrase is rejected client-side before any server request is made.

This prevents wasted OTP attempts and server load from wrong-passphrase requests.

---

## 5. Payload Padding

**Design:** Fixed-bucket padding with a 4-byte big-endian length prefix  
**Bucket sizes:** 4,096 / 16,384 / 65,536 / 131,072 / 204,800 bytes  
**Padding bytes:** Filled with CSPRNG random bytes (not zeros, to resist differential analysis)  
**IV Chunking:** Large padding fills are generated in 64 KB chunks (the maximum per `getRandomValues` call) to comply with browser API constraints  

**Recovery:** The 4-byte prefix stores the exact original byte length, allowing exact reconstruction of the unpadded payload on the recipient side.

**Backward compatibility:** If the 4-byte length prefix produces a value exceeding the remaining buffer length, the padding is assumed to be absent (legacy link) and the full buffer is returned as-is.

---

## 6. Email HMAC Fingerprinting

**Algorithm:** HMAC-SHA-256  
**Key:** `HMAC_SECRET` (server environment variable) concatenated with a per-secret `emailHmacSalt`  
**Input:** Normalized email address (trimmed, lowercased)  
**Output:** 256-bit digest, stored in the database  

The two-component key `HMAC_SECRET || emailHmacSalt` ensures that:
- Different secrets produce different digests for the same email (the per-secret salt prevents cross-secret correlation).
- An attacker with the database but not `HMAC_SECRET` cannot verify any email guess.
- An attacker with `HMAC_SECRET` but not a specific `emailHmacSalt` cannot compute the digest for that secret's recipients.

---

## 7. OTP Generation & Storage

**Generation:** 32 bits from OS CSPRNG, reduced modulo 1,000,000, zero-padded to 6 digits  
**Delivery:** Out-of-band via transactional email  
**Storage:** SHA-256 hash of the OTP string (not the raw OTP)  
**Expiration:** Short TTL enforced server-side  
**Attempt limiting:** Maximum 3 failed verification attempts; OTP is invalidated on the 3rd failure  
**Single-use:** OTP is cleared from the database immediately upon successful verification  

---

## 8. Randomness

All randomness used in VanishShare client-side cryptography is sourced from `crypto.getRandomValues`, which delegates to the operating system's CSPRNG:

- Linux: `getrandom(2)` / `/dev/urandom`
- macOS / iOS: `SecRandomCopyBytes`
- Windows: `BCryptGenRandom`

Server-side randomness (OTP generation, email HMAC salt, file storage key) uses Node.js `crypto.randomBytes`, which also delegates to the OS CSPRNG.

No pseudorandom number generator (PRNG) seeded with predictable values (timestamps, Math.random, etc.) is used anywhere in the cryptographic path.
