# VanishShare — Security Design & Threat Model

> **Public security documentation for [VanishShare](https://vanishshare.app)** — a zero-knowledge ephemeral secret sharing service.

This repository is the authoritative, public record of VanishShare's security architecture, cryptographic specification, and threat model. It is maintained separately from the application codebase so that security researchers, enterprise evaluators, and independent auditors can review the design without access to proprietary implementation details.

---

## Repository Structure

| Document | Description |
| :--- | :--- |
| [`ARCHITECTURE.md`](./ARCHITECTURE.md) | Zero-knowledge system architecture and cryptographic pipeline |
| [`THREAT_MODEL.md`](./THREAT_MODEL.md) | Threat model, attack surfaces, mitigations, and residual risks |
| [`CRYPTOGRAPHY.md`](./CRYPTOGRAPHY.md) | Detailed cryptographic primitives specification |
| [`AUDIT_RESPONSES.md`](./AUDIT_RESPONSES.md) | Formal responses to external security audit findings |
| [`TRUST_BOUNDARIES.md`](./TRUST_BOUNDARIES.md) | Explicit trust boundaries and zero-knowledge scope |

---

## Core Security Guarantee

VanishShare's fundamental security property is:

> **The server (and anyone with access to it) is mathematically incapable of decrypting any secret payload, even under legal compulsion, insider threat, or full infrastructure compromise.**

This is achieved through strict client-side cryptography: all encryption and key management happens in the browser. The server only ever receives and stores opaque AES-256-GCM ciphertext.

---

## Security Contact

To report a vulnerability or security concern, please email: **contact@vanishshare.app**

We follow responsible disclosure. Please allow 90 days for remediation before public disclosure.

---

## Changelog

| Date | Change |
| :--- | :--- |
| 2026-10-02 | Initial public release of security documentation |
| 2026-10-02 | PBKDF2 iterations upgraded from 100,000 → 600,000 (OWASP 2024+ alignment) |
| 2026-10-02 | Fixed-bucket payload padding implemented to prevent ciphertext size fingerprinting |
