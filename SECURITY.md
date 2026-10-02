# Security Contact & Responsible Disclosure

## Reporting a Vulnerability

If you discover a security vulnerability in VanishShare, we appreciate your responsible disclosure.

**Email:** contact@vanishshare.app  
**PGP Key:** *(to be published)*

We follow responsible disclosure principles:

1. Please **do not** publicly disclose the vulnerability until we have had 90 days to investigate and remediate.
2. We will acknowledge receipt of your report within **48 hours**.
3. We will provide a status update within **7 business days**.
4. We will notify you when the issue is remediated and credit you in our changelog (unless you prefer anonymity).

## Scope

The following are **in-scope** for security reports:

- Cryptographic design flaws that compromise secret confidentiality
- Server-side vulnerabilities that allow unauthorized access to ciphertext
- Authentication or OTP verification bypasses
- Denial-of-service vulnerabilities in the core secret delivery flow
- Injection vulnerabilities (XSS, injection) in web interfaces
- Information leakage of sensitive metadata

The following are **out of scope**:

- Theoretical web delivery trust model concerns (acknowledged and documented in `TRUST_BOUNDARIES.md`)
- Browser extension threat vectors (outside the application's trust boundary)
- Endpoint device compromise scenarios
- Rate limiting bypass via distributed attacks (report these anyway; we'll consider them case-by-case)
- Missing security headers on non-sensitive static marketing pages

## Bug Bounty

We do not currently operate a formal bug bounty program. However, we will acknowledge significant findings publicly and may offer compensation at our discretion for critical vulnerabilities that result in actual security improvements.
