# Security policy

parda's job is to keep personal data from leaving the user's machine. We treat both of these as security issues:

- **Leaks:** personal data reaching an upstream API unredacted where parda should have caught it (for example a supported format that is missed, a streaming edge case, a fail-open path in strict mode).
- **Classic vulnerabilities:** anything that lets another program, web page or user read the vault, the key, the IPC socket or proxied traffic, or makes the proxy reachable from outside the machine.

## Reporting

Please report privately via GitHub's *Report a vulnerability* (Security → Advisories) on this repository. Include a **synthetic** reproduction — never real personal data. We aim to acknowledge within 3 days and to ship a fix or mitigation within 30 days for confirmed issues.

Detection misses for unusual names are usually not security issues; open a normal issue with the `PII leak` template (synthetic text only) unless the miss affects a validated, checksum-bearing format.

## Threat model (v0.1)

In scope: other local users, web pages in the user's browser (DNS rebinding, CSRF against the proxy), malformed or hostile upstream responses, crash/timeout behaviour of the model.

Out of scope: an attacker with the user's own account privileges (they can read the keychain and the clipboard anyway), PII inside images and documents (documented as unscanned), and inference of public facts by the AI.

## Hardening in place

Loopback-only proxy with Host and Origin guards; 0700 config/data/socket directories; 0600 key file when no keyring; XChaCha20-Poly1305 encryption of real values with a keyed HMAC index; SHA-256-pinned model downloads; strict (fail-closed) default mode; no raw values in logs or events.
