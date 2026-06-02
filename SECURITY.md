# Security Policy

The CIP-309 TypeScript SDKs implement a standard for cryptographic Proof of
Existence. Their security properties matter to everyone who relies on a proof,
so we take reports seriously and ask that they be handled responsibly.

## Scope

This repository holds the **TypeScript implementation**: the cryptographic
primitives (`@cardanowall/crypto-core`), the wire-format library
(`@cardanowall/poe-standard`), and the high-level SDK (`@cardanowall/sdk-ts`) —
the structural validator, public verifier, recipient verifier with sealed-PoE
decryption, and the gateway-agnostic HTTP client.

In scope for a report here:

- A flaw in these packages that lets a verifier be misled into accepting an
  invalid proof, decrypt something it should not, leak information it should
  not, or that weakens the secure-by-default HTTP egress (SSRF guard, deny-host
  policy, bounded bodies/timeouts).
- A divergence between these packages and the canonical conformance vectors that
  enshrines an insecure behaviour.

Out of scope here (report it in the relevant repository instead):

- A flaw or ambiguity in the **standard** itself — report it in the
  [`cip309`](https://github.com/cardanowall/cip309) standard repository.
- A bug in another implementation — `cip309-py`, `cip309-rs`, or the
  `cip309-cli` command-line tool. Use that repository's security policy.

## Core security goals

A report is **high priority** if it undermines any of the standard's core
guarantees as realised by these packages:

- **Standalone verifiability** — a proof verifies from the transaction metadata,
  the optional content bytes, and a public blockchain explorer alone.
- **Zero issuer trust** — verifying a proof never requires trusting the
  publisher, their domain, or any server.
- **Confidentiality of sealed PoE** — only an intended recipient can decrypt a
  sealed payload, and trial-decryption does not leak which recipient matched.
- **Algorithm agility done safely** — registry additions cannot weaken existing
  records or enable downgrade.

## Reporting a vulnerability

**Please report privately. Do not open a public issue for a security report.**

Preferred channel: GitHub's **private vulnerability reporting** for this
repository (the *Security* tab → *Report a vulnerability*).

Alternative contact: `hello@cardanowall.com`.

Please include, as far as you can:

- A clear description of the issue and the security property it breaks.
- The exact location — package, module, or test — and a minimal reproduction.
- The impact and, if you have one, a suggested remediation.

## What to expect

- We aim to acknowledge a report promptly and to keep you informed as we
  investigate.
- We practise **coordinated disclosure**: we will agree a disclosure timeline
  with you, fix the issue, and credit you unless you prefer otherwise.
- Because these packages are **pre-1.0**, there are no long-term-supported
  released versions yet; fixes land on the current line.

Thank you for helping keep CIP-309 trustworthy.
