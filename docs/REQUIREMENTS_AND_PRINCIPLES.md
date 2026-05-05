# NH DAO Registry: requirements and principles

A short framing document for the design discussion. The goal is to make
the disagreement productive — not by pre-deciding it, but by separating
*what the registry must do* from *how to do it*. Once those are
documented, an architecture argument is possible. Without them, every
proposal is talking past every other proposal.

This is a working draft for the collab doc; treat it as a starting point
to amend, not a settled position.

## What the registry IS

1. **A recorder of intake evidence** for filings under RSA 301-B. The
   filer submits a fixed evidence checklist (governance bytes,
   smart-contract addresses, registered agent, decentralization
   attestation, etc.); the registry validates the shape and pins a
   tamper-evident copy.
2. **An issuer of signed attestations** about the entities it has
   accepted. Every accepted filing produces (a) a `did:web` DID document
   for the DAO and the registered agent, signed by the registry's
   controller key, and (b) a Verifiable Credential of standing that
   third parties (banks, vendors, smart contracts, agents) can verify
   without contacting the SoS at all.
3. **A public-read service.** Anyone can resolve the DID, fetch the
   signed VC, and recompute the hash chain. No account, no API key, no
   gatekeeping for read access.
4. **A pointer hub.** The registry references on-chain artifacts (smart
   contract addresses, anchor transactions) and off-chain artifacts
   (governance documents on IPFS/Arweave) by hash and URL — but the
   *legal record* is what the SoS signs.

## What the registry is NOT

1. **Not a gatekeeper.** RSA 301-B does not authorize the SoS to verify
   the legality of a DAO under the statute or to certify decentralization.
   Filing is intake of evidence; legal status is `not-determined` until
   adjudicated elsewhere.
2. **Not on-chain authoritative.** The SoS is the legal source of truth.
   A blockchain anchor is *evidence* of what the SoS recorded at a point
   in time — not a substitute for the SoS record. If the chain disagrees
   with the SoS, the SoS wins.
3. **Not chain-bound.** The registry must not require any DAO to use any
   specific blockchain. DAOs come from many chains; the registry must
   reference all of them by CAIP-2 chain identifier and never privilege
   one.
4. **Not a KYC system.** Selective disclosures are acceptable for proving
   entity claims; full identity collection is not in scope and is
   actively undesirable for the consumer-protection posture.
5. **Not a legal-status oracle.** The registry does not decide piercing
   the corporate veil, decentralization sufficiency, or tax treatment.

## Core constraints

These shape what an implementation can and cannot do.

| # | Constraint | Source |
|---|---|---|
| C1 | SoS is the legal source of truth | NH constitutional / statutory framing |
| C2 | Public reads must be permissionless and machine-readable | Statutory transparency intent |
| C3 | Output must be verifiable from web2 *and* from on-chain contexts | Cross-context interop requirement |
| C4 | Records must survive single-node failure of any one custody system (registry, IPFS gateway, blockchain node) | Operational continuity |
| C5 | Cryptographic primitives must follow public W3C / IETF standards (DID, VC, JWS) | Reuse and durability |
| C6 | Implementation must be open source | Reuse across SoS offices, audit-ability |

## Non-functional requirements

- **Cybersecurity-operated, not feature-developed forever.** Once the
  reference implementation conforms to standards, ongoing investment is
  in hardening (operations, audit, key rotation, redundancy), not new
  proprietary features. Bugs go upstream to the standard library.
- **Cross-SoS interoperability.** The data model and API must support
  pointers between foreign jurisdictions' registry records, so that a
  NH-registered DAO with a WY foreign filing can be cross-verified
  without bespoke integration.
- **Lifecycle completeness.** Creation, update, dissolution, and fork
  must each have a documented record path. (Today's MVP has creation
  hardened; update and dissolution are stubs; fork has a data-model
  question to settle.)
- **Recorder-grade audit log.** Every mutation by an SoS reviewer is
  appended to an audit log with reviewer identity, action, reason, and
  timestamp. This already exists.
- **Configurable, not bespoke.** The implementation should prefer
  schema/config knobs over new code, since every line of bespoke code
  is owned forever as security surface.

## Principles for resolving design disputes

When two technical proposals can each satisfy the requirements above,
prefer the one that:

1. **Adds the least new code.** Standards + configuration > glue >
   bespoke.
2. **Is portable to the next SoS that adopts the design.** If something
   only works for NH's specific stack, it loses.
3. **Verifies independently.** Any third party with a public network
   connection should be able to verify any registry claim without
   asking the SoS for credentials.
4. **Treats blockchain as evidence, not authority.** Anchors and
   on-chain references are public timestamps and pointers, not the
   record itself.
5. **Defers contested legal questions** ("calculation of
   decentralization", "is this a security?") to the policy track.
   Technical reference should not pretend to settle them.

## Out of scope for the technical reference

These belong on the policy track and will not be answered by the
implementation:

- Definition of "calculation of decentralization" sufficient to defeat
  federal regulatory classification.
- KYC/AML applicability to DAO members.
- Tax treatment of yield from DAO-held assets.
- Liability allocation between members, officers, and the entity.
- Hard fork as continuation vs. new entity (the data model can record
  either; the legal answer is statute or case law).

## Open requirements questions

These are the items the collab doc should converge on:

1. Is cross-SoS pointer support a v1 requirement or v2?
2. What is the registry's posture when an underlying smart contract
   is upgraded (i.e., the DAO's on-chain code changes)? Self-report?
   Re-attest? Auto-detect?
3. Dissolution: filer-initiated, SoS-initiated, both? With what
   evidence?
4. Self-expiring VCs: what cadence? 1 year? Tied to annual report
   filing?
5. Revocation: who can trigger? On what grounds?
6. Fork: treat as new entity (default) or as continuation when token
   holders ratify? Both?
