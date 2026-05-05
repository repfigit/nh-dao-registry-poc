# NH DAO Registry POC — Open Items

This file tracks known MVP gaps that remain after the current Fly deployment.
It is intentionally practical: each item states current status, risk, and the
next implementation step.

## 1. Uploaded File Trust Boundary

**Status:** Open.

The app accepts uploaded governance/bylaws bytes, hashes them, stores them under
a local CID, and optionally posts the same bytes to Arweave. The backend enforces
size and byte-shape constraints, but it does not deeply validate or inspect file
content.

Remaining work:

- Detect actual MIME type from file bytes, not only filename or browser hints.
- Restrict supported file classes for the MVP, probably PDF plus JSON/text.
- Add malware scanning before accepting public uploads.
- Extract PDF text and metadata for reviewer search.
- Generate a safe admin preview or rendered snapshot.
- Record file inspection results in metadata.

## 2. Admin Approval Bound To Evidence

**Status:** Mostly implemented.

Approval now creates `meta.approvalEvidence.snapshotHash` and includes the
reviewed governance CID/hash, compliance evidence hash, and submitted document
hashes. The approved DAO/agent DID documents and the
`RegisteredNHDAOCredential` include the evidence snapshot hash.

Remaining work:

- Add an admin UI action that explicitly displays “approving evidence snapshot
  X” at the moment of approval.
- Store a reviewer acknowledgment timestamp for the exact snapshot shown.
- Prevent approval if the record changed after the admin opened the detail view.

## 3. Real User Accounts

**Status:** Open and highest-priority production gap.

The MVP uses bearer tokens through `FILING_API_KEY` and `ADMIN_API_KEY`. This is
acceptable for a controlled POC, but it is not a real filing workflow.

Remaining work:

- Filer accounts and filing sessions.
- Staff accounts with roles such as reviewer, supervisor, and admin.
- MFA for staff.
- Session expiration and revocation.
- Audit trails tied to real user identity.
- Optional wallet/DID signature for filer-submitted correction or amendment
  packets.

## 4. Filesystem Store

**Status:** Open.

The current store is a filesystem-backed record cabinet on the Fly volume. This
is adequate for a single-process MVP, but not for a production registry.

Remaining work:

- Add a storage abstraction.
- Implement Postgres for record metadata, DID documents, lifecycle events,
  credentials, and audit entries.
- Move governance bytes to object storage under content-addressed keys.
- Add export/import tooling from the current filesystem layout.
- Add backup and restore tests.

## 5. Public/Private Data Boundary

**Status:** Open; needs legal review.

The public record exposes selected filing metadata, evidence URLs, governance
metadata, lifecycle information, credentials, and approval evidence references.
Admin detail exposes more. The legal disclosure boundary has not been formally
reviewed.

Remaining work:

- Decide which registered-agent contact fields are public.
- Decide whether uploaded governance documents are always public records.
- Decide whether admin reasons, correction reasons, and audit details are public.
- Add field-level public/private classification in code and docs.
- Add redaction/export policy.

## 6. Arweave Durability Confirmation

**Status:** Partially implemented.

The app posts to Arweave when `ARWEAVE_JWK` is configured and records the
transaction id, URI, gateway URL, reward, and upload status. The verifier can
fetch the Arweave gateway URL and hash-check the returned bytes.

Remaining work:

- Poll Arweave after upload until the transaction is retrievable or confirmed
  failed.
- Record confirmation state separately from submission state.
- Surface confirmation status in admin and public inspection views.
- Add retry/reconciliation tooling for failed or pending Arweave uploads.

## 7. File Versioning And Corrections

**Status:** Partially implemented.

The backend supports `POST /api/records/:id/correction`, which records hashed
correction or amendment packets. If a record is in `needs_correction`, a
correction packet requeues it to `submitted`. The old record and packet hash are
preserved.

Remaining work:

- Add public UI for submitting correction/amendment packets.
- Add admin UI for reviewing correction history.
- Decide when a correction should issue a new DID document version.
- Preserve old governance file hashes and new governance file hashes as separate
  reviewed evidence sets.
- Define whether post-approval amendments revoke, supersede, or extend existing
  credentials.

## 8. Operational Security

**Status:** Open.

The app has request body limits, simple rate limits, bearer-token auth, and
production readiness checks. Operational hardening is still thin.

Remaining work:

- Add security headers and a Content Security Policy.
- Replace in-memory rate limiting with shared rate limiting for multi-instance
  deployment.
- Tune upload-specific request body limits.
- Add secret rotation procedure.
- Add immutable or hash-chained audit logging.
- Add admin session controls once real auth exists.
- Add monitoring and alerting around anchoring, Arweave, failed filings, and
  storage health.

## 9. Production Filing And Payment Workflow

**Status:** Open.

The MVP submits directly to `POST /api/file`. A real Secretary of State workflow
likely needs drafts, fee handling, receipts, and formal filing timestamps.

Remaining work:

- Draft filing sessions.
- Fee calculation.
- Payment provider integration.
- Receipt IDs and payment audit trail.
- Rejection/refund handling.
- Formal submission timestamp separate from draft creation.

## 10. Legal Meaning Of Approval

**Status:** Open; needs legal/spec decision.

The app currently records approval as `approved-registration` and issues a
`RegisteredNHDAOCredential` with `legalStatus: registered`. That may be too
broad or exactly right depending on how the Secretary of State wants to describe
the legal effect.

Remaining work:

- Define controlled vocabulary for submitted, under review, needs correction,
  approved, denied, revoked, dissolved, amended, and superseded.
- Decide whether the credential asserts registration only, compliance only, or
  standing under a specific statutory category.
- Add legal disclaimers to public verification and credential docs.
- Update DID services and VC fields to avoid overclaiming statutory
  certification.

## Current Highest Priority

The next major implementation item is **real user accounts and sessions**. It is
the largest remaining gap between a working public POC and a credible production
filing workflow.
