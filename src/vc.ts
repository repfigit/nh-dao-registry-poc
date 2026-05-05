/**
 * Verifiable Credential issuance for the NH DAO Registry.
 *
 * Each filing produces one or more credentials over its lifecycle:
 *
 *   IntakeAcknowledgement
 *     Issued at filing time. Asserts that the registry received the filing
 *     and recorded the canonical hash. legalStatus = `not-determined`.
 *
 *   RegisteredNHDAOCredential
 *     Issued when an SoS reviewer approves the filing. Asserts that the
 *     DAO is registered under RSA 301-B as of `validFrom`, valid until
 *     `validUntil` (one year by default, tied to annual report cadence).
 *     legalStatus = `registered`.
 *
 * Credentials are W3C VC Data Model 2.0, JSON-LD with a `proof` block
 * carrying a detached `JsonWebSignature2020` over the canonicalized
 * unsigned credential — the same signing primitive used for the DID
 * documents, with the same `JWS_DOMAIN` so a credential signature
 * cannot be replayed against a DID-document verifier and vice versa.
 *
 * `credentialStatus` points at a published Bitstring Status List entry
 * so revocation is checkable by any third party without contacting the
 * SoS over a private channel.
 */

import { canonicalize, canonicalBytes } from './canonicalize.js';
import { detachedJws, sha256Hex, verifyDetachedJws, jwkToPublicKey } from './crypto.js';

const VC_CONTEXT_V2 = 'https://www.w3.org/ns/credentials/v2';
const JWS_2020_CONTEXT = 'https://w3id.org/security/suites/jws-2020/v1';
const STATUS_LIST_CONTEXT = 'https://w3id.org/vc/status-list/2021/v1';

const DEFAULT_VALIDITY_MS = 365 * 24 * 60 * 60 * 1000; // one year

export const CREDENTIAL_KIND = {
  INTAKE: 'IntakeAcknowledgement',
  REGISTRATION: 'RegisteredNHDAOCredential',
} as const;

type CredentialKind = typeof CREDENTIAL_KIND[keyof typeof CREDENTIAL_KIND];

export interface BuildCredentialOpts {
  issuerDid: string;
  daoDid: string;
  agentDid: string;
  registryId: string;
  daoName: string;
  governanceContentHash: string;   // sha256 hex (no prefix)
  daoDocumentHash: string;          // sha256 hex of canonical DAO did doc
  registryEntryUrl: string;         // public URL of the registry record
  statusListUrl: string;            // public URL of the status list VC
  statusListIndex: number;          // bit index in the status list
  validFrom: string;                // ISO-8601
  validUntil?: string;              // ISO-8601; defaults to validFrom + 1 year
  issuedAt: string;                 // ISO-8601
  filingVersion: number;
}

function ensureValidUntil(validFrom: string, supplied?: string) {
  if (supplied) return supplied;
  const start = Date.parse(validFrom);
  if (!Number.isFinite(start)) throw new TypeError(`vc: invalid validFrom ${validFrom}`);
  return new Date(start + DEFAULT_VALIDITY_MS).toISOString().replace(/\.\d+Z$/, 'Z');
}

function credentialId(issuerDid: string, kind: CredentialKind, registryId: string, version: number) {
  return `${issuerDid}#credential/${kind}/${registryId}/v${version}`;
}

function baseCredential(kind: CredentialKind, opts: BuildCredentialOpts) {
  const validUntil = ensureValidUntil(opts.validFrom, opts.validUntil);
  return {
    '@context': [VC_CONTEXT_V2, STATUS_LIST_CONTEXT, JWS_2020_CONTEXT],
    id: credentialId(opts.issuerDid, kind, opts.registryId, opts.filingVersion),
    type: ['VerifiableCredential', kind],
    issuer: opts.issuerDid,
    validFrom: opts.validFrom,
    validUntil,
    credentialSubject: {
      id: opts.daoDid,
      type: 'NHRegisteredDAO',
      daoName: opts.daoName,
      registeredAgent: opts.agentDid,
      registryEntry: opts.registryEntryUrl,
      registryId: opts.registryId,
      filingVersion: opts.filingVersion,
      governanceContentHash: `sha256:${opts.governanceContentHash}`,
      daoDocumentHash: `sha256:${opts.daoDocumentHash}`,
    },
    credentialStatus: {
      id: `${opts.statusListUrl}#${opts.statusListIndex}`,
      type: 'BitstringStatusListEntry',
      statusPurpose: 'revocation',
      statusListIndex: String(opts.statusListIndex),
      statusListCredential: opts.statusListUrl,
    },
    issued: opts.issuedAt,
  };
}

/**
 * Build the unsigned IntakeAcknowledgement VC. Asserts only that the
 * filing was received; legal status is explicitly not determined.
 */
export function buildIntakeCredential(opts: BuildCredentialOpts) {
  const vc = baseCredential(CREDENTIAL_KIND.INTAKE, opts);
  vc.credentialSubject = {
    ...vc.credentialSubject,
    // @ts-expect-error - extending credential subject with kind-specific fields
    legalStatus: 'not-determined',
    registryLifecycle: 'submitted-intake',
    statute: 'NH RSA 301-B',
    purpose: 'Acknowledgement of evidence intake; not a legal determination.',
  };
  return vc;
}

/**
 * Build the unsigned RegisteredNHDAOCredential VC. Asserts that the SoS
 * reviewer approved the filing and the DAO is registered under RSA
 * 301-B for the validity window.
 */
export function buildRegistrationCredential(opts: BuildCredentialOpts & {
  approval?: {
    approvedBy?: string | null;
    reason?: string | null;
    evidenceSnapshotHash?: string | null;
    governanceContentHash?: string | null;
    governanceCid?: string | null;
    complianceEvidenceHash?: string | null;
  };
}) {
  const vc = baseCredential(CREDENTIAL_KIND.REGISTRATION, opts);
  vc.credentialSubject = {
    ...vc.credentialSubject,
    // @ts-expect-error - extending credential subject with kind-specific fields
    legalStatus: 'registered',
    registryLifecycle: 'approved-registration',
    statute: 'NH RSA 301-B',
    approval: opts.approval || null,
  };
  return vc;
}

/**
 * Sign a VC by attaching a JsonWebSignature2020 proof. The signing input
 * is the canonicalized credential with `proof` stripped, identical to
 * the DID-document signing scheme. Returns a new object; the input is
 * not mutated.
 */
export function signCredential(vc: any, privateKey: Uint8Array, controllerKid: string, created: string) {
  const { proof: _drop, ...unsigned } = vc;
  const payloadBytes = canonicalBytes(unsigned);
  const jws = detachedJws(privateKey, payloadBytes);
  return {
    ...unsigned,
    proof: {
      type: 'JsonWebSignature2020',
      created,
      verificationMethod: `${unsigned.issuer}#${controllerKid}`,
      proofPurpose: 'assertionMethod',
      jws,
    },
  };
}

/**
 * Verify a credential's signature against a public-key JWK. Reconstructs
 * the canonical bytes (proof stripped) and runs detached JWS verification.
 * Throws on malformed credential; returns false on signature mismatch.
 */
export function verifyCredentialSignature(vc: any, publicKeyJwk: any) {
  if (!vc?.proof?.jws) throw new Error('vc: missing proof.jws');
  if (vc.proof.proofPurpose !== 'assertionMethod') {
    throw new Error(`vc: unexpected proofPurpose ${JSON.stringify(vc.proof.proofPurpose)}`);
  }
  const { proof: _drop, ...unsigned } = vc;
  const payloadBytes = canonicalBytes(unsigned);
  const publicKey = jwkToPublicKey(publicKeyJwk);
  return verifyDetachedJws(vc.proof.jws, publicKey, payloadBytes);
}

/**
 * Canonical hash of an unsigned credential (proof stripped). Used for
 * the on-chain anchor and for storage integrity checks.
 */
export function canonicalCredentialHash(vc: any) {
  const { proof: _drop, ...unsigned } = vc;
  return sha256Hex(canonicalize(unsigned));
}
