/**
 * Bitstring Status List 2021 implementation for credential revocation.
 *
 * Each issued credential is assigned an integer index. The published
 * status list is a bitstring; bit `i` set to 1 means the credential
 * with index `i` has been revoked. The list itself is wrapped in a
 * Verifiable Credential (`StatusList2021Credential`), gzipped, and
 * base64url-encoded — exactly per the W3C Bitstring Status List spec.
 *
 * Verifiers fetch the list VC, verify its signature with the registry's
 * controller key, decode the bitstring, and check the bit at the
 * relevant index. They do not need credentials, accounts, or an SoS
 * API key to do this.
 *
 * Allocation is monotonic: each new credential gets the next free
 * index. An allocator file persists the high-water mark and the set
 * of revoked indices. This keeps the in-memory state simple and the
 * filesystem reflects the source of truth.
 */

import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { canonicalBytes, canonicalize } from './canonicalize.js';
import { detachedJws, sha256Hex, b64uEncode } from './crypto.js';

/**
 * Total bit length of the status list. The W3C spec recommends a
 * minimum of 131,072 bits (16 KiB) so a list-fetch reveals nothing
 * about which credential was checked. For the POC we use 16,384 bits
 * (2 KiB) — large enough to avoid trivial fingerprinting at registry
 * scale and small enough for the reference deployment to ship in
 * git-able size. Production deployments should bump this to the spec
 * minimum.
 */
export const STATUS_LIST_BITS = 16384;

const STATE_PATH = path.join('data', 'status-list.json');

interface StatusListState {
  nextIndex: number;
  revoked: number[];        // indices currently set to 1
  totalBits: number;
  lastUpdated: string;
}

function readState(): StatusListState {
  if (!fs.existsSync(STATE_PATH)) {
    return { nextIndex: 0, revoked: [], totalBits: STATUS_LIST_BITS, lastUpdated: new Date().toISOString().replace(/\.\d+Z$/, 'Z') };
  }
  try {
    const raw = JSON.parse(fs.readFileSync(STATE_PATH, 'utf8'));
    return {
      nextIndex: Number(raw.nextIndex || 0),
      revoked: Array.isArray(raw.revoked) ? raw.revoked.map(Number).filter(Number.isFinite) : [],
      totalBits: Number(raw.totalBits || STATUS_LIST_BITS),
      lastUpdated: String(raw.lastUpdated || new Date().toISOString()),
    };
  } catch {
    return { nextIndex: 0, revoked: [], totalBits: STATUS_LIST_BITS, lastUpdated: new Date().toISOString().replace(/\.\d+Z$/, 'Z') };
  }
}

function writeState(state: StatusListState) {
  fs.mkdirSync(path.dirname(STATE_PATH), { recursive: true });
  const tmp = `${STATE_PATH}.${process.pid}.${Date.now()}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(state, null, 2));
  fs.renameSync(tmp, STATE_PATH);
}

/**
 * Allocate the next status list index and persist the new high-water
 * mark. Each issued credential should consume exactly one index.
 */
export function allocateIndex(): number {
  const state = readState();
  const i = state.nextIndex;
  if (i >= state.totalBits) {
    throw new Error(`statuslist: exhausted (totalBits=${state.totalBits}); rotate the list before issuing more credentials`);
  }
  state.nextIndex = i + 1;
  state.lastUpdated = new Date().toISOString().replace(/\.\d+Z$/, 'Z');
  writeState(state);
  return i;
}

/**
 * Mark an index as revoked. Idempotent: revoking an already-revoked
 * index is a no-op.
 */
export function revokeIndex(index: number): { changed: boolean; index: number } {
  const state = readState();
  if (index < 0 || index >= state.totalBits) {
    throw new Error(`statuslist: index ${index} out of range [0, ${state.totalBits})`);
  }
  if (state.revoked.includes(index)) return { changed: false, index };
  state.revoked = [...state.revoked, index].sort((a, b) => a - b);
  state.lastUpdated = new Date().toISOString().replace(/\.\d+Z$/, 'Z');
  writeState(state);
  return { changed: true, index };
}

/**
 * Read the status of an index (true = revoked).
 */
export function isRevoked(index: number): boolean {
  return readState().revoked.includes(index);
}

export function readStatusListState() {
  return readState();
}

/**
 * Build the gzipped + base64url bitstring required by the W3C status
 * list VC `encodedList` field. The bit at position `index` is set
 * iff that index appears in `revoked`.
 */
export function encodeBitstring(revoked: number[], totalBits: number): string {
  const totalBytes = Math.ceil(totalBits / 8);
  const bits = new Uint8Array(totalBytes);
  for (const index of revoked) {
    if (index < 0 || index >= totalBits) continue;
    const byte = Math.floor(index / 8);
    const bit = 7 - (index % 8); // big-endian bit order per the spec
    bits[byte] |= 1 << bit;
  }
  const gz = zlib.gzipSync(Buffer.from(bits));
  return b64uEncode(new Uint8Array(gz));
}

/**
 * Build the unsigned StatusList2021Credential VC. Sign with the same
 * controller key as DAO documents and ordinary credentials.
 */
export function buildStatusListCredential(opts: {
  issuerDid: string;
  statusListUrl: string;
  issuedAt: string;
  validFrom: string;
}) {
  const state = readState();
  const encodedList = encodeBitstring(state.revoked, state.totalBits);
  return {
    '@context': [
      'https://www.w3.org/ns/credentials/v2',
      'https://w3id.org/vc/status-list/2021/v1',
      'https://w3id.org/security/suites/jws-2020/v1',
    ],
    id: opts.statusListUrl,
    type: ['VerifiableCredential', 'StatusList2021Credential'],
    issuer: opts.issuerDid,
    validFrom: opts.validFrom,
    issued: opts.issuedAt,
    credentialSubject: {
      id: `${opts.statusListUrl}#list`,
      type: 'StatusList2021',
      statusPurpose: 'revocation',
      encodedList,
      totalBits: state.totalBits,
      revokedCount: state.revoked.length,
    },
  };
}

/**
 * Sign the status list credential. Same JWS_2020 detached scheme as
 * elsewhere in the registry.
 */
export function signStatusListCredential(vc: any, privateKey: Uint8Array, controllerKid: string, created: string) {
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
 * Hash of the canonical (unsigned) status list credential. Useful for
 * cache validation and external integrity checks.
 */
export function canonicalStatusListHash(vc: any) {
  const { proof: _drop, ...unsigned } = vc;
  return sha256Hex(canonicalize(unsigned));
}

/**
 * Decode an `encodedList` string into a Uint8Array of length
 * `Math.ceil(totalBits / 8)`. Verifiers use this to check a single
 * bit without trusting the registry's revokedCount field.
 */
export function decodeBitstring(encodedList: string): Uint8Array {
  const padded = encodedList + '==='.slice((encodedList.length + 3) % 4);
  const compressed = Buffer.from(padded.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  return new Uint8Array(zlib.gunzipSync(compressed));
}

/**
 * Test a specific bit position in a decoded bitstring. Returns true
 * when the credential at that index is revoked.
 */
export function bitAt(bytes: Uint8Array, index: number): boolean {
  const byte = Math.floor(index / 8);
  const bit = 7 - (index % 8);
  if (byte >= bytes.length) return false;
  return (bytes[byte] & (1 << bit)) !== 0;
}
