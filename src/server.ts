/**
 * NH DAO Registry MVP server.
 *
 * Routes:
 *
 *   GET  /                              filing UI
 *   GET  /healthz                       process liveness
 *   GET  /readyz                        readiness/config checks
 *   GET  /inspect                       record list and inspector
 *   GET  /admin                         Secretary of State review portal
 *   GET  /api/records                   list filings
 *   POST /api/file                      submit a filing
 *   GET  /api/records/:id               public record projection
 *   GET  /api/admin/balances            operator wallet balances
 *   GET  /api/admin/records             admin review queue
 *   GET  /api/admin/records/:id         admin filing detail + audit history
 *   POST /api/admin/records/:id/:action admin review action
 *   GET  /api/verify/:id                run end-to-end verification
 *   GET  /dao/:id/did.json              did:web resolution for DAO DID
 *   GET  /agent/:id/did.json            did:web resolution for agent DID
 *   GET  /.well-known/did.json          registry's own DID document
 *   GET  /ipfs/:cid                     local IPFS blob fallback
 *
 * The did:web routes serve the documents that the publication service
 * produced. They are real did:web documents: a resolver fetching
 * did:web:<host>:dao:<id> at https://<host>/dao/<id>/did.json gets the
 * exact JSON the registry signed.
 */

import 'dotenv/config';
import express from 'express';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';

import { file as runFiling, issueApprovedRegistration } from './publication.js';
import { verifyDao } from './verifier.js';
import { operationalBalances } from './balances.js';
import {
  listRegistryIds, loadRecord, loadDao, loadAgent, loadMeta,
  saveMeta, appendAdminAudit, listAdminAudit,
  loadCredential, listCredentialKinds,
} from './store.js';
import { loadOrCreateKeyPair } from './crypto.js';
import { publicKeyJwk } from './crypto.js';
import { anchorEnabled } from './anchor.js';
import { readLocal } from './ipfs.js';
import { registryDid } from './didweb.js';
import {
  buildStatusListCredential, signStatusListCredential,
  revokeIndex, readStatusListState, isRevoked,
} from './statuslist.js';
import { serverConfig, filingApiKey, adminApiKey, filingRate, verifyRate, productionConfigIssues, hasPublicPinning } from './config.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = [
  path.resolve(__dirname, '..', 'public'),       // tsx/dev: src/ -> public/
  path.resolve(__dirname, '..', '..', 'public'), // compiled: dist/src/ -> public/
].find(dir => fs.existsSync(dir)) || path.resolve('public');

const { host: HOST, scheme: SCHEME, controllerKeyPath: CONTROLLER_KEY_PATH, bodyLimit: REQUEST_BODY_LIMIT, port: PORT, isTest: IS_TEST } = serverConfig();
const FILING_API_KEY = filingApiKey();
const ADMIN_API_KEY = adminApiKey();

const ADMIN_STATUSES = new Set(['submitted', 'under_review', 'needs_correction', 'approved', 'denied', 'withdrawn', 'revoked']);
const ADMIN_ACTIONS = new Map([
  ['review', 'under_review'],
  ['request-correction', 'needs_correction'],
  ['approve', 'approved'],
  ['deny', 'denied'],
  ['withdraw', 'withdrawn'],
  ['revoke', 'revoked'],
]);

const app = express();
app.use(express.json({ limit: REQUEST_BODY_LIMIT }));
app.use(express.static(PUBLIC_DIR));

app.get('/healthz', (_, res) => {
  res.json({ status: 'ok' });
});

app.get('/readyz', (_, res) => {
  const checks = {
    storeWritable: false,
    controllerKeyAvailable: false,
    anchorConfigured: anchorEnabled(),
    filingAuthConfigured: Boolean(FILING_API_KEY),
    adminAuthConfigured: Boolean(ADMIN_API_KEY),
    arweaveConfigured: hasPublicPinning(),
    productionConfig: productionConfigIssues(),
  };

  try {
    const tmp = path.resolve('data', `.readyz-${process.pid}.tmp`);
    fs.mkdirSync(path.dirname(tmp), { recursive: true });
    fs.writeFileSync(tmp, 'ok');
    fs.rmSync(tmp, { force: true });
    checks.storeWritable = true;
  } catch {
    checks.storeWritable = false;
  }

  try {
    loadOrCreateKeyPair(CONTROLLER_KEY_PATH);
    checks.controllerKeyAvailable = true;
  } catch {
    checks.controllerKeyAvailable = false;
  }

  const ready = checks.storeWritable && checks.controllerKeyAvailable && checks.productionConfig.length === 0;
  res.status(ready ? 200 : 503).json({ status: ready ? 'ready' : 'not-ready', checks });
});

/**
 * Constant-time string comparison. Avoids leaking the API key length
 * via early-exit comparison when an attacker probes for it.
 */
function constantTimeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  let mismatch = 0;
  for (let i = 0; i < a.length; i++) mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return mismatch === 0;
}

/**
 * Opt-in bearer token auth. If FILING_API_KEY is set, /api/file requires
 * `Authorization: Bearer <token>`. If unset, the endpoint is open (the
 * reference-impl default; production deployments must set the key).
 */
function requireFilingAuth(req, res, next) {
  if (!FILING_API_KEY) return next();
  const header = req.get('authorization') || '';
  const m = header.match(/^Bearer\s+(.+)$/i);
  if (!m || !constantTimeEqual(m[1].trim(), FILING_API_KEY)) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  next();
}

function requireAdminAuth(req, res, next) {
  if (!ADMIN_API_KEY) return res.status(503).json({ error: 'admin auth not configured' });
  const header = req.get('authorization') || '';
  const m = header.match(/^Bearer\s+(.+)$/i);
  if (!m || !constantTimeEqual(m[1].trim(), ADMIN_API_KEY)) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  next();
}

function nowIso() {
  return new Date().toISOString().replace(/\.\d+Z$/, 'Z');
}

function ensureAdmin(meta) {
  return {
    reviewStatus: 'submitted',
    submittedAt: meta.filed || null,
    reviewedAt: null,
    reviewedBy: null,
    decisionReason: null,
    correctionRequestedAt: null,
    notesCount: 0,
    ...(meta.admin || {}),
  };
}

function summarizeRecord(id: string, meta: any) {
  const admin = ensureAdmin(meta);
  return {
    registryId: id,
    daoDid: meta.daoDid,
    agentDid: meta.agentDid,
    daoName: meta.daoName,
    agentName: meta.agentName,
    filed: meta.filed,
    anchorStatus: meta.status,
    reviewStatus: admin.reviewStatus,
    reviewedAt: admin.reviewedAt,
    reviewedBy: admin.reviewedBy,
    hasWarnings: Array.isArray(meta.warnings) && meta.warnings.some(w => !(w.category === 'anchor' && w.kind === 'config')),
  };
}

function publicRecord(record: any) {
  const { meta } = record;
  const admin = ensureAdmin(meta);
  return {
    registryId: meta.registryId,
    daoDid: meta.daoDid,
    agentDid: meta.agentDid,
    daoName: meta.daoName,
    agentName: meta.agentName,
    filed: meta.filed,
    version: meta.version,
    anchorStatus: meta.status,
    reviewStatus: admin.reviewStatus,
    approvedAt: meta.approvedAt || null,
    registryLifecycle: meta.registryLifecycle || 'submitted-intake',
    governance: {
      cid: meta.governance?.cid || null,
      ipfsUri: meta.governance?.ipfsUri || null,
      gatewayUrl: meta.governance?.gatewayUrl || null,
      contentHash: meta.governance?.contentHash || null,
      arweave: meta.governance?.arweave || null,
    },
    contracts: meta.contracts || [],
    compliance: meta.compliance ? {
      status: meta.compliance.status,
      legalStatus: meta.compliance.legalStatus,
      statute: meta.compliance.statute,
      registeredDomain: meta.compliance.registeredDomain,
      publicAddress: meta.compliance.publicAddress,
      lifecycleStatus: meta.compliance.lifecycleStatus,
      evidence: meta.compliance.evidence,
      assurance: meta.compliance.assurance,
      attestations: meta.compliance.attestations,
    } : null,
    anchors: meta.anchors || null,
    credentials: meta.credentials || null,
    warnings: meta.warnings || [],
    links: {
      daoDidDocument: `/dao/${meta.registryId}/did.json`,
      agentDidDocument: `/agent/${meta.registryId}/did.json`,
      verify: `/api/verify/${meta.registryId}`,
      credentials: `/api/credentials/${meta.registryId}`,
      intakeCredential: meta.credentials?.intake ? `/credentials/${meta.registryId}/intake.json` : null,
      registrationCredential: meta.credentials?.registration ? `/credentials/${meta.registryId}/registration.json` : null,
      statusList: `/status/registry.json`,
    },
  };
}

function applyAdminAction(registryId: string, meta: any, action: string, body: any = {}) {
  const targetStatus = ADMIN_ACTIONS.get(action) || body.reviewStatus;
  if (!ADMIN_STATUSES.has(targetStatus)) {
    const err: any = new Error('unsupported review status');
    err.statusCode = 400;
    throw err;
  }

  const reviewer = String(body.reviewer || 'Secretary of State reviewer').trim().slice(0, 120);
  const reason = String(body.reason || '').trim().slice(0, 2000);
  const note = String(body.note || '').trim().slice(0, 4000);
  if (['approve', 'deny', 'request-correction', 'revoke'].includes(action) && !reason) {
    const err: any = new Error('decision reason is required for this admin action');
    err.statusCode = 400;
    throw err;
  }
  const at = nowIso();
  const previousAdmin = ensureAdmin(meta);

  const admin = {
    ...previousAdmin,
    reviewStatus: targetStatus,
    reviewedAt: at,
    reviewedBy: reviewer,
    decisionReason: reason || null,
    correctionRequestedAt: targetStatus === 'needs_correction' ? at : previousAdmin.correctionRequestedAt,
    notesCount: previousAdmin.notesCount + (note ? 1 : 0),
  };
  meta.admin = admin;
  saveMeta(registryId, meta);

  const event = {
    at,
    registryId,
    action,
    fromStatus: previousAdmin.reviewStatus,
    toStatus: targetStatus,
    reviewer,
    reason: reason || null,
    note: note || null,
  };
  appendAdminAudit(event);
  return { meta, event };
}

/**
 * In-memory token-bucket rate limiter, keyed by client IP. Per-route limits
 * are configured at mount. This is sufficient for a single-process POC; a
 * production deployment behind a load balancer should use a shared store
 * (e.g. Redis) or rely on the LB's rate limiter.
 */
function rateLimiter({ windowMs, max }) {
  const buckets = new Map();
  return (req, res, next) => {
    const key = req.ip || req.socket?.remoteAddress || 'unknown';
    const now = Date.now();
    let b = buckets.get(key);
    if (!b || now - b.start >= windowMs) {
      b = { start: now, count: 0 };
      buckets.set(key, b);
    }
    b.count += 1;
    if (b.count > max) {
      const retryAfter = Math.ceil((b.start + windowMs - now) / 1000);
      res.setHeader('Retry-After', String(Math.max(retryAfter, 1)));
      return res.status(429).json({ error: 'too many requests' });
    }
    next();
  };
}

const filingLimiter = rateLimiter(filingRate());
const verifyLimiter = rateLimiter(verifyRate());

/* ---------- did:web hosting ---------- */

app.get('/.well-known/did.json', (req, res) => {
  // The registry's own DID document. Its controller key signs every
  // DAO and agent document it issues.
  const kp = loadOrCreateKeyPair(CONTROLLER_KEY_PATH);
  const id = registryDid(HOST);
  res.type('application/did+json').json({
    '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/jws-2020/v1'],
    id,
    controller: id,
    name: 'NH DAO Registry (POC)',
    verificationMethod: [{
      id: `${id}#controller-1`,
      type: 'JsonWebKey2020',
      controller: id,
      publicKeyJwk: publicKeyJwk(kp.publicKey),
    }],
    assertionMethod:    [`${id}#controller-1`],
    authentication:     [`${id}#controller-1`],
  });
});

app.get('/dao/:id/did.json', (req, res) => {
  const doc = loadDao(req.params.id);
  if (!doc) return res.status(404).json({ error: 'not found' });
  res.type('application/did+json').json(doc);
});

app.get('/agent/:id/did.json', (req, res) => {
  const doc = loadAgent(req.params.id);
  if (!doc) return res.status(404).json({ error: 'not found' });
  res.type('application/did+json').json(doc);
});

/* ---------- public Verifiable Credentials ---------- */

function nowIsoNoMs() {
  return new Date().toISOString().replace(/\.\d+Z$/, 'Z');
}

app.get('/credentials/:id/:kind.json', (req, res) => {
  const credential = loadCredential(req.params.id, req.params.kind);
  if (!credential) return res.status(404).json({ error: 'credential not issued' });
  res.type('application/vc+ld+json').json(credential);
});

app.get('/api/credentials/:id', (req, res) => {
  const meta = loadMeta(req.params.id);
  if (!meta) return res.status(404).json({ error: 'not found' });
  const kinds = listCredentialKinds(req.params.id);
  const credentials: Record<string, any> = {};
  for (const k of kinds) {
    credentials[k] = loadCredential(req.params.id, k);
  }
  res.json({
    registryId: req.params.id,
    daoDid: meta.daoDid,
    agentDid: meta.agentDid,
    metadata: meta.credentials || null,
    credentials,
  });
});

/* ---------- Lifecycle: dissolution, update notice, forks ---------- */

/**
 * Mark a registered DAO as dissolved. Sets `meta.lifecycle.dissolution`,
 * revokes the registration credential (if issued), and writes an audit
 * event. Dissolution is recorded; the underlying DAO documents and
 * intake credentials remain published as historical record. Production
 * deployments should require an operator + reason and a quorum of
 * lifecycle approvers; this MVP requires admin auth and a written
 * reason.
 *
 * Open question (deferred to statute): can dissolution be filer-
 * initiated, SoS-initiated, or both, and on what evidence? This stub
 * supports SoS-initiated dissolution only.
 */
app.post('/api/admin/records/:id/dissolve', requireAdminAuth, (req, res) => {
  const meta = loadMeta(req.params.id);
  if (!meta) return res.status(404).json({ error: 'not found' });
  const reviewer = String((req.body || {}).reviewer || '').trim().slice(0, 120) || 'Secretary of State reviewer';
  const reason = String((req.body || {}).reason || '').trim().slice(0, 2000);
  if (!reason) return res.status(400).json({ error: 'reason is required for dissolution' });
  const at = nowIsoNoMs();

  meta.lifecycle = meta.lifecycle || { dissolution: null, updateNotices: [] };
  meta.lifecycle.dissolution = { at, reviewer, reason };

  let revocation: any = null;
  const registrationCredential = loadCredential(req.params.id, 'registration');
  if (registrationCredential) {
    const idx = Number(registrationCredential.credentialStatus?.statusListIndex);
    if (Number.isInteger(idx) && idx >= 0) {
      revocation = revokeIndex(idx);
    }
  }

  saveMeta(req.params.id, meta);
  appendAdminAudit({
    at, registryId: req.params.id, action: 'dissolve',
    reviewer, reason, credentialRevocation: revocation,
  });
  res.json({ registryId: req.params.id, lifecycle: meta.lifecycle, credentialRevocation: revocation });
});

/**
 * Append a filer-reported notice that the DAO's smart-contract code,
 * governance, or operational state has changed. The notice is signed
 * implicitly by the registry on inclusion (the meta is part of the
 * record), but the *content* of the notice is the filer's claim and
 * is recorded as such. This is a stub: a complete implementation would
 * trigger a re-attestation flow and possibly a credential-validity
 * extension; the MVP just records.
 *
 * Open question (deferred): should code updates auto-detect via
 * on-chain bytecode polling, or rely on filer self-report? This stub
 * supports self-report only.
 */
app.post('/api/records/:id/update-notice', filingLimiter, requireFilingAuth, (req, res) => {
  const meta = loadMeta(req.params.id);
  if (!meta) return res.status(404).json({ error: 'not found' });
  const summary = String((req.body || {}).summary || '').trim().slice(0, 2000);
  const contractAddress = String((req.body || {}).contractAddress || '').trim().slice(0, 120);
  const newCodeHash = String((req.body || {}).newCodeHash || '').trim().slice(0, 200);
  if (!summary) return res.status(400).json({ error: 'summary is required' });
  const at = nowIsoNoMs();
  meta.lifecycle = meta.lifecycle || { dissolution: null, updateNotices: [] };
  meta.lifecycle.updateNotices = [
    ...meta.lifecycle.updateNotices,
    { at, summary, contractAddress: contractAddress || null, newCodeHash: newCodeHash || null },
  ];
  saveMeta(req.params.id, meta);
  res.json({ registryId: req.params.id, lifecycle: meta.lifecycle });
});

/**
 * List filings whose `forkOf` field points at this registry id. Useful
 * for showing fork provenance forward (the parent doesn't otherwise
 * know about its forks).
 */
app.get('/api/records/:id/forks', (req, res) => {
  const out = listRegistryIds()
    .map(id => ({ id, meta: loadMeta(id) }))
    .filter(({ meta }) => meta && meta.forkOf === req.params.id)
    .map(({ id, meta }) => summarizeRecord(id, meta));
  res.json({ parent: req.params.id, count: out.length, forks: out });
});

/* ---------- Bitstring Status List ---------- */

app.get('/status/registry.json', (_, res) => {
  const kp = loadOrCreateKeyPair(CONTROLLER_KEY_PATH);
  const issuer = registryDid(HOST);
  const url = `${SCHEME}://${HOST}/status/registry.json`;
  const issuedAt = nowIsoNoMs();
  const unsigned = buildStatusListCredential({
    issuerDid: issuer,
    statusListUrl: url,
    issuedAt,
    validFrom: issuedAt,
  });
  const signed = signStatusListCredential(unsigned, kp.privateKey, 'controller-1', issuedAt);
  res.type('application/vc+ld+json').json(signed);
});

app.get('/api/status/state', (_, res) => {
  const state = readStatusListState();
  res.json({
    nextIndex: state.nextIndex,
    revokedCount: state.revoked.length,
    totalBits: state.totalBits,
    lastUpdated: state.lastUpdated,
  });
});

app.post('/api/admin/credentials/:id/:kind/revoke', requireAdminAuth, (req, res) => {
  const credential = loadCredential(req.params.id, req.params.kind);
  if (!credential) return res.status(404).json({ error: 'credential not issued' });
  const indexStr = credential.credentialStatus?.statusListIndex;
  const index = Number(indexStr);
  if (!Number.isInteger(index) || index < 0) {
    return res.status(409).json({ error: 'credential has no valid statusListIndex' });
  }
  const reviewer = String((req.body || {}).reviewer || '').trim().slice(0, 120) || 'Secretary of State reviewer';
  const reason = String((req.body || {}).reason || '').trim().slice(0, 2000);
  if (!reason) return res.status(400).json({ error: 'reason is required for revocation' });
  const result = revokeIndex(index);
  appendAdminAudit({
    at: nowIsoNoMs(),
    registryId: req.params.id,
    action: 'credential-revoke',
    kind: req.params.kind,
    index,
    changed: result.changed,
    reviewer,
    reason,
  });
  res.json({ ...result, revoked: isRevoked(index) });
});

/* ---------- local IPFS gateway (fallback) ---------- */

app.get('/ipfs/:cid', (req, res) => {
  const bytes = readLocal(req.params.cid);
  if (!bytes) return res.status(404).send('not found');
  res.type('application/octet-stream').send(Buffer.from(bytes));
});

/* ---------- API ---------- */

app.get('/api/records', (req, res) => {
  const out = listRegistryIds().map(id => {
    const meta = loadMeta(id);
    return { ...summarizeRecord(id, meta), anchored: !!(meta.anchors && meta.anchors.dao) };
  });
  out.sort((a, b) => (b.filed || '').localeCompare(a.filed || ''));
  res.json({ records: out, anchorEnabled: anchorEnabled() });
});

app.get('/api/records/:id', (req, res) => {
  const r = loadRecord(req.params.id);
  if (!r) return res.status(404).json({ error: 'not found' });
  res.json(publicRecord(r));
});

/**
 * Public no-auth lookup by DAO name (case-insensitive substring) or by
 * DID (exact match). Returns an array of matching summaries; clients can
 * follow up with `/api/registry/:id/bundle` for the full payload. The
 * USPTO-TESS-style discovery endpoint web3iam.eth asked for in the
 * design discussion: any third party can resolve a DAO by name or DID
 * without an account or API key.
 */
app.get('/api/registry/lookup', (req, res) => {
  const name = typeof req.query.name === 'string' ? req.query.name.trim().toLowerCase() : '';
  const did = typeof req.query.did === 'string' ? req.query.did.trim() : '';
  if (!name && !did) return res.status(400).json({ error: 'must supply name= or did=' });

  const out = listRegistryIds()
    .map(id => ({ id, meta: loadMeta(id) }))
    .filter(({ meta }) => {
      if (!meta) return false;
      if (did) return meta.daoDid === did || meta.agentDid === did;
      const haystack = String(meta.daoName || '').toLowerCase();
      return haystack.includes(name);
    })
    .map(({ id, meta }) => ({
      ...summarizeRecord(id, meta),
      anchored: !!(meta.anchors && meta.anchors.dao),
    }));

  res.json({ count: out.length, records: out });
});

/**
 * Single-fetch bundle: everything a third party needs to verify a
 * registered DAO without making N round-trips. Returns the public
 * record projection plus the actual DAO and agent DID documents and
 * any issued credentials. Tag the response so caches treat each
 * version as immutable.
 */
app.get('/api/registry/:id/bundle', (req, res) => {
  const r = loadRecord(req.params.id);
  if (!r) return res.status(404).json({ error: 'not found' });
  const credentials: Record<string, any> = {};
  for (const k of listCredentialKinds(req.params.id)) {
    credentials[k] = loadCredential(req.params.id, k);
  }
  res.set('Cache-Control', 'public, max-age=60');
  res.json({
    public: publicRecord(r),
    daoDocument: r.dao,
    agentDocument: r.agent,
    credentials,
    statusListUrl: '/status/registry.json',
  });
});

app.get('/api/admin/balances', requireAdminAuth, async (_, res) => {
  res.json(await operationalBalances());
});

app.get('/api/admin/records', requireAdminAuth, (req, res) => {
  const wanted = req.query.status && String(req.query.status);
  if (wanted && !ADMIN_STATUSES.has(wanted)) return res.status(400).json({ error: 'unsupported review status' });
  const records = listRegistryIds().map(id => summarizeRecord(id, loadMeta(id)))
    .filter(r => !wanted || r.reviewStatus === wanted)
    .sort((a, b) => {
      const statusCompare = a.reviewStatus.localeCompare(b.reviewStatus);
      if (wanted || statusCompare === 0) return (b.filed || '').localeCompare(a.filed || '');
      return statusCompare;
    });
  res.json({ records, statuses: [...ADMIN_STATUSES] });
});

app.get('/api/admin/records/:id', requireAdminAuth, (req, res) => {
  const record = loadRecord(req.params.id);
  if (!record) return res.status(404).json({ error: 'not found' });
  record.meta.admin = ensureAdmin(record.meta);
  res.json({ ...record, audit: listAdminAudit(req.params.id) });
});

app.post('/api/admin/records/:id/:action', requireAdminAuth, async (req, res) => {
  const meta = loadMeta(req.params.id);
  if (!meta) return res.status(404).json({ error: 'not found' });
  const action = req.params.action;
  if (!ADMIN_ACTIONS.has(action) && action !== 'status') {
    return res.status(400).json({ error: 'unsupported admin action' });
  }
  try {
    const result: any = applyAdminAction(req.params.id, meta, action, req.body || {});
    if (action === 'approve') {
      const issued = await issueApprovedRegistration(req.params.id, {
        host: HOST, scheme: SCHEME, controllerKeyPath: CONTROLLER_KEY_PATH,
      }, {
        reviewer: result.event.reviewer,
        reason: result.event.reason,
      });
      result.meta = issued.meta;
      result.dao = issued.dao;
      result.agent = issued.agent;
      result.warnings = issued.warnings;
    }
    res.json(result);
  } catch (e) {
    res.status(e.statusCode || 500).json({ error: e.message });
  }
});

app.post('/api/file', filingLimiter, requireFilingAuth, async (req, res) => {
  try {
    const result = await runFiling(req.body || {}, {
      host: HOST, scheme: SCHEME, controllerKeyPath: CONTROLLER_KEY_PATH,
    });
    res.json(result);
  } catch (e) {
    if (e.statusCode === 400) {
      return res.status(400).json({ error: e.message, details: e.details });
    }
    // eslint-disable-next-line no-console
    console.error(e);
    res.status(500).json({ error: 'filing failed' });
  }
});

app.get('/api/verify/:id', verifyLimiter, async (req, res) => {
  try {
    const report = await verifyDao(req.params.id, { host: HOST, scheme: SCHEME });
    res.json(report);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'verification failed' });
  }
});

/* ---------- routes that serve the SPA-ish HTML ---------- */

app.get('/', (_, res) => res.sendFile(path.join(PUBLIC_DIR, 'index.html')));
app.get('/inspect', (_, res) => res.sendFile(path.join(PUBLIC_DIR, 'inspect.html')));
app.get('/admin', (_, res) => res.sendFile(path.join(PUBLIC_DIR, 'admin.html')));

if (!IS_TEST) {
  const productionIssues = productionConfigIssues();
  if (productionIssues.length) {
    // eslint-disable-next-line no-console
    console.error(`Refusing to start with unsafe production config: ${productionIssues.join('; ')}`);
    process.exit(1);
  }
  app.listen(PORT, () => {
    // eslint-disable-next-line no-console
    console.log(`NH DAO Registry MVP listening on ${SCHEME}://${HOST} (port ${PORT})`);
    // eslint-disable-next-line no-console
    console.log(`Registry DID: ${registryDid(HOST)}`);
    // eslint-disable-next-line no-console
    console.log(`Anchor: ${anchorEnabled() ? 'enabled (Polygon Amoy)' : 'disabled (set AMOY_RPC_URL, ANCHOR_CONTRACT_ADDRESS, ANCHOR_PRIVATE_KEY in .env)'}`);
    // eslint-disable-next-line no-console
    console.log(`Filing auth: ${FILING_API_KEY ? 'enabled (Bearer token required)' : 'DISABLED — set FILING_API_KEY before exposing this server'}`);
  });
}

export { app };
