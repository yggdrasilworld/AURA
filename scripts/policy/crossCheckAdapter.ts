import fs from 'fs';
import path from 'path';

export type CrossCheckRequirement = {
  id: string;
  title: string;
  description?: string;
  type: 'boolean' | 'enum' | 'number' | 'string' | 'datetime';
  required?: boolean;
  severity?: 'hard' | 'soft' | 'info';
  options?: string[];
  threshold?: { operator: string; value: number };
  evidence_weight?: number;
  enforcement?: { actionOnFail?: 'veto' | 'require_manual_review' | 'mark_pending' };
};

export type CrossCheckRunResult = {
  id: string;
  verifier: string;
  result: any;
  ok: boolean;
  weight_applied: number;
  ts: string;
  notes?: string;
};

export type EvaluationSummary = {
  auditEntries: CrossCheckRunResult[];
  total_weight: number;
  failed_requirements: string[];
  decisionHints: { veto: boolean; require_manual_review: boolean; pending: boolean };
};

// ── bounty-scope helpers ──────────────────────────────────────────────────
// Cached offline snapshot — resolved relative to this module first, then the
// working directory, so callers outside the repo root still find it. A failed
// load is NOT permanently cached: a later call retries the read.
let _bountySnapshotCache: any[] | null = null;
function loadBountySnapshot(): any[] {
  if (_bountySnapshotCache !== null) return _bountySnapshotCache as any[];
  const candidates = [
    path.resolve(__dirname, '..', '..', 'config', 'snapshots', 'bounty-programs.json'),
    path.resolve(process.cwd(), 'config', 'snapshots', 'bounty-programs.json'),
  ];
  for (const p of candidates) {
    try {
      const raw = fs.readFileSync(p, 'utf8');
      const d = JSON.parse(raw);
      const progs = Array.isArray(d && d.programs) ? d.programs : (Array.isArray(d) ? d : []);
      if (progs.length) { _bountySnapshotCache = progs; return progs; }
    } catch { /* try the next candidate location */ }
  }
  return [];  // deliberately not cached — a later call retries
}

// Keys that are routing/category metadata, NOT a target or program — so a
// case's top-level `domain` (a routing field in the schema) is never read as
// the bounty target.
const ROUTING_ONLY_KEYS = new Set(['domain', 'category', 'type', 'id']);

// Pull a field out of a case. Searches top-level, meta, then each params
// object IN TURN for a nonempty requested key — an empty `params` must not
// shadow a populated `requirement_parameters`.
function extractField(caseObj: any, keys: string[]): string {
  if (!caseObj || typeof caseObj !== 'object') return '';
  const wanted = keys.filter(k => !ROUTING_ONLY_KEYS.has(k));
  const sources = [
    caseObj,
    (caseObj as any).meta,
    (caseObj as any).params,
    (caseObj as any).requirement_parameters,
  ];
  for (const src of sources) {
    if (!src || typeof src !== 'object') continue;
    for (const k of wanted) {
      const v = (src as any)[k];
      if (v !== undefined && v !== null && v !== '') return String(v);
    }
  }
  return '';
}

// A strict dotted-quad IPv4 address — rejects trailing junk and out-of-range
// octets (so '10.1.2.3junk' or '999.1.1.1' never pass a CIDR check).
const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
function isIPv4(s: string): boolean {
  const m = IPV4_RE.exec(String(s).trim());
  if (!m) return false;
  for (let i = 1; i <= 4; i++) {
    const o = parseInt(m[i], 10);
    if (isNaN(o) || o < 0 || o > 255) return false;
  }
  return true;
}

// Whether a target domain/IP falls inside a scope entry.
//  - CIDR entry: strict IPv4 containment — malformed input fails closed
//  - wildcard '*.example.com': the apex + subdomains
//  - exact 'example.com': the exact hostname ONLY — no implicit subdomains
function domainInScope(target: string, scope: string): boolean {
  const t = String(target || '').trim().toLowerCase();
  const s = String(scope || '').trim().toLowerCase();
  if (!t || !s) return false;
  if (s.includes('/')) return cidrMatch(t, s);
  if (s.startsWith('*.')) {
    const apex = s.slice(2);
    return t === apex || t.endsWith('.' + apex);
  }
  return t === s;
}

// Minimal IPv4 CIDR containment — '10.0.0.0/8' covers '10.1.2.3'. Both sides
// must be valid dotted-quad; a malformed IP fails closed rather than matching.
function cidrMatch(ip: string, cidr: string): boolean {
  if (!isIPv4(ip)) return false;
  const [base, bitsStr] = cidr.split('/');
  if (!isIPv4(base)) return false;
  const bits = parseInt(bitsStr, 10);
  if (isNaN(bits) || bits < 0 || bits > 32) return false;
  const toInt = (a: string) => a.split('.').reduce((acc, o) => (acc << 8) + parseInt(o, 10), 0) >>> 0;
  const ipInt = toInt(ip);
  const baseInt = toInt(base);
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (ipInt & mask) === (baseInt & mask);
}

// ── pgp-verify helpers ──────────────────────────────────────────────────
// Static trusted-key allow-list — loaded once per process from the reviewed
// config/trusted-keys/ dir + manifest.json. Zero-trust: keys are committed
// explicitly, never fetched. Resolved relative to this module (not cwd).
let _trustedKeysCache: any[] | null = null;
function loadTrustedKeys(): any[] {
  if (_trustedKeysCache !== null) return _trustedKeysCache as any[];
  const base = path.resolve(__dirname, '..', '..', 'config', 'trusted-keys');
  const out: any[] = [];
  try {
    const manifest = JSON.parse(fs.readFileSync(path.join(base, 'manifest.json'), 'utf8'));
    for (const k of (manifest.keys || [])) {
      try {
        const armored = fs.readFileSync(path.join(base, String(k.file || '')), 'utf8');
        out.push({ ...k, armored });
      } catch { /* skip unreadable key files */ }
    }
  } catch { /* manifest missing/malformed */ }
  if (out.length) _trustedKeysCache = out;
  return out;  // not permanently cached on failure — a later call retries
}

// Cryptographically verify a detached or cleartext PGP signature against the
// trusted allow-list. openpgp is a peer dep — require lazily so the module
// loads even where openpgp isn't installed.
let _openpgp: any = null;
function getOpenPGP(): any {
  if (_openpgp) return _openpgp;
  try { _openpgp = require('openpgp'); } catch { _openpgp = null; }
  return _openpgp;
}

// Whether an armored block is a cleartext-signed message vs a detached signature.
function isCleartext(sig: string): boolean {
  return /BEGIN PGP SIGNED MESSAGE/.test(sig);
}

// Match a signature's key id / fingerprint against the trusted list — the
// signer must be an approved key, not just any well-formed signature.
function fingerprintOf(hexKeyId: string): string {
  return String(hexKeyId || '').replace(/\s+/g, '').toUpperCase();
}

async function verifyPGP(message: string, signature: string, trusted: any[]): Promise<{ result: any; ok: boolean; notes: string }> {
  const op = getOpenPGP();
  if (!op) return { result: null, ok: false, notes: 'openpgp unavailable — cannot verify' };
  try {
    // Parse the signature — detached armored sig or a cleartext-signed message.
    let sigObj: any, msgText = message;
    if (isCleartext(signature)) {
      const cleartext = await op.readCleartextMessage({ cleartextMessage: signature });
      sigObj = cleartext;
      msgText = cleartext.getText();  // the embedded message is authoritative
    } else {
      sigObj = await op.readSignature({ armoredSignature: signature });
    }
    // Load the trusted public keys.
    const pubkeys: any[] = [];
    for (const k of trusted) {
      try {
        const pk = await op.readKey({ armoredKey: k.armored });
        pubkeys.push({ pk, meta: k });
      } catch { /* skip unparseable keys */ }
    }
    if (!pubkeys.length) return { result: null, ok: false, notes: 'no usable trusted keys' };

    // Identify the signing key from the signature packets — getSigningKeyIDs
    // gives the issuerKeyID the signer claims. Match it against the allow-list
    // FIRST so an untrusted signer is reported as untrusted, not as 'forged'.
    let signerKeyIds: string[] = [];
    try {
      const ids = (sigObj.getSigningKeyIDs && sigObj.getSigningKeyIDs()) || [];
      signerKeyIds = ids.map((id: any) => fingerprintOf(id.toHex ? id.toHex() : id));
    } catch { /* no signing-key-id readable */ }
    const signerEntry = pubkeys.find((p: any) => {
      const fp = fingerprintOf((p.pk.getFingerprint && p.pk.getFingerprint()) || p.meta.fingerprint || '');
      return signerKeyIds.some((id: string) => fp === id || fp.endsWith(id) || id.endsWith(fp));
    });
    if (signerKeyIds.length && !signerEntry) {
      return { result: { key_id: signerKeyIds[0] }, ok: false, notes: `signature key '${signerKeyIds[0]}' is not in the trusted allow-list` };
    }
    // Reject an EXPIRED trusted key — a lapsed allow-list entry must fail
    // closed, not silently keep verifying.
    if (signerEntry) {
      try {
        const exp = await signerEntry.pk.getExpirationTime();
        if (exp && exp instanceof Date && exp.getTime() < Date.now()) {
          return { result: { key_id: signerKeyIds[0] || '', fingerprint: fingerprintOf(signerEntry.pk.getFingerprint()) }, ok: false, notes: `trusted signer key expired (${exp.toISOString().slice(0,10)})` };
        }
      } catch { /* no expiry info — treated as non-expiring */ }
    }

    // Verify the signature against the trusted keys. For a cleartext-signed
    // input the message IS the signed object — the signature is embedded, so
    // no separate `signature` param. For detached, pass the parsed signature.
    const verifyArgs: any = {
      message: isCleartext(signature) ? sigObj : await op.createMessage({ text: msgText }),
      verificationKeys: pubkeys.map((p: any) => p.pk),
    };
    if (!isCleartext(signature)) verifyArgs.signature = sigObj;
    const verification = await op.verify(verifyArgs);
    const sigs = (verification && verification.signatures) ? verification.signatures : [];
    if (!sigs.length) return { result: null, ok: false, notes: 'no verifiable signatures on the message' };
    for (const s of sigs) {
      try {
        const valid = await s.verified;
        if (valid && signerEntry) {
          return {
            result: {
              key_id: signerKeyIds[0] || '',
              fingerprint: fingerprintOf(signerEntry.pk.getFingerprint()),
              signer_identity: signerEntry.meta.signer_identity || '',
              verification_status: 'verified',
            },
            ok: true,
            notes: `signature verified — trusted signer ${signerEntry.meta.signer_identity || signerKeyIds[0]}`,
          };
        }
        if (valid && !signerEntry) {
          return { result: null, ok: false, notes: 'signature verified cryptographically but the signing key is not in the trusted allow-list' };
        }
      } catch { /* this sub-sig failed to evaluate */ }
    }
    return { result: { key_id: signerKeyIds[0] || null }, ok: false, notes: 'signature failed cryptographic verification (forged or corrupted)' };
  } catch (err) {
    const msg = (err as any && (err as any).message) ? (err as any).message : String(err);
    return { result: null, ok: false, notes: `verification failed: ${msg}` };
  }
}

// Minimal class-based adapter manager. Adapters can be registered via
// `registerAdapter(name, fn)` where fn(req, caseObj) => Promise<{result, ok, notes}>.
/**
 * CrossCheckAdapter
 * Класс-менеджер адаптеров для выполнения машинно-читаемых cross-check требований.
 * Методы:
 * - registerAdapter(name, fn): регистрирует адаптер (fn возвращает Promise<{result, ok, notes}>)
 * - validateRequirementSchema(req): базовая валидация объекта требования
 * - runAdaptersForCase(caseObj, requirements, adaptersConfig): запускает адаптеры и возвращает массив аудита
 * - evaluateCrossChecks(caseObj, requirements, adaptersConfig): сводит результаты, считает `total_weight` и `decisionHints`
 *
 * По умолчанию регистрируется адаптер `noop`, чтобы поведение было обратносовместимым при отсутствии конфигурации.
 */
export class CrossCheckAdapter {
  private adapters: Map<string, Function> = new Map();

  constructor() {
    // register noop adapter by default
    this.registerAdapter('noop', async (_req: CrossCheckRequirement, _caseObj: any) => ({ result: null, ok: false, notes: 'noop' }));
    // register simple mock adapters useful for testing and initial integration
    this.registerAdapter('ip-geolocate', async (req: CrossCheckRequirement, caseObj: any) => {
      // Support both quick mocks (caseObj.mock_ip_geo) and structured meta.ip_country matching
      const quickOk = !!(caseObj && (caseObj as any).mock_ip_geo === true);
      if (quickOk) return { result: true, ok: true, notes: 'ip geolocation matched (mock quick)' };
      const ipCountry = caseObj && caseObj.meta && caseObj.meta.ip_country ? String(caseObj.meta.ip_country) : null;
      const expected = req && Array.isArray(req.options) && req.options.length ? String(req.options[0]) : null;
      if (expected && ipCountry && expected.toLowerCase() === ipCountry.toLowerCase()) return { result: ipCountry, ok: true, notes: 'ip matched (meta)' };
      return { result: ipCountry, ok: false, notes: 'ip mismatch or missing' };
    });

    // register an email verification adapter supporting quick mock and meta field
    this.registerAdapter('email-verify', async (_req: CrossCheckRequirement, caseObj: any) => {
      const quickOk = !!(caseObj && (caseObj as any).mock_email_verified === true);
      if (quickOk) return { result: true, ok: true, notes: 'email verified (mock quick)' };
      const verified = caseObj && caseObj.meta && !!caseObj.meta.email_verified;
      return { result: !!verified, ok: !!verified, notes: verified ? 'email verified (meta)' : 'email unverified' };
    });

    // register the offline bounty-scope adapter — verifies a case-claimed bug
    // bounty program + target domain/IP against the curated offline snapshot in
    // config/snapshots/bounty-programs.json. Works 100% offline.
    this.registerAdapter('bounty-scope', async (_req: CrossCheckRequirement, caseObj: any) => {
      const quickOk = !!(caseObj && (caseObj as any).mock_bounty_scope === true);
      if (quickOk) return { result: true, ok: true, notes: 'bounty scope matched (mock quick)' };
      const programId = extractField(caseObj, ['bounty_program_id', 'program_id', 'bounty_program', 'program']);
      const target = extractField(caseObj, ['target_domain', 'target', 'target_ip', 'host']);
      const snapshot = loadBountySnapshot();
      if (!snapshot.length) return { result: null, ok: false, notes: 'bounty snapshot unavailable or empty' };
      // Match on the program_id ONLY — never the platform label, so a case
      // claiming 'hackerone' can't resolve to an arbitrary HackerOne program.
      const program = snapshot.find((p: any) =>
        String(p.program_id || '').toLowerCase() === String(programId || '').toLowerCase()
      );
      if (!program) return { result: { program_id: programId }, ok: false, notes: `program '${programId}' not found in offline bounty snapshot` };
      const status = String(program.status || '').toLowerCase();
      if (status !== 'active') return { result: { program_id: programId, status }, ok: false, notes: `program '${programId}' is not active (status: ${status})` };
      // A missing target is NOT a pass — the claim asserted program coverage
      // but there's no target to verify against scope, so it can't be
      // confirmed. Return not-ok rather than granting unverified evidence weight.
      if (!target) return { result: { program_id: programId }, ok: false, notes: `program '${programId}' is active but no target supplied — scope coverage unverified` };
      const scopes = Array.isArray(program.in_scope_domains) ? program.in_scope_domains : [];
      const inScope = scopes.some((s: string) => domainInScope(target, String(s)));
      if (!inScope) return { result: { program_id: programId, target }, ok: false, notes: `target '${target}' out of scope for program '${programId}'` };
      return { result: { program_id: program.program_id, platform: program.platform, target }, ok: true, notes: `program '${program.program_id}' active and target '${target}' in scope` };
    });

    // register the PGP-verification adapter — cryptographically verifies a
    // detached or cleartext signature against the STATIC trusted-key allow-list
    // in config/trusted-keys/. Zero-trust: no TOFU, no keyserver fetches —
    // only reviewed, committed keys. Fails closed on unknown/forged/expired.
    this.registerAdapter('pgp-verify', async (_req: CrossCheckRequirement, caseObj: any) => {
      // 'signed_message' etc. are explicit — bare 'message' is excluded because
      // a case's top-level message field is the case description, not the
      // signed text (same collision class as the routing-field bug).
      const message = extractField(caseObj, ['signed_message', 'signed_text', 'message_text', 'plaintext', 'signed_body']);
      const signature = extractField(caseObj, ['signature', 'detached_signature', 'pgp_signature', 'sig']);
      if (!message) return { result: null, ok: false, notes: 'no signed message supplied' };
      if (!signature) return { result: null, ok: false, notes: 'no signature supplied' };
      const trusted = loadTrustedKeys();
      if (!trusted.length) return { result: null, ok: false, notes: 'trusted-key allow-list unavailable or empty' };
      try {
        const res = await verifyPGP(message, signature, trusted);
        return res;
      } catch (err) {
        const msg = (err as any && (err as any).message) ? (err as any).message : String(err);
        return { result: null, ok: false, notes: `verification error: ${msg}` };
      }
    });
  }

  // Register a new adapter function by name. The function should accept a requirement and a case object, and return a Promise resolving to {result, ok, notes}.
  registerAdapter(name: string, fn: Function) {
    this.adapters.set(name, fn);
  }

  // Validate the schema of a cross-check requirement object. Throws an error if the requirement is invalid.
  validateRequirementSchema(req: any) {
    if (!req || typeof req !== 'object') throw new Error('requirement must be object');
    if (!req.id || !req.title || !req.type) throw new Error('requirement missing id/title/type');
  }

  // Run all registered adapters for a given case and set of requirements. Returns an array of audit results.
  async runAdaptersForCase(caseObj: any, requirements: CrossCheckRequirement[], adaptersConfig?: any): Promise<CrossCheckRunResult[]> {
    const out: CrossCheckRunResult[] = [];
    for (const r of requirements) {
      try {
        this.validateRequirementSchema(r);
      } catch (err) {
        const msg = (err as any && (err as any).message) ? (err as any).message : String(err);
        out.push({ id: r.id || '<no-id>', verifier: 'system', result: null, ok: false, weight_applied: 0, ts: new Date().toISOString(), notes: msg });
        continue;
      }
      // choose adapter by convention: adaptersConfig may map requirement id to adapter name
      const adapterName = adaptersConfig && adaptersConfig[r.id] ? String(adaptersConfig[r.id]) : 'noop';
      const adapterFn = this.adapters.get(adapterName) || this.adapters.get('noop');
      let res: any = { result: null, ok: false, notes: 'no adapter' };
      try {
        res = await (adapterFn as any)(r, caseObj);
      } catch (err) {
        const msg = (err as any && (err as any).message) ? (err as any).message : String(err);
        res = { result: null, ok: false, notes: msg };
      }
      const weight = (typeof r.evidence_weight === 'number' && res.ok) ? Number(r.evidence_weight) : 0;
      out.push({ id: r.id, verifier: `adapter:${adapterName}`, result: res.result, ok: !!res.ok, weight_applied: weight, ts: new Date().toISOString(), notes: res.notes });
    }
    return out;
  }

  // Evaluate the cross-checks for a given case. Returns a summary including total weight, failed requirements, and decision hints.
  async evaluateCrossChecks(caseObj: any, requirements: CrossCheckRequirement[], adaptersConfig?: any): Promise<EvaluationSummary> {
    const auditEntries = await this.runAdaptersForCase(caseObj, requirements || [], adaptersConfig);
    let total = 0;
    const failed: string[] = [];
    const hints = { veto: false, require_manual_review: false, pending: false };
    for (let i = 0; i < auditEntries.length; i++) {
      const a = auditEntries[i];
      total += (typeof a.weight_applied === 'number') ? a.weight_applied : 0;
      if (!a.ok) failed.push(a.id);
    }
    // derive hints from requirements enforcement if failures exist
    for (const r of requirements || []) {
      if (!r.enforcement) continue;
      if (!r.required && (!r.evidence_weight || r.evidence_weight === 0)) continue;
      const found = auditEntries.find(x => x.id === r.id);
      if (found && !found.ok) {
        const a = r.enforcement.actionOnFail;
        if (a === 'veto') hints.veto = true;
        if (a === 'require_manual_review') hints.require_manual_review = true;
        if (a === 'mark_pending') hints.pending = true;
      }
    }
    return { auditEntries, total_weight: Math.round(total * 100) / 100, failed_requirements: failed, decisionHints: hints };
  }
}

// Export default instance for quick use
const defaultAdapter = new CrossCheckAdapter();
export default defaultAdapter;
