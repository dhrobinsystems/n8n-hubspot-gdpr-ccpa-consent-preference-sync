'use strict';

/**
 * consent.test.js
 *
 * Run with: npm test   (node --test, zero dependencies)
 *
 *   1. Config fail-safe defaults, placeholders, and gates
 *   2. Signature verification
 *   3. Mapping validation
 *   4. Provider normalization (custom, OneTrust, Cookiebot, Osano shapes)
 *   5. Jurisdiction resolution
 *   6. Compliance plan rules (GDPR opt-in, CCPA opt-out, GPC, restriction, safety invariants)
 *   7. Engine end-to-end: dry run, sandbox writes, ordering, conflicts, server
 *   8. workflow.json validation and Code-node parity
 *   9. Repository security scan
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const crypto = require('node:crypto');

const ROOT = path.resolve(__dirname, '..');
const config = require('../src/config');
const c = require('../src/consent');
const engine = require('../src/index');
const builder = require('../scripts/build-workflow');
const validator = require('../scripts/validate-workflow');

const FIXTURE = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', 'consent-events.mock.json'), 'utf8'));
const MAPPING = JSON.parse(fs.readFileSync(path.join(ROOT, 'config', 'consent-mapping.example.json'), 'utf8'));
const NOW = new Date(FIXTURE._meta.reference_now);
const SECRET = 'mock_signing_secret_for_tests';
const N = builder.NODES;

function plain(v) { return JSON.parse(JSON.stringify(v)); }
function cfgFrom(env) { return config.parseConfig(env || {}); }
function mappingWithIds() {
  const m = plain(MAPPING);
  m.subscriptions.marketing_subscription_ids = ['1001', '1002'];
  return m;
}
function hmac(secret, data) { return crypto.createHmac('sha256', secret).update(data).digest('hex'); }
function signedHeaders(raw, atMs) {
  const ts = String(Math.floor((atMs || NOW.getTime()) / 1000));
  return { 'x-consent-timestamp': ts, 'x-consent-signature': 'sha256=' + hmac(SECRET, ts + '.' + raw) };
}
function body(i) { return plain(FIXTURE.events[i].body); }
function normalized(i, mapping) {
  const out = c.normalizeConsentEvent(body(i), mapping || MAPPING, NOW.getTime());
  assert.equal(out.ok, true, JSON.stringify(out.errors));
  return out.event;
}
function contactFor(email) {
  const hit = FIXTURE.mock_responses.contacts[email];
  return hit ? { ok: true, found: true, contactId: hit.id, properties: plain(hit.properties) } : { ok: true, found: false, contactId: null, properties: {} };
}
function planFor(i, opts) {
  const o = opts || {};
  const mapping = o.mapping || MAPPING;
  const event = normalized(i, mapping);
  return c.buildConsentPlan({ event: event, mapping: mapping, config: o.config || cfgFrom(), contact: o.contact || contactFor(event.email) });
}

// ---------------------------------------------------------------------------
// 1. Config
// ---------------------------------------------------------------------------

test('config: defaults are dry run, sandbox, and signature required', function () {
  const cfg = cfgFrom({});
  assert.deepEqual([cfg.dryRun, cfg.sandboxMode, cfg.writeMode, cfg.writesEnabled, cfg.requireSignature, cfg.createMissingContacts, cfg.reviewTicket], [true, true, 'dry_run', false, true, false, null]);
});

test('config: your_..._here placeholders behave exactly like blank values', function () {
  const cfg = cfgFrom({ DRY_RUN: 'your_dry_run_flag_here', TARGET_PIPELINE_ID: 'your_hubspot_ticket_pipeline_id_here', TARGET_PIPELINE_STAGE_ID: 'your_hubspot_ticket_stage_id_here', HUBSPOT_SANDBOX_PORTAL_ID: 'your_hubspot_sandbox_portal_id_here' });
  assert.deepEqual([cfg.dryRun, cfg.reviewTicket, cfg.sandboxPortalId], [true, null, null]);
  assert.equal(config.cfgUnset('your_hubspot_private_app_token_here'), true);
});

test('config: only the literal string "false" disables a safety flag', function () {
  ['0', 'no', 'off', 'flase'].forEach(function (v) { assert.equal(cfgFrom({ DRY_RUN: v }).dryRun, true, v); });
  assert.equal(cfgFrom({ DRY_RUN: 'False' }).writeMode, 'sandbox');
});

test('config: production needs ALLOW_PRODUCTION_MODE; pipeline and stage go together', function () {
  assert.throws(function () { cfgFrom({ SANDBOX_MODE: 'false' }); }, /ALLOW_PRODUCTION_MODE/);
  assert.equal(cfgFrom({ SANDBOX_MODE: 'false', ALLOW_PRODUCTION_MODE: 'true', DRY_RUN: 'false' }).writeMode, 'production');
  assert.throws(function () { cfgFrom({ TARGET_PIPELINE_ID: '0' }); }, /set together/);
  assert.deepEqual(cfgFrom({ TARGET_PIPELINE_ID: '0', TARGET_PIPELINE_STAGE_ID: '1' }).reviewTicket, { pipelineId: '0', stageId: '1' });
  assert.throws(function () { cfgFrom({ HUBSPOT_BASE_URL: 'http://api.example.com' }); }, /https/);
});

test('config: loadConfig requires a real signing secret and redacts secrets', function () {
  assert.throws(function () { config.loadConfig({ WEBHOOK_SIGNING_SECRET: 'your_webhook_signing_secret_here' }); }, /WEBHOOK_SIGNING_SECRET/);
  const cfg = config.loadConfig({ WEBHOOK_SIGNING_SECRET: SECRET, HUBSPOT_PRIVATE_APP_TOKEN: 'mock_token_here' });
  assert.equal(config.describeConfig(cfg).hubspotPrivateAppToken, '[redacted]');
  assert.equal(config.describeConfig(cfg).webhookSigningSecret, '[redacted]');
});

test('config: HubSpot gate allows only sandbox or developer test portals in sandbox mode', function () {
  assert.equal(config.evaluateHubSpotTarget(cfgFrom(), { accountType: 'STANDARD' }).allowed, false);
  assert.equal(config.evaluateHubSpotTarget(cfgFrom(), { accountType: 'SANDBOX', portalId: 1001 }).allowed, true);
});

// ---------------------------------------------------------------------------
// 2. Signature
// ---------------------------------------------------------------------------

test('signature: valid HMACs pass; tampering, replay, malformed headers, and placeholder secrets fail', function () {
  const raw = JSON.stringify(body(0));
  const h = signedHeaders(raw);
  const now = NOW.getTime();
  assert.equal(c.verifySignature(raw, h['x-consent-signature'], h['x-consent-timestamp'], SECRET, now, 300, hmac).ok, true);
  assert.equal(c.verifySignature(raw + ' ', h['x-consent-signature'], h['x-consent-timestamp'], SECRET, now, 300, hmac).reason, 'signature_mismatch');
  const old = signedHeaders(raw, now - 3600000);
  assert.equal(c.verifySignature(raw, old['x-consent-signature'], old['x-consent-timestamp'], SECRET, now, 300, hmac).reason, 'signature_timestamp_outside_tolerance');
  assert.equal(c.verifySignature(raw, 'sha256=xyz', '1', SECRET, now, 300, hmac).reason, 'signature_headers_malformed');
  assert.equal(c.verifySignature(raw, null, null, SECRET, now, 300, hmac).reason, 'signature_headers_missing');
  assert.equal(c.verifySignature(raw, h['x-consent-signature'], h['x-consent-timestamp'], 'your_webhook_signing_secret_here', now, 300, hmac).reason, 'signing_secret_not_configured');
});

// ---------------------------------------------------------------------------
// 3. Mapping validation
// ---------------------------------------------------------------------------

test('mapping: the example mapping is valid and flags its placeholder subscription ID', function () {
  const out = c.validateMapping(MAPPING);
  assert.deepEqual(out.errors, []);
  assert.equal(out.warnings.length, 1);
  assert.match(out.warnings[0], /placeholder/);
  assert.deepEqual(c.validateMapping(mappingWithIds()).warnings, []);
});

test('mapping: invalid mappings are rejected with specific errors', function () {
  const bad = plain(MAPPING);
  bad.jurisdictions.GDPR.model = 'opt_out';
  bad.hubspot_properties.analytics = 'Consent Analytics';
  bad.hubspot_properties.functional = bad.hubspot_properties.marketing;
  bad.providers.osano.denied_values.push('ACCEPT');
  bad.providers.onetrust.categories.aliases.C0009 = 'advertising';
  bad.subscriptions.legal_basis = 'BECAUSE';
  bad.rules.honor_gpc_as_do_not_sell = 'yes';
  delete bad.jurisdictions.OTHER;
  const errors = c.validateMapping(bad).errors;
  ['GDPR.model must be opt_in', 'hubspot_properties.analytics', 'reuses property', 'both granted and denied', 'unknown category "advertising"', 'legal_basis', 'rules.honor_gpc_as_do_not_sell', 'jurisdictions.OTHER'].forEach(function (msg) {
    assert.ok(errors.some(function (e) { return e.indexOf(msg) !== -1; }), msg + ' in ' + JSON.stringify(errors));
  });
});

// ---------------------------------------------------------------------------
// 4. Normalization
// ---------------------------------------------------------------------------

test('normalize: custom banner payloads map directly to canonical categories', function () {
  const e = normalized(0);
  assert.deepEqual([e.provider, e.email, e.country, e.receiptId, e.policyVersion], ['custom', 'anna.example@example.org', 'DE', 'rcpt_evt_1001', '2026-10']);
  assert.deepEqual(e.categories, { necessary: true, functional: false, analytics: false, marketing: false, sale_sharing: null });
  assert.match(e.emailHash, /^h_[0-9a-f]{16}$/);
});

test('normalize: OneTrust-style purpose arrays, where any denial in a category wins', function () {
  const e = normalized(1);
  assert.deepEqual(e.categories, { necessary: true, functional: true, analytics: true, marketing: false, sale_sharing: null }, 'C0004 WITHDRAWN beats C0005 CONFIRMED');
  assert.deepEqual([e.country, e.receiptId, e.policyVersion], ['FR', 'rcpt_ot_2002', 'v7']);
});

test('normalize: Cookiebot-style booleans, ignored keys, and epoch-millisecond timestamps', function () {
  const out = c.normalizeConsentEvent(body(2), MAPPING, NOW.getTime());
  assert.deepEqual(out.event.categories, { necessary: true, functional: true, analytics: true, marketing: true, sale_sharing: null });
  assert.deepEqual(out.warnings, [], '"method" is listed in ignore_keys');
  assert.equal(out.event.country, 'DE', 'country codes are uppercased');
  assert.equal(out.event.occurredAt, new Date(1794672000000).toISOString());
});

test('normalize: Osano-style OPT_OUT ACCEPT inverts to sale_sharing = false, and GPC is captured', function () {
  const e = normalized(3);
  assert.deepEqual(e.categories, { necessary: true, functional: true, analytics: true, marketing: true, sale_sharing: false });
  assert.deepEqual([e.region, e.signals.gpc], ['CA', true]);
});

test('normalize: invalid events and unknown values are rejected or flagged', function () {
  assert.deepEqual(c.normalizeConsentEvent(body(9), MAPPING, NOW.getTime()).errors, ['email_missing_or_invalid']);
  assert.deepEqual(c.normalizeConsentEvent(body(10), MAPPING, NOW.getTime()).errors, ['unknown_provider:some_other_cmp']);
  const future = body(0);
  future.occurred_at = '2027-01-01T00:00:00Z';
  assert.deepEqual(c.normalizeConsentEvent(future, MAPPING, NOW.getTime()).errors, ['occurred_at_in_future']);
  const odd = body(0);
  odd.consents.analytics = 'maybe';
  odd.consents.advertising = true;
  const out = c.normalizeConsentEvent(odd, MAPPING, NOW.getTime());
  assert.deepEqual(out.warnings.sort(), ['unmapped_category:advertising', 'unrecognized_value_for:analytics']);
  assert.equal(out.event.categories.analytics, null);
  const noCats = body(0);
  delete noCats.consents;
  assert.deepEqual(c.normalizeConsentEvent(noCats, MAPPING, NOW.getTime()).errors, ['consent_categories_missing']);
});

// ---------------------------------------------------------------------------
// 5. Jurisdiction
// ---------------------------------------------------------------------------

test('jurisdiction: EU/EEA/UK are GDPR opt-in; California is CCPA opt-out; others fall back', function () {
  const r = function (cc, region) { return c.resolveJurisdiction(cc, region, MAPPING); };
  assert.deepEqual(r('DE', null), { code: 'GDPR', model: 'opt_in' });
  assert.deepEqual(r('GB', null), { code: 'GDPR', model: 'opt_in' });
  assert.deepEqual(r('NO', null), { code: 'GDPR', model: 'opt_in' });
  assert.deepEqual(r('US', 'CA'), { code: 'CCPA', model: 'opt_out' });
  assert.deepEqual(r('US', 'CO'), { code: 'US_STATE_PRIVACY', model: 'opt_out' });
  assert.deepEqual(r('US', 'NY'), { code: 'OTHER', model: 'opt_in' });
  assert.deepEqual(r(null, null), { code: 'OTHER', model: 'opt_in' });
});

// ---------------------------------------------------------------------------
// 6. Compliance plan
// ---------------------------------------------------------------------------

test('plan: GDPR full withdrawal unsubscribes marketing types and all email', function () {
  const p = planFor(0, { mapping: mappingWithIds() });
  assert.equal(p.action, 'update');
  assert.deepEqual(p.effective, { necessary: true, functional: false, analytics: false, marketing: false, sale_sharing: false });
  assert.equal(p.fullWithdrawal, true);
  assert.equal(p.globalUnsubscribe, true);
  assert.deepEqual(p.subscriptionChanges.inputs.map(function (i) { return [i.subscriberIdString, i.channel, i.statusState, i.subscriptionId, i.legalBasis]; }), [
    ['anna.example@example.org', 'EMAIL', 'NOT_SUBSCRIBED', 1001, 'CONSENT_WITH_NOTICE'],
    ['anna.example@example.org', 'EMAIL', 'NOT_SUBSCRIBED', 1002, 'CONSENT_WITH_NOTICE']
  ]);
  assert.equal(p.decisions.sale_sharing, 'not_reported_opt_in_treated_as_denied');
  assert.equal(p.properties.consent_marketing, 'false');
  assert.equal(p.properties.ccpa_do_not_sell_or_share, 'true');
  assert.equal(p.properties.privacy_jurisdiction, 'GDPR');
});

test('plan: a missing subscription type ID is warned about, never guessed', function () {
  const p = planFor(1);
  assert.equal(p.subscriptionChanges, null);
  assert.ok(p.warnings.includes('marketing_denied_but_no_subscription_type_ids_configured'));
  assert.equal(p.globalUnsubscribe, false, 'partial withdrawal is not a global unsubscribe');
});

test('plan: granting marketing consent never subscribes anyone', function () {
  const p = planFor(2, { mapping: mappingWithIds() });
  assert.equal(p.subscriptionChanges, null);
  assert.equal(p.globalUnsubscribe, false);
  assert.ok(p.warnings.includes('opt_in_recorded_only_this_pipeline_never_subscribes_contacts'));
  assert.equal(p.properties.consent_marketing, 'true');
  assert.equal(JSON.stringify(p).indexOf('SUBSCRIBED"'), -1, 'no SUBSCRIBED status anywhere in the plan');
});

test('plan: CCPA opt-out model with GPC sets do-not-sell and keeps unreported categories', function () {
  const osano = planFor(3);
  assert.deepEqual([osano.jurisdiction.code, osano.effective.sale_sharing, osano.properties.ccpa_do_not_sell_or_share, osano.properties.privacy_gpc_signal], ['CCPA', false, 'true', 'true']);
  assert.equal(osano.subscriptionChanges, null, 'CCPA does not force an email unsubscribe');
  const gpcOnly = planFor(4);
  assert.deepEqual(gpcOnly.effective, { necessary: true, functional: true, analytics: false, marketing: true, sale_sharing: false });
  assert.deepEqual([gpcOnly.decisions.analytics, gpcOnly.decisions.marketing, gpcOnly.decisions.sale_sharing], ['not_reported_kept_previous', 'not_reported_opt_out_default_allowed', 'gpc_signal_opt_out']);
  const mapping = plain(MAPPING);
  mapping.rules.honor_gpc_as_do_not_sell = false;
  assert.equal(planFor(4, { mapping: mapping }).effective.sale_sharing, true);
});

test('plan: restriction requests restrict processing, unsubscribe all, and open a review ticket', function () {
  const cfg = cfgFrom({ TARGET_PIPELINE_ID: '0', TARGET_PIPELINE_STAGE_ID: '1' });
  const p = planFor(5, { config: cfg });
  assert.deepEqual([p.restrictProcessing, p.globalUnsubscribe, p.properties.privacy_processing_restricted], [true, true, 'true']);
  assert.deepEqual(p.reviewTicket.triggers, ['processing_restricted', 'global_unsubscribe']);
  assert.deepEqual([p.reviewTicket.properties.hs_pipeline, p.reviewTicket.properties.hs_pipeline_stage, p.reviewTicket.properties.hs_ticket_priority, p.reviewTicket.associationTypeId], ['0', '1', 'HIGH', 16]);
  assert.equal(p.reviewTicket.properties.content.indexOf('@'), -1, 'ticket text carries no email address');
  assert.ok(planFor(5).warnings.some(function (w) { return /TARGET_PIPELINE_ID_not_set/.test(w); }));
});

test('plan: an existing processing restriction is never lifted automatically', function () {
  const contact = contactFor('carla.example@example.org');
  contact.properties.privacy_processing_restricted = 'true';
  const p = planFor(2, { contact: contact });
  assert.equal(p.restrictProcessing, true);
  assert.equal(p.decisions.processing_restricted, 'kept_existing_restriction_requires_manual_review_to_lift');
  assert.equal('privacy_processing_restricted' in p.properties, false, 'unchanged value is not re-sent');
});

test('plan: GDPR full-withdrawal restriction is opt-in via rules', function () {
  const mapping = mappingWithIds();
  mapping.rules.restrict_processing_on_full_withdrawal_gdpr = true;
  assert.equal(planFor(0, { mapping: mapping }).restrictProcessing, true);
  assert.equal(planFor(0, { mapping: mappingWithIds() }).restrictProcessing, false);
});

test('plan: stale events, replayed receipts, and unknown contacts are skipped', function () {
  assert.deepEqual([planFor(6).action, planFor(6).reason], ['skip', 'stale_event_older_than_stored_consent']);
  assert.deepEqual([planFor(7).action, planFor(7).reason], ['skip', 'duplicate_receipt']);
  assert.deepEqual([planFor(8).action, planFor(8).reason], ['skip', 'contact_not_found']);
  const create = planFor(8, { config: cfgFrom({ CREATE_MISSING_CONTACTS: 'true' }) });
  assert.deepEqual([create.action, create.properties.email], ['create', 'nobody.example@example.org']);
});

test('plan: essential cookies are always recorded as granted, and unchanged values are not re-sent', function () {
  const b = body(0);
  b.consents.necessary = false;
  const event = c.normalizeConsentEvent(b, MAPPING, NOW.getTime()).event;
  const p = c.buildConsentPlan({ event: event, mapping: MAPPING, config: cfgFrom(), contact: contactFor(event.email) });
  assert.deepEqual([p.effective.necessary, p.decisions.necessary], [true, 'essential_always_recorded_granted']);
  const stored = contactFor('anna.example@example.org');
  stored.properties.consent_functional = 'false';
  stored.properties.privacy_jurisdiction = 'GDPR';
  const again = c.buildConsentPlan({ event: normalized(0), mapping: MAPPING, config: cfgFrom(), contact: stored });
  assert.equal('consent_functional' in again.properties, false);
  assert.equal('privacy_jurisdiction' in again.properties, false);
  assert.ok('consent_last_updated' in again.properties, 'the timestamp is always written');
});

test('audit: entries are pseudonymous and never contain a raw email', function () {
  const event = normalized(5);
  const entry = c.buildAuditEntry(event, planFor(5), 'dry_run', 'dry_run', NOW.toISOString());
  assert.equal(JSON.stringify(entry).indexOf('@'), -1);
  assert.equal(entry.subject, c.hashIdentifier('fay.example@example.org'));
  assert.deepEqual([entry.jurisdiction, entry.globalUnsubscribe, entry.restrictProcessing], ['GDPR', true, true]);
});

// ---------------------------------------------------------------------------
// 7. Engine
// ---------------------------------------------------------------------------

function deps(env, extra) {
  const cfg = config.loadConfig(Object.assign({ WEBHOOK_SIGNING_SECRET: SECRET, HUBSPOT_PRIVATE_APP_TOKEN: 'mock_token_here' }, env || {}));
  return Object.assign({ config: cfg, hubspotClient: engine.createFixtureHubSpot(plain(FIXTURE)), mapping: plain(MAPPING), now: function () { return NOW; } }, extra || {});
}

function signedCall(i) {
  const raw = JSON.stringify(body(i));
  return { raw: raw, headers: signedHeaders(raw) };
}

function recordingHubSpot() {
  const base = engine.createFixtureHubSpot(plain(FIXTURE));
  const writes = [];
  return {
    writes: writes,
    request: async function (method, apiPath, b) {
      const isRead = (method === 'GET' && apiPath === '/account-info/v3/details') || apiPath === '/crm/v3/objects/contacts/search';
      if (isRead) return base.request(method, apiPath, b);
      writes.push({ method: method, path: apiPath, body: b });
      if (apiPath === '/crm/v3/objects/contacts') return { statusCode: 409, body: { message: 'Contact already exists. Existing ID: 2999' } };
      if (apiPath === '/crm/v3/objects/tickets') return { statusCode: 201, body: { id: '9001' } };
      return { statusCode: 200, body: {} };
    }
  };
}

test('engine: every fixture event produces its documented dry-run outcome', async function () {
  for (let i = 0; i < FIXTURE.events.length; i++) {
    const e = FIXTURE.events[i];
    const s = signedCall(i);
    const out = await engine.handleConsentWebhook(s.raw, s.headers, deps());
    assert.equal(out.body.status, e.expected_status, e.label);
    if (e.expected_reason) assert.equal(out.body.plan.reason, e.expected_reason, e.label);
  }
});

test('engine: bad signatures are rejected before any API call', async function () {
  const calls = [];
  const spy = { request: async function (m, p) { calls.push(m + ' ' + p); return { statusCode: 500, body: {} }; } };
  const raw = JSON.stringify(body(0));
  const out = await engine.handleConsentWebhook(raw, signedHeaders(raw + 'x'), deps({}, { hubspotClient: spy }));
  assert.deepEqual([out.httpStatus, out.body.reason], [401, 'signature_mismatch']);
  assert.equal(JSON.stringify(out.audit).indexOf('@'), -1);
  assert.deepEqual(calls, []);
});

test('engine: the portal gate blocks a STANDARD portal, and a failed lookup blocks all action', async function () {
  const fx = plain(FIXTURE);
  fx.mock_responses.account.body.accountType = 'STANDARD';
  const s = signedCall(0);
  await assert.rejects(engine.handleConsentWebhook(s.raw, s.headers, deps({}, { hubspotClient: engine.createFixtureHubSpot(fx) })), /blocked by gate/);
  const failing = { request: async function (m, p) { return p === '/account-info/v3/details' ? { statusCode: 200, body: { accountType: 'SANDBOX' } } : { statusCode: 500, body: {} }; } };
  await assert.rejects(engine.handleConsentWebhook(s.raw, s.headers, deps({}, { hubspotClient: failing })), /refusing to act/);
});

test('engine: sandbox writes run withdrawals first, then properties, then the review ticket', async function () {
  const hubspot = recordingHubSpot();
  const s = signedCall(5);
  const out = await engine.handleConsentWebhook(s.raw, s.headers, deps({ DRY_RUN: 'false', TARGET_PIPELINE_ID: '0', TARGET_PIPELINE_STAGE_ID: '1' }, { hubspotClient: hubspot, mapping: mappingWithIds() }));
  assert.equal(out.body.status, 'written');
  assert.deepEqual(hubspot.writes.map(function (w) { return w.method + ' ' + w.path; }), [
    'POST /communication-preferences/v4/statuses/batch/write',
    'POST /communication-preferences/v4/statuses/fay.example%40example.org/unsubscribe-all?channel=EMAIL',
    'PATCH /crm/v3/objects/contacts/2006',
    'POST /crm/v3/objects/tickets'
  ]);
  assert.deepEqual(hubspot.writes[3].body.associations, [{ to: { id: '2006' }, types: [{ associationCategory: 'HUBSPOT_DEFINED', associationTypeId: 16 }] }]);
  assert.equal(hubspot.writes[2].body.properties.privacy_processing_restricted, 'true');
});

test('engine: CREATE_MISSING_CONTACTS handles a concurrent-create 409 by patching the existing contact', async function () {
  const hubspot = recordingHubSpot();
  const s = signedCall(8);
  const out = await engine.handleConsentWebhook(s.raw, s.headers, deps({ DRY_RUN: 'false', CREATE_MISSING_CONTACTS: 'true' }, { hubspotClient: hubspot, mapping: mappingWithIds() }));
  assert.equal(out.body.results.contact, 'updated_after_conflict');
  const patch = hubspot.writes.find(function (w) { return w.method === 'PATCH'; });
  assert.equal(patch.path, '/crm/v3/objects/contacts/2999');
  assert.equal('email' in patch.body.properties, false);
});

test('engine: dry run writes nothing for any fixture', async function () {
  const hubspot = recordingHubSpot();
  for (let i = 0; i < FIXTURE.events.length; i++) {
    const s = signedCall(i);
    await engine.handleConsentWebhook(s.raw, s.headers, deps({}, { hubspotClient: hubspot }));
  }
  assert.deepEqual(hubspot.writes, []);
});

test('engine: writes require a real mapping file; the example mapping is dry-run only', function () {
  assert.throws(function () { engine.loadMapping(cfgFrom({ DRY_RUN: 'false' })); }, /CONSENT_MAPPING_FILE/);
  assert.equal(engine.loadMapping(cfgFrom()).version, 1);
});

test('engine: HTTP server returns 200 / 401 / 502 and audit forwarding is optional', async function () {
  const failing = { request: async function () { return { statusCode: 500, body: {} }; } };
  const server = engine.createWebhookServer(deps({}, { hubspotClient: failing }));
  const okServer = engine.createWebhookServer(deps());
  await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
  await new Promise(function (r) { okServer.listen(0, '127.0.0.1', r); });
  try {
    const s = signedCall(0);
    const post = function (srv, headers) {
      return fetch('http://127.0.0.1:' + srv.address().port + engine.WEBHOOK_PATH, { method: 'POST', headers: Object.assign({ 'Content-Type': 'application/json' }, headers), body: s.raw });
    };
    assert.equal((await post(okServer, s.headers)).status, 200);
    assert.equal((await post(okServer, {})).status, 401);
    assert.equal((await post(server, s.headers)).status, 502, 'upstream failure asks the relay to retry');
  } finally {
    server.close();
    okServer.close();
  }
});

// ---------------------------------------------------------------------------
// 8. workflow.json
// ---------------------------------------------------------------------------

const WORKFLOW_TEXT = fs.readFileSync(path.join(ROOT, 'workflow.json'), 'utf8');
const WORKFLOW = JSON.parse(WORKFLOW_TEXT);

class FixedDate extends Date {
  constructor(...args) { super(...(args.length ? args : [NOW.getTime()])); }
  static now() { return NOW.getTime(); }
}

function nodeCode(name) {
  const node = WORKFLOW.nodes.find(function (n) { return n.name === name; });
  assert.ok(node, 'missing node ' + name);
  return node.parameters.jsCode;
}

async function runCodeNode(name, context, self) {
  const quiet = { log: function () {}, error: function () {} };
  const sandbox = Object.assign({ console: quiet, Intl: Intl, Date: FixedDate, require: require, unescape: unescape, encodeURIComponent: encodeURIComponent }, context);
  vm.createContext(sandbox);
  const fn = vm.runInContext('(async function () {\n' + nodeCode(name) + '\n})', sandbox);
  return plain(await fn.call(self || { helpers: {} }));
}

function itemsOf(list) {
  return { first: function () { return { json: list[0] }; }, all: function () { return list.map(function (j) { return { json: j }; }); } };
}
function refs(outputs) {
  return function (name) {
    if (!(name in outputs)) throw new Error('Unexpected node reference ' + name);
    return itemsOf([outputs[name]]);
  };
}
function binary(raw) {
  return { helpers: { getBinaryDataBuffer: async function () { return Buffer.from(raw, 'utf8'); } } };
}

test('workflow: passes the validator and is in sync with src/', function () {
  assert.deepEqual(validator.validateWorkflow(WORKFLOW, { text: WORKFLOW_TEXT }).errors, []);
  assert.equal(WORKFLOW_TEXT, builder.render());
  const required = [N.webhook, N.verify, N.plan, N.patch, N.logFailure];
  required.forEach(function (n) { assert.ok(WORKFLOW.nodes.some(function (x) { return x.name === n; }), n); });
});

test('workflow: the validator catches gate bypasses, real credential IDs, and missing error routes', function () {
  const bypass = plain(WORKFLOW);
  bypass.connections[N.plan].main[0].push({ node: N.global, type: 'main', index: 0 });
  assert.ok(validator.validateWorkflow(bypass, {}).errors.some(function (e) { return /reachable without "Apply Changes\?"/.test(e); }));
  const realCred = plain(WORKFLOW);
  realCred.nodes.find(function (n) { return n.name === N.patch; }).credentials.hubspotAppToken.id = '12345';
  assert.ok(validator.validateWorkflow(realCred, {}).errors.some(function (e) { return /non-placeholder credential/.test(e); }));
  const noErr = plain(WORKFLOW);
  noErr.connections[N.subs].main[1] = [];
  assert.ok(validator.validateWorkflow(noErr, {}).errors.some(function (e) { return /route errors/.test(e); }));
});

async function n8nPlan(index, env, staticMapping) {
  const raw = JSON.stringify(body(index));
  const vEnv = Object.assign({ WEBHOOK_SIGNING_SECRET: SECRET }, env || {});
  if (staticMapping) vEnv.CONSENT_MAPPING_JSON = JSON.stringify(staticMapping);
  const verified = (await runCodeNode(N.verify, { $env: vEnv, $input: itemsOf([{ headers: signedHeaders(raw) }]) }, binary(raw)))[0].json;
  if (!verified.accepted) return { verified: verified };
  const gated = (await runCodeNode(N.gate, { $: refs({ [N.verify]: verified }), $input: itemsOf([FIXTURE.mock_responses.account.body]) }))[0].json;
  const hit = FIXTURE.mock_responses.contacts[verified.event.email];
  const lookup = { statusCode: 200, body: { total: hit ? 1 : 0, results: hit ? [hit] : [] } };
  const planned = (await runCodeNode(N.plan, { $: refs({ [N.gate]: gated }), $input: itemsOf([lookup]) }))[0].json;
  return { verified: verified, planned: planned };
}

test('workflow: verify node accepts signed raw bodies and fails closed otherwise', async function () {
  const raw = JSON.stringify(body(0));
  const good = (await runCodeNode(N.verify, { $env: { WEBHOOK_SIGNING_SECRET: SECRET }, $input: itemsOf([{ headers: signedHeaders(raw) }]) }, binary(raw)))[0].json;
  assert.equal(good.accepted, true);
  assert.equal(good.config.writeMode, 'dry_run');
  const bad = (await runCodeNode(N.verify, { $env: { WEBHOOK_SIGNING_SECRET: SECRET }, $input: itemsOf([{ headers: signedHeaders(raw + ' ') }]) }, binary(raw)))[0].json;
  assert.deepEqual([bad.accepted, bad.httpStatus, bad.reason], [false, 401, 'signature_mismatch']);
  const blocked = new Proxy({}, { get: function () { throw new Error('access to env vars denied'); } });
  const locked = (await runCodeNode(N.verify, { $env: blocked, $input: itemsOf([{ headers: signedHeaders(raw) }]) }, binary(raw)))[0].json;
  assert.deepEqual([locked.accepted, locked.reason], [false, 'signing_secret_not_configured']);
  await assert.rejects(runCodeNode(N.verify, { $env: { WEBHOOK_SIGNING_SECRET: SECRET, DRY_RUN: 'false' }, $input: itemsOf([{ headers: signedHeaders(raw) }]) }, binary(raw)), /CONSENT_MAPPING_JSON is blank/);
});

test('workflow: the n8n node chain builds the same compliance plan as the Node engine', async function () {
  for (const index of [0, 1, 3, 4, 5, 6, 7, 8]) {
    const n8n = await n8nPlan(index, {}, mappingWithIds());
    const s = signedCall(index);
    const node = await engine.handleConsentWebhook(s.raw, s.headers, deps({}, { mapping: mappingWithIds() }));
    assert.deepEqual(n8n.planned.plan, plain(node.body.plan), 'event ' + index);
    assert.equal(n8n.planned.apply, false, 'dry run never applies');
  }
  const rejected = await n8nPlan(9);
  assert.deepEqual([rejected.verified.httpStatus, rejected.verified.errors], [422, ['email_missing_or_invalid']]);
});

test('workflow: resolve node handles create, conflict, and update paths', async function () {
  const scoreCreate = { createContact: true, plan: { contactId: null, properties: { email: 'x@example.org', consent_marketing: 'false' } } };
  const created = (await runCodeNode(N.resolve, { $: refs({ [N.plan]: scoreCreate }), $input: itemsOf([{ statusCode: 201, body: { id: '7001' } }]) }))[0].json;
  assert.deepEqual([created.contactId, created.needsPatch], ['7001', false]);
  const conflict = (await runCodeNode(N.resolve, { $: refs({ [N.plan]: scoreCreate }), $input: itemsOf([{ statusCode: 409, body: { message: 'Contact already exists. Existing ID: 2999' } }]) }))[0].json;
  assert.deepEqual([conflict.contactId, conflict.needsPatch, 'email' in conflict.properties], ['2999', true, false]);
  const update = (await runCodeNode(N.resolve, { $: refs({ [N.plan]: { createContact: false, plan: { contactId: '2001', properties: { a: '1' } } } }), $input: itemsOf([{}]) }))[0].json;
  assert.deepEqual([update.contactId, update.needsPatch], ['2001', true]);
});

test('workflow: audit and failure log nodes never emit a raw email', async function () {
  const n8n = await n8nPlan(5, {}, mappingWithIds());
  const audit = (await runCodeNode(N.audit, { $: refs({ [N.plan]: n8n.planned }), $env: {} }))[0].json;
  assert.equal(JSON.stringify(audit.audit).indexOf('@'), -1);
  assert.equal(audit.response.status, 'dry_run');
  const fail = (await runCodeNode(N.logFailure, { $: refs({ [N.plan]: n8n.planned }), $input: itemsOf([{ error: { message: 'HubSpot 500' } }]) }))[0].json;
  assert.deepEqual([fail.status, fail.audit.outcome, JSON.stringify(fail.audit).indexOf('@')], ['error', 'failed', -1]);
});

// ---------------------------------------------------------------------------
// 9. Security scan
// ---------------------------------------------------------------------------

const DOMAIN_ALLOWLIST = {
  'dhrobinsystems.com': 'author website and contact (README author block)',
  'behance.net': 'author portfolio (README author block)',
  'linkedin.com': 'author profile (README author block)',
  'github.com': 'repository links in README and package.json',
  'hubapi.com': 'HubSpot API base URL'
};
const ALLOWED_EMAIL_DOMAINS = ['dhrobinsystems.com'];
const SKIP_DIRS = new Set(['.git', 'node_modules', 'coverage']);

function listRepoFiles(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap(function (entry) {
    if (SKIP_DIRS.has(entry.name)) return [];
    const full = path.join(dir, entry.name);
    return entry.isDirectory() ? listRepoFiles(full) : [full];
  });
}
function isRfc2606(host) {
  return /(^|\.)example\.(com|org|net)$/.test(host) || /(^|\.)(test|example|invalid|localhost)$/.test(host);
}
function isAllowedHost(host) {
  const h = host.toLowerCase().replace(/^www\./, '');
  return isRfc2606(h) || Object.keys(DOMAIN_ALLOWLIST).some(function (d) { return h === d || h.endsWith('.' + d); });
}

const SECRET_PATTERNS = [
  { name: 'private key block', re: new RegExp(['-----BEGIN', '[A-Z ]*PRIVATE KEY-----'].join(' ')) },
  { name: 'HubSpot private app token', re: /\bpat-(?:na|eu|ap)\d-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/i },
  { name: 'HubSpot legacy API key', re: /hapikey=[0-9a-f]{8}-[0-9a-f]{4}-/i },
  { name: 'JSON Web Token', re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\./ },
  { name: 'Google API key', re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { name: 'AWS access key', re: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: 'GitHub token', re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/ },
  { name: 'Slack token', re: /\bxox[abposr]-[A-Za-z0-9-]{10,}/ },
  { name: 'Stripe live key', re: /\b[sr]k_live_[A-Za-z0-9]{16,}/ },
  { name: 'hard-coded secret assignment', re: /\b[A-Z0-9_]*(?:TOKEN|SECRET|API_KEY|PASSWORD)[ \t]*[=:][ \t]*["']?(?!your_[a-z0-9_]+_here|mock_)[A-Za-z0-9\-_./+:]{16,}/ }
];

test('security: no real secrets, keys, or tokens in any repository file', function () {
  const findings = [];
  listRepoFiles(ROOT).forEach(function (file) {
    const text = fs.readFileSync(file, 'utf8');
    SECRET_PATTERNS.forEach(function (p) { if (p.re.test(text)) findings.push(path.relative(ROOT, file) + ': ' + p.name); });
  });
  assert.deepEqual(findings, []);
});

test('security: .env.example holds only placeholders, blanks, or fail-safe defaults; no .env is committed', function () {
  assert.equal(fs.existsSync(path.join(ROOT, '.env')), false);
  const lines = fs.readFileSync(path.join(ROOT, '.env.example'), 'utf8').split('\n').filter(function (l) { return l.trim() && !l.trim().startsWith('#'); });
  const safe = /^(|your_[a-z0-9_]+_here|true|false|\d+|https:\/\/api\.hubapi\.com|127\.0\.0\.1)$/;
  lines.forEach(function (line) { assert.match(line.slice(line.indexOf('=') + 1), safe, line); });
  ['DRY_RUN=true', 'SANDBOX_MODE=true', 'REQUIRE_SIGNATURE=true', 'ALLOW_PRODUCTION_MODE=false', 'HUBSPOT_PRIVATE_APP_TOKEN=your_hubspot_private_app_token_here', 'WEBHOOK_SIGNING_SECRET=your_webhook_signing_secret_here'].forEach(function (l) { assert.ok(lines.includes(l), l); });
  lines.filter(function (l) { return /TOKEN|SECRET|_ID=|_URL=|MAPPING_JSON|MAPPING_FILE/.test(l) && !/HUBSPOT_BASE_URL/.test(l); }).forEach(function (l) {
    assert.match(l.slice(l.indexOf('=') + 1), /^(|your_[a-z0-9_]+_here)$/, 'secrets and IDs ship as placeholders: ' + l);
  });
});

test('security: only RFC 2606 domains (plus the documented allowlist) appear in any file', function () {
  const domainRe = /\b((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+(?:com|net|org|io|co|ai|app|dev))\b/gi;
  const findings = [];
  listRepoFiles(ROOT).forEach(function (file) {
    const text = fs.readFileSync(file, 'utf8');
    let match;
    while ((match = domainRe.exec(text)) !== null) {
      const host = text.charAt(match.index - 1) === '%' ? match[1].slice(2) : match[1];
      if (!isAllowedHost(host)) findings.push(path.relative(ROOT, file) + ': ' + host);
    }
  });
  assert.deepEqual(Array.from(new Set(findings)), []);
});

test('security: every email address uses an RFC 2606 domain or the documented author contact', function () {
  const emailRe = /\b[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)\b/g;
  const findings = [];
  listRepoFiles(ROOT).forEach(function (file) {
    const text = fs.readFileSync(file, 'utf8');
    let match;
    while ((match = emailRe.exec(text)) !== null) {
      const domain = match[1].toLowerCase();
      if (!isRfc2606(domain) && !ALLOWED_EMAIL_DOMAINS.includes(domain)) findings.push(path.relative(ROOT, file) + ': ' + match[0]);
    }
  });
  assert.deepEqual(findings, []);
});

test('security: the scanner catches planted secrets and foreign domains', function () {
  const token = ['pat', 'na1', '12345678-1234-1234-1234-123456789abc'].join('-');
  const assignment = 'WEBHOOK_SIGNING_SECRET=' + ['live', 'signing', 'secret', '0123456789'].join('_');
  [token, assignment].forEach(function (s) { assert.ok(SECRET_PATTERNS.some(function (p) { return p.re.test(s); }), s.slice(0, 12)); });
  assert.equal(SECRET_PATTERNS.some(function (p) { return p.re.test('HUBSPOT_PRIVATE_APP_TOKEN=your_hubspot_private_app_token_here'); }), false);
  assert.equal(isAllowedHost(['acme-corp', 'com'].join('.')), false);
});
