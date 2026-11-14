#!/usr/bin/env node
'use strict';

/**
 * index.js
 *
 * Standalone consent webhook handler. It mirrors workflow.json step for step:
 *
 *   raw body -> HMAC signature check -> mapping validation -> normalize consent event
 *     -> HubSpot portal gate -> contact lookup -> buildConsentPlan()
 *     -> [dry run: return plan + audit entry]
 *     -> unsubscribe marketing types -> global unsubscribe -> update / create contact
 *     -> privacy review ticket -> audit log (forwarded if configured)
 *
 * Usage:
 *   node --env-file=.env src/index.js --serve
 *   REQUIRE_SIGNATURE=false node src/index.js --fixture test/fixtures/consent-events.mock.json --event 0
 *
 * Zero runtime dependencies: global fetch (Node 18+), node:http, node:crypto, node:fs.
 */

const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const crypto = require('node:crypto');

const { loadConfig, evaluateHubSpotTarget, describeConfig } = require('./config');
const c = require('./consent');

const WEBHOOK_PATH = '/webhook/consent-preference-sync';
const MAX_BODY_BYTES = 128 * 1024;
const EXAMPLE_MAPPING = path.join(__dirname, '..', 'config', 'consent-mapping.example.json');

function hmacHex(secret, data) {
  return crypto.createHmac('sha256', secret).update(data).digest('hex');
}

function createLogger(options) {
  const silent = Boolean(options && options.silent);
  const write = function (level, message, fields) {
    if (silent) return;
    process.stderr.write(JSON.stringify(Object.assign({ level: level, time: new Date().toISOString(), message: message }, fields || {})) + '\n');
  };
  return { info: function (m, f) { write('info', m, f); }, warn: function (m, f) { write('warn', m, f); }, error: function (m, f) { write('error', m, f); } };
}

/** JSON-over-HTTPS client with 429 / 5xx retries and timeouts. */
class JsonClient {
  constructor(options) {
    this.baseUrl = String(options.baseUrl || '').replace(/\/+$/, '');
    this.headers = options.headers || {};
    this.fetch = options.fetchImpl || globalThis.fetch;
    this.maxRetries = options.maxRetries === undefined ? 3 : options.maxRetries;
    this.baseDelayMs = options.baseDelayMs === undefined ? 400 : options.baseDelayMs;
    this.timeoutMs = options.timeoutMs || 20000;
    this.sleep = options.sleep || function (ms) { return new Promise(function (r) { setTimeout(r, ms); }); };
    if (typeof this.fetch !== 'function') throw new Error('No fetch implementation available (Node 18+ required).');
  }

  async request(method, urlOrPath, body) {
    const url = /^https?:\/\//.test(urlOrPath) ? urlOrPath : this.baseUrl + urlOrPath;
    for (let attempt = 0; ; attempt++) {
      const controller = new AbortController();
      const timer = setTimeout(function () { controller.abort(); }, this.timeoutMs);
      let response;
      try {
        response = await this.fetch(url, {
          method: method,
          headers: Object.assign({ Accept: 'application/json' }, body === undefined || body === null ? {} : { 'Content-Type': 'application/json' }, this.headers),
          body: body === undefined || body === null ? undefined : JSON.stringify(body),
          signal: controller.signal
        });
      } catch (error) {
        clearTimeout(timer);
        if (attempt < this.maxRetries) { await this.sleep(this.baseDelayMs * Math.pow(2, attempt)); continue; }
        return { statusCode: 0, body: { message: error.message } };
      }
      clearTimeout(timer);
      const text = await response.text();
      let parsed = null;
      if (text) { try { parsed = JSON.parse(text); } catch (error) { parsed = { raw: text.slice(0, 2000) }; } }
      if ((response.status === 429 || response.status >= 500) && attempt < this.maxRetries) {
        const retryAfter = Number(response.headers && response.headers.get ? response.headers.get('retry-after') : NaN);
        await this.sleep(Number.isFinite(retryAfter) && retryAfter > 0 ? retryAfter * 1000 : this.baseDelayMs * Math.pow(2, attempt));
        continue;
      }
      return { statusCode: response.status, body: parsed };
    }
  }
}

function expectOk(result, context) {
  if (result.statusCode >= 200 && result.statusCode < 300) return result.body;
  const detail = result.body && result.body.message ? ': ' + result.body.message : '';
  const error = new Error(context + ' failed with status ' + result.statusCode + detail);
  error.statusCode = result.statusCode;
  throw error;
}

function loadMapping(cfg) {
  if (cfg.consentMappingFile) return JSON.parse(fs.readFileSync(path.resolve(cfg.consentMappingFile), 'utf8'));
  if (cfg.writesEnabled) throw new Error('CONSENT_MAPPING_FILE is blank. The example mapping may only be used in dry run.');
  return JSON.parse(fs.readFileSync(EXAMPLE_MAPPING, 'utf8'));
}

/** Offline HubSpot client answering from recorded responses, for tests and `npm run dry-run`. */
function createFixtureHubSpot(fixture) {
  const responses = fixture.mock_responses;
  return {
    request: async function (method, apiPath, body) {
      if (method === 'GET' && apiPath === '/account-info/v3/details') return JSON.parse(JSON.stringify(responses.account));
      if (method === 'POST' && apiPath === '/crm/v3/objects/contacts/search') {
        const hit = responses.contacts[body.filterGroups[0].filters[0].value];
        return { statusCode: 200, body: { total: hit ? 1 : 0, results: hit ? [JSON.parse(JSON.stringify(hit))] : [] } };
      }
      return { statusCode: 404, body: { message: 'No fixture for ' + method + ' ' + apiPath } };
    }
  };
}

async function handleConsentWebhook(rawBody, headers, deps) {
  const cfg = deps.config;
  const logger = deps.logger || createLogger({ silent: true });
  const nowMs = deps.now ? deps.now().getTime() : Date.now();
  const nowIso = new Date(nowMs).toISOString();
  const raw = Buffer.isBuffer(rawBody) ? rawBody.toString('utf8') : String(rawBody);
  const reject = function (status, reason, errors) {
    const audit = c.buildAuditEntry(null, null, 'rejected:' + reason, cfg.writeMode, nowIso);
    logger.warn('consent_rejected', audit);
    return { httpStatus: status, body: { status: 'rejected', reason: reason, errors: errors || [] }, audit: audit };
  };

  if (cfg.requireSignature) {
    const verdict = c.verifySignature(raw, headers['x-consent-signature'], headers['x-consent-timestamp'], cfg.webhookSigningSecret, nowMs, cfg.signatureToleranceSeconds, hmacHex);
    if (!verdict.ok) return reject(401, verdict.reason);
  }
  let payload;
  try { payload = JSON.parse(raw); } catch (error) { return reject(400, 'invalid_json'); }

  const mapping = deps.mapping || loadMapping(cfg);
  const mappingCheck = c.validateMapping(mapping);
  if (!mappingCheck.ok) throw new Error('Consent mapping is invalid: ' + mappingCheck.errors.join('; '));

  const normalized = c.normalizeConsentEvent(payload, mapping, nowMs);
  if (!normalized.ok) return reject(422, 'invalid_payload', normalized.errors);
  const event = normalized.event;

  const hubspot = deps.hubspotClient || (cfg.hubspotPrivateAppToken
    ? new JsonClient({ baseUrl: cfg.hubspotBaseUrl, headers: { Authorization: 'Bearer ' + cfg.hubspotPrivateAppToken }, fetchImpl: deps.fetchImpl })
    : null);
  if (!hubspot) throw new Error('HUBSPOT_PRIVATE_APP_TOKEN is blank. Use a sandbox private app token, or --fixture for an offline dry run.');

  const account = expectOk(await hubspot.request('GET', '/account-info/v3/details'), 'HubSpot account details');
  const gate = evaluateHubSpotTarget(cfg, account);
  if (!gate.allowed) throw new Error('HubSpot access blocked by gate: ' + gate.reason);

  const lookup = c.buildContactLookup(event.email, mapping);
  const contact = c.readContactLookup(await hubspot.request(lookup.method, lookup.path, lookup.body));
  if (!contact.ok) throw new Error('HubSpot contact lookup failed; refusing to act on consent without a confirmed lookup.');

  const plan = c.buildConsentPlan({ event: event, mapping: mapping, config: cfg, contact: contact });
  plan.warnings = normalized.warnings.concat(mappingCheck.warnings, plan.warnings);

  if (!cfg.writesEnabled || plan.action === 'skip') {
    const outcome = plan.action === 'skip' ? 'skipped:' + plan.reason : 'dry_run';
    const audit = c.buildAuditEntry(event, plan, outcome, cfg.writeMode, nowIso);
    logger.info('consent_planned', audit);
    return { httpStatus: 200, body: { status: plan.action === 'skip' ? 'skipped' : 'dry_run', writeMode: cfg.writeMode, plan: plan }, audit: audit };
  }

  const results = { subscriptions: null, globalUnsubscribe: null, contact: null, reviewTicket: null };
  const commPrefs = '/communication-preferences/v4/statuses';

  // Withdrawals first: the most important compliance effect lands even if a later step fails.
  if (plan.subscriptionChanges) {
    expectOk(await hubspot.request('POST', commPrefs + '/batch/write', plan.subscriptionChanges), 'Unsubscribe marketing subscription types');
    results.subscriptions = plan.subscriptionChanges.inputs.length + '_unsubscribed';
  }
  if (plan.globalUnsubscribe) {
    expectOk(await hubspot.request('POST', commPrefs + '/' + encodeURIComponent(event.email) + '/unsubscribe-all?channel=EMAIL'), 'Global email unsubscribe');
    results.globalUnsubscribe = 'unsubscribed_from_all_email';
  }

  let contactId = plan.contactId;
  if (plan.action === 'create') {
    const created = await hubspot.request('POST', '/crm/v3/objects/contacts', { properties: plan.properties });
    if (created.statusCode === 201 || created.statusCode === 200) {
      contactId = String(created.body.id);
      results.contact = 'created';
    } else if (created.statusCode === 409) {
      contactId = c.parseExistingContactId(created.body);
      if (!contactId) throw new Error('Contact create returned 409 without an existing ID.');
      const props = Object.assign({}, plan.properties);
      delete props.email;
      expectOk(await hubspot.request('PATCH', '/crm/v3/objects/contacts/' + encodeURIComponent(contactId), { properties: props }), 'Contact update after conflict');
      results.contact = 'updated_after_conflict';
    } else {
      expectOk(created, 'Contact create');
    }
  } else {
    expectOk(await hubspot.request('PATCH', '/crm/v3/objects/contacts/' + encodeURIComponent(contactId), { properties: plan.properties }), 'Contact consent update');
    results.contact = 'updated';
  }

  if (plan.reviewTicket) {
    const body = { properties: plan.reviewTicket.properties };
    if (contactId) body.associations = [{ to: { id: contactId }, types: [{ associationCategory: 'HUBSPOT_DEFINED', associationTypeId: plan.reviewTicket.associationTypeId }] }];
    const ticket = expectOk(await hubspot.request('POST', '/crm/v3/objects/tickets', body), 'Privacy review ticket');
    results.reviewTicket = ticket && ticket.id ? 'created' : 'created_without_id';
  }

  const audit = c.buildAuditEntry(event, plan, 'written', cfg.writeMode, nowIso);
  if (cfg.auditLogWebhookUrl) {
    const hook = deps.auditClient || new JsonClient({ fetchImpl: deps.fetchImpl, maxRetries: 2 });
    const res = await hook.request('POST', cfg.auditLogWebhookUrl, audit);
    results.auditForward = res.statusCode >= 200 && res.statusCode < 300 ? 'sent' : 'failed_' + res.statusCode;
  }
  logger.info('consent_written', audit);
  return { httpStatus: 200, body: { status: 'written', writeMode: cfg.writeMode, plan: plan, results: results }, audit: audit };
}

function createWebhookServer(deps) {
  const send = function (res, status, payload) { res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(payload)); };
  return http.createServer(function (req, res) {
    if (req.method !== 'POST' || req.url.split('?')[0] !== WEBHOOK_PATH) return send(res, 404, { status: 'not_found' });
    const chunks = [];
    let size = 0;
    let aborted = false;
    req.on('data', function (chunk) {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) { aborted = true; send(res, 413, { status: 'payload_too_large' }); req.destroy(); return; }
      chunks.push(chunk);
    });
    req.on('end', async function () {
      if (aborted) return;
      try {
        const out = await handleConsentWebhook(Buffer.concat(chunks), req.headers, deps);
        send(res, out.httpStatus, out.body);
      } catch (error) {
        // 502 tells the consent relay to retry; replays are safe (stale / duplicate checks).
        (deps.logger || createLogger()).error('consent_failed', { error: error.message });
        send(res, 502, { status: 'error', error: error.message });
      }
    });
  });
}

function parseArgs(argv) {
  const args = { event: 0 };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--serve') args.serve = true;
    else if (argv[i] === '--fixture') args.fixture = argv[++i];
    else if (argv[i] === '--event') args.event = Number(argv[++i]);
    else if (argv[i] === '--help' || argv[i] === '-h') args.help = true;
  }
  return args;
}

async function main(argv) {
  const args = parseArgs(argv);
  if (args.help || (!args.serve && !args.fixture)) {
    process.stdout.write('Usage: node src/index.js --serve | --fixture <file.json> [--event <index>]\n');
    return 0;
  }
  const cfg = loadConfig(process.env);
  const logger = createLogger();
  logger.info('config_loaded', { config: describeConfig(cfg) });
  if (args.fixture) {
    if (cfg.writesEnabled) throw new Error('--fixture is only allowed in dry run.');
    const fixture = JSON.parse(fs.readFileSync(path.resolve(args.fixture), 'utf8'));
    const entry = fixture.events[args.event];
    if (!entry) throw new Error('No event at index ' + args.event);
    const out = await handleConsentWebhook(JSON.stringify(entry.body), {}, {
      config: cfg, logger: logger, hubspotClient: createFixtureHubSpot(fixture), now: function () { return new Date(fixture._meta.reference_now); }
    });
    process.stdout.write(JSON.stringify(out, null, 2) + '\n');
    return 0;
  }
  const server = createWebhookServer({ config: cfg, logger: logger });
  await new Promise(function (r) { server.listen(cfg.port, cfg.host, r); });
  logger.info('webhook_listening', { url: 'http://' + cfg.host + ':' + cfg.port + WEBHOOK_PATH, writeMode: cfg.writeMode });
  return null;
}

if (require.main === module) {
  main(process.argv.slice(2)).then(function (code) { if (typeof code === 'number') process.exitCode = code; }).catch(function (error) {
    process.stderr.write(JSON.stringify({ level: 'error', message: error.message }) + '\n');
    process.exitCode = 1;
  });
}

module.exports = {
  WEBHOOK_PATH,
  hmacHex,
  JsonClient,
  loadMapping,
  createFixtureHubSpot,
  handleConsentWebhook,
  createWebhookServer,
  main
};
