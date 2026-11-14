#!/usr/bin/env node
'use strict';

/**
 * build-workflow.js
 *
 * Generates workflow.json from src/ so the n8n Code nodes run exactly the same
 * signature check, mapping validation, consent normalization, jurisdiction
 * rules, and gates as the standalone engine.
 *
 *   node scripts/build-workflow.js          regenerate workflow.json
 *   node scripts/build-workflow.js --check  exit 1 if workflow.json is stale
 *
 * Credential references use placeholder IDs (your_n8n_..._here). After import I
 * select my own HubSpot credential on each HTTP node.
 */

const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');
const OUTPUT = path.join(ROOT, 'workflow.json');
const N = {
  webhook: 'Consent Webhook',
  verify: 'Verify & Normalize Consent',
  accepted: 'Accepted?',
  logRejection: 'Log Rejection',
  rejected: 'Respond: Rejected',
  account: 'HubSpot: Account Details',
  gate: 'Enforce Portal Gate',
  lookup: 'HubSpot: Find Contact by Email',
  plan: 'Build Consent Plan',
  apply: 'Apply Changes?',
  subsGate: 'Unsubscribe Marketing Types?',
  subs: 'HubSpot: Unsubscribe Marketing Types',
  globalGate: 'Global Unsubscribe?',
  global: 'HubSpot: Unsubscribe From All Email',
  createGate: 'Create Contact?',
  create: 'HubSpot: Create Contact',
  resolve: 'Resolve Contact',
  patchGate: 'Patch Contact?',
  patch: 'HubSpot: Update Consent Properties',
  ticketGate: 'Review Ticket?',
  ticket: 'HubSpot: Create Privacy Review Ticket',
  audit: 'Audit Log',
  forwardGate: 'Forward Audit Log?',
  forward: 'Audit Log: Forward',
  ok: 'Respond: OK',
  logFailure: 'Log Failure',
  failed: 'Respond: Failed (502)'
};

function extractCore(relativeFile, name) {
  const source = fs.readFileSync(path.join(ROOT, relativeFile), 'utf8');
  const start = '// <n8n-core:' + name + '>';
  const end = '// </n8n-core:' + name + '>';
  const i = source.indexOf(start);
  const j = source.indexOf(end);
  if (i === -1 || j === -1 || j < i) throw new Error('Missing n8n-core:' + name + ' markers in ' + relativeFile);
  return source.slice(i, j + end.length);
}

function bodyOf(fn) {
  const text = fn.toString();
  const lines = text.slice(text.indexOf('{') + 1, text.lastIndexOf('}')).split('\n');
  while (lines.length && lines[0].trim() === '') lines.shift();
  while (lines.length && lines[lines.length - 1].trim() === '') lines.pop();
  const indent = Math.min.apply(null, lines.filter(function (l) { return l.trim(); }).map(function (l) { return l.match(/^ */)[0].length; }));
  return lines.map(function (l) { return l.slice(indent); }).join('\n');
}

/* eslint-disable no-undef */
// These functions never run in Node; their bodies become Code-node source.

async function verifyGlue() {
  const readEnv = (key) => {
    try {
      const value = $env[key];
      return value === undefined || value === null ? undefined : String(value);
    } catch (error) {
      return undefined; // N8N_BLOCK_ENV_ACCESS_IN_NODE=true: fail-safe defaults apply
    }
  };
  const env = {};
  for (const key of CONFIG_KEYS) env[key] = readEnv(key);
  const config = parseConfig(env);
  const nowMs = Date.now();
  const item = $input.first();
  const headers = (item.json && item.json.headers) || {};
  const reject = (httpStatus, reason, errors) => [{ json: { accepted: false, httpStatus, reason, errors: errors || [], writeMode: config.writeMode } }];

  let raw = null;
  try {
    raw = (await this.helpers.getBinaryDataBuffer(0, 'data')).toString('utf8');
  } catch (error) {
    raw = null;
  }

  if (config.requireSignature) {
    let cryptoLib = null;
    try { cryptoLib = require('crypto'); } catch (error) { cryptoLib = null; }
    if (!cryptoLib) return reject(500, 'crypto_unavailable_set_NODE_FUNCTION_ALLOW_BUILTIN_to_crypto');
    if (raw === null) return reject(500, 'raw_body_unavailable_enable_webhook_raw_body_option');
    const hmac = (secret, data) => cryptoLib.createHmac('sha256', secret).update(data).digest('hex');
    const verdict = verifySignature(raw, headers['x-consent-signature'], headers['x-consent-timestamp'], readEnv('WEBHOOK_SIGNING_SECRET'), nowMs, config.signatureToleranceSeconds, hmac);
    if (!verdict.ok) return reject(401, verdict.reason);
  }

  let mapping = null;
  try {
    const value = readEnv('CONSENT_MAPPING_JSON');
    if (value && value.trim() && !/^your_[a-z0-9_]+_here$/i.test(value.trim())) mapping = JSON.parse(value);
  } catch (error) {
    throw new Error('CONSENT_MAPPING_JSON is not valid JSON.');
  }
  if (!mapping) {
    if (config.writesEnabled) throw new Error('CONSENT_MAPPING_JSON is blank. The example mapping may only be used in dry run.');
    mapping = EXAMPLE_MAPPING;
  }
  const check = validateMapping(mapping);
  if (!check.ok) throw new Error('Consent mapping is invalid: ' + check.errors.join('; '));

  let payload;
  try {
    payload = raw !== null ? JSON.parse(raw) : item.json.body;
  } catch (error) {
    return reject(400, 'invalid_json');
  }
  const normalized = normalizeConsentEvent(payload, mapping, nowMs);
  if (!normalized.ok) return reject(422, 'invalid_payload', normalized.errors);
  return [{
    json: {
      accepted: true,
      config,
      mapping,
      event: normalized.event,
      warnings: normalized.warnings.concat(check.warnings),
      contactLookup: buildContactLookup(normalized.event.email, mapping)
    }
  }];
}

function logRejectionGlue() {
  const rejection = $input.first().json;
  const entry = buildAuditEntry(null, null, 'rejected:' + rejection.reason, rejection.writeMode, new Date().toISOString());
  console.log('[consent-audit]', JSON.stringify(entry));
  return [{ json: Object.assign({}, rejection, { audit: entry }) }];
}

function gateGlue() {
  const base = $('Verify & Normalize Consent').first().json;
  const account = $input.first().json;
  const verdict = evaluateHubSpotTarget(base.config, account);
  if (!verdict.allowed) throw new Error('HubSpot access blocked by gate: ' + verdict.reason);
  return [{ json: Object.assign({}, base, { portal: { portalId: account.portalId, accountType: account.accountType } }) }];
}

function planGlue() {
  const base = $('Enforce Portal Gate').first().json;
  const lookup = $input.first().json;
  const contact = readContactLookup(lookup.error ? null : { statusCode: lookup.statusCode, body: lookup.body });
  if (!contact.ok) throw new Error('HubSpot contact lookup failed; refusing to act on consent without a confirmed lookup.');
  const plan = buildConsentPlan({ event: base.event, mapping: base.mapping, config: base.config, contact });
  plan.warnings = base.warnings.concat(plan.warnings);
  const apply = base.config.writesEnabled && plan.action !== 'skip';
  return [{
    json: {
      apply,
      writeMode: base.config.writeMode,
      hubspotBaseUrl: base.config.hubspotBaseUrl,
      event: base.event,
      plan,
      hasSubscriptionChanges: apply && Boolean(plan.subscriptionChanges),
      globalUnsubscribe: apply && plan.globalUnsubscribe,
      createContact: apply && plan.action === 'create',
      hasReviewTicket: apply && Boolean(plan.reviewTicket)
    }
  }];
}

function resolveGlue() {
  const s = $('Build Consent Plan').first().json;
  const plan = s.plan;
  if (!s.createContact) {
    return [{ json: { contactId: plan.contactId, needsPatch: Object.keys(plan.properties).length > 0, properties: plan.properties, contactResult: 'update' } }];
  }
  const res = $input.first().json;
  const status = Number(res.statusCode);
  if (status === 200 || status === 201) return [{ json: { contactId: String(res.body.id), needsPatch: false, properties: {}, contactResult: 'created' } }];
  if (status === 409) {
    const contactId = parseExistingContactId(res.body);
    if (!contactId) throw new Error('Contact create returned 409 without an existing ID.');
    const properties = Object.assign({}, plan.properties);
    delete properties.email;
    return [{ json: { contactId, needsPatch: true, properties, contactResult: 'updated_after_conflict' } }];
  }
  throw new Error('HubSpot contact create failed with status ' + (res.statusCode || 'n/a') + '.');
}

function auditGlue() {
  const s = $('Build Consent Plan').first().json;
  const outcome = !s.apply ? (s.plan.action === 'skip' ? 'skipped:' + s.plan.reason : 'dry_run') : 'written';
  const entry = buildAuditEntry(s.event, s.plan, outcome, s.writeMode, new Date().toISOString());
  console.log('[consent-audit]', JSON.stringify(entry));
  let forward = false;
  try { forward = Boolean($env.AUDIT_LOG_WEBHOOK_URL) && /^https:\/\//i.test(String($env.AUDIT_LOG_WEBHOOK_URL)); } catch (error) { forward = false; }
  return [{
    json: {
      audit: entry,
      forward,
      response: { status: !s.apply ? (s.plan.action === 'skip' ? 'skipped' : 'dry_run') : 'written', writeMode: s.writeMode, plan: s.plan }
    }
  }];
}

function logFailureGlue() {
  const failure = $input.first().json;
  let event = null;
  let plan = null;
  let writeMode = null;
  try { const s = $('Build Consent Plan').first().json; event = s.event; plan = s.plan; writeMode = s.writeMode; } catch (error) { /* failed before planning */ }
  const message = failure && failure.error ? (failure.error.message || JSON.stringify(failure.error)).slice(0, 500) : 'unknown_error';
  const entry = buildAuditEntry(event, plan, 'failed', writeMode, new Date().toISOString());
  entry.error = message;
  console.error('[consent-audit]', JSON.stringify(entry));
  return [{ json: { status: 'error', error: message, audit: entry } }];
}
/* eslint-enable no-undef */

function codeNode(name, id, position, cores, body, extra) {
  return Object.assign({
    parameters: { jsCode: '// GENERATED by scripts/build-workflow.js from src/. Edit src/, then rebuild.\n' + cores.concat([body]).join('\n\n') + '\n' },
    id: id, name: name, type: 'n8n-nodes-base.code', typeVersion: 2, position: position
  }, extra || {});
}

function ifNode(name, id, position, expression) {
  return {
    parameters: {
      conditions: {
        options: { caseSensitive: true, leftValue: '', typeValidation: 'strict' },
        conditions: [{ id: id + '-condition', leftValue: expression, rightValue: true, operator: { type: 'boolean', operation: 'true', singleValue: true } }],
        combinator: 'and'
      },
      options: {}
    },
    id: id, name: name, type: 'n8n-nodes-base.if', typeVersion: 2, position: position
  };
}

function respondNode(name, id, position, code, body) {
  return {
    parameters: { respondWith: 'json', responseBody: body, options: { responseCode: code } },
    id: id, name: name, type: 'n8n-nodes-base.respondToWebhook', typeVersion: 1.1, position: position
  };
}

const HUBSPOT_CREDENTIAL = {
  hubspotAppToken: { id: 'your_n8n_hubspot_credential_id_here', name: 'HubSpot Private App (your_credential_name_here)' }
};
const CATCH = { onError: 'continueErrorOutput', retryOnFail: true, maxTries: 3, waitBetweenTries: 1500 };
const BASE = "{{ $('" + N.verify + "').first().json.config.hubspotBaseUrl }}";
const PLAN = "$('" + N.plan + "').first().json";

function hubspotNode(name, id, position, method, apiPath, extra, settings) {
  return Object.assign({
    parameters: Object.assign({
      method: method,
      url: '=' + BASE + apiPath,
      authentication: 'predefinedCredentialType',
      nodeCredentialType: 'hubspotAppToken',
      options: {}
    }, extra || {}),
    id: id, name: name, type: 'n8n-nodes-base.httpRequest', typeVersion: 4.2, position: position,
    credentials: HUBSPOT_CREDENTIAL
  }, settings || CATCH);
}

function jsonBody(expression) {
  return { sendBody: true, specifyBody: 'json', jsonBody: '={{ JSON.stringify(' + expression + ') }}' };
}

function buildWorkflow() {
  const configCore = extractCore('src/config.js', 'config');
  const consentCore = extractCore('src/consent.js', 'consent');
  const example = JSON.parse(fs.readFileSync(path.join(ROOT, 'config', 'consent-mapping.example.json'), 'utf8'));
  const mappingConst = '// Example mapping. Used ONLY in dry run when CONSENT_MAPPING_JSON is blank.\nconst EXAMPLE_MAPPING = ' + JSON.stringify(example) + ';';
  let counter = 0;
  const id = function () { counter++; return '7007a000-0000-4000-8000-' + String(counter).padStart(12, '0'); };

  const nodes = [
    {
      parameters: { httpMethod: 'POST', path: 'consent-preference-sync', responseMode: 'responseNode', options: { rawBody: true } },
      id: id(), name: N.webhook, type: 'n8n-nodes-base.webhook', typeVersion: 2, position: [0, 300], webhookId: '8008b000-0000-4000-8000-000000000001'
    },
    codeNode(N.verify, id(), [220, 300], [configCore, consentCore, mappingConst], bodyOf(verifyGlue), { onError: 'continueErrorOutput' }),
    ifNode(N.accepted, id(), [440, 300], '={{ $json.accepted }}'),
    codeNode(N.logRejection, id(), [660, 520], [consentCore], bodyOf(logRejectionGlue)),
    respondNode(N.rejected, id(), [880, 520], '={{ $json.httpStatus }}', "={{ JSON.stringify({ status: 'rejected', reason: $json.reason, errors: $json.errors }) }}"),
    hubspotNode(N.account, id(), [660, 200], 'GET', '/account-info/v3/details'),
    codeNode(N.gate, id(), [880, 200], [configCore], bodyOf(gateGlue), { onError: 'continueErrorOutput' }),
    hubspotNode(N.lookup, id(), [1100, 200], 'POST', '/crm/v3/objects/contacts/search',
      Object.assign(jsonBody('$json.contactLookup.body'), { options: { response: { response: { fullResponse: true, neverError: true } } } }),
      { onError: 'continueRegularOutput', retryOnFail: true, maxTries: 3, waitBetweenTries: 1500 }),
    codeNode(N.plan, id(), [1320, 200], [configCore, consentCore], bodyOf(planGlue), { onError: 'continueErrorOutput' }),
    ifNode(N.apply, id(), [1540, 200], '={{ $json.apply }}'),
    ifNode(N.subsGate, id(), [1760, 80], '={{ $json.hasSubscriptionChanges }}'),
    hubspotNode(N.subs, id(), [1980, -20], 'POST', '/communication-preferences/v4/statuses/batch/write', jsonBody(PLAN + '.plan.subscriptionChanges')),
    ifNode(N.globalGate, id(), [2200, 80], '={{ ' + PLAN + '.globalUnsubscribe }}'),
    hubspotNode(N.global, id(), [2420, -20], 'POST', "/communication-preferences/v4/statuses/{{ encodeURIComponent(" + PLAN + ".event.email) }}/unsubscribe-all", {
      sendQuery: true, queryParameters: { parameters: [{ name: 'channel', value: 'EMAIL' }] }
    }),
    ifNode(N.createGate, id(), [2640, 80], '={{ ' + PLAN + '.createContact }}'),
    hubspotNode(N.create, id(), [2860, -20], 'POST', '/crm/v3/objects/contacts',
      Object.assign(jsonBody('{ properties: ' + PLAN + '.plan.properties }'), { options: { response: { response: { fullResponse: true, neverError: true } } } })),
    codeNode(N.resolve, id(), [3080, 80], [consentCore], bodyOf(resolveGlue), { onError: 'continueErrorOutput' }),
    ifNode(N.patchGate, id(), [3300, 80], '={{ $json.needsPatch }}'),
    hubspotNode(N.patch, id(), [3520, -20], 'PATCH', '/crm/v3/objects/contacts/{{ $json.contactId }}', jsonBody('{ properties: $json.properties }')),
    ifNode(N.ticketGate, id(), [3740, 80], '={{ ' + PLAN + '.hasReviewTicket }}'),
    hubspotNode(N.ticket, id(), [3960, -20], 'POST', '/crm/v3/objects/tickets', jsonBody(
      "Object.assign({ properties: " + PLAN + ".plan.reviewTicket.properties }, $('" + N.resolve + "').first().json.contactId ? { associations: [{ to: { id: $('" + N.resolve + "').first().json.contactId }, types: [{ associationCategory: 'HUBSPOT_DEFINED', associationTypeId: " + PLAN + ".plan.reviewTicket.associationTypeId }] }] } : {})"
    )),
    codeNode(N.audit, id(), [4180, 300], [consentCore], bodyOf(auditGlue)),
    ifNode(N.forwardGate, id(), [4400, 300], '={{ $json.forward }}'),
    {
      parameters: {
        method: 'POST', url: '={{ $env.AUDIT_LOG_WEBHOOK_URL }}', sendBody: true, specifyBody: 'json',
        jsonBody: '={{ JSON.stringify($json.audit) }}', options: { timeout: 15000 }
      },
      id: id(), name: N.forward, type: 'n8n-nodes-base.httpRequest', typeVersion: 4.2, position: [4620, 200],
      onError: 'continueRegularOutput', retryOnFail: true, maxTries: 2, waitBetweenTries: 2000
    },
    respondNode(N.ok, id(), [4840, 300], 200, "={{ JSON.stringify($('" + N.audit + "').first().json.response) }}"),
    codeNode(N.logFailure, id(), [2640, 640], [consentCore], bodyOf(logFailureGlue)),
    respondNode(N.failed, id(), [2860, 640], 502, '={{ JSON.stringify({ status: $json.status, error: $json.error }) }}')
  ];

  const connections = {};
  const link = function (from, to, output) {
    const index = output || 0;
    connections[from] = connections[from] || { main: [] };
    while (connections[from].main.length <= index) connections[from].main.push([]);
    connections[from].main[index].push({ node: to, type: 'main', index: 0 });
  };
  link(N.webhook, N.verify);
  link(N.verify, N.accepted, 0);
  link(N.verify, N.logFailure, 1);
  link(N.accepted, N.account, 0);
  link(N.accepted, N.logRejection, 1);
  link(N.logRejection, N.rejected);
  link(N.account, N.gate, 0);
  link(N.account, N.logFailure, 1);
  link(N.gate, N.lookup, 0);
  link(N.gate, N.logFailure, 1);
  link(N.lookup, N.plan);
  link(N.plan, N.apply, 0);
  link(N.plan, N.logFailure, 1);
  link(N.apply, N.subsGate, 0);
  link(N.apply, N.audit, 1);
  link(N.subsGate, N.subs, 0);
  link(N.subsGate, N.globalGate, 1);
  link(N.subs, N.globalGate, 0);
  link(N.subs, N.logFailure, 1);
  link(N.globalGate, N.global, 0);
  link(N.globalGate, N.createGate, 1);
  link(N.global, N.createGate, 0);
  link(N.global, N.logFailure, 1);
  link(N.createGate, N.create, 0);
  link(N.createGate, N.resolve, 1);
  link(N.create, N.resolve, 0);
  link(N.create, N.logFailure, 1);
  link(N.resolve, N.patchGate, 0);
  link(N.resolve, N.logFailure, 1);
  link(N.patchGate, N.patch, 0);
  link(N.patchGate, N.ticketGate, 1);
  link(N.patch, N.ticketGate, 0);
  link(N.patch, N.logFailure, 1);
  link(N.ticketGate, N.ticket, 0);
  link(N.ticketGate, N.audit, 1);
  link(N.ticket, N.audit, 0);
  link(N.ticket, N.logFailure, 1);
  link(N.audit, N.forwardGate);
  link(N.forwardGate, N.forward, 0);
  link(N.forwardGate, N.ok, 1);
  link(N.forward, N.ok);
  link(N.logFailure, N.failed);

  return {
    name: 'HubSpot GDPR / CCPA Consent Preference Sync (DRY RUN + SANDBOX by default)',
    nodes: nodes,
    connections: connections,
    active: false,
    settings: { executionOrder: 'v1', saveManualExecutions: true, callerPolicy: 'workflowsFromSameOwner' },
    pinData: {},
    meta: { templateCredsSetupCompleted: false },
    tags: []
  };
}

function render() {
  return JSON.stringify(buildWorkflow(), null, 2) + '\n';
}

if (require.main === module) {
  const output = render();
  if (process.argv.includes('--check')) {
    const current = fs.existsSync(OUTPUT) ? fs.readFileSync(OUTPUT, 'utf8') : '';
    if (current !== output) {
      process.stderr.write('workflow.json is out of date. Run: npm run build:workflow\n');
      process.exitCode = 1;
    } else {
      process.stdout.write('workflow.json is in sync with src/.\n');
    }
  } else {
    fs.writeFileSync(OUTPUT, output);
    process.stdout.write('Wrote ' + path.relative(process.cwd(), OUTPUT) + '\n');
  }
}

module.exports = { buildWorkflow, render, extractCore, bodyOf, NODES: N };
