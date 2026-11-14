'use strict';

/**
 * consent.js
 *
 * Core consent logic. It runs identically in Node.js and in the n8n Code nodes
 * (scripts/build-workflow.js embeds the n8n-core:consent region verbatim). It is
 * pure: no network, no clock, no crypto. The caller passes in the time and an
 * HMAC function.
 *
 *   verifySignature()        HMAC-SHA256 over "<timestamp>.<raw body>", with a replay window
 *   validateMapping()        checks config/consent-mapping*.json before anything runs
 *   normalizeConsentEvent()  provider payload -> canonical consent event, driven by
 *                            per-provider field paths, category aliases, and value lists
 *   resolveJurisdiction()    country / region -> GDPR, CCPA, US_STATE_PRIVACY, or OTHER,
 *                            each with an opt_in or opt_out consent model
 *   buildConsentPlan()       the compliance decision: HubSpot properties, marketing
 *                            unsubscribes, global unsubscribe, processing restriction,
 *                            and an optional review ticket
 *
 * Compliance rules I enforce in code, whatever the mapping says:
 *   - This pipeline never subscribes anyone. Accepting marketing cookies is not
 *     consent to marketing email, so opt-ins are recorded but never acted on.
 *   - A processing restriction or global unsubscribe is never lifted automatically.
 *   - Older (out-of-order) events and replayed receipts never overwrite newer state.
 *   - In opt-in jurisdictions, a category the banner did not report counts as denied.
 *   - Essential ("necessary") cookies are always recorded as granted.
 */

// <n8n-core:consent>
const CANONICAL_CATEGORIES = ['necessary', 'functional', 'analytics', 'marketing', 'sale_sharing'];
const OPTIONAL_CATEGORIES = ['functional', 'analytics', 'marketing', 'sale_sharing'];
const REQUIRED_PROPERTY_KEYS = [
  'necessary', 'functional', 'analytics', 'marketing', 'sale_sharing', 'do_not_sell', 'jurisdiction',
  'consent_model', 'gpc', 'processing_restricted', 'last_updated', 'source', 'receipt_id', 'policy_version'
];
const RULE_KEYS = [
  'unsubscribe_marketing_on_denial', 'global_unsubscribe_on_full_withdrawal', 'global_unsubscribe_on_explicit_request',
  'restrict_processing_on_request', 'restrict_processing_on_full_withdrawal_gdpr', 'honor_gpc_as_do_not_sell'
];
const REVIEW_TRIGGERS = ['processing_restricted', 'global_unsubscribe', 'do_not_sell'];
const LEGAL_BASES = [
  'LEGITIMATE_INTEREST_PQL', 'LEGITIMATE_INTEREST_CLIENT', 'LEGITIMATE_INTEREST_OTHER', 'PERFORMANCE_OF_CONTRACT',
  'CONSENT_WITH_NOTICE', 'NON_GDPR', 'PROCESS_AND_STORE'
];
const CONSENT_EMAIL_SHAPE = /^[^\s@<>()"',;:]+@[a-z0-9-]+(\.[a-z0-9-]+)+$/;
const CONSENT_PLACEHOLDER = /^your_[a-z0-9_]+_here$/i;
const PROPERTY_NAME_SHAPE = /^[a-z][a-z0-9_]{0,99}$/;
const FUTURE_SKEW_MS = 10 * 60 * 1000;
// HUBSPOT_DEFINED association: ticket -> contact.
const TICKET_TO_CONTACT_ASSOCIATION = 16;

function conBlank(value) {
  return value === undefined || value === null || (typeof value === 'string' && value.trim() === '');
}

function getPath(obj, path) {
  if (conBlank(path)) return undefined;
  return String(path).split('.').reduce(function (acc, key) {
    if (acc === undefined || acc === null) return undefined;
    return acc[key];
  }, obj);
}

function conEmail(value) {
  if (conBlank(value) || typeof value !== 'string') return null;
  const email = value.trim().toLowerCase();
  return CONSENT_EMAIL_SHAPE.test(email) && email.length <= 254 ? email : null;
}

function conIso(value) {
  if (conBlank(value)) return null;
  const text = String(value).trim();
  let ms;
  if (typeof value === 'number' || /^\d+(\.\d+)?$/.test(text)) {
    const n = Number(text);
    ms = n < 1e12 ? Math.round(n * 1000) : Math.round(n);
  } else {
    ms = Date.parse(text);
  }
  return Number.isFinite(ms) ? new Date(ms).toISOString() : null;
}

function conMs(value) {
  const iso = conIso(value);
  return iso ? Date.parse(iso) : null;
}

function conFlag(value) {
  if (value === true || value === false) return value;
  if (conBlank(value)) return null;
  const v = String(value).trim().toLowerCase();
  if (v === 'true' || v === '1' || v === 'yes') return true;
  if (v === 'false' || v === '0' || v === 'no') return false;
  return null;
}

function conText(value, max) {
  if (conBlank(value) || typeof value === 'object') return null;
  const text = String(value).replace(/[\u0000-\u001f\u007f]+/g, ' ').replace(/\s+/g, ' ').trim();
  return text.length > max ? text.slice(0, max) : text;
}

function hashIdentifier(value) {
  // FNV-1a 64-bit pseudonymous ID for logs. Pseudonymization, not anonymization.
  let hash = BigInt('0xcbf29ce484222325');
  const prime = BigInt('0x100000001b3');
  const mask = BigInt('0xffffffffffffffff');
  const text = unescape(encodeURIComponent(String(value || '')));
  for (let i = 0; i < text.length; i++) {
    hash = hash ^ BigInt(text.charCodeAt(i));
    hash = (hash * prime) & mask;
  }
  return 'h_' + hash.toString(16).padStart(16, '0');
}

function constantTimeEquals(a, b) {
  const x = String(a);
  const y = String(b);
  let diff = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i++) diff |= (x.charCodeAt(i) || 0) ^ (y.charCodeAt(i) || 0);
  return diff === 0;
}

/**
 * Relay contract: X-Consent-Timestamp: <unix seconds>
 *                 X-Consent-Signature: sha256=<hex HMAC-SHA256(secret, "<timestamp>.<raw body>")>
 */
function verifySignature(rawBody, signatureHeader, timestampHeader, secret, nowMs, toleranceSeconds, hmacHex) {
  if (conBlank(secret) || CONSENT_PLACEHOLDER.test(String(secret).trim())) return { ok: false, reason: 'signing_secret_not_configured' };
  if (conBlank(signatureHeader) || conBlank(timestampHeader)) return { ok: false, reason: 'signature_headers_missing' };
  const ts = String(timestampHeader).trim();
  const sig = String(signatureHeader).trim().replace(/^sha256=/i, '');
  if (!/^\d+$/.test(ts) || !/^[0-9a-f]{64}$/i.test(sig)) return { ok: false, reason: 'signature_headers_malformed' };
  if (Math.abs(nowMs - Number(ts) * 1000) > toleranceSeconds * 1000) return { ok: false, reason: 'signature_timestamp_outside_tolerance' };
  const expected = String(hmacHex(secret, ts + '.' + rawBody)).toLowerCase();
  return constantTimeEquals(expected, sig.toLowerCase()) ? { ok: true, reason: null } : { ok: false, reason: 'signature_mismatch' };
}

function validateMapping(mapping) {
  const errors = [];
  const warnings = [];
  const m = mapping && typeof mapping === 'object' ? mapping : {};
  if (m.version !== 1) errors.push('version must be 1');
  const cats = Array.isArray(m.canonical_categories) ? m.canonical_categories : [];
  if (cats.length !== CANONICAL_CATEGORIES.length || CANONICAL_CATEGORIES.some(function (c) { return cats.indexOf(c) === -1; })) {
    errors.push('canonical_categories must be exactly: ' + CANONICAL_CATEGORIES.join(', '));
  }

  const props = m.hubspot_properties && typeof m.hubspot_properties === 'object' ? m.hubspot_properties : {};
  const seenProps = {};
  REQUIRED_PROPERTY_KEYS.forEach(function (key) {
    const name = props[key];
    if (!PROPERTY_NAME_SHAPE.test(String(name || ''))) errors.push('hubspot_properties.' + key + ' must be a HubSpot internal property name');
    else if (seenProps[name]) errors.push('hubspot_properties.' + key + ' reuses property ' + name);
    else seenProps[name] = true;
  });

  const providers = m.providers && typeof m.providers === 'object' ? m.providers : {};
  if (!Object.keys(providers).length) errors.push('providers must define at least one provider');
  Object.keys(providers).forEach(function (name) {
    const p = providers[name] || {};
    const label = 'providers.' + name;
    if (!/^[a-z0-9_-]+$/.test(name)) errors.push(label + ': provider keys must be lowercase');
    if (!p.paths || conBlank(p.paths.email) || conBlank(p.paths.occurred_at)) errors.push(label + '.paths needs email and occurred_at');
    const c = p.categories || {};
    if (conBlank(c.path)) errors.push(label + '.categories.path is required');
    if (c.format !== 'object' && c.format !== 'array') errors.push(label + '.categories.format must be "object" or "array"');
    if (c.format === 'array' && (conBlank(c.key_field) || conBlank(c.value_field))) errors.push(label + '.categories needs key_field and value_field for arrays');
    Object.keys(c.aliases || {}).forEach(function (raw) {
      const target = c.aliases[raw];
      const category = typeof target === 'object' && target ? target.category : target;
      if (CANONICAL_CATEGORIES.indexOf(category) === -1) errors.push(label + '.categories.aliases.' + raw + ' maps to unknown category "' + category + '"');
    });
    if (!Object.keys(c.aliases || {}).length) errors.push(label + '.categories.aliases is empty');
    const granted = Array.isArray(p.granted_values) ? p.granted_values.map(function (v) { return String(v).toLowerCase(); }) : [];
    const denied = Array.isArray(p.denied_values) ? p.denied_values.map(function (v) { return String(v).toLowerCase(); }) : [];
    if (!granted.length || !denied.length) errors.push(label + ' needs granted_values and denied_values');
    granted.forEach(function (v) { if (denied.indexOf(v) !== -1) errors.push(label + ': value "' + v + '" is both granted and denied'); });
  });

  const juris = m.jurisdictions && typeof m.jurisdictions === 'object' ? m.jurisdictions : {};
  if (!juris.OTHER) errors.push('jurisdictions.OTHER is required as the fallback');
  Object.keys(juris).forEach(function (code) {
    const j = juris[code] || {};
    if (j.model !== 'opt_in' && j.model !== 'opt_out') errors.push('jurisdictions.' + code + '.model must be opt_in or opt_out');
    if (code !== 'OTHER' && (!Array.isArray(j.countries) || !j.countries.length)) errors.push('jurisdictions.' + code + '.countries is required');
    (j.countries || []).concat(j.regions || []).forEach(function (cc) {
      if (!/^[A-Z]{2}$/.test(String(cc))) errors.push('jurisdictions.' + code + ': "' + cc + '" must be a 2-letter uppercase code');
    });
  });
  if (juris.GDPR && juris.GDPR.model !== 'opt_in') errors.push('jurisdictions.GDPR.model must be opt_in');

  const subs = m.subscriptions && typeof m.subscriptions === 'object' ? m.subscriptions : {};
  const ids = Array.isArray(subs.marketing_subscription_ids) ? subs.marketing_subscription_ids : [];
  ids.forEach(function (id) {
    const text = String(id);
    if (CONSENT_PLACEHOLDER.test(text)) warnings.push('subscriptions.marketing_subscription_ids contains a placeholder; per-type unsubscribes are skipped until it is replaced');
    else if (!/^\d+$/.test(text)) errors.push('subscriptions.marketing_subscription_ids must be numeric HubSpot subscription type IDs');
  });
  if (LEGAL_BASES.indexOf(subs.legal_basis) === -1) errors.push('subscriptions.legal_basis must be one of: ' + LEGAL_BASES.join(', '));

  const rules = m.rules && typeof m.rules === 'object' ? m.rules : {};
  RULE_KEYS.forEach(function (key) { if (typeof rules[key] !== 'boolean') errors.push('rules.' + key + ' must be true or false'); });
  (rules.review_ticket_on || []).forEach(function (t) { if (REVIEW_TRIGGERS.indexOf(t) === -1) errors.push('rules.review_ticket_on: unknown trigger "' + t + '"'); });

  return { ok: errors.length === 0, errors: errors, warnings: warnings };
}

function readState(value, provider) {
  if (value === undefined || value === null) return null;
  const v = typeof value === 'boolean' ? String(value) : String(value).trim().toLowerCase();
  const granted = provider.granted_values.map(function (x) { return String(x).toLowerCase(); });
  const denied = provider.denied_values.map(function (x) { return String(x).toLowerCase(); });
  if (granted.indexOf(v) !== -1) return true;
  if (denied.indexOf(v) !== -1) return false;
  return null;
}

function aliasFor(aliases, rawKey) {
  if (Object.prototype.hasOwnProperty.call(aliases, rawKey)) return aliases[rawKey];
  const lower = String(rawKey).toLowerCase();
  const key = Object.keys(aliases).find(function (k) { return k.toLowerCase() === lower; });
  return key ? aliases[key] : null;
}

function normalizeConsentEvent(body, mapping, nowMs) {
  const errors = [];
  const warnings = [];
  if (!body || typeof body !== 'object' || Array.isArray(body)) return { ok: false, errors: ['payload_must_be_a_json_object'], warnings: warnings, event: null };
  const providerName = String(body.provider || '').trim().toLowerCase();
  const provider = mapping.providers[providerName];
  if (!provider) return { ok: false, errors: ['unknown_provider:' + (providerName || 'missing')], warnings: warnings, event: null };
  const paths = provider.paths;

  const email = conEmail(getPath(body, paths.email));
  if (!email) errors.push('email_missing_or_invalid');
  const occurredAt = conIso(getPath(body, paths.occurred_at));
  if (!occurredAt) errors.push('occurred_at_missing_or_invalid');
  else if (Date.parse(occurredAt) > nowMs + FUTURE_SKEW_MS) errors.push('occurred_at_in_future');

  const categories = {};
  CANONICAL_CATEGORIES.forEach(function (c) { categories[c] = null; });
  const container = getPath(body, provider.categories.path);
  const entries = [];
  if (provider.categories.format === 'object' && container && typeof container === 'object' && !Array.isArray(container)) {
    Object.keys(container).forEach(function (k) { entries.push([k, container[k]]); });
  } else if (provider.categories.format === 'array' && Array.isArray(container)) {
    container.forEach(function (row) { if (row && typeof row === 'object') entries.push([row[provider.categories.key_field], row[provider.categories.value_field]]); });
  } else {
    errors.push('consent_categories_missing');
  }
  const ignored = (provider.categories.ignore_keys || []).map(function (k) { return String(k).toLowerCase(); });
  entries.forEach(function (pair) {
    if (ignored.indexOf(String(pair[0]).toLowerCase()) !== -1) return;
    const target = aliasFor(provider.categories.aliases, pair[0]);
    if (!target) { warnings.push('unmapped_category:' + conText(pair[0], 60)); return; }
    const category = typeof target === 'object' ? target.category : target;
    let state = readState(pair[1], provider);
    if (state === null) { warnings.push('unrecognized_value_for:' + conText(pair[0], 60)); return; }
    if (typeof target === 'object' && target.invert) state = !state;
    // Several raw categories can map to one canonical category: any denial wins.
    categories[category] = categories[category] === false ? false : state;
  });
  if (errors.length) return { ok: false, errors: errors, warnings: warnings, event: null };

  const country = conText(getPath(body, paths.country), 2);
  const region = conText(getPath(body, paths.region), 10);
  const receiptId = conText(getPath(body, paths.receipt_id), 200);
  const eventId = conText(getPath(body, paths.event_id), 200);
  return {
    ok: true,
    errors: [],
    warnings: warnings,
    event: {
      provider: providerName,
      eventId: eventId || hashIdentifier(email + '|' + occurredAt + '|' + JSON.stringify(categories)),
      email: email,
      emailHash: hashIdentifier(email),
      occurredAt: occurredAt,
      country: country ? country.toUpperCase() : null,
      region: region ? region.toUpperCase().replace(/^US-/, '') : null,
      receiptId: receiptId,
      policyVersion: conText(getPath(body, paths.policy_version), 60),
      categories: categories,
      signals: {
        gpc: conFlag(getPath(body, paths.gpc)) === true,
        doNotSell: conFlag(getPath(body, paths.do_not_sell)) === true,
        unsubscribeAll: conFlag(getPath(body, paths.unsubscribe_all)) === true,
        restrictProcessing: conFlag(getPath(body, paths.restrict_processing)) === true,
        emailMarketingOptIn: conFlag(getPath(body, paths.email_marketing_opt_in)) === true
      }
    }
  };
}

function resolveJurisdiction(country, region, mapping) {
  const j = mapping.jurisdictions;
  const codes = Object.keys(j).filter(function (c) { return c !== 'OTHER'; })
    .sort(function (a, b) { return (j[b].regions ? 1 : 0) - (j[a].regions ? 1 : 0); });
  for (let i = 0; i < codes.length; i++) {
    const def = j[codes[i]];
    if (!country || def.countries.indexOf(country) === -1) continue;
    if (Array.isArray(def.regions) && def.regions.length && def.regions.indexOf(region) === -1) continue;
    return { code: codes[i], model: def.model };
  }
  return { code: 'OTHER', model: j.OTHER.model };
}

function storedFlag(props, name) {
  if (!props || conBlank(props[name])) return null;
  return String(props[name]).trim().toLowerCase() === 'true';
}

function buildConsentPlan(input) {
  const event = input.event;
  const mapping = input.mapping;
  const cfg = input.config;
  const contact = input.contact || { found: false, contactId: null, properties: {} };
  const stored = contact.properties || {};
  const P = mapping.hubspot_properties;
  const rules = mapping.rules;
  const warnings = [];
  const decisions = {};
  const jurisdiction = resolveJurisdiction(event.country, event.region, mapping);
  const base = { email: event.email, emailHash: event.emailHash, contactId: contact.contactId || null, jurisdiction: jurisdiction };

  if (!contact.found && !cfg.createMissingContacts) {
    return Object.assign(base, { action: 'skip', reason: 'contact_not_found', properties: {}, subscriptionChanges: null, globalUnsubscribe: false, restrictProcessing: false, reviewTicket: null, decisions: decisions, warnings: warnings });
  }
  const storedMs = conMs(stored[P.last_updated]);
  const eventMs = Date.parse(event.occurredAt);
  if (storedMs !== null && eventMs < storedMs) {
    return Object.assign(base, { action: 'skip', reason: 'stale_event_older_than_stored_consent', properties: {}, subscriptionChanges: null, globalUnsubscribe: false, restrictProcessing: false, reviewTicket: null, decisions: decisions, warnings: warnings });
  }
  if (event.receiptId && stored[P.receipt_id] === event.receiptId) {
    return Object.assign(base, { action: 'skip', reason: 'duplicate_receipt', properties: {}, subscriptionChanges: null, globalUnsubscribe: false, restrictProcessing: false, reviewTicket: null, decisions: decisions, warnings: warnings });
  }

  // 1. Effective category states under the jurisdiction's consent model.
  const effective = {};
  effective.necessary = true;
  decisions.necessary = event.categories.necessary === false ? 'essential_always_recorded_granted' : 'granted';
  OPTIONAL_CATEGORIES.forEach(function (c) {
    const reported = event.categories[c];
    if (reported !== null) {
      effective[c] = reported;
      decisions[c] = reported ? 'granted' : 'denied';
    } else if (jurisdiction.model === 'opt_in') {
      effective[c] = false;
      decisions[c] = 'not_reported_opt_in_treated_as_denied';
    } else {
      const previous = storedFlag(stored, P[c]);
      effective[c] = previous === null ? true : previous;
      decisions[c] = previous === null ? 'not_reported_opt_out_default_allowed' : 'not_reported_kept_previous';
    }
  });
  if (event.signals.doNotSell && effective.sale_sharing) { effective.sale_sharing = false; decisions.sale_sharing = 'do_not_sell_request'; }
  if (event.signals.gpc && rules.honor_gpc_as_do_not_sell && effective.sale_sharing) { effective.sale_sharing = false; decisions.sale_sharing = 'gpc_signal_opt_out'; }

  // 2. Subscription actions. This pipeline only ever removes subscriptions.
  const fullWithdrawal = OPTIONAL_CATEGORIES.filter(function (c) { return c !== 'sale_sharing'; }).every(function (c) { return effective[c] === false; });
  let subscriptionChanges = null;
  if (!effective.marketing && rules.unsubscribe_marketing_on_denial) {
    const ids = (mapping.subscriptions.marketing_subscription_ids || []).filter(function (id) { return /^\d+$/.test(String(id)); });
    if (ids.length) {
      subscriptionChanges = {
        inputs: ids.map(function (id) {
          return {
            subscriberIdString: event.email,
            channel: 'EMAIL',
            statusState: 'NOT_SUBSCRIBED',
            subscriptionId: Number(id),
            legalBasis: mapping.subscriptions.legal_basis,
            legalBasisExplanation: conText(mapping.subscriptions.legal_basis_explanation, 500) || 'Consent withdrawn via consent banner.'
          };
        })
      };
    } else {
      warnings.push('marketing_denied_but_no_subscription_type_ids_configured');
    }
  }
  const globalUnsubscribe = (event.signals.unsubscribeAll && rules.global_unsubscribe_on_explicit_request) ||
    (fullWithdrawal && rules.global_unsubscribe_on_full_withdrawal);
  if (event.categories.marketing === true || event.signals.emailMarketingOptIn) {
    warnings.push('opt_in_recorded_only_this_pipeline_never_subscribes_contacts');
  }

  // 3. Processing restriction. Never lifted automatically.
  const alreadyRestricted = storedFlag(stored, P.processing_restricted) === true;
  const requested = event.signals.restrictProcessing && rules.restrict_processing_on_request;
  const gdprWithdrawal = jurisdiction.code === 'GDPR' && fullWithdrawal && rules.restrict_processing_on_full_withdrawal_gdpr;
  const restrictProcessing = alreadyRestricted || requested || gdprWithdrawal;
  if (alreadyRestricted && !requested) decisions.processing_restricted = 'kept_existing_restriction_requires_manual_review_to_lift';
  else if (restrictProcessing) decisions.processing_restricted = requested ? 'restriction_requested' : 'gdpr_full_withdrawal_rule';

  // 4. HubSpot properties.
  const properties = {};
  CANONICAL_CATEGORIES.forEach(function (c) { properties[P[c]] = String(effective[c]); });
  properties[P.do_not_sell] = String(!effective.sale_sharing);
  properties[P.jurisdiction] = jurisdiction.code;
  properties[P.consent_model] = jurisdiction.model;
  properties[P.gpc] = String(event.signals.gpc);
  properties[P.processing_restricted] = String(restrictProcessing);
  properties[P.last_updated] = String(eventMs);
  properties[P.source] = event.provider;
  properties[P.receipt_id] = event.receiptId || event.eventId;
  if (event.policyVersion) properties[P.policy_version] = event.policyVersion;
  if (!contact.found) properties.email = event.email;
  if (contact.found) {
    Object.keys(properties).forEach(function (k) {
      if (k === P.last_updated) return;
      if (!conBlank(stored[k]) && String(stored[k]) === properties[k]) delete properties[k];
    });
  }

  // 5. Review ticket for the privacy team.
  const triggers = [];
  const reviewOn = rules.review_ticket_on || [];
  if (restrictProcessing && !alreadyRestricted && reviewOn.indexOf('processing_restricted') !== -1) triggers.push('processing_restricted');
  if (globalUnsubscribe && reviewOn.indexOf('global_unsubscribe') !== -1) triggers.push('global_unsubscribe');
  if (!effective.sale_sharing && storedFlag(stored, P.do_not_sell) !== true && reviewOn.indexOf('do_not_sell') !== -1) triggers.push('do_not_sell');
  let reviewTicket = null;
  if (triggers.length && cfg.reviewTicket) {
    reviewTicket = {
      properties: {
        subject: 'Privacy review: ' + triggers.join(', ') + ' (' + jurisdiction.code + ')',
        content: 'Automated consent sync recorded: ' + triggers.join(', ') + '. Source: ' + event.provider + ', receipt ' + (event.receiptId || event.eventId) +
          ', occurred ' + event.occurredAt + '. Verify downstream systems honour this request.',
        hs_pipeline: cfg.reviewTicket.pipelineId,
        hs_pipeline_stage: cfg.reviewTicket.stageId,
        hs_ticket_priority: triggers.indexOf('processing_restricted') !== -1 ? 'HIGH' : 'MEDIUM'
      },
      associationTypeId: TICKET_TO_CONTACT_ASSOCIATION,
      triggers: triggers
    };
  } else if (triggers.length) {
    warnings.push('review_ticket_triggers_present_but_TARGET_PIPELINE_ID_not_set:' + triggers.join('+'));
  }

  return Object.assign(base, {
    action: contact.found ? 'update' : 'create',
    reason: null,
    effective: effective,
    fullWithdrawal: fullWithdrawal,
    properties: properties,
    subscriptionChanges: subscriptionChanges,
    globalUnsubscribe: globalUnsubscribe,
    restrictProcessing: restrictProcessing,
    reviewTicket: reviewTicket,
    decisions: decisions,
    warnings: warnings
  });
}

function buildContactLookup(email, mapping) {
  const P = mapping.hubspot_properties;
  return {
    method: 'POST',
    path: '/crm/v3/objects/contacts/search',
    body: {
      filterGroups: [{ filters: [{ propertyName: 'email', operator: 'EQ', value: email }] }],
      properties: ['email'].concat(REQUIRED_PROPERTY_KEYS.map(function (k) { return P[k]; })),
      limit: 1
    }
  };
}

function readContactLookup(response) {
  if (!response || Number(response.statusCode) !== 200) return { ok: false, found: false, contactId: null, properties: {} };
  const results = response.body && Array.isArray(response.body.results) ? response.body.results : [];
  if (!results.length) return { ok: true, found: false, contactId: null, properties: {} };
  return { ok: true, found: true, contactId: String(results[0].id), properties: results[0].properties || {} };
}

function parseExistingContactId(body) {
  const message = body && typeof body === 'object' ? String(body.message || '') : '';
  const match = /Existing ID:\s*(\d+)/i.exec(message);
  return match ? match[1] : null;
}

function buildAuditEntry(event, plan, outcome, writeMode, atIso) {
  // No raw email in logs: only the pseudonymous hash.
  return {
    at: atIso,
    writeMode: writeMode,
    outcome: outcome,
    provider: event ? event.provider : null,
    eventId: event ? event.eventId : null,
    receiptId: event ? event.receiptId : null,
    subject: event ? event.emailHash : null,
    jurisdiction: plan && plan.jurisdiction ? plan.jurisdiction.code : null,
    action: plan ? plan.action : null,
    reason: plan ? plan.reason : null,
    unsubscribedTypes: plan && plan.subscriptionChanges ? plan.subscriptionChanges.inputs.map(function (i) { return i.subscriptionId; }) : [],
    globalUnsubscribe: Boolean(plan && plan.globalUnsubscribe),
    restrictProcessing: Boolean(plan && plan.restrictProcessing),
    reviewTicket: Boolean(plan && plan.reviewTicket),
    warnings: plan ? plan.warnings : []
  };
}
// </n8n-core:consent>

module.exports = {
  CANONICAL_CATEGORIES,
  REQUIRED_PROPERTY_KEYS,
  RULE_KEYS,
  LEGAL_BASES,
  TICKET_TO_CONTACT_ASSOCIATION,
  getPath,
  conIso,
  hashIdentifier,
  constantTimeEquals,
  verifySignature,
  validateMapping,
  readState,
  normalizeConsentEvent,
  resolveJurisdiction,
  buildConsentPlan,
  buildContactLookup,
  readContactLookup,
  parseExistingContactId,
  buildAuditEntry
};
