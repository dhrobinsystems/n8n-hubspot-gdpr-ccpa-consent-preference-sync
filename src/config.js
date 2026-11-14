'use strict';

/**
 * config.js
 *
 * Environment loader and safety gates for the consent preference sync.
 *
 * Fail-safe defaults (blank or placeholder values count as unset):
 *
 *   DRY_RUN=true            Build the full compliance plan and return it; write nothing.
 *   SANDBOX_MODE=true       Use HubSpot only after the portal is verified as a
 *                           SANDBOX or DEVELOPER_TEST account.
 *   REQUIRE_SIGNATURE=true  Reject consent webhooks without a valid HMAC signature.
 *
 * SANDBOX_MODE=false also requires ALLOW_PRODUCTION_MODE=true. Only the literal
 * string "false" turns a safety flag off. Values shaped like
 * "your_something_here" are treated as placeholders, never as real settings.
 *
 * The n8n-core:config region is embedded verbatim into the n8n Code nodes by
 * scripts/build-workflow.js, so it stays dependency-free.
 */

// <n8n-core:config>
const CONFIG_KEYS = [
  'DRY_RUN',
  'SANDBOX_MODE',
  'ALLOW_PRODUCTION_MODE',
  'REQUIRE_SIGNATURE',
  'SIGNATURE_TOLERANCE_SECONDS',
  'HUBSPOT_BASE_URL',
  'HUBSPOT_SANDBOX_PORTAL_ID',
  'CREATE_MISSING_CONTACTS',
  'TARGET_PIPELINE_ID',
  'TARGET_PIPELINE_STAGE_ID'
];

const SANDBOX_ACCOUNT_TYPES = ['SANDBOX', 'DEVELOPER_TEST'];
const PLACEHOLDER_PATTERN = /^your_[a-z0-9_]+_here$/i;

function cfgUnset(value) {
  if (value === undefined || value === null) return true;
  const text = String(value).trim();
  return text === '' || PLACEHOLDER_PATTERN.test(text);
}

function safetyFlag(value) {
  if (cfgUnset(value)) return true;
  return String(value).trim().toLowerCase() !== 'false';
}

function optInFlag(value) {
  if (cfgUnset(value)) return false;
  return String(value).trim().toLowerCase() === 'true';
}

function boundedInt(value, fallback, min, max, name) {
  if (cfgUnset(value)) return fallback;
  const parsed = Number(String(value).trim());
  if (!Number.isInteger(parsed) || parsed < min || parsed > max) {
    throw new Error(name + ' must be an integer between ' + min + ' and ' + max + ' (received "' + value + '").');
  }
  return parsed;
}

function hubspotId(value, name) {
  if (cfgUnset(value)) return null;
  const id = String(value).trim();
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(id)) throw new Error(name + ' must be a HubSpot pipeline or stage ID.');
  return id;
}

function parseConfig(env) {
  const e = env || {};
  const dryRun = safetyFlag(e.DRY_RUN);
  const sandboxMode = safetyFlag(e.SANDBOX_MODE);
  const allowProductionMode = optInFlag(e.ALLOW_PRODUCTION_MODE);
  if (!sandboxMode && !allowProductionMode) {
    throw new Error(
      'Refusing to start: SANDBOX_MODE=false changes consent and subscription status on production contacts. ' +
      'Set ALLOW_PRODUCTION_MODE=true only after validating every mapping in a HubSpot sandbox.'
    );
  }
  const baseUrl = (cfgUnset(e.HUBSPOT_BASE_URL) ? 'https://api.hubapi.com' : String(e.HUBSPOT_BASE_URL).trim()).replace(/\/+$/, '');
  if (!/^https:\/\//i.test(baseUrl)) throw new Error('HUBSPOT_BASE_URL must use https://.');
  const portal = cfgUnset(e.HUBSPOT_SANDBOX_PORTAL_ID) ? null : String(e.HUBSPOT_SANDBOX_PORTAL_ID).trim();
  if (portal && !/^\d+$/.test(portal)) throw new Error('HUBSPOT_SANDBOX_PORTAL_ID must be numeric.');

  const pipelineId = hubspotId(e.TARGET_PIPELINE_ID, 'TARGET_PIPELINE_ID');
  const stageId = hubspotId(e.TARGET_PIPELINE_STAGE_ID, 'TARGET_PIPELINE_STAGE_ID');
  if ((pipelineId && !stageId) || (!pipelineId && stageId)) {
    throw new Error('TARGET_PIPELINE_ID and TARGET_PIPELINE_STAGE_ID must be set together (or both left blank).');
  }
  const writeMode = dryRun ? 'dry_run' : (sandboxMode ? 'sandbox' : 'production');

  return {
    dryRun: dryRun,
    sandboxMode: sandboxMode,
    allowProductionMode: allowProductionMode,
    writeMode: writeMode,
    writesEnabled: writeMode !== 'dry_run',
    requireSignature: safetyFlag(e.REQUIRE_SIGNATURE),
    signatureToleranceSeconds: boundedInt(e.SIGNATURE_TOLERANCE_SECONDS, 300, 30, 900, 'SIGNATURE_TOLERANCE_SECONDS'),
    hubspotBaseUrl: baseUrl,
    sandboxPortalId: portal,
    createMissingContacts: optInFlag(e.CREATE_MISSING_CONTACTS),
    reviewTicket: pipelineId ? { pipelineId: pipelineId, stageId: stageId } : null
  };
}

function evaluateHubSpotTarget(cfg, account) {
  if (!cfg) return { allowed: false, reason: 'missing_config' };
  if (!cfg.sandboxMode) {
    return cfg.allowProductionMode
      ? { allowed: true, reason: 'production_mode_explicitly_allowed' }
      : { allowed: false, reason: 'production_mode_not_allowed' };
  }
  const type = String((account && account.accountType) || '').toUpperCase();
  if (SANDBOX_ACCOUNT_TYPES.indexOf(type) === -1) {
    return { allowed: false, reason: 'sandbox_mode_requires_sandbox_or_developer_test_portal (received "' + (type || 'unknown') + '")' };
  }
  if (cfg.sandboxPortalId && String(account.portalId) !== cfg.sandboxPortalId) {
    return { allowed: false, reason: 'sandbox_portal_id_mismatch' };
  }
  return { allowed: true, reason: 'sandbox_portal_verified' };
}
// </n8n-core:config>

/** Full runtime config for the standalone engine, including secrets. */
function loadConfig(env) {
  const source = env || process.env;
  const settings = parseConfig(source);
  const secret = function (name) { return cfgUnset(source[name]) ? null : String(source[name]).trim(); };
  const cfg = Object.assign({}, settings, {
    hubspotPrivateAppToken: secret('HUBSPOT_PRIVATE_APP_TOKEN'),
    webhookSigningSecret: secret('WEBHOOK_SIGNING_SECRET'),
    consentMappingFile: secret('CONSENT_MAPPING_FILE'),
    auditLogWebhookUrl: secret('AUDIT_LOG_WEBHOOK_URL'),
    host: secret('HOST') || '127.0.0.1',
    port: boundedInt(source.PORT, 8791, 1, 65535, 'PORT')
  });
  if (cfg.requireSignature && !cfg.webhookSigningSecret) {
    throw new Error('REQUIRE_SIGNATURE is on (the default) but WEBHOOK_SIGNING_SECRET is blank or a placeholder.');
  }
  if (cfg.auditLogWebhookUrl && !/^https:\/\//i.test(cfg.auditLogWebhookUrl)) {
    throw new Error('AUDIT_LOG_WEBHOOK_URL must use https://.');
  }
  return Object.freeze(cfg);
}

function describeConfig(cfg) {
  const view = Object.assign({}, cfg);
  ['hubspotPrivateAppToken', 'webhookSigningSecret', 'auditLogWebhookUrl'].forEach(function (key) {
    if (key in view) view[key] = view[key] ? '[redacted]' : null;
  });
  return view;
}

module.exports = {
  CONFIG_KEYS,
  SANDBOX_ACCOUNT_TYPES,
  PLACEHOLDER_PATTERN,
  cfgUnset,
  safetyFlag,
  optInFlag,
  parseConfig,
  evaluateHubSpotTarget,
  loadConfig,
  describeConfig
};
