#!/usr/bin/env node
'use strict';

/**
 * validate-workflow.js
 *
 * Structural and safety validation for workflow.json, usable in CI:
 *
 *   node scripts/validate-workflow.js [path/to/workflow.json]
 *
 * Checks:
 *   - valid nodes / connections, unique names, no dangling links, imports inactive
 *   - credential references are placeholders only (your_..._here) and no secrets are embedded
 *   - the webhook keeps the raw body (required for HMAC signature checks)
 *   - every HubSpot write is reachable only through "Apply Changes?"
 *   - every HubSpot read after the account check is reachable only through the portal gate
 *   - HubSpot is reachable only after a passed signature / validation check
 *   - every HubSpot write routes its error output to "Log Failure"
 *   - workflow.json is in sync with src/
 */

const fs = require('node:fs');
const path = require('node:path');
const builder = require('./build-workflow');

const N = builder.NODES;
const WRITE_NODES = [N.subs, N.global, N.create, N.patch, N.ticket];
const GATED_READS = [N.lookup];
const PLACEHOLDER = /^your_[a-z0-9_]+_here$/i;
const SECRET_HINTS = [/\bpat-(?:na|eu|ap)\d-[0-9a-f]{8}-/i, /Bearer\s+[A-Za-z0-9._-]{20,}/, /\bxox[abposr]-[A-Za-z0-9-]{10,}/, /hapikey=/i];

function edgesOf(workflow) {
  const edges = [];
  Object.keys(workflow.connections || {}).forEach(function (from) {
    (workflow.connections[from].main || []).forEach(function (branch, out) {
      (branch || []).forEach(function (e) { edges.push({ from: from, out: out, to: e.node }); });
    });
  });
  return edges;
}

function reachable(workflow, start, skip) {
  const edges = edgesOf(workflow);
  const seen = new Set([start]);
  const queue = [start];
  while (queue.length) {
    const current = queue.shift();
    edges.filter(function (e) { return e.from === current && !skip(e); }).forEach(function (e) {
      if (!seen.has(e.to)) { seen.add(e.to); queue.push(e.to); }
    });
  }
  return seen;
}

function validateWorkflow(workflow, options) {
  const opts = options || {};
  const errors = [];
  if (!workflow || !Array.isArray(workflow.nodes) || typeof workflow.connections !== 'object') {
    return { ok: false, errors: ['workflow must contain nodes[] and connections{}'] };
  }
  const names = workflow.nodes.map(function (n) { return n.name; });
  if (new Set(names).size !== names.length) errors.push('node names must be unique');
  edgesOf(workflow).forEach(function (e) {
    if (names.indexOf(e.from) === -1) errors.push('connection from unknown node: ' + e.from);
    if (names.indexOf(e.to) === -1) errors.push('connection to unknown node: ' + e.to);
  });
  if (workflow.active !== false) errors.push('workflow must import inactive (active: false)');

  workflow.nodes.forEach(function (node) {
    Object.keys(node.credentials || {}).forEach(function (type) {
      if (!PLACEHOLDER.test(String(node.credentials[type].id || ''))) errors.push('node "' + node.name + '" has a non-placeholder credential ID');
    });
    const params = JSON.stringify(node.parameters || {});
    SECRET_HINTS.forEach(function (re) { if (re.test(params)) errors.push('node "' + node.name + '" appears to embed a secret'); });
  });

  const webhook = workflow.nodes.find(function (n) { return n.name === N.webhook; });
  if (!webhook) errors.push('missing webhook node');
  else if (!webhook.parameters.options || webhook.parameters.options.rawBody !== true) errors.push('webhook must keep the raw body for signature verification');

  const all = reachable(workflow, N.webhook, function () { return false; });
  WRITE_NODES.concat(GATED_READS, [N.logFailure, N.audit]).forEach(function (n) { if (!all.has(n)) errors.push('node "' + n + '" is missing or not wired'); });
  const noApplyGate = reachable(workflow, N.webhook, function (e) { return e.from === N.apply && e.out === 0; });
  WRITE_NODES.forEach(function (n) { if (noApplyGate.has(n)) errors.push('write node "' + n + '" is reachable without "' + N.apply + '"'); });
  const noPortalGate = reachable(workflow, N.webhook, function (e) { return e.from === N.gate && e.out === 0; });
  GATED_READS.concat(WRITE_NODES).forEach(function (n) { if (noPortalGate.has(n)) errors.push('node "' + n + '" is reachable without "' + N.gate + '"'); });
  const noAccepted = reachable(workflow, N.webhook, function (e) { return e.from === N.accepted && e.out === 0; });
  if (noAccepted.has(N.account)) errors.push('HubSpot is reachable without passing "' + N.accepted + '"');

  const edges = edgesOf(workflow);
  WRITE_NODES.forEach(function (n) {
    const node = workflow.nodes.find(function (x) { return x.name === n; });
    if (!node || node.onError !== 'continueErrorOutput') errors.push('write node "' + n + '" must use onError=continueErrorOutput');
    if (!edges.some(function (e) { return e.from === n && e.out === 1 && e.to === N.logFailure; })) errors.push('write node "' + n + '" must route errors to "' + N.logFailure + '"');
  });

  if (opts.text !== undefined && opts.text !== builder.render()) errors.push('workflow.json is out of sync with src/ (run npm run build:workflow)');
  return { ok: errors.length === 0, errors: errors };
}

if (require.main === module) {
  const file = path.resolve(process.argv[2] || path.join(__dirname, '..', 'workflow.json'));
  let text;
  let workflow;
  try {
    text = fs.readFileSync(file, 'utf8');
    workflow = JSON.parse(text);
  } catch (error) {
    process.stderr.write('Cannot read ' + file + ': ' + error.message + '\n');
    process.exit(1);
  }
  const result = validateWorkflow(workflow, { text: text });
  if (result.ok) {
    process.stdout.write('workflow.json is valid: ' + workflow.nodes.length + ' nodes, gates and error routes intact, placeholder credentials only, in sync with src/.\n');
  } else {
    result.errors.forEach(function (e) { process.stderr.write('✗ ' + e + '\n'); });
    process.exitCode = 1;
  }
}

module.exports = { validateWorkflow, reachable, edgesOf, WRITE_NODES };
