/**
 * Minimal AWS WAF Classic (waf-regional) JSON 1.1 API.
 * LocalStack Community returns 501 for wafv2 AND waf-regional (Pro-only).
 */
const http = require('http');
const crypto = require('crypto');

const PORT = Number(process.env.PORT || 4573);

const db = {
  tokens: new Set(),
  byteSets: new Map(),
  rules: new Map(),
  webAcls: new Map(),
};

function id() {
  return crypto.randomUUID();
}

function token() {
  const t = id();
  db.tokens.add(t);
  return t;
}

function ok(res, body) {
  const json = JSON.stringify(body);
  res.writeHead(200, {
    'Content-Type': 'application/x-amz-json-1.1',
    'Content-Length': Buffer.byteLength(json),
  });
  res.end(json);
}

function err(res, status, type, message) {
  const json = JSON.stringify({ __type: type, message });
  res.writeHead(status, {
    'Content-Type': 'application/x-amz-json-1.1',
    'x-amzn-errortype': type,
    'Content-Length': Buffer.byteLength(json),
  });
  res.end(json);
}

function opFromTarget(target) {
  const parts = String(target || '').split('.');
  return parts[parts.length - 1] || '';
}

function handlers(op, input) {
  switch (op) {
    case 'GetChangeToken':
      return { ChangeToken: token() };
    case 'CreateByteMatchSet': {
      const item = { ByteMatchSetId: id(), Name: input.Name, ByteMatchTuples: [] };
      db.byteSets.set(item.ByteMatchSetId, item);
      return { ByteMatchSet: item, ChangeToken: token() };
    }
    case 'UpdateByteMatchSet': {
      const item = db.byteSets.get(input.ByteMatchSetId);
      if (!item) throw Object.assign(new Error('ByteMatchSet not found'), { http: 400 });
      for (const u of input.Updates || []) {
        if (u.Action === 'INSERT' && u.ByteMatchTuple) item.ByteMatchTuples.push(u.ByteMatchTuple);
      }
      return { ChangeToken: token() };
    }
    case 'CreateRule': {
      const item = { RuleId: id(), Name: input.Name, MetricName: input.MetricName, Predicates: [] };
      db.rules.set(item.RuleId, item);
      return { Rule: item, ChangeToken: token() };
    }
    case 'UpdateRule': {
      const item = db.rules.get(input.RuleId);
      if (!item) throw Object.assign(new Error('Rule not found'), { http: 400 });
      for (const u of input.Updates || []) {
        if (u.Action === 'INSERT' && u.Predicate) item.Predicates.push(u.Predicate);
      }
      return { ChangeToken: token() };
    }
    case 'GetRule':
      return { Rule: db.rules.get(input.RuleId) };
    case 'CreateWebACL': {
      const item = {
        WebACLId: id(),
        Name: input.Name,
        MetricName: input.MetricName,
        DefaultAction: input.DefaultAction || { Type: 'ALLOW' },
        Rules: [],
      };
      db.webAcls.set(item.WebACLId, item);
      return { WebACL: item, ChangeToken: token() };
    }
    case 'UpdateWebACL': {
      const item = db.webAcls.get(input.WebACLId);
      if (!item) throw Object.assign(new Error('WebACL not found'), { http: 400 });
      for (const u of input.Updates || []) {
        if (u.Action === 'INSERT' && u.ActivatedRule) item.Rules.push(u.ActivatedRule);
      }
      return { ChangeToken: token() };
    }
    case 'GetWebACL':
      return { WebACL: db.webAcls.get(input.WebACLId) };
    case 'ListWebACLs':
      return {
        WebACLs: [...db.webAcls.values()].map((w) => ({ WebACLId: w.WebACLId, Name: w.Name })),
      };
    case 'ListRules':
      return {
        Rules: [...db.rules.values()].map((r) => ({ RuleId: r.RuleId, Name: r.Name })),
      };
    case 'ListByteMatchSets':
      return {
        ByteMatchSets: [...db.byteSets.values()].map((s) => ({
          ByteMatchSetId: s.ByteMatchSetId,
          Name: s.Name,
        })),
      };
    default:
      return null;
  }
}

const server = http.createServer((req, res) => {
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', () => {
    let input = {};
    try {
      input = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
    } catch {
      return err(res, 400, 'SerializationException', 'Invalid JSON');
    }
    const op = opFromTarget(req.headers['x-amz-target']);
    console.log(`[waf-classic] ${op || req.method + ' ' + req.url}`);
    try {
      const out = handlers(op, input);
      if (!out) {
        return err(res, 400, 'InvalidAction', `Unsupported WAF Classic operation: ${op}`);
      }
      return ok(res, out);
    } catch (e) {
      return err(res, e.http || 500, 'WAFInternalErrorException', e.message);
    }
  });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`[waf-classic] AWS WAF Classic API on ${PORT} (waf-regional JSON 1.1)`);
});
