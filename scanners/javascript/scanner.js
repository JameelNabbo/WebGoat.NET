'use strict';

const express = require('express');
const { parse } = require('@babel/parser');
const traverse = require('@babel/traverse').default || require('@babel/traverse');
const crypto = require('crypto');

// Inline UUID v4 generator (avoids ESM-only uuid v13 dependency)
function uuidv4() {
  const bytes = crypto.randomBytes(16);
  bytes[6] = (bytes[6] & 0x0f) | 0x40; // version 4
  bytes[8] = (bytes[8] & 0x3f) | 0x80; // variant 1
  const hex = bytes.toString('hex');
  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20, 32),
  ].join('-');
}

// ============================================================================
// Configuration
// ============================================================================
const PORT = 9002;
const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB per file
const PARSE_TIMEOUT = 30000; // 30s per file

// ============================================================================
// CWE & OWASP Mappings
// ============================================================================
const CWE = {
  SQL_INJECTION: 'CWE-89',
  NOSQL_INJECTION: 'CWE-943',
  COMMAND_INJECTION: 'CWE-78',
  CODE_INJECTION: 'CWE-94',
  XSS: 'CWE-79',
  PATH_TRAVERSAL: 'CWE-22',
  SSRF: 'CWE-918',
  OPEN_REDIRECT: 'CWE-601',
  PROTOTYPE_POLLUTION: 'CWE-1321',
  HARDCODED_SECRET: 'CWE-798',
  WEAK_CRYPTO: 'CWE-327',
  INSECURE_RANDOM: 'CWE-330',
  CORS_MISCONFIG: 'CWE-942',
  CSRF_MISSING: 'CWE-352',
  SECURITY_HEADERS: 'CWE-693',
  JWT_ISSUES: 'CWE-347',
  INSECURE_COOKIE: 'CWE-614',
  SSL_TLS: 'CWE-295',
  REGEX_DOS: 'CWE-1333',
  TEMPLATE_INJECTION: 'CWE-1336',
  MASS_ASSIGNMENT: 'CWE-915',
  MISSING_AUTH: 'CWE-306',
  INFO_DISCLOSURE: 'CWE-200',
  TIMING_ATTACK: 'CWE-208',
  UNSAFE_UPLOAD: 'CWE-434',
  LOG_SENSITIVE: 'CWE-532',
  DESERIALIZATION: 'CWE-502',
};

const OWASP = {
  INJECTION: 'A03:2021',
  BROKEN_AUTH: 'A07:2021',
  SENSITIVE_DATA: 'A02:2021',
  XSS: 'A03:2021',
  SECURITY_MISCONFIG: 'A05:2021',
  BROKEN_ACCESS: 'A01:2021',
  CRYPTO_FAILURE: 'A02:2021',
  SSRF: 'A10:2021',
  SOFTWARE_INTEGRITY: 'A08:2021',
  LOGGING_MONITORING: 'A09:2021',
};

// ============================================================================
// Taint Tracking System
// ============================================================================
class TaintTracker {
  constructor() {
    // Maps variable name -> taint info
    this.taintedVars = new Map();
    // Function-scoped taint (parameter tracking)
    this.functionParams = new Map();
  }

  reset() {
    this.taintedVars.clear();
    this.functionParams.clear();
  }

  markTainted(varName, source, scope) {
    this.taintedVars.set(this._scopedName(varName, scope), {
      source,
      scope,
      propagations: [],
    });
  }

  isTainted(varName, scope) {
    return (
      this.taintedVars.has(this._scopedName(varName, scope)) ||
      this.taintedVars.has(this._scopedName(varName, 'global'))
    );
  }

  getTaintInfo(varName, scope) {
    return (
      this.taintedVars.get(this._scopedName(varName, scope)) ||
      this.taintedVars.get(this._scopedName(varName, 'global'))
    );
  }

  propagate(fromVar, toVar, scope) {
    if (this.isTainted(fromVar, scope)) {
      const info = this.getTaintInfo(fromVar, scope);
      this.markTainted(toVar, info ? info.source : 'propagated', scope);
    }
  }

  _scopedName(varName, scope) {
    return scope ? `${scope}::${varName}` : varName;
  }
}

// ============================================================================
// Taint Sources, Sinks, and Sanitizers
// ============================================================================
const TAINT_SOURCES = {
  // Express request properties
  memberExpressions: [
    { object: 'req', properties: ['body', 'query', 'params', 'headers', 'cookies', 'url', 'path', 'hostname', 'ip'] },
    { object: 'request', properties: ['body', 'query', 'params', 'headers', 'cookies', 'url', 'path'] },
    { object: 'ctx', properties: ['request', 'query', 'params', 'body'] },
  ],
  // Functions that return tainted data
  functions: [
    'readline', 'prompt', 'readFileSync', 'readFile',
  ],
  // Global sources
  globals: ['process.argv', 'process.env'],
};

const TAINT_SINKS = {
  sqlInjection: {
    functions: ['query', 'execute', 'raw', 'prepare'],
    objects: ['db', 'connection', 'pool', 'knex', 'sequelize', 'mysql', 'pg', 'sqlite3'],
  },
  commandInjection: {
    functions: ['exec', 'execSync', 'spawn', 'spawnSync', 'execFile', 'execFileSync', 'fork'],
    modules: ['child_process'],
  },
  codeInjection: {
    functions: ['eval', 'Function', 'setTimeout', 'setInterval', 'setImmediate'],
  },
  pathTraversal: {
    functions: ['readFile', 'readFileSync', 'writeFile', 'writeFileSync', 'createReadStream',
      'createWriteStream', 'access', 'accessSync', 'stat', 'statSync', 'unlink', 'unlinkSync',
      'readdir', 'readdirSync', 'open', 'openSync', 'rename', 'renameSync'],
    modules: ['fs', 'fs/promises'],
  },
  ssrf: {
    functions: ['fetch', 'get', 'post', 'put', 'delete', 'patch', 'request', 'ajax'],
    modules: ['axios', 'node-fetch', 'http', 'https', 'request', 'got', 'superagent'],
  },
  xss: {
    properties: ['innerHTML', 'outerHTML'],
    functions: ['write', 'writeln', 'insertAdjacentHTML'],
    objects: ['document'],
  },
};

const SANITIZERS = new Set([
  'escape', 'escapeHtml', 'sanitize', 'sanitizeHtml', 'encode',
  'encodeURIComponent', 'encodeURI', 'htmlEscape', 'htmlEncode',
  'sqlEscape', 'parameterize', 'prepared', 'placeholder',
  'parseInt', 'parseFloat', 'Number', 'Boolean',
  'validator', 'validate', 'DOMPurify', 'purify', 'clean',
  'xss', 'strip', 'stripTags',
]);

// ============================================================================
// Secret Patterns (for hardcoded secret detection)
// ============================================================================
const SECRET_PATTERNS = [
  { name: 'AWS Access Key', pattern: /AKIA[0-9A-Z]{16}/ },
  { name: 'AWS Secret Key', pattern: /[A-Za-z0-9/+=]{40}/, context: ['aws', 'secret', 'key'] },
  { name: 'GitHub Token', pattern: /gh[pousr]_[A-Za-z0-9_]{36,}/ },
  { name: 'GitLab Token', pattern: /glpat-[A-Za-z0-9_-]{20,}/ },
  { name: 'Slack Token', pattern: /xox[baprs]-[A-Za-z0-9-]+/ },
  { name: 'Google API Key', pattern: /AIza[0-9A-Za-z_-]{35}/ },
  { name: 'Stripe Key', pattern: /[sr]k_(test|live)_[A-Za-z0-9]{20,}/ },
  { name: 'JWT Token', pattern: /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/ },
  { name: 'Private Key', pattern: /-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/ },
  { name: 'Heroku API Key', pattern: /[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/, context: ['heroku', 'api'] },
  { name: 'SendGrid API Key', pattern: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/ },
  { name: 'Twilio', pattern: /SK[0-9a-fA-F]{32}/ },
];

const SECRET_VAR_NAMES = /(?:password|passwd|pwd|secret|api_?key|apikey|access_?key|auth_?token|token|private_?key|jwt_?secret|encryption_?key|session_?secret|client_?secret|db_?password|database_?password|mongo_?uri|connection_?string)/i;

// ============================================================================
// Regex DoS patterns
// ============================================================================
function isVulnerableRegex(pattern) {
  // Detect evil regex patterns: nested quantifiers, overlapping alternations
  const evilPatterns = [
    /\(.*[+*].*\)[+*]/, // (a+)+ nested quantifiers
    /\(.*\|.*\)[+*]/, // (a|a)+ overlapping alternation with quantifier
    /\(.*[+*].*\)\{/, // (a+){n} nested quantifier with repetition
    /\([^)]*\.\*[^)]*\)[+*]/, // (.*x)+ greedy with quantifier
    /\([\s\S]*?\)\1/, // backreference exploitation
  ];
  return evilPatterns.some(ep => ep.test(pattern));
}

// ============================================================================
// AST Utility Functions
// ============================================================================
function getNodeName(node) {
  if (!node) return null;
  if (node.type === 'Identifier') return node.name;
  if (node.type === 'MemberExpression') {
    const obj = getNodeName(node.object);
    const prop = node.computed ? null : getNodeName(node.property);
    if (obj && prop) return `${obj}.${prop}`;
    return obj || prop;
  }
  if (node.type === 'StringLiteral') return node.value;
  if (node.type === 'TemplateLiteral') return '<template>';
  return null;
}

function getStringValue(node) {
  if (!node) return null;
  if (node.type === 'StringLiteral') return node.value;
  if (node.type === 'TemplateLiteral' && node.quasis && node.quasis.length === 1 && (!node.expressions || node.expressions.length === 0)) {
    return node.quasis[0].value.raw;
  }
  return null;
}

function hasTemplateExpressions(node) {
  return node.type === 'TemplateLiteral' && node.expressions && node.expressions.length > 0;
}

function isMemberOf(node, objectName, propertyNames) {
  if (node.type !== 'MemberExpression') return false;
  const objName = getNodeName(node.object);
  if (!objName) return false;
  // Allow both exact match and dot-notation sub-match
  const objMatch = objName === objectName || objName.startsWith(objectName + '.');
  if (!objMatch) return false;
  if (propertyNames) {
    const propName = getNodeName(node.property);
    return propertyNames.includes(propName);
  }
  return true;
}

function isTaintSource(node) {
  for (const src of TAINT_SOURCES.memberExpressions) {
    if (isMemberOf(node, src.object, src.properties)) return true;
    // Also check deeper access like req.body.username
    const fullName = getNodeName(node);
    if (fullName) {
      for (const prop of src.properties) {
        if (fullName.startsWith(`${src.object}.${prop}`)) return true;
      }
    }
  }
  return false;
}

function nodeContainsTaint(node, taintTracker, scope) {
  if (!node) return false;

  if (node.type === 'Identifier') {
    return taintTracker.isTainted(node.name, scope);
  }

  if (node.type === 'MemberExpression') {
    if (isTaintSource(node)) return true;
    const baseName = getNodeName(node.object);
    if (baseName && taintTracker.isTainted(baseName, scope)) return true;
    return nodeContainsTaint(node.object, taintTracker, scope);
  }

  if (node.type === 'TemplateLiteral') {
    return node.expressions && node.expressions.some(e => nodeContainsTaint(e, taintTracker, scope));
  }

  if (node.type === 'BinaryExpression' && node.operator === '+') {
    return nodeContainsTaint(node.left, taintTracker, scope) || nodeContainsTaint(node.right, taintTracker, scope);
  }

  if (node.type === 'CallExpression') {
    // Check if the function is a sanitizer
    const calleeName = getNodeName(node.callee);
    if (calleeName && isSanitizer(calleeName)) return false;
    // Check if arguments are tainted
    return node.arguments && node.arguments.some(a => nodeContainsTaint(a, taintTracker, scope));
  }

  if (node.type === 'ConditionalExpression') {
    return nodeContainsTaint(node.consequent, taintTracker, scope) || nodeContainsTaint(node.alternate, taintTracker, scope);
  }

  if (node.type === 'LogicalExpression') {
    return nodeContainsTaint(node.left, taintTracker, scope) || nodeContainsTaint(node.right, taintTracker, scope);
  }

  return false;
}

function isSanitizer(name) {
  if (!name) return false;
  const parts = name.split('.');
  return parts.some(p => SANITIZERS.has(p));
}

function getCodeSnippet(code, line, col) {
  if (!code) return '';
  const lines = code.split('\n');
  const start = Math.max(0, line - 2);
  const end = Math.min(lines.length, line + 1);
  return lines.slice(start, end).join('\n');
}

function getFunctionScope(path) {
  let current = path;
  while (current) {
    if (current.isFunctionDeclaration() || current.isFunctionExpression() || current.isArrowFunctionExpression()) {
      const parent = current.parentPath;
      if (parent && parent.isVariableDeclarator()) {
        return getNodeName(parent.node.id);
      }
      if (current.node.id) return current.node.id.name;
      return `anon_${current.node.loc ? current.node.loc.start.line : 'unknown'}`;
    }
    current = current.parentPath;
  }
  return 'global';
}

// ============================================================================
// Core Vulnerability Detectors
// ============================================================================

function createVuln(opts) {
  return {
    id: uuidv4(),
    title: opts.title,
    severity: opts.severity || 'Medium',
    confidence: opts.confidence || 'Medium',
    cwe: opts.cwe,
    owasp: opts.owasp || '',
    filePath: opts.filePath,
    lineNumber: opts.line || 0,
    columnOffset: opts.column || 0,
    codeSnippet: opts.snippet || '',
    remediation: opts.remediation || '',
    category: opts.category || '',
  };
}

// ============================================================================
// Detector: SQL Injection
// ============================================================================
function detectSQLInjection(path, node, filePath, code, taintTracker, scope) {
  const vulns = [];

  if (node.type === 'CallExpression') {
    const calleeName = getNodeName(node.callee);
    if (!calleeName) return vulns;

    const isSqlFunc = TAINT_SINKS.sqlInjection.functions.some(f => calleeName.endsWith(f) || calleeName.endsWith('.' + f));

    if (isSqlFunc && node.arguments.length > 0) {
      const firstArg = node.arguments[0];

      // Check for string concatenation with tainted data
      if (firstArg.type === 'BinaryExpression' && firstArg.operator === '+') {
        if (nodeContainsTaint(firstArg, taintTracker, scope)) {
          vulns.push(createVuln({
            title: 'SQL Injection via String Concatenation',
            severity: 'Critical',
            confidence: 'High',
            cwe: CWE.SQL_INJECTION,
            owasp: OWASP.INJECTION,
            filePath,
            line: node.loc ? node.loc.start.line : 0,
            column: node.loc ? node.loc.start.column : 0,
            snippet: getCodeSnippet(code, node.loc ? node.loc.start.line : 0),
            remediation: 'Use parameterized queries or prepared statements instead of string concatenation.',
            category: 'SQL Injection',
          }));
        }
      }

      // Check for template literal with expressions
      if (firstArg.type === 'TemplateLiteral' && hasTemplateExpressions(firstArg)) {
        if (nodeContainsTaint(firstArg, taintTracker, scope)) {
          vulns.push(createVuln({
            title: 'SQL Injection via Template Literal',
            severity: 'Critical',
            confidence: 'High',
            cwe: CWE.SQL_INJECTION,
            owasp: OWASP.INJECTION,
            filePath,
            line: node.loc ? node.loc.start.line : 0,
            column: node.loc ? node.loc.start.column : 0,
            snippet: getCodeSnippet(code, node.loc ? node.loc.start.line : 0),
            remediation: 'Use parameterized queries. Replace template literals with query parameter placeholders (e.g., $1, ?).',
            category: 'SQL Injection',
          }));
        }
      }
    }
  }

  // Tagged template: sql`SELECT * FROM users WHERE id = ${userId}`
  if (node.type === 'TaggedTemplateExpression') {
    const tag = getNodeName(node.tag);
    if (tag && /sql|query/i.test(tag) && hasTemplateExpressions(node.quasi)) {
      if (nodeContainsTaint(node.quasi, taintTracker, scope)) {
        vulns.push(createVuln({
          title: 'SQL Injection via Tagged Template',
          severity: 'Critical',
          confidence: 'Medium',
          cwe: CWE.SQL_INJECTION,
          owasp: OWASP.INJECTION,
          filePath,
          line: node.loc ? node.loc.start.line : 0,
          column: node.loc ? node.loc.start.column : 0,
          snippet: getCodeSnippet(code, node.loc ? node.loc.start.line : 0),
          remediation: 'Ensure the tagged template function properly escapes interpolated values.',
          category: 'SQL Injection',
        }));
      }
    }
  }

  return vulns;
}

// ============================================================================
// Detector: NoSQL Injection
// ============================================================================
function detectNoSQLInjection(path, node, filePath, code, taintTracker, scope) {
  const vulns = [];
  if (node.type !== 'CallExpression') return vulns;

  const calleeName = getNodeName(node.callee);
  if (!calleeName) return vulns;

  const nosqlFuncs = ['find', 'findOne', 'findOneAndUpdate', 'findOneAndDelete',
    'updateOne', 'updateMany', 'deleteOne', 'deleteMany', 'aggregate',
    'countDocuments', 'distinct'];

  const isNoSqlFunc = nosqlFuncs.some(f => calleeName.endsWith(f) || calleeName.endsWith('.' + f));

  if (isNoSqlFunc && node.arguments.length > 0) {
    const firstArg = node.arguments[0];

    // Direct user input as query object
    if (nodeContainsTaint(firstArg, taintTracker, scope)) {
      vulns.push(createVuln({
        title: 'NoSQL Injection - User Input in Query',
        severity: 'Critical',
        confidence: 'High',
        cwe: CWE.NOSQL_INJECTION,
        owasp: OWASP.INJECTION,
        filePath,
        line: node.loc ? node.loc.start.line : 0,
        column: node.loc ? node.loc.start.column : 0,
        snippet: getCodeSnippet(code, node.loc ? node.loc.start.line : 0),
        remediation: 'Validate and sanitize user input before using in MongoDB queries. Use explicit field access instead of passing entire user objects.',
        category: 'NoSQL Injection',
      }));
    }

    // Check for $where with tainted data
    if (firstArg.type === 'ObjectExpression') {
      for (const prop of firstArg.properties || []) {
        if (prop.type === 'ObjectProperty' || prop.type === 'Property') {
          const key = getNodeName(prop.key) || getStringValue(prop.key);
          if (key === '$where' && nodeContainsTaint(prop.value, taintTracker, scope)) {
            vulns.push(createVuln({
              title: 'NoSQL Injection via $where Operator',
              severity: 'Critical',
              confidence: 'High',
              cwe: CWE.NOSQL_INJECTION,
              owasp: OWASP.INJECTION,
              filePath,
              line: prop.loc ? prop.loc.start.line : 0,
              column: prop.loc ? prop.loc.start.column : 0,
              snippet: getCodeSnippet(code, prop.loc ? prop.loc.start.line : 0),
              remediation: 'Never use $where with user input. Use standard query operators instead.',
              category: 'NoSQL Injection',
            }));
          }
        }
      }
    }
  }

  return vulns;
}

// ============================================================================
// Detector: Command Injection
// ============================================================================
function detectCommandInjection(path, node, filePath, code, taintTracker, scope) {
  const vulns = [];
  if (node.type !== 'CallExpression') return vulns;

  const calleeName = getNodeName(node.callee);
  if (!calleeName) return vulns;

  const cmdFuncs = TAINT_SINKS.commandInjection.functions;
  const isCmdFunc = cmdFuncs.some(f => calleeName === f || calleeName.endsWith('.' + f));

  if (isCmdFunc && node.arguments.length > 0) {
    const firstArg = node.arguments[0];

    if (nodeContainsTaint(firstArg, taintTracker, scope)) {
      vulns.push(createVuln({
        title: 'Command Injection',
        severity: 'Critical',
        confidence: 'High',
        cwe: CWE.COMMAND_INJECTION,
        owasp: OWASP.INJECTION,
        filePath,
        line: node.loc ? node.loc.start.line : 0,
        column: node.loc ? node.loc.start.column : 0,
        snippet: getCodeSnippet(code, node.loc ? node.loc.start.line : 0),
        remediation: 'Avoid exec/execSync with user input. Use execFile with an argument array instead. Validate and whitelist allowed commands.',
        category: 'Command Injection',
      }));
    }

    // Even without taint, template literals / concatenation in exec are suspicious
    if (firstArg.type === 'TemplateLiteral' && hasTemplateExpressions(firstArg)) {
      vulns.push(createVuln({
        title: 'Potential Command Injection via Template Literal',
        severity: 'High',
        confidence: 'Medium',
        cwe: CWE.COMMAND_INJECTION,
        owasp: OWASP.INJECTION,
        filePath,
        line: node.loc ? node.loc.start.line : 0,
        column: node.loc ? node.loc.start.column : 0,
        snippet: getCodeSnippet(code, node.loc ? node.loc.start.line : 0),
        remediation: 'Avoid string interpolation in shell commands. Use execFile with argument arrays.',
        category: 'Command Injection',
      }));
    }
  }

  return vulns;
}

// ============================================================================
// Detector: Code Injection (eval, Function, etc.)
// ============================================================================
function detectCodeInjection(path, node, filePath, code, taintTracker, scope) {
  const vulns = [];
  if (node.type !== 'CallExpression') return vulns;

  const calleeName = getNodeName(node.callee);
  if (!calleeName) return vulns;

  // eval()
  if (calleeName === 'eval' && node.arguments.length > 0) {
    const severity = nodeContainsTaint(node.arguments[0], taintTracker, scope) ? 'Critical' : 'High';
    vulns.push(createVuln({
      title: 'Code Injection via eval()',
      severity,
      confidence: nodeContainsTaint(node.arguments[0], taintTracker, scope) ? 'High' : 'Medium',
      cwe: CWE.CODE_INJECTION,
      owasp: OWASP.INJECTION,
      filePath,
      line: node.loc ? node.loc.start.line : 0,
      column: node.loc ? node.loc.start.column : 0,
      snippet: getCodeSnippet(code, node.loc ? node.loc.start.line : 0),
      remediation: 'Never use eval() with dynamic content. Use JSON.parse() for data or a sandboxed environment.',
      category: 'Code Injection',
    }));
  }

  // new Function()
  if (node.type === 'CallExpression' && node.callee.type === 'Identifier' && node.callee.name === 'Function') {
    vulns.push(createVuln({
      title: 'Code Injection via Function Constructor',
      severity: 'High',
      confidence: 'Medium',
      cwe: CWE.CODE_INJECTION,
      owasp: OWASP.INJECTION,
      filePath,
      line: node.loc ? node.loc.start.line : 0,
      column: node.loc ? node.loc.start.column : 0,
      snippet: getCodeSnippet(code, node.loc ? node.loc.start.line : 0),
      remediation: 'Avoid using the Function constructor to create functions from strings.',
      category: 'Code Injection',
    }));
  }

  // setTimeout/setInterval with string argument
  if ((calleeName === 'setTimeout' || calleeName === 'setInterval') && node.arguments.length > 0) {
    const firstArg = node.arguments[0];
    if (firstArg.type === 'StringLiteral' || (firstArg.type === 'TemplateLiteral') || (firstArg.type === 'Identifier' && taintTracker.isTainted(firstArg.name, scope))) {
      if (firstArg.type !== 'ArrowFunctionExpression' && firstArg.type !== 'FunctionExpression') {
        vulns.push(createVuln({
          title: `Code Injection via ${calleeName} with String`,
          severity: 'High',
          confidence: 'Medium',
          cwe: CWE.CODE_INJECTION,
          owasp: OWASP.INJECTION,
          filePath,
          line: node.loc ? node.loc.start.line : 0,
          column: node.loc ? node.loc.start.column : 0,
          snippet: getCodeSnippet(code, node.loc ? node.loc.start.line : 0),
          remediation: `Pass a function reference to ${calleeName} instead of a string.`,
          category: 'Code Injection',
        }));
      }
    }
  }

  return vulns;
}

// ============================================================================
// Detector: XSS (DOM-based, React, reflected)
// ============================================================================
function detectXSS(path, node, filePath, code, taintTracker, scope) {
  const vulns = [];

  // DOM XSS: element.innerHTML = userInput
  if (node.type === 'AssignmentExpression') {
    const left = node.left;
    if (left.type === 'MemberExpression') {
      const propName = getNodeName(left.property);
      if (propName === 'innerHTML' || propName === 'outerHTML') {
        if (nodeContainsTaint(node.right, taintTracker, scope) || node.right.type !== 'StringLiteral') {
          vulns.push(createVuln({
            title: `DOM-based XSS via ${propName}`,
            severity: 'High',
            confidence: nodeContainsTaint(node.right, taintTracker, scope) ? 'High' : 'Medium',
            cwe: CWE.XSS,
            owasp: OWASP.XSS,
            filePath,
            line: node.loc ? node.loc.start.line : 0,
            column: node.loc ? node.loc.start.column : 0,
            snippet: getCodeSnippet(code, node.loc ? node.loc.start.line : 0),
            remediation: 'Use textContent or innerText instead of innerHTML. Sanitize HTML with DOMPurify.',
            category: 'Cross-Site Scripting (XSS)',
          }));
        }
      }
    }
  }

  // document.write
  if (node.type === 'CallExpression') {
    const calleeName = getNodeName(node.callee);
    if (calleeName === 'document.write' || calleeName === 'document.writeln') {
      vulns.push(createVuln({
        title: 'DOM XSS via document.write()',
        severity: 'High',
        confidence: 'Medium',
        cwe: CWE.XSS,
        owasp: OWASP.XSS,
        filePath,
        line: node.loc ? node.loc.start.line : 0,
        column: node.loc ? node.loc.start.column : 0,
        snippet: getCodeSnippet(code, node.loc ? node.loc.start.line : 0),
        remediation: 'Avoid document.write(). Use DOM manipulation methods like createElement and appendChild.',
        category: 'Cross-Site Scripting (XSS)',
      }));
    }
  }

  // React: dangerouslySetInnerHTML
  if (node.type === 'JSXAttribute') {
    const attrName = getNodeName(node.name);
    if (attrName === 'dangerouslySetInnerHTML') {
      vulns.push(createVuln({
        title: 'React XSS via dangerouslySetInnerHTML',
        severity: 'High',
        confidence: 'Medium',
        cwe: CWE.XSS,
        owasp: OWASP.XSS,
        filePath,
        line: node.loc ? node.loc.start.line : 0,
        column: node.loc ? node.loc.start.column : 0,
        snippet: getCodeSnippet(code, node.loc ? node.loc.start.line : 0),
        remediation: 'Avoid dangerouslySetInnerHTML. Use DOMPurify to sanitize HTML before rendering.',
        category: 'Cross-Site Scripting (XSS)',
      }));
    }
  }

  // Reflected XSS: res.send(req.body/query/params)
  if (node.type === 'CallExpression') {
    const calleeName = getNodeName(node.callee);
    if (calleeName && (calleeName.endsWith('.send') || calleeName.endsWith('.end') || calleeName.endsWith('.write'))) {
      if (node.arguments.length > 0 && nodeContainsTaint(node.arguments[0], taintTracker, scope)) {
        const objName = getNodeName(node.callee.object);
        if (objName === 'res' || objName === 'response' || objName === 'ctx') {
          vulns.push(createVuln({
            title: 'Reflected XSS - User Input in Response',
            severity: 'High',
            confidence: 'High',
            cwe: CWE.XSS,
            owasp: OWASP.XSS,
            filePath,
            line: node.loc ? node.loc.start.line : 0,
            column: node.loc ? node.loc.start.column : 0,
            snippet: getCodeSnippet(code, node.loc ? node.loc.start.line : 0),
            remediation: 'Sanitize or encode user input before including it in HTTP responses. Use a templating engine with auto-escaping.',
            category: 'Cross-Site Scripting (XSS)',
          }));
        }
      }
    }
  }

  return vulns;
}

// ============================================================================
// Detector: Path Traversal
// ============================================================================
function detectPathTraversal(path, node, filePath, code, taintTracker, scope) {
  const vulns = [];
  if (node.type !== 'CallExpression') return vulns;

  const calleeName = getNodeName(node.callee);
  if (!calleeName) return vulns;

  const fsFuncs = TAINT_SINKS.pathTraversal.functions;
  const isFsFunc = fsFuncs.some(f => calleeName === f || calleeName.endsWith('.' + f));

  if (isFsFunc && node.arguments.length > 0) {
    const firstArg = node.arguments[0];
    if (nodeContainsTaint(firstArg, taintTracker, scope)) {
      // Check if path.join/resolve is used (partial mitigation)
      let partiallyMitigated = false;
      if (firstArg.type === 'CallExpression') {
        const innerCallee = getNodeName(firstArg.callee);
        if (innerCallee && (innerCallee === 'path.join' || innerCallee === 'path.resolve')) {
          partiallyMitigated = true;
        }
      }

      vulns.push(createVuln({
        title: 'Path Traversal',
        severity: partiallyMitigated ? 'Medium' : 'High',
        confidence: partiallyMitigated ? 'Medium' : 'High',
        cwe: CWE.PATH_TRAVERSAL,
        owasp: OWASP.BROKEN_ACCESS,
        filePath,
        line: node.loc ? node.loc.start.line : 0,
        column: node.loc ? node.loc.start.column : 0,
        snippet: getCodeSnippet(code, node.loc ? node.loc.start.line : 0),
        remediation: 'Validate file paths against a whitelist. Use path.resolve() and verify the resolved path starts with the expected base directory.',
        category: 'Path Traversal',
      }));
    }
  }

  return vulns;
}

// ============================================================================
// Detector: SSRF
// ============================================================================
function detectSSRF(path, node, filePath, code, taintTracker, scope) {
  const vulns = [];
  if (node.type !== 'CallExpression') return vulns;

  const calleeName = getNodeName(node.callee);
  if (!calleeName) return vulns;

  const ssrfFuncs = TAINT_SINKS.ssrf.functions;
  const isHttpFunc = ssrfFuncs.some(f => calleeName === f || calleeName.endsWith('.' + f));

  if (isHttpFunc && node.arguments.length > 0) {
    const firstArg = node.arguments[0];
    if (nodeContainsTaint(firstArg, taintTracker, scope)) {
      vulns.push(createVuln({
        title: 'Server-Side Request Forgery (SSRF)',
        severity: 'High',
        confidence: 'High',
        cwe: CWE.SSRF,
        owasp: OWASP.SSRF,
        filePath,
        line: node.loc ? node.loc.start.line : 0,
        column: node.loc ? node.loc.start.column : 0,
        snippet: getCodeSnippet(code, node.loc ? node.loc.start.line : 0),
        remediation: 'Validate URLs against an allowlist of permitted hosts. Block access to internal/private IP ranges.',
        category: 'Server-Side Request Forgery',
      }));
    }
  }

  return vulns;
}

// ============================================================================
// Detector: Open Redirect
// ============================================================================
function detectOpenRedirect(path, node, filePath, code, taintTracker, scope) {
  const vulns = [];
  if (node.type !== 'CallExpression') return vulns;

  const calleeName = getNodeName(node.callee);
  if (!calleeName) return vulns;

  if (calleeName.endsWith('.redirect') && node.arguments.length > 0) {
    const arg = node.arguments.length > 1 ? node.arguments[1] : node.arguments[0];
    if (nodeContainsTaint(arg, taintTracker, scope)) {
      vulns.push(createVuln({
        title: 'Open Redirect',
        severity: 'Medium',
        confidence: 'High',
        cwe: CWE.OPEN_REDIRECT,
        owasp: OWASP.BROKEN_ACCESS,
        filePath,
        line: node.loc ? node.loc.start.line : 0,
        column: node.loc ? node.loc.start.column : 0,
        snippet: getCodeSnippet(code, node.loc ? node.loc.start.line : 0),
        remediation: 'Validate redirect URLs against a whitelist of allowed destinations. Use relative paths where possible.',
        category: 'Open Redirect',
      }));
    }
  }

  // window.location / document.location
  if (node.type === 'AssignmentExpression') {
    const leftName = getNodeName(node.left);
    if (leftName && (leftName.includes('location.href') || leftName.includes('location') || leftName === 'window.location')) {
      if (nodeContainsTaint(node.right, taintTracker, scope)) {
        vulns.push(createVuln({
          title: 'Open Redirect via Location Assignment',
          severity: 'Medium',
          confidence: 'High',
          cwe: CWE.OPEN_REDIRECT,
          owasp: OWASP.BROKEN_ACCESS,
          filePath,
          line: node.loc ? node.loc.start.line : 0,
          column: node.loc ? node.loc.start.column : 0,
          snippet: getCodeSnippet(code, node.loc ? node.loc.start.line : 0),
          remediation: 'Validate redirect targets against an allowlist before assigning to window.location.',
          category: 'Open Redirect',
        }));
      }
    }
  }

  return vulns;
}

// ============================================================================
// Detector: Prototype Pollution
// ============================================================================
function detectPrototypePollution(path, node, filePath, code, taintTracker, scope) {
  const vulns = [];

  // Check for __proto__ assignment
  if (node.type === 'MemberExpression') {
    const propName = getNodeName(node.property);
    if (propName === '__proto__' || propName === 'constructor') {
      const parent = path.parent;
      if (parent && parent.type === 'AssignmentExpression' && parent.left === node) {
        vulns.push(createVuln({
          title: 'Prototype Pollution',
          severity: 'High',
          confidence: 'High',
          cwe: CWE.PROTOTYPE_POLLUTION,
          owasp: OWASP.INJECTION,
          filePath,
          line: node.loc ? node.loc.start.line : 0,
          column: node.loc ? node.loc.start.column : 0,
          snippet: getCodeSnippet(code, node.loc ? node.loc.start.line : 0),
          remediation: 'Freeze Object.prototype. Use Object.create(null) for dictionary objects. Validate property names against __proto__ and constructor.',
          category: 'Prototype Pollution',
        }));
      }
    }
  }

  // Dynamic property assignment with tainted key: obj[userInput] = value
  if (node.type === 'AssignmentExpression' &&
    node.left.type === 'MemberExpression' &&
    node.left.computed) {
    if (nodeContainsTaint(node.left.property, taintTracker, scope)) {
      vulns.push(createVuln({
        title: 'Potential Prototype Pollution via Dynamic Property',
        severity: 'High',
        confidence: 'Medium',
        cwe: CWE.PROTOTYPE_POLLUTION,
        owasp: OWASP.INJECTION,
        filePath,
        line: node.loc ? node.loc.start.line : 0,
        column: node.loc ? node.loc.start.column : 0,
        snippet: getCodeSnippet(code, node.loc ? node.loc.start.line : 0),
        remediation: 'Validate property names. Reject __proto__, constructor, and prototype. Use a Map instead of plain objects.',
        category: 'Prototype Pollution',
      }));
    }
  }

  // Object.assign / lodash merge / deep extend with tainted source
  if (node.type === 'CallExpression') {
    const calleeName = getNodeName(node.callee);
    if (calleeName && /Object\.assign|\.merge|\.extend|\.defaultsDeep|deepmerge/.test(calleeName)) {
      if (node.arguments.some(a => nodeContainsTaint(a, taintTracker, scope))) {
        vulns.push(createVuln({
          title: 'Prototype Pollution via Object Merge',
          severity: 'High',
          confidence: 'Medium',
          cwe: CWE.PROTOTYPE_POLLUTION,
          owasp: OWASP.INJECTION,
          filePath,
          line: node.loc ? node.loc.start.line : 0,
          column: node.loc ? node.loc.start.column : 0,
          snippet: getCodeSnippet(code, node.loc ? node.loc.start.line : 0),
          remediation: 'Validate merged objects. Strip __proto__ and constructor properties. Use libraries that are safe against prototype pollution.',
          category: 'Prototype Pollution',
        }));
      }
    }
  }

  return vulns;
}

// ============================================================================
// Detector: Hardcoded Secrets
// ============================================================================
function detectHardcodedSecrets(path, node, filePath, code) {
  const vulns = [];

  // Variable declarations with secret-looking names and string values
  if (node.type === 'VariableDeclarator' && node.init) {
    const varName = getNodeName(node.id);
    const value = getStringValue(node.init);

    if (varName && value && SECRET_VAR_NAMES.test(varName) && value.length >= 4) {
      // Skip obvious placeholders
      if (/^(xxx|changeme|your_|todo|placeholder|example|test|dummy|fake|sample)/i.test(value)) return vulns;
      if (value === '' || value === 'undefined' || value === 'null') return vulns;

      vulns.push(createVuln({
        title: `Hardcoded Secret in Variable "${varName}"`,
        severity: 'High',
        confidence: 'High',
        cwe: CWE.HARDCODED_SECRET,
        owasp: OWASP.CRYPTO_FAILURE,
        filePath,
        line: node.loc ? node.loc.start.line : 0,
        column: node.loc ? node.loc.start.column : 0,
        snippet: getCodeSnippet(code, node.loc ? node.loc.start.line : 0),
        remediation: 'Use environment variables or a secure vault to store secrets. Never hardcode credentials in source code.',
        category: 'Hardcoded Secrets',
      }));
    }

    // Check for known token patterns
    if (value) {
      for (const sp of SECRET_PATTERNS) {
        if (sp.pattern.test(value)) {
          if (sp.context) {
            const contextMatch = sp.context.some(c => (varName && varName.toLowerCase().includes(c)));
            if (!contextMatch) continue;
          }
          vulns.push(createVuln({
            title: `Hardcoded ${sp.name} Detected`,
            severity: 'Critical',
            confidence: 'High',
            cwe: CWE.HARDCODED_SECRET,
            owasp: OWASP.CRYPTO_FAILURE,
            filePath,
            line: node.loc ? node.loc.start.line : 0,
            column: node.loc ? node.loc.start.column : 0,
            snippet: getCodeSnippet(code, node.loc ? node.loc.start.line : 0),
            remediation: `Revoke this ${sp.name} immediately and use environment variables or a secret management service.`,
            category: 'Hardcoded Secrets',
          }));
          break;
        }
      }
    }
  }

  // Object property assignments: { password: "secret123" }
  if ((node.type === 'ObjectProperty' || node.type === 'Property') && !node.computed) {
    const key = getNodeName(node.key) || getStringValue(node.key);
    const value = getStringValue(node.value);

    if (key && value && SECRET_VAR_NAMES.test(key) && value.length >= 4) {
      if (/^(xxx|changeme|your_|todo|placeholder|example|test|dummy|fake|sample)/i.test(value)) return vulns;

      vulns.push(createVuln({
        title: `Hardcoded Secret in Property "${key}"`,
        severity: 'High',
        confidence: 'High',
        cwe: CWE.HARDCODED_SECRET,
        owasp: OWASP.CRYPTO_FAILURE,
        filePath,
        line: node.loc ? node.loc.start.line : 0,
        column: node.loc ? node.loc.start.column : 0,
        snippet: getCodeSnippet(code, node.loc ? node.loc.start.line : 0),
        remediation: 'Use environment variables or a configuration management system for sensitive values.',
        category: 'Hardcoded Secrets',
      }));
    }
  }

  return vulns;
}

// ============================================================================
// Detector: Weak Cryptography
// ============================================================================
function detectWeakCrypto(path, node, filePath, code) {
  const vulns = [];
  if (node.type !== 'CallExpression') return vulns;

  const calleeName = getNodeName(node.callee);
  if (!calleeName) return vulns;

  // createHash with weak algorithm
  if (calleeName.endsWith('createHash') && node.arguments.length > 0) {
    const algo = getStringValue(node.arguments[0]);
    if (algo && /^(md4|md5|sha1|ripemd)$/i.test(algo)) {
      vulns.push(createVuln({
        title: `Weak Hash Algorithm: ${algo.toUpperCase()}`,
        severity: 'Medium',
        confidence: 'High',
        cwe: CWE.WEAK_CRYPTO,
        owasp: OWASP.CRYPTO_FAILURE,
        filePath,
        line: node.loc ? node.loc.start.line : 0,
        column: node.loc ? node.loc.start.column : 0,
        snippet: getCodeSnippet(code, node.loc ? node.loc.start.line : 0),
        remediation: 'Use SHA-256 or SHA-3 for hashing. For passwords, use bcrypt, scrypt, or Argon2.',
        category: 'Weak Cryptography',
      }));
    }
  }

  // createCipher (deprecated, not authenticated)
  if (calleeName.endsWith('createCipher') && !calleeName.endsWith('createCipheriv')) {
    vulns.push(createVuln({
      title: 'Deprecated createCipher() - No IV Used',
      severity: 'High',
      confidence: 'High',
      cwe: CWE.WEAK_CRYPTO,
      owasp: OWASP.CRYPTO_FAILURE,
      filePath,
      line: node.loc ? node.loc.start.line : 0,
      column: node.loc ? node.loc.start.column : 0,
      snippet: getCodeSnippet(code, node.loc ? node.loc.start.line : 0),
      remediation: 'Use createCipheriv() with a random IV. Prefer AES-256-GCM for authenticated encryption.',
      category: 'Weak Cryptography',
    }));
  }

  // Weak cipher algorithms
  if ((calleeName.endsWith('createCipheriv') || calleeName.endsWith('createDecipheriv')) && node.arguments.length > 0) {
    const algo = getStringValue(node.arguments[0]);
    if (algo && /^(des|rc4|rc2|blowfish|aes-\d+-ecb)/i.test(algo)) {
      vulns.push(createVuln({
        title: `Weak Cipher Algorithm: ${algo}`,
        severity: 'High',
        confidence: 'High',
        cwe: CWE.WEAK_CRYPTO,
        owasp: OWASP.CRYPTO_FAILURE,
        filePath,
        line: node.loc ? node.loc.start.line : 0,
        column: node.loc ? node.loc.start.column : 0,
        snippet: getCodeSnippet(code, node.loc ? node.loc.start.line : 0),
        remediation: 'Use AES-256-GCM or ChaCha20-Poly1305 for encryption.',
        category: 'Weak Cryptography',
      }));
    }
  }

  return vulns;
}

// ============================================================================
// Detector: Insecure Random
// ============================================================================
function detectInsecureRandom(path, node, filePath, code) {
  const vulns = [];

  if (node.type === 'CallExpression') {
    const calleeName = getNodeName(node.callee);
    if (calleeName === 'Math.random') {
      // Check context: is it used for security purposes?
      const parent = path.parent;
      let assignedTo = null;

      if (parent && parent.type === 'VariableDeclarator') {
        assignedTo = getNodeName(parent.id);
      }

      const securityContext = assignedTo && /token|key|secret|nonce|salt|password|session|csrf|otp|code|hash/i.test(assignedTo);

      vulns.push(createVuln({
        title: 'Insecure Random Number Generator',
        severity: securityContext ? 'High' : 'Low',
        confidence: securityContext ? 'High' : 'Medium',
        cwe: CWE.INSECURE_RANDOM,
        owasp: OWASP.CRYPTO_FAILURE,
        filePath,
        line: node.loc ? node.loc.start.line : 0,
        column: node.loc ? node.loc.start.column : 0,
        snippet: getCodeSnippet(code, node.loc ? node.loc.start.line : 0),
        remediation: 'Use crypto.randomBytes() or crypto.randomUUID() for security-sensitive operations.',
        category: 'Insecure Random',
      }));
    }
  }

  return vulns;
}

// ============================================================================
// Detector: CORS Misconfiguration
// ============================================================================
function detectCORSMisconfig(path, node, filePath, code) {
  const vulns = [];

  // cors({ origin: '*' }) or cors({ origin: true })
  if (node.type === 'CallExpression') {
    const calleeName = getNodeName(node.callee);
    if (calleeName === 'cors' && node.arguments.length > 0) {
      const arg = node.arguments[0];
      if (arg.type === 'ObjectExpression') {
        for (const prop of arg.properties || []) {
          const key = getNodeName(prop.key) || getStringValue(prop.key);
          if (key === 'origin') {
            const val = getStringValue(prop.value);
            if (val === '*' || (prop.value.type === 'BooleanLiteral' && prop.value.value === true)) {
              vulns.push(createVuln({
                title: 'CORS Misconfiguration - Wildcard Origin',
                severity: 'Medium',
                confidence: 'High',
                cwe: CWE.CORS_MISCONFIG,
                owasp: OWASP.SECURITY_MISCONFIG,
                filePath,
                line: prop.loc ? prop.loc.start.line : 0,
                column: prop.loc ? prop.loc.start.column : 0,
                snippet: getCodeSnippet(code, prop.loc ? prop.loc.start.line : 0),
                remediation: 'Restrict CORS origin to specific trusted domains instead of using wildcard.',
                category: 'CORS Misconfiguration',
              }));
            }
          }
          if (key === 'credentials' && prop.value.type === 'BooleanLiteral' && prop.value.value === true) {
            // credentials: true is fine alone, but with origin: * is dangerous
            // Already handled above
          }
        }
      }
    }
  }

  // res.setHeader('Access-Control-Allow-Origin', '*')
  if (node.type === 'CallExpression') {
    const calleeName = getNodeName(node.callee);
    if (calleeName && (calleeName.endsWith('.setHeader') || calleeName.endsWith('.header') || calleeName.endsWith('.set'))) {
      if (node.arguments.length >= 2) {
        const headerName = getStringValue(node.arguments[0]);
        const headerVal = getStringValue(node.arguments[1]);
        if (headerName && headerName.toLowerCase() === 'access-control-allow-origin' && headerVal === '*') {
          vulns.push(createVuln({
            title: 'CORS Misconfiguration - Wildcard Allow-Origin Header',
            severity: 'Medium',
            confidence: 'High',
            cwe: CWE.CORS_MISCONFIG,
            owasp: OWASP.SECURITY_MISCONFIG,
            filePath,
            line: node.loc ? node.loc.start.line : 0,
            column: node.loc ? node.loc.start.column : 0,
            snippet: getCodeSnippet(code, node.loc ? node.loc.start.line : 0),
            remediation: 'Set Access-Control-Allow-Origin to specific trusted origins.',
            category: 'CORS Misconfiguration',
          }));
        }
      }
    }
  }

  return vulns;
}

// ============================================================================
// Detector: Insecure Cookies
// ============================================================================
function detectInsecureCookies(path, node, filePath, code) {
  const vulns = [];

  if (node.type === 'CallExpression') {
    const calleeName = getNodeName(node.callee);
    if (calleeName && calleeName.endsWith('.cookie') && node.arguments.length >= 2) {
      const cookieOptions = node.arguments.length >= 3 ? node.arguments[2] : null;

      if (cookieOptions && cookieOptions.type === 'ObjectExpression') {
        let hasSecure = false, hasHttpOnly = false, hasSameSite = false;

        for (const prop of cookieOptions.properties || []) {
          const key = getNodeName(prop.key) || getStringValue(prop.key);
          if (key === 'secure') {
            hasSecure = prop.value.type === 'BooleanLiteral' && prop.value.value === true;
          }
          if (key === 'httpOnly') {
            hasHttpOnly = prop.value.type === 'BooleanLiteral' && prop.value.value === true;
          }
          if (key === 'sameSite') {
            hasSameSite = true;
          }
        }

        if (!hasSecure) {
          vulns.push(createVuln({
            title: 'Insecure Cookie - Missing Secure Flag',
            severity: 'Medium',
            confidence: 'High',
            cwe: CWE.INSECURE_COOKIE,
            owasp: OWASP.SECURITY_MISCONFIG,
            filePath,
            line: node.loc ? node.loc.start.line : 0,
            column: node.loc ? node.loc.start.column : 0,
            snippet: getCodeSnippet(code, node.loc ? node.loc.start.line : 0),
            remediation: 'Set secure: true to ensure the cookie is only sent over HTTPS.',
            category: 'Insecure Cookie',
          }));
        }

        if (!hasHttpOnly) {
          vulns.push(createVuln({
            title: 'Insecure Cookie - Missing HttpOnly Flag',
            severity: 'Medium',
            confidence: 'High',
            cwe: CWE.INSECURE_COOKIE,
            owasp: OWASP.SECURITY_MISCONFIG,
            filePath,
            line: node.loc ? node.loc.start.line : 0,
            column: node.loc ? node.loc.start.column : 0,
            snippet: getCodeSnippet(code, node.loc ? node.loc.start.line : 0),
            remediation: 'Set httpOnly: true to prevent JavaScript access to the cookie.',
            category: 'Insecure Cookie',
          }));
        }

        if (!hasSameSite) {
          vulns.push(createVuln({
            title: 'Insecure Cookie - Missing SameSite Attribute',
            severity: 'Low',
            confidence: 'Medium',
            cwe: CWE.CSRF_MISSING,
            owasp: OWASP.SECURITY_MISCONFIG,
            filePath,
            line: node.loc ? node.loc.start.line : 0,
            column: node.loc ? node.loc.start.column : 0,
            snippet: getCodeSnippet(code, node.loc ? node.loc.start.line : 0),
            remediation: 'Set sameSite: "Strict" or "Lax" to prevent CSRF attacks.',
            category: 'Insecure Cookie',
          }));
        }
      } else if (!cookieOptions) {
        vulns.push(createVuln({
          title: 'Insecure Cookie - No Security Options Set',
          severity: 'Medium',
          confidence: 'High',
          cwe: CWE.INSECURE_COOKIE,
          owasp: OWASP.SECURITY_MISCONFIG,
          filePath,
          line: node.loc ? node.loc.start.line : 0,
          column: node.loc ? node.loc.start.column : 0,
          snippet: getCodeSnippet(code, node.loc ? node.loc.start.line : 0),
          remediation: 'Set cookie options: { secure: true, httpOnly: true, sameSite: "Strict" }.',
          category: 'Insecure Cookie',
        }));
      }
    }
  }

  return vulns;
}

// ============================================================================
// Detector: JWT Issues
// ============================================================================
function detectJWTIssues(path, node, filePath, code) {
  const vulns = [];
  if (node.type !== 'CallExpression') return vulns;

  const calleeName = getNodeName(node.callee);
  if (!calleeName) return vulns;

  // jwt.sign with weak/no algorithm
  if (calleeName.endsWith('.sign') || calleeName.endsWith('.verify')) {
    const isJwt = calleeName.includes('jwt') || calleeName.includes('jsonwebtoken');

    // Check options for algorithm
    for (const arg of node.arguments) {
      if (arg.type === 'ObjectExpression') {
        for (const prop of arg.properties || []) {
          const key = getNodeName(prop.key) || getStringValue(prop.key);
          if (key === 'algorithm' || key === 'algorithms') {
            const val = getStringValue(prop.value);
            if (val === 'none') {
              vulns.push(createVuln({
                title: 'JWT - Algorithm "none" Allowed',
                severity: 'Critical',
                confidence: 'High',
                cwe: CWE.JWT_ISSUES,
                owasp: OWASP.BROKEN_AUTH,
                filePath,
                line: prop.loc ? prop.loc.start.line : 0,
                column: prop.loc ? prop.loc.start.column : 0,
                snippet: getCodeSnippet(code, prop.loc ? prop.loc.start.line : 0),
                remediation: 'Never allow algorithm "none". Use RS256 or ES256 for JWT signing.',
                category: 'JWT Issues',
              }));
            }
            if (val === 'HS256' && isJwt) {
              vulns.push(createVuln({
                title: 'JWT - Weak Algorithm HS256',
                severity: 'Medium',
                confidence: 'Medium',
                cwe: CWE.JWT_ISSUES,
                owasp: OWASP.BROKEN_AUTH,
                filePath,
                line: prop.loc ? prop.loc.start.line : 0,
                column: prop.loc ? prop.loc.start.column : 0,
                snippet: getCodeSnippet(code, prop.loc ? prop.loc.start.line : 0),
                remediation: 'Consider using RS256 or ES256 for stronger JWT security.',
                category: 'JWT Issues',
              }));
            }
          }
          if (key === 'expiresIn' || key === 'exp') {
            // Having expiry is good - skip
          }
        }
      }
    }

    // jwt.verify without algorithms restriction
    if (calleeName.endsWith('.verify')) {
      let hasAlgoRestriction = false;
      for (const arg of node.arguments) {
        if (arg.type === 'ObjectExpression') {
          for (const prop of arg.properties || []) {
            const key = getNodeName(prop.key) || getStringValue(prop.key);
            if (key === 'algorithms') hasAlgoRestriction = true;
          }
        }
      }
      if (!hasAlgoRestriction && node.arguments.length <= 2) {
        vulns.push(createVuln({
          title: 'JWT Verify - No Algorithm Restriction',
          severity: 'High',
          confidence: 'Medium',
          cwe: CWE.JWT_ISSUES,
          owasp: OWASP.BROKEN_AUTH,
          filePath,
          line: node.loc ? node.loc.start.line : 0,
          column: node.loc ? node.loc.start.column : 0,
          snippet: getCodeSnippet(code, node.loc ? node.loc.start.line : 0),
          remediation: 'Always specify allowed algorithms in jwt.verify(): { algorithms: ["RS256"] }.',
          category: 'JWT Issues',
        }));
      }
    }
  }

  return vulns;
}

// ============================================================================
// Detector: SSL/TLS Issues
// ============================================================================
function detectSSLIssues(path, node, filePath, code) {
  const vulns = [];

  // process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'
  if (node.type === 'AssignmentExpression') {
    const leftName = getNodeName(node.left);
    if (leftName === 'process.env.NODE_TLS_REJECT_UNAUTHORIZED') {
      const val = getStringValue(node.right);
      if (val === '0') {
        vulns.push(createVuln({
          title: 'TLS Certificate Verification Disabled',
          severity: 'High',
          confidence: 'High',
          cwe: CWE.SSL_TLS,
          owasp: OWASP.CRYPTO_FAILURE,
          filePath,
          line: node.loc ? node.loc.start.line : 0,
          column: node.loc ? node.loc.start.column : 0,
          snippet: getCodeSnippet(code, node.loc ? node.loc.start.line : 0),
          remediation: 'Never disable TLS certificate verification. Fix the underlying certificate issue instead.',
          category: 'SSL/TLS Issues',
        }));
      }
    }
  }

  // rejectUnauthorized: false in options
  if ((node.type === 'ObjectProperty' || node.type === 'Property') && !node.computed) {
    const key = getNodeName(node.key) || getStringValue(node.key);
    if (key === 'rejectUnauthorized' && node.value.type === 'BooleanLiteral' && node.value.value === false) {
      vulns.push(createVuln({
        title: 'TLS Certificate Verification Disabled',
        severity: 'High',
        confidence: 'High',
        cwe: CWE.SSL_TLS,
        owasp: OWASP.CRYPTO_FAILURE,
        filePath,
        line: node.loc ? node.loc.start.line : 0,
        column: node.loc ? node.loc.start.column : 0,
        snippet: getCodeSnippet(code, node.loc ? node.loc.start.line : 0),
        remediation: 'Never set rejectUnauthorized to false. Use proper CA certificates instead.',
        category: 'SSL/TLS Issues',
      }));
    }
  }

  return vulns;
}

// ============================================================================
// Detector: Regex DoS
// ============================================================================
function detectRegexDoS(path, node, filePath, code) {
  const vulns = [];

  // new RegExp() with tainted content or evil patterns
  if (node.type === 'NewExpression') {
    const calleeName = getNodeName(node.callee);
    if (calleeName === 'RegExp' && node.arguments.length > 0) {
      const patternStr = getStringValue(node.arguments[0]);
      if (patternStr && isVulnerableRegex(patternStr)) {
        vulns.push(createVuln({
          title: 'Regular Expression Denial of Service (ReDoS)',
          severity: 'Medium',
          confidence: 'Medium',
          cwe: CWE.REGEX_DOS,
          owasp: OWASP.SECURITY_MISCONFIG,
          filePath,
          line: node.loc ? node.loc.start.line : 0,
          column: node.loc ? node.loc.start.column : 0,
          snippet: getCodeSnippet(code, node.loc ? node.loc.start.line : 0),
          remediation: 'Avoid nested quantifiers in regex. Use atomic groups or possessive quantifiers. Consider using re2 library.',
          category: 'Regex DoS',
        }));
      }
    }
  }

  // Regex literal
  if (node.type === 'RegExpLiteral') {
    if (isVulnerableRegex(node.pattern)) {
      vulns.push(createVuln({
        title: 'Regular Expression Denial of Service (ReDoS)',
        severity: 'Medium',
        confidence: 'Medium',
        cwe: CWE.REGEX_DOS,
        owasp: OWASP.SECURITY_MISCONFIG,
        filePath,
        line: node.loc ? node.loc.start.line : 0,
        column: node.loc ? node.loc.start.column : 0,
        snippet: getCodeSnippet(code, node.loc ? node.loc.start.line : 0),
        remediation: 'Simplify the regex pattern to avoid catastrophic backtracking. Use re2 for untrusted input.',
        category: 'Regex DoS',
      }));
    }
  }

  return vulns;
}

// ============================================================================
// Detector: Template Injection
// ============================================================================
function detectTemplateInjection(path, node, filePath, code, taintTracker, scope) {
  const vulns = [];
  if (node.type !== 'CallExpression') return vulns;

  const calleeName = getNodeName(node.callee);
  if (!calleeName) return vulns;

  // Server-side template injection: ejs.render, pug.render, handlebars.compile, nunjucks.renderString
  const templateFuncs = ['ejs.render', 'ejs.renderFile', 'pug.render', 'pug.renderFile',
    'handlebars.compile', 'nunjucks.renderString', 'mustache.render',
    'Mustache.render', 'dot.template', 'jade.render'];

  if (templateFuncs.some(f => calleeName === f || calleeName.endsWith('.' + f.split('.')[1]))) {
    if (node.arguments.length > 0 && nodeContainsTaint(node.arguments[0], taintTracker, scope)) {
      vulns.push(createVuln({
        title: 'Server-Side Template Injection (SSTI)',
        severity: 'Critical',
        confidence: 'High',
        cwe: CWE.TEMPLATE_INJECTION,
        owasp: OWASP.INJECTION,
        filePath,
        line: node.loc ? node.loc.start.line : 0,
        column: node.loc ? node.loc.start.column : 0,
        snippet: getCodeSnippet(code, node.loc ? node.loc.start.line : 0),
        remediation: 'Never pass user input as the template string. Use template data/context variables instead.',
        category: 'Template Injection',
      }));
    }
  }

  return vulns;
}

// ============================================================================
// Detector: Mass Assignment
// ============================================================================
function detectMassAssignment(path, node, filePath, code, taintTracker, scope) {
  const vulns = [];

  // Spread of request body into database operations
  if (node.type === 'CallExpression') {
    const calleeName = getNodeName(node.callee);
    if (!calleeName) return vulns;

    const dbOps = ['create', 'update', 'findOneAndUpdate', 'updateOne', 'insertOne', 'save', 'upsert'];
    const isDbOp = dbOps.some(f => calleeName.endsWith(f) || calleeName.endsWith('.' + f));

    if (isDbOp && node.arguments.length > 0) {
      for (const arg of node.arguments) {
        // Check for spread of tainted data
        if (arg.type === 'ObjectExpression') {
          for (const prop of arg.properties || []) {
            if (prop.type === 'SpreadElement' && nodeContainsTaint(prop.argument, taintTracker, scope)) {
              vulns.push(createVuln({
                title: 'Mass Assignment via Spread Operator',
                severity: 'High',
                confidence: 'High',
                cwe: CWE.MASS_ASSIGNMENT,
                owasp: OWASP.BROKEN_ACCESS,
                filePath,
                line: prop.loc ? prop.loc.start.line : 0,
                column: prop.loc ? prop.loc.start.column : 0,
                snippet: getCodeSnippet(code, prop.loc ? prop.loc.start.line : 0),
                remediation: 'Explicitly pick allowed fields from user input instead of spreading the entire object.',
                category: 'Mass Assignment',
              }));
            }
          }
        }

        // Direct tainted object passed to DB operation
        if (arg.type === 'Identifier' && taintTracker.isTainted(arg.name, scope)) {
          vulns.push(createVuln({
            title: 'Mass Assignment - Direct User Input to Database',
            severity: 'High',
            confidence: 'Medium',
            cwe: CWE.MASS_ASSIGNMENT,
            owasp: OWASP.BROKEN_ACCESS,
            filePath,
            line: arg.loc ? arg.loc.start.line : 0,
            column: arg.loc ? arg.loc.start.column : 0,
            snippet: getCodeSnippet(code, arg.loc ? arg.loc.start.line : 0),
            remediation: 'Validate and whitelist allowed fields before passing user input to database operations.',
            category: 'Mass Assignment',
          }));
        }
      }
    }
  }

  return vulns;
}

// ============================================================================
// Detector: Information Disclosure
// ============================================================================
function detectInfoDisclosure(path, node, filePath, code) {
  const vulns = [];

  // Stack traces in error responses
  if (node.type === 'CallExpression') {
    const calleeName = getNodeName(node.callee);
    if (calleeName && (calleeName.endsWith('.send') || calleeName.endsWith('.json'))) {
      if (node.arguments.length > 0) {
        const arg = node.arguments[0];
        // Check if sending error.stack or err.message
        if (arg.type === 'MemberExpression') {
          const propName = getNodeName(arg.property);
          if (propName === 'stack' || propName === 'message') {
            const objName = getNodeName(arg.object);
            if (objName && /err|error|e|ex/i.test(objName)) {
              vulns.push(createVuln({
                title: 'Information Disclosure - Error Details in Response',
                severity: 'Low',
                confidence: 'Medium',
                cwe: CWE.INFO_DISCLOSURE,
                owasp: OWASP.SECURITY_MISCONFIG,
                filePath,
                line: node.loc ? node.loc.start.line : 0,
                column: node.loc ? node.loc.start.column : 0,
                snippet: getCodeSnippet(code, node.loc ? node.loc.start.line : 0),
                remediation: 'Log error details server-side. Return generic error messages to clients.',
                category: 'Information Disclosure',
              }));
            }
          }
        }
        // Sending entire error object
        if (arg.type === 'ObjectExpression') {
          for (const prop of arg.properties || []) {
            const key = getNodeName(prop.key) || getStringValue(prop.key);
            if (key && (key === 'stack' || key === 'error')) {
              vulns.push(createVuln({
                title: 'Information Disclosure - Stack Trace in Response',
                severity: 'Medium',
                confidence: 'Medium',
                cwe: CWE.INFO_DISCLOSURE,
                owasp: OWASP.SECURITY_MISCONFIG,
                filePath,
                line: prop.loc ? prop.loc.start.line : 0,
                column: prop.loc ? prop.loc.start.column : 0,
                snippet: getCodeSnippet(code, prop.loc ? prop.loc.start.line : 0),
                remediation: 'Never include stack traces in API responses. Log server-side only.',
                category: 'Information Disclosure',
              }));
            }
          }
        }
      }
    }
  }

  return vulns;
}

// ============================================================================
// Detector: Logging Sensitive Data
// ============================================================================
function detectLogSensitiveData(path, node, filePath, code) {
  const vulns = [];
  if (node.type !== 'CallExpression') return vulns;

  const calleeName = getNodeName(node.callee);
  if (!calleeName) return vulns;

  const logFuncs = ['console.log', 'console.info', 'console.warn', 'console.error', 'console.debug',
    'logger.info', 'logger.debug', 'logger.warn', 'logger.error', 'log.info', 'log.debug'];

  if (logFuncs.some(f => calleeName === f)) {
    for (const arg of node.arguments) {
      const argName = getNodeName(arg);
      if (argName && SECRET_VAR_NAMES.test(argName)) {
        vulns.push(createVuln({
          title: 'Sensitive Data Logged',
          severity: 'Medium',
          confidence: 'Medium',
          cwe: CWE.LOG_SENSITIVE,
          owasp: OWASP.LOGGING_MONITORING,
          filePath,
          line: node.loc ? node.loc.start.line : 0,
          column: node.loc ? node.loc.start.column : 0,
          snippet: getCodeSnippet(code, node.loc ? node.loc.start.line : 0),
          remediation: 'Never log sensitive data like passwords, tokens, or API keys. Mask or redact sensitive values.',
          category: 'Logging Sensitive Data',
        }));
      }

      // Logging template with sensitive member access
      if (arg.type === 'TemplateLiteral' && arg.expressions) {
        for (const expr of arg.expressions) {
          const exprName = getNodeName(expr);
          if (exprName && SECRET_VAR_NAMES.test(exprName)) {
            vulns.push(createVuln({
              title: 'Sensitive Data in Log Template',
              severity: 'Medium',
              confidence: 'Medium',
              cwe: CWE.LOG_SENSITIVE,
              owasp: OWASP.LOGGING_MONITORING,
              filePath,
              line: node.loc ? node.loc.start.line : 0,
              column: node.loc ? node.loc.start.column : 0,
              snippet: getCodeSnippet(code, node.loc ? node.loc.start.line : 0),
              remediation: 'Mask sensitive data before logging. Use structured logging with redaction.',
              category: 'Logging Sensitive Data',
            }));
          }
        }
      }
    }
  }

  return vulns;
}

// ============================================================================
// Detector: Timing Attacks
// ============================================================================
function detectTimingAttacks(path, node, filePath, code) {
  const vulns = [];

  // String comparison of secrets: if (token === userToken)
  if (node.type === 'BinaryExpression' && (node.operator === '===' || node.operator === '==')) {
    const leftName = getNodeName(node.left);
    const rightName = getNodeName(node.right);

    const isSensitiveComparison = (
      (leftName && SECRET_VAR_NAMES.test(leftName)) ||
      (rightName && SECRET_VAR_NAMES.test(rightName))
    );

    if (isSensitiveComparison) {
      vulns.push(createVuln({
        title: 'Timing Attack - String Comparison of Secrets',
        severity: 'Medium',
        confidence: 'Medium',
        cwe: CWE.TIMING_ATTACK,
        owasp: OWASP.CRYPTO_FAILURE,
        filePath,
        line: node.loc ? node.loc.start.line : 0,
        column: node.loc ? node.loc.start.column : 0,
        snippet: getCodeSnippet(code, node.loc ? node.loc.start.line : 0),
        remediation: 'Use crypto.timingSafeEqual() for constant-time comparison of secrets and tokens.',
        category: 'Timing Attack',
      }));
    }
  }

  return vulns;
}

// ============================================================================
// Detector: Unsafe Deserialization
// ============================================================================
function detectUnsafeDeserialization(path, node, filePath, code, taintTracker, scope) {
  const vulns = [];
  if (node.type !== 'CallExpression') return vulns;

  const calleeName = getNodeName(node.callee);
  if (!calleeName) return vulns;

  // node-serialize, serialize-javascript (with eval)
  const unsafeDeserFuncs = ['unserialize', 'deserialize', 'YAML.load', 'yaml.load'];
  if (unsafeDeserFuncs.some(f => calleeName === f || calleeName.endsWith('.' + f))) {
    if (node.arguments.length > 0 && nodeContainsTaint(node.arguments[0], taintTracker, scope)) {
      vulns.push(createVuln({
        title: 'Unsafe Deserialization',
        severity: 'Critical',
        confidence: 'High',
        cwe: CWE.DESERIALIZATION,
        owasp: OWASP.SOFTWARE_INTEGRITY,
        filePath,
        line: node.loc ? node.loc.start.line : 0,
        column: node.loc ? node.loc.start.column : 0,
        snippet: getCodeSnippet(code, node.loc ? node.loc.start.line : 0),
        remediation: 'Avoid deserializing untrusted data. Use JSON.parse() instead. For YAML, use yaml.safeLoad().',
        category: 'Unsafe Deserialization',
      }));
    }
  }

  return vulns;
}

// ============================================================================
// Detector: Express-specific Issues
// ============================================================================
function detectExpressIssues(path, node, filePath, code) {
  const vulns = [];
  if (node.type !== 'CallExpression') return vulns;

  const calleeName = getNodeName(node.callee);
  if (!calleeName) return vulns;

  // Helmet not used (check for app.use(helmet()) or app.disable())
  // We track this at a higher level

  // app.disable('x-powered-by') or no helmet
  if (calleeName.endsWith('.disable')) {
    // This is actually good security practice
    return vulns;
  }

  // Express trust proxy misconfiguration
  if (calleeName.endsWith('.set') && node.arguments.length >= 2) {
    const setting = getStringValue(node.arguments[0]);
    if (setting === 'trust proxy' && node.arguments[1].type === 'BooleanLiteral' && node.arguments[1].value === true) {
      vulns.push(createVuln({
        title: 'Express - Trust Proxy Set to True',
        severity: 'Low',
        confidence: 'Medium',
        cwe: CWE.SECURITY_HEADERS,
        owasp: OWASP.SECURITY_MISCONFIG,
        filePath,
        line: node.loc ? node.loc.start.line : 0,
        column: node.loc ? node.loc.start.column : 0,
        snippet: getCodeSnippet(code, node.loc ? node.loc.start.line : 0),
        remediation: 'Set trust proxy to a specific value (e.g., loopback address) instead of true to prevent IP spoofing.',
        category: 'Express Security',
      }));
    }
  }

  return vulns;
}

// ============================================================================
// Detector: React-specific Issues
// ============================================================================
function detectReactIssues(path, node, filePath, code) {
  const vulns = [];

  // href="javascript:" in JSX
  if (node.type === 'JSXAttribute') {
    const attrName = getNodeName(node.name);
    if (attrName === 'href' && node.value) {
      const val = getStringValue(node.value) || (node.value.type === 'JSXExpressionContainer' ? getStringValue(node.value.expression) : null);
      if (val && val.toLowerCase().startsWith('javascript:')) {
        vulns.push(createVuln({
          title: 'React XSS via javascript: URL',
          severity: 'High',
          confidence: 'High',
          cwe: CWE.XSS,
          owasp: OWASP.XSS,
          filePath,
          line: node.loc ? node.loc.start.line : 0,
          column: node.loc ? node.loc.start.column : 0,
          snippet: getCodeSnippet(code, node.loc ? node.loc.start.line : 0),
          remediation: 'Never use javascript: URLs. Use onClick handlers instead.',
          category: 'React Security',
        }));
      }
    }
  }

  // React ref abuse for DOM manipulation
  if (node.type === 'MemberExpression') {
    const fullName = getNodeName(node);
    if (fullName && fullName.includes('.current.innerHTML')) {
      vulns.push(createVuln({
        title: 'React XSS via ref.innerHTML',
        severity: 'High',
        confidence: 'Medium',
        cwe: CWE.XSS,
        owasp: OWASP.XSS,
        filePath,
        line: node.loc ? node.loc.start.line : 0,
        column: node.loc ? node.loc.start.column : 0,
        snippet: getCodeSnippet(code, node.loc ? node.loc.start.line : 0),
        remediation: 'Avoid direct DOM manipulation via refs. Use React state and props for rendering.',
        category: 'React Security',
      }));
    }
  }

  return vulns;
}

// ============================================================================
// Detector: Angular-specific Issues
// ============================================================================
function detectAngularIssues(path, node, filePath, code) {
  const vulns = [];

  // bypassSecurityTrust*
  if (node.type === 'CallExpression') {
    const calleeName = getNodeName(node.callee);
    if (calleeName && /bypassSecurityTrust(Html|Script|Style|Url|ResourceUrl)/.test(calleeName)) {
      vulns.push(createVuln({
        title: `Angular Security Bypass: ${calleeName.split('.').pop()}`,
        severity: 'High',
        confidence: 'High',
        cwe: CWE.XSS,
        owasp: OWASP.XSS,
        filePath,
        line: node.loc ? node.loc.start.line : 0,
        column: node.loc ? node.loc.start.column : 0,
        snippet: getCodeSnippet(code, node.loc ? node.loc.start.line : 0),
        remediation: 'Avoid bypassing Angular sanitization. If necessary, thoroughly validate input before marking as trusted.',
        category: 'Angular Security',
      }));
    }
  }

  return vulns;
}

// ============================================================================
// Detector: Vue-specific Issues
// ============================================================================
function detectVueIssues(path, node, filePath, code) {
  const vulns = [];

  // v-html directive (via JSX or template)
  if (node.type === 'JSXAttribute') {
    const attrName = getNodeName(node.name);
    if (attrName === 'v-html' || attrName === 'domPropsInnerHTML') {
      vulns.push(createVuln({
        title: 'Vue XSS via v-html Directive',
        severity: 'High',
        confidence: 'Medium',
        cwe: CWE.XSS,
        owasp: OWASP.XSS,
        filePath,
        line: node.loc ? node.loc.start.line : 0,
        column: node.loc ? node.loc.start.column : 0,
        snippet: getCodeSnippet(code, node.loc ? node.loc.start.line : 0),
        remediation: 'Avoid v-html with user input. Use v-text or {{ }} interpolation for safe rendering.',
        category: 'Vue Security',
      }));
    }
  }

  return vulns;
}

// ============================================================================
// Detector: Next.js-specific Issues
// ============================================================================
function detectNextJSIssues(path, node, filePath, code) {
  const vulns = [];

  // getServerSideProps leaking sensitive data
  if (node.type === 'ExportNamedDeclaration') {
    const decl = node.declaration;
    if (decl && (decl.type === 'FunctionDeclaration' || decl.type === 'VariableDeclaration')) {
      const name = decl.type === 'FunctionDeclaration' ? decl.id && decl.id.name : null;
      if (name === 'getServerSideProps' || name === 'getStaticProps') {
        // Check if returning sensitive-looking props
        // This is a basic check - looking for properties in the returned object
        // Full analysis would require control flow tracking
      }
    }
  }

  // API routes without auth
  if (filePath.includes('/api/') || filePath.includes('/pages/api/')) {
    if (node.type === 'ExportDefaultDeclaration') {
      // Heuristic: check if handler function checks for auth
      const funcNode = node.declaration;
      if (funcNode && (funcNode.type === 'FunctionDeclaration' || funcNode.type === 'ArrowFunctionExpression')) {
        // Basic: we just flag API routes as needing review
      }
    }
  }

  return vulns;
}

// ============================================================================
// Detector: Missing Authentication
// ============================================================================
function detectMissingAuth(path, node, filePath, code) {
  const vulns = [];

  // Express routes without auth middleware
  if (node.type === 'CallExpression') {
    const calleeName = getNodeName(node.callee);
    if (!calleeName) return vulns;

    const routeMethods = ['get', 'post', 'put', 'delete', 'patch'];
    const isRoute = routeMethods.some(m => calleeName.endsWith('.' + m));

    if (isRoute && node.arguments.length >= 2) {
      const routePath = getStringValue(node.arguments[0]);
      if (!routePath) return vulns;

      // Sensitive routes that should have auth
      const sensitivePatterns = ['/admin', '/user', '/account', '/dashboard', '/settings', '/api/'];
      const isSensitive = sensitivePatterns.some(p => routePath.includes(p));

      if (isSensitive) {
        // Check if there's auth middleware (any function between path and handler)
        const hasMiddleware = node.arguments.length > 2;
        if (!hasMiddleware) {
          vulns.push(createVuln({
            title: `Missing Authentication on Sensitive Route: ${routePath}`,
            severity: 'High',
            confidence: 'Low',
            cwe: CWE.MISSING_AUTH,
            owasp: OWASP.BROKEN_ACCESS,
            filePath,
            line: node.loc ? node.loc.start.line : 0,
            column: node.loc ? node.loc.start.column : 0,
            snippet: getCodeSnippet(code, node.loc ? node.loc.start.line : 0),
            remediation: 'Add authentication middleware to sensitive routes. Use passport.js, express-jwt, or similar.',
            category: 'Missing Authentication',
          }));
        }
      }
    }
  }

  return vulns;
}

// ============================================================================
// Detector: Unsafe File Upload
// ============================================================================
function detectUnsafeUpload(path, node, filePath, code) {
  const vulns = [];
  if (node.type !== 'CallExpression') return vulns;

  const calleeName = getNodeName(node.callee);
  if (!calleeName) return vulns;

  // multer without file filter
  if (calleeName === 'multer') {
    if (node.arguments.length > 0 && node.arguments[0].type === 'ObjectExpression') {
      let hasFileFilter = false;
      for (const prop of node.arguments[0].properties || []) {
        const key = getNodeName(prop.key) || getStringValue(prop.key);
        if (key === 'fileFilter') hasFileFilter = true;
      }
      if (!hasFileFilter) {
        vulns.push(createVuln({
          title: 'Unsafe File Upload - No File Type Validation',
          severity: 'High',
          confidence: 'Medium',
          cwe: CWE.UNSAFE_UPLOAD,
          owasp: OWASP.SECURITY_MISCONFIG,
          filePath,
          line: node.loc ? node.loc.start.line : 0,
          column: node.loc ? node.loc.start.column : 0,
          snippet: getCodeSnippet(code, node.loc ? node.loc.start.line : 0),
          remediation: 'Configure multer with a fileFilter to validate file types. Set limits for file size.',
          category: 'Unsafe File Upload',
        }));
      }
    }
  }

  return vulns;
}

// ============================================================================
// Detector: Security Headers (Express)
// ============================================================================
function detectMissingHeaders(ast, filePath, code) {
  const vulns = [];
  let hasHelmet = false;
  let hasXPoweredBy = false;

  // Check if file is an Express app (heuristic: has require('express') and app.listen/app.use)
  let isExpressApp = false;
  let hasAppListen = false;

  try {
    traverse(ast, {
      CallExpression(path) {
        const calleeName = getNodeName(path.node.callee);
        if (!calleeName) return;

        // Check for require('express')
        if (calleeName === 'require' && path.node.arguments.length > 0) {
          const modName = getStringValue(path.node.arguments[0]);
          if (modName === 'express') isExpressApp = true;
          if (modName === 'helmet') hasHelmet = true;
        }

        // Import of helmet
        if (calleeName === 'helmet' || (calleeName && calleeName.includes('helmet'))) {
          hasHelmet = true;
        }

        // app.listen
        if (calleeName.endsWith('.listen')) hasAppListen = true;

        // app.disable('x-powered-by')
        if (calleeName.endsWith('.disable') && path.node.arguments.length > 0) {
          const val = getStringValue(path.node.arguments[0]);
          if (val === 'x-powered-by') hasXPoweredBy = true;
        }

        // app.use(helmet())
        if (calleeName.endsWith('.use') && path.node.arguments.length > 0) {
          const arg = path.node.arguments[0];
          if (arg.type === 'CallExpression') {
            const innerCallee = getNodeName(arg.callee);
            if (innerCallee === 'helmet') hasHelmet = true;
          }
        }
      },

      ImportDeclaration(path) {
        if (path.node.source.value === 'helmet') hasHelmet = true;
        if (path.node.source.value === 'express') isExpressApp = true;
      },
    });
  } catch (e) {
    // Ignore traversal errors for this detector
  }

  if (isExpressApp && hasAppListen && !hasHelmet && !hasXPoweredBy) {
    vulns.push(createVuln({
      title: 'Missing Security Headers (No Helmet)',
      severity: 'Medium',
      confidence: 'Medium',
      cwe: CWE.SECURITY_HEADERS,
      owasp: OWASP.SECURITY_MISCONFIG,
      filePath,
      line: 1,
      column: 0,
      snippet: '',
      remediation: 'Use helmet middleware: app.use(helmet()) to set security headers (CSP, HSTS, X-Frame-Options, etc.).',
      category: 'Security Headers',
    }));
  }

  return vulns;
}

// ============================================================================
// Detector: CSRF Missing
// ============================================================================
function detectCSRFMissing(ast, filePath, code) {
  const vulns = [];
  let isExpressApp = false;
  let hasCSRF = false;
  let hasSession = false;

  try {
    traverse(ast, {
      CallExpression(path) {
        const calleeName = getNodeName(path.node.callee);
        if (!calleeName) return;

        if (calleeName === 'require') {
          const mod = getStringValue(path.node.arguments[0]);
          if (mod === 'express') isExpressApp = true;
          if (mod === 'csurf' || mod === 'csrf' || mod === 'lusca') hasCSRF = true;
          if (mod === 'express-session' || mod === 'cookie-session') hasSession = true;
        }
      },
      ImportDeclaration(path) {
        const src = path.node.source.value;
        if (src === 'express') isExpressApp = true;
        if (src === 'csurf' || src === 'csrf' || src === 'lusca') hasCSRF = true;
        if (src === 'express-session' || src === 'cookie-session') hasSession = true;
      },
    });
  } catch (e) {
    // Ignore
  }

  if (isExpressApp && hasSession && !hasCSRF) {
    vulns.push(createVuln({
      title: 'Missing CSRF Protection',
      severity: 'Medium',
      confidence: 'Medium',
      cwe: CWE.CSRF_MISSING,
      owasp: OWASP.SECURITY_MISCONFIG,
      filePath,
      line: 1,
      column: 0,
      snippet: '',
      remediation: 'Use csurf or lusca middleware for CSRF protection when sessions are enabled.',
      category: 'CSRF Missing',
    }));
  }

  return vulns;
}

// ============================================================================
// Main Scanner Function
// ============================================================================
function scanFile(filePath, content) {
  const vulns = [];

  // Parse the file
  let ast;
  try {
    ast = parse(content, {
      sourceType: 'unambiguous',
      plugins: [
        'jsx',
        'typescript',
        'decorators-legacy',
        'classProperties',
        'classPrivateProperties',
        'classPrivateMethods',
        'dynamicImport',
        'optionalChaining',
        'nullishCoalescingOperator',
        'optionalCatchBinding',
        'exportDefaultFrom',
        'exportNamespaceFrom',
        'asyncGenerators',
        'objectRestSpread',
        'topLevelAwait',
      ],
      errorRecovery: true,
      allowImportExportEverywhere: true,
      allowReturnOutsideFunction: true,
      allowSuperOutsideMethod: true,
      allowUndeclaredExports: true,
    });
  } catch (parseErr) {
    // Try again without TypeScript if it failed
    try {
      ast = parse(content, {
        sourceType: 'unambiguous',
        plugins: [
          'jsx',
          'decorators-legacy',
          'classProperties',
          'dynamicImport',
          'optionalChaining',
          'nullishCoalescingOperator',
          'objectRestSpread',
          'topLevelAwait',
        ],
        errorRecovery: true,
        allowImportExportEverywhere: true,
        allowReturnOutsideFunction: true,
      });
    } catch (e2) {
      // File is unparseable
      return { vulns: [], parseError: e2.message };
    }
  }

  const taintTracker = new TaintTracker();

  // First pass: file-level detectors
  try {
    vulns.push(...detectMissingHeaders(ast, filePath, content));
    vulns.push(...detectCSRFMissing(ast, filePath, content));
  } catch (e) {
    // Non-critical
  }

  // Main traversal pass
  try {
    traverse(ast, {
      enter(path) {
        const node = path.node;
        if (!node || !node.type) return;

        const scope = getFunctionScope(path);

        // ---- Taint Propagation ----

        // Mark function parameters as tainted if they look like request handlers
        if (node.type === 'ArrowFunctionExpression' || node.type === 'FunctionExpression' || node.type === 'FunctionDeclaration') {
          if (node.params && node.params.length >= 2) {
            const firstParam = node.params[0];
            const paramName = getNodeName(firstParam);
            if (paramName && /^(req|request|ctx|context)$/i.test(paramName)) {
              const innerScope = scope;
              taintTracker.markTainted(paramName, 'http_request', innerScope);
              // Also mark sub-properties
              for (const prop of ['body', 'query', 'params', 'headers', 'cookies', 'url', 'path']) {
                taintTracker.markTainted(`${paramName}.${prop}`, 'http_request', innerScope);
              }
            }
          }
        }

        // Track variable assignments from taint sources
        if (node.type === 'VariableDeclarator' && node.init) {
          const varName = getNodeName(node.id);
          if (varName) {
            if (isTaintSource(node.init) || nodeContainsTaint(node.init, taintTracker, scope)) {
              taintTracker.markTainted(varName, 'assignment', scope);
            }

            // Destructuring from tainted source: const { name } = req.body
            if (node.id.type === 'ObjectPattern' && node.init) {
              if (isTaintSource(node.init) || nodeContainsTaint(node.init, taintTracker, scope)) {
                for (const prop of node.id.properties || []) {
                  const propName = getNodeName(prop.value) || getNodeName(prop.key);
                  if (propName) {
                    taintTracker.markTainted(propName, 'destructuring', scope);
                  }
                }
              }
            }
          }
        }

        // Track assignments: x = req.body.foo
        if (node.type === 'AssignmentExpression') {
          const leftName = getNodeName(node.left);
          if (leftName) {
            if (isTaintSource(node.right) || nodeContainsTaint(node.right, taintTracker, scope)) {
              taintTracker.markTainted(leftName, 'assignment', scope);
            }
          }
        }

        // ---- Run Detectors ----
        try { vulns.push(...detectSQLInjection(path, node, filePath, content, taintTracker, scope)); } catch (e) { /* skip */ }
        try { vulns.push(...detectNoSQLInjection(path, node, filePath, content, taintTracker, scope)); } catch (e) { /* skip */ }
        try { vulns.push(...detectCommandInjection(path, node, filePath, content, taintTracker, scope)); } catch (e) { /* skip */ }
        try { vulns.push(...detectCodeInjection(path, node, filePath, content, taintTracker, scope)); } catch (e) { /* skip */ }
        try { vulns.push(...detectXSS(path, node, filePath, content, taintTracker, scope)); } catch (e) { /* skip */ }
        try { vulns.push(...detectPathTraversal(path, node, filePath, content, taintTracker, scope)); } catch (e) { /* skip */ }
        try { vulns.push(...detectSSRF(path, node, filePath, content, taintTracker, scope)); } catch (e) { /* skip */ }
        try { vulns.push(...detectOpenRedirect(path, node, filePath, content, taintTracker, scope)); } catch (e) { /* skip */ }
        try { vulns.push(...detectPrototypePollution(path, node, filePath, content, taintTracker, scope)); } catch (e) { /* skip */ }
        try { vulns.push(...detectHardcodedSecrets(path, node, filePath, content)); } catch (e) { /* skip */ }
        try { vulns.push(...detectWeakCrypto(path, node, filePath, content)); } catch (e) { /* skip */ }
        try { vulns.push(...detectInsecureRandom(path, node, filePath, content)); } catch (e) { /* skip */ }
        try { vulns.push(...detectCORSMisconfig(path, node, filePath, content)); } catch (e) { /* skip */ }
        try { vulns.push(...detectInsecureCookies(path, node, filePath, content)); } catch (e) { /* skip */ }
        try { vulns.push(...detectJWTIssues(path, node, filePath, content)); } catch (e) { /* skip */ }
        try { vulns.push(...detectSSLIssues(path, node, filePath, content)); } catch (e) { /* skip */ }
        try { vulns.push(...detectRegexDoS(path, node, filePath, content)); } catch (e) { /* skip */ }
        try { vulns.push(...detectTemplateInjection(path, node, filePath, content, taintTracker, scope)); } catch (e) { /* skip */ }
        try { vulns.push(...detectMassAssignment(path, node, filePath, content, taintTracker, scope)); } catch (e) { /* skip */ }
        try { vulns.push(...detectInfoDisclosure(path, node, filePath, content)); } catch (e) { /* skip */ }
        try { vulns.push(...detectLogSensitiveData(path, node, filePath, content)); } catch (e) { /* skip */ }
        try { vulns.push(...detectTimingAttacks(path, node, filePath, content)); } catch (e) { /* skip */ }
        try { vulns.push(...detectUnsafeDeserialization(path, node, filePath, content, taintTracker, scope)); } catch (e) { /* skip */ }
        try { vulns.push(...detectExpressIssues(path, node, filePath, content)); } catch (e) { /* skip */ }
        try { vulns.push(...detectReactIssues(path, node, filePath, content)); } catch (e) { /* skip */ }
        try { vulns.push(...detectAngularIssues(path, node, filePath, content)); } catch (e) { /* skip */ }
        try { vulns.push(...detectVueIssues(path, node, filePath, content)); } catch (e) { /* skip */ }
        try { vulns.push(...detectNextJSIssues(path, node, filePath, content)); } catch (e) { /* skip */ }
        try { vulns.push(...detectMissingAuth(path, node, filePath, content)); } catch (e) { /* skip */ }
        try { vulns.push(...detectUnsafeUpload(path, node, filePath, content)); } catch (e) { /* skip */ }
      },
    });
  } catch (traverseErr) {
    // If traversal fails, return whatever we found so far
    return { vulns, parseError: `Traversal error: ${traverseErr.message}` };
  }

  return { vulns, parseError: null };
}

// ============================================================================
// Express Server
// ============================================================================
const app = express();

// Increase body size limit for large codebases
app.use(express.json({ limit: '100mb' }));

// Health endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    scanner: 'javascript-typescript',
    version: '1.0.0',
    uptime: process.uptime(),
    memoryUsage: process.memoryUsage(),
    supportedExtensions: ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'],
    capabilities: [
      'taint-tracking',
      'sql-injection', 'nosql-injection', 'command-injection', 'code-injection',
      'xss-dom', 'xss-reflected', 'xss-react',
      'path-traversal', 'ssrf', 'open-redirect',
      'prototype-pollution', 'hardcoded-secrets',
      'weak-cryptography', 'insecure-random',
      'cors-misconfiguration', 'csrf-missing', 'security-headers',
      'jwt-issues', 'insecure-cookies', 'ssl-tls',
      'regex-dos', 'template-injection', 'mass-assignment',
      'missing-authentication', 'information-disclosure',
      'timing-attacks', 'unsafe-file-upload', 'logging-sensitive-data',
      'unsafe-deserialization',
      'express-specific', 'react-specific', 'angular-specific', 'vue-specific', 'nextjs-specific',
    ],
  });
});

// Scan endpoint
app.post('/scan', (req, res) => {
  const startTime = Date.now();
  const { files, scanId } = req.body;

  if (!files || typeof files !== 'object') {
    return res.status(400).json({
      error: 'Missing or invalid "files" object. Expected {"path/file.js": "content", ...}',
    });
  }

  const effectiveScanId = scanId || uuidv4();
  const allVulns = [];
  let filesScanned = 0;
  let filesErrored = 0;
  const errors = [];

  const fileEntries = Object.entries(files);

  for (const [filePath, content] of fileEntries) {
    // Skip non JS/TS files
    const ext = filePath.toLowerCase().split('.').pop();
    if (!['js', 'jsx', 'ts', 'tsx', 'mjs', 'cjs'].includes(ext)) {
      continue;
    }

    // Skip files that are too large
    if (typeof content !== 'string') {
      errors.push({ file: filePath, error: 'Content is not a string' });
      filesErrored++;
      continue;
    }

    if (content.length > MAX_FILE_SIZE) {
      errors.push({ file: filePath, error: `File too large (${(content.length / 1024 / 1024).toFixed(1)}MB > ${MAX_FILE_SIZE / 1024 / 1024}MB limit)` });
      filesErrored++;
      continue;
    }

    // Skip minified files (heuristic: very long lines, very few newlines)
    const lineCount = content.split('\n').length;
    if (content.length > 10000 && lineCount < content.length / 500) {
      errors.push({ file: filePath, error: 'Skipped (appears to be minified)' });
      continue;
    }

    // Skip node_modules, vendor, dist, build directories
    if (/[/\\](node_modules|vendor|dist|build|\.next|\.nuxt|coverage)[/\\]/.test(filePath)) {
      continue;
    }

    try {
      const result = scanFile(filePath, content);
      allVulns.push(...result.vulns);
      filesScanned++;

      if (result.parseError) {
        errors.push({ file: filePath, error: `Parse warning: ${result.parseError}` });
      }
    } catch (scanErr) {
      errors.push({ file: filePath, error: scanErr.message });
      filesErrored++;
    }
  }

  // Deduplicate vulnerabilities (same file, line, CWE)
  const seen = new Set();
  const dedupedVulns = allVulns.filter(v => {
    const key = `${v.filePath}:${v.lineNumber}:${v.cwe}:${v.title}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  const elapsed = ((Date.now() - startTime) / 1000).toFixed(2);

  const summary = {
    total: dedupedVulns.length,
    critical: dedupedVulns.filter(v => v.severity === 'Critical').length,
    high: dedupedVulns.filter(v => v.severity === 'High').length,
    medium: dedupedVulns.filter(v => v.severity === 'Medium').length,
    low: dedupedVulns.filter(v => v.severity === 'Low').length,
  };

  res.json({
    scanId: effectiveScanId,
    vulnerabilities: dedupedVulns,
    summary,
    scanDuration: `${elapsed}s`,
    filesScanned,
    filesErrored,
    errors: errors.length > 0 ? errors : undefined,
  });
});

// Error handler
app.use((err, req, res, next) => {
  console.error('Scanner error:', err.message);
  res.status(500).json({ error: 'Internal scanner error', message: err.message });
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`[JS/TS SAST Scanner] Running on port ${PORT}`);
  console.log(`[JS/TS SAST Scanner] Health: GET http://localhost:${PORT}/health`);
  console.log(`[JS/TS SAST Scanner] Scan:   POST http://localhost:${PORT}/scan`);
});
