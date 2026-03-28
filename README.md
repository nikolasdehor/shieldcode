<p align="center">
  <img src="assets/banner.svg" width="800" alt="ShieldCode">
</p>

<p align="center">
  <strong>Stop shipping vulnerable code</strong><br>
  <sub>Security hardening and production-grade error handling expertise for Claude Code</sub>
</p>

<p align="center">
  <a href="#install">Install</a> ·
  <a href="#what-it-covers">Coverage</a> ·
  <a href="#before--after">Examples</a> ·
  <a href="#how-it-works">How it Works</a>
</p>

<p align="center">
  <img src="https://img.shields.io/github/stars/nikolasdehor/shieldcode?style=flat-square&labelColor=09090b&color=10b981" alt="Stars">
  <img src="https://img.shields.io/badge/license-MIT-10b981?style=flat-square&labelColor=09090b" alt="License">
  <img src="https://img.shields.io/badge/Claude_Code-compatible-06b6d4?style=flat-square&labelColor=09090b" alt="Claude Code compatible">
  <img src="https://img.shields.io/badge/OWASP-Top_10-10b981?style=flat-square&labelColor=09090b" alt="OWASP Top 10">
</p>

---

## The Problem

**62% of AI-generated code contains at least one security vulnerability.**

45% fail OWASP Top 10 checks. Error handling gaps are 2x more common in AI code than in human-written code. Claude is excellent at writing code fast - but without active guidance, it takes shortcuts: concatenating user input into SQL queries, using `MD5` for passwords, swallowing exceptions silently, leaking stack traces to clients.

ShieldCode fixes this by giving Claude a set of non-negotiable rules that activate automatically whenever it touches user input, authentication, databases, APIs, file operations, or error handling.

---

## What It Covers

**Security (8 rules):**

| Rule | What it enforces |
|---|---|
| Input Validation | Allowlist patterns, type/length/format/range checks |
| SQL Injection Prevention | Parameterized queries only - no string concatenation |
| XSS Prevention | Safe DOM APIs, Content Security Policy, template autoescape |
| Authentication | bcrypt/argon2 only, full JWT verification, rate limiting, secure cookies |
| Authorization | Server-side role checks, resource ownership validation |
| Secrets Management | Environment variables only - no hardcoded keys, no secret logging |
| File Security | Path traversal prevention, upload type/size restrictions |
| Dependency Safety | Only real, known packages (slopsquatting prevention) |

**Error Handling (6 rules):**

| Rule | What it enforces |
|---|---|
| Exception Hierarchy | Typed error classes - no raw `Error` throws |
| HTTP Status Codes | Correct 400/401/403/404/409/422/429/500 usage |
| Secure Logging | Structured JSON with correlation IDs, no PII or secrets |
| Retry with Backoff | Exponential backoff + jitter on all external calls |
| Circuit Breaker | Fail fast, recover gracefully |
| Async Error Safety | Handled promises, no unhandled rejections |

---

## Before / After

Every rule includes concrete UNSAFE vs SAFE examples in TypeScript and Python.

**SQL Injection**

```javascript
// UNSAFE
db.query(`SELECT * FROM users WHERE id = '${id}'`);
```

```javascript
// SAFE
db.query('SELECT * FROM users WHERE id = $1', [id]);
```

**Password Hashing**

```javascript
// UNSAFE
const hash = crypto.createHash('md5').update(password).digest('hex');
```

```javascript
// SAFE
const hash = await bcrypt.hash(password, 12);
```

**Error Leakage**

```javascript
// UNSAFE
res.status(500).json({ error: err.stack });
```

```javascript
// SAFE
logger.error({ correlationId, err });
res.status(500).json({ error: 'Internal server error', correlationId });
```

---

## How it Works

1. Install ShieldCode (one command)
2. Write code normally
3. Claude automatically follows secure patterns
4. Ship secure code every time

ShieldCode is a knowledge skill - a `SKILL.md` file that Claude Code loads from `~/.claude/skills/shieldcode/`. No tools. No scripts. No external calls. Pure guidance that shapes Claude's output at the source.

---

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/nikolasdehor/shieldcode/main/install.sh | bash
```

```bash
# Claude Code plugin
claude plugins install github:nikolasdehor/shieldcode
```

```bash
# Manual
mkdir -p ~/.claude/skills/shieldcode
curl -o ~/.claude/skills/shieldcode/SKILL.md \
  https://raw.githubusercontent.com/nikolasdehor/shieldcode/main/skills/shieldcode/SKILL.md
```

After installing, **restart Claude Code**. The skill activates automatically on security-sensitive code.

---

## Requirements

- **Claude Code** - any plan (Free, Pro, Teams)
- That's it. Zero dependencies.

---

## Roadmap

- [x] v1.0 - OWASP Top 10 + Error Handling (current)
- [ ] v1.1 - CSRF protection, rate limiting patterns
- [ ] v1.2 - Database design security patterns
- [ ] v2.0 - Auto-scan mode (detect vulnerabilities in existing code)

---

## License

MIT - see [LICENSE](LICENSE)

---

<p align="center">
  Built by <a href="https://github.com/nikolasdehor">Nikolas de Hor</a>
  <br>
  <sub>Because 62% is not acceptable</sub>
</p>
