# ShieldCode

Stop Claude from generating insecure code.

ShieldCode is a Claude Code skill that bakes security hardening and production-grade error handling into every line Claude writes. It covers OWASP Top 10 vulnerabilities, secure defaults, and correct error handling patterns for JavaScript/TypeScript and Python.

## The Problem

62% of AI-generated code contains at least one security vulnerability. Claude is excellent at writing code fast - but without active guidance, it takes shortcuts: concatenating user input into SQL queries, using weak password hashing, swallowing exceptions silently, returning stack traces to clients.

ShieldCode fixes this by giving Claude a set of non-negotiable rules that activate automatically when generating code that touches user input, authentication, databases, APIs, file operations, or error handling.

## What It Covers

**Security (OWASP Top 10):**
- Input validation - allowlist patterns, type/length/format/range checks
- SQL injection prevention - parameterized queries only, no concatenation
- XSS prevention - safe DOM APIs, Content Security Policy, Jinja2 autoescape
- Authentication - bcrypt/argon2 only, full JWT verification, rate limiting, secure cookies
- Authorization - server-side role checks, resource ownership validation
- Secrets management - environment variables, no hardcoded keys, no secret logging
- File operation safety - path traversal prevention, upload type/size restrictions
- Dependency safety - only real, known packages (slopsquatting prevention)

**Error Handling:**
- No silent catch blocks
- No internal details exposed to clients
- Correct HTTP status codes (400/401/403/404/409/422/429/500)
- Typed error class hierarchies
- Structured JSON logging with correlation IDs
- No sensitive data in logs
- Timeouts and exponential backoff on all external calls
- Handled promises and async background tasks

Every rule includes UNSAFE vs SAFE code examples in both TypeScript and Python.

## Install

```bash
git clone https://github.com/nikolasdehor/shieldcode
cd shieldcode
./install.sh
```

Or manually:

```bash
mkdir -p ~/.claude/skills/shieldcode
curl -o ~/.claude/skills/shieldcode/SKILL.md \
  https://raw.githubusercontent.com/nikolasdehor/shieldcode/main/skills/shieldcode/SKILL.md
```

## Uninstall

```bash
./uninstall.sh
```

## How It Works

ShieldCode is a knowledge skill - a SKILL.md file that Claude Code loads from `~/.claude/skills/shieldcode/`. When you work on code involving security-sensitive areas, Claude automatically applies the rules without any prompting.

No tools. No scripts. No external calls. Pure knowledge that guides Claude's code generation.

## License

MIT - see [LICENSE](LICENSE).
