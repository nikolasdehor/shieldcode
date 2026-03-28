# Changelog

## [1.0.0] - 2026-03-27

### Added
- Initial release
- Input validation rules with Zod (TypeScript) and Pydantic (Python)
- SQL injection prevention with parameterized query examples
- XSS prevention with safe DOM API patterns and CSP headers
- Authentication rules: bcrypt/argon2, full JWT verification, rate limiting, secure cookies
- Authorization rules: server-side role checks, ownership validation
- Secrets management: env var validation at startup, no hardcoded credentials
- File operation safety: path traversal prevention, upload restrictions
- Dependency safety: slopsquatting prevention, trusted package reference list
- Error handling: custom error class hierarchy for TypeScript and Python
- HTTP status code reference table
- Structured logging with pino (TypeScript) and structlog (Python)
- External call safety: timeouts, exponential backoff, tenacity integration
- Async safety: promise handling, Node.js global error handlers, FastAPI BackgroundTasks
- Quick reference checklist covering all rules
