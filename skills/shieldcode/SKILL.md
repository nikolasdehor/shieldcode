---
name: shieldcode
description: >
  Security hardening and production-grade error handling for all code Claude generates.
  Auto-activates when writing code that handles user input, database queries, authentication,
  API endpoints, file operations, error handling, or logging. Prevents OWASP Top 10
  vulnerabilities and enforces secure defaults across JavaScript/TypeScript and Python.
---

# ShieldCode - Security & Error Handling

You MUST follow these rules when generating ANY code. These are non-negotiable constraints, not suggestions.

---

## PART 1: SECURITY RULES

---

### 1. Input Validation

**Rule:** ALWAYS validate and sanitize ALL user input before processing. Use allowlist validation (define what IS allowed), never blocklist. Validate type, length, format, and range. Never trust client-side validation alone.

```typescript
// UNSAFE - no validation, trusts client
app.post('/user', async (req, res) => {
  const { username, age, role } = req.body;
  await db.query(`INSERT INTO users VALUES ('${username}', ${age}, '${role}')`);
});

// SAFE - allowlist validation with Zod (TypeScript)
import { z } from 'zod';

const CreateUserSchema = z.object({
  username: z.string().min(3).max(32).regex(/^[a-zA-Z0-9_]+$/),
  age: z.number().int().min(13).max(120),
  role: z.enum(['user', 'moderator']),  // allowlist of valid roles
});

app.post('/user', async (req, res) => {
  const result = CreateUserSchema.safeParse(req.body);
  if (!result.success) {
    return res.status(400).json({ message: 'Invalid input', errors: result.error.flatten() });
  }
  const { username, age, role } = result.data;
  await db.query('INSERT INTO users (username, age, role) VALUES ($1, $2, $3)', [username, age, role]);
});
```

```python
# UNSAFE - no validation
@app.post("/user")
async def create_user(request: Request):
    data = await request.json()
    username = data["username"]
    age = data["age"]
    role = data["role"]
    await db.execute(f"INSERT INTO users VALUES ('{username}', {age}, '{role}')")

# SAFE - Pydantic with strict validation (Python/FastAPI)
from pydantic import BaseModel, Field, field_validator
from enum import Enum
import re

class UserRole(str, Enum):
    user = "user"
    moderator = "moderator"

class CreateUserRequest(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    age: int = Field(ge=13, le=120)
    role: UserRole

    @field_validator("username")
    @classmethod
    def username_alphanumeric(cls, v: str) -> str:
        if not re.match(r'^[a-zA-Z0-9_]+$', v):
            raise ValueError("Username must be alphanumeric")
        return v

@app.post("/user")
async def create_user(body: CreateUserRequest):
    await db.execute(
        "INSERT INTO users (username, age, role) VALUES ($1, $2, $3)",
        body.username, body.age, body.role.value
    )
```

---

### 2. SQL / NoSQL Injection Prevention

**Rule:** ALWAYS use parameterized queries or prepared statements. NEVER concatenate user input into query strings. This applies to ALL databases: PostgreSQL, MySQL, SQLite, MongoDB.

```typescript
// UNSAFE - SQL injection vulnerability
const userId = req.params.id;
const user = await db.query(`SELECT * FROM users WHERE id = ${userId}`);

// SAFE - parameterized queries
const userId = req.params.id;
const user = await db.query('SELECT * FROM users WHERE id = $1', [userId]);

// SAFE - LIKE with parameterization
const search = req.query.search as string;
const sanitizedSearch = search.replace(/[%_\\]/g, '\\$&');
const results = await db.query(
  'SELECT * FROM products WHERE name ILIKE $1',
  [`%${sanitizedSearch}%`]
);

// SAFE - ORM (always use parameterized methods)
const user = await prisma.user.findUnique({ where: { id: parseInt(userId) } });
```

```python
# UNSAFE
user_id = request.path_params["id"]
user = await db.fetchrow(f"SELECT * FROM users WHERE id = {user_id}")

# SAFE - asyncpg parameterized
user_id = request.path_params["id"]
user = await db.fetchrow("SELECT * FROM users WHERE id = $1", int(user_id))

# SAFE - SQLAlchemy ORM
from sqlalchemy import select
stmt = select(User).where(User.id == int(user_id))
result = await session.execute(stmt)
user = result.scalar_one_or_none()
```

---

### 3. XSS Prevention

**Rule:** ALWAYS escape output rendered in HTML. Use Content-Security-Policy headers. Never assign user-controlled data to innerHTML, outerHTML, document.write, or similar DOM sinks. Use textContent instead. In React, never use the dangerouslySetInnerHTML prop without sanitization.

```typescript
// UNSAFE - XSS via direct DOM assignment
const username = searchParams.get('name');
document.getElementById('greeting').innerHTML = `Hello, ${username}!`;

// SAFE - use textContent (automatic escaping)
const username = searchParams.get('name') ?? '';
document.getElementById('greeting').textContent = `Hello, ${username}!`;

// SAFE - React escapes variables by default in JSX expressions
function Comment({ text }: { text: string }) {
  return <div>{text}</div>;
}

// SAFE - if you genuinely need to render trusted HTML, use DOMPurify
import DOMPurify from 'dompurify';
// Only pass sanitized HTML to any DOM property that accepts HTML
const cleanHtml = DOMPurify.sanitize(trustedHtmlContent);
```

```python
# UNSAFE - XSS in Jinja2 when autoescape is off
from jinja2 import Environment
env = Environment(autoescape=False)
template = env.from_string("<p>Hello {{ name }}</p>")

# SAFE - always use autoescape=True (default for HTML templates in Jinja2)
from jinja2 import Environment
env = Environment(autoescape=True)
template = env.from_string("<p>Hello {{ name }}</p>")

# SAFE - FastAPI with Jinja2Templates uses autoescape by default
from fastapi.templating import Jinja2Templates
templates = Jinja2Templates(directory="templates")
```

**Always set these security response headers:**

```python
# FastAPI security headers middleware
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response
```

```typescript
// Express security headers middleware
app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'");
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});
// Or use the helmet package: app.use(helmet())
```

---

### 4. Authentication

**Rule:** ALWAYS use bcrypt or argon2 for password hashing. NEVER use md5, sha1, sha256, or any fast hash for passwords. ALWAYS validate JWT signature, expiration, AND issuer. ALWAYS rate-limit auth endpoints. Use secure cookie attributes.

```typescript
// UNSAFE - weak hashing
import crypto from 'crypto';
const hash = crypto.createHash('sha256').update(password).digest('hex');

// UNSAFE - jwt.decode() skips ALL verification
import jwt from 'jsonwebtoken';
const payload = jwt.decode(token);

// SAFE - bcrypt password hashing
import bcrypt from 'bcrypt';
const SALT_ROUNDS = 12;
const hash = await bcrypt.hash(password, SALT_ROUNDS);
const isValid = await bcrypt.compare(password, hash);

// SAFE - JWT verification with full options
const payload = jwt.verify(token, process.env.JWT_SECRET!, {
  algorithms: ['HS256'],
  issuer: 'my-app',
  audience: 'my-app-users',
  // expiration is checked automatically when present in token
}) as JwtPayload;

// SAFE - secure cookie
res.cookie('session', token, {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'strict',
  maxAge: 15 * 60 * 1000,  // 15 minutes
});

// SAFE - rate limiting on auth endpoints (express-rate-limit)
import rateLimit from 'express-rate-limit';
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { message: 'Too many login attempts, try again later' },
  standardHeaders: true,
  legacyHeaders: false,
});
app.post('/auth/login', authLimiter, loginHandler);
```

```python
# UNSAFE
import hashlib
hashed = hashlib.sha256(password.encode()).hexdigest()

# SAFE - bcrypt (Python)
import bcrypt
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
is_valid = bcrypt.checkpw(password.encode(), hashed)

# SAFE - argon2 (stronger, preferred for new projects)
from argon2 import PasswordHasher
ph = PasswordHasher(time_cost=2, memory_cost=65536, parallelism=2)
hashed = ph.hash(password)
try:
    ph.verify(hashed, password)
    is_valid = True
except Exception:
    is_valid = False

# SAFE - JWT verification (python-jose)
from jose import jwt, JWTError
from datetime import datetime, timezone

def verify_token(token: str) -> dict:
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET,
            algorithms=["HS256"],
            options={"require": ["exp", "iat", "sub"]}
        )
        if payload["exp"] < datetime.now(timezone.utc).timestamp():
            raise ValueError("Token expired")
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# SAFE - rate limiting with slowapi (FastAPI)
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)

@app.post("/auth/login")
@limiter.limit("10/15minutes")
async def login(request: Request, body: LoginRequest):
    ...
```

---

### 5. Authorization

**Rule:** ALWAYS check permissions server-side. Never trust client-provided role or permission fields. Validate resource ownership before allowing access or modification. Apply principle of least privilege.

```typescript
// UNSAFE - trusts client-provided role
app.post('/admin/action', async (req, res) => {
  if (req.body.role === 'admin') {  // role comes from client - never do this
    await performAdminAction();
  }
});

// UNSAFE - no ownership check
app.delete('/post/:id', authenticate, async (req, res) => {
  await db.query('DELETE FROM posts WHERE id = $1', [req.params.id]);
  // Any authenticated user can delete any post!
});

// SAFE - server-side role from verified JWT
app.post('/admin/action', authenticate, requireRole('admin'), async (req, res) => {
  await performAdminAction();
});

function requireRole(role: string) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (req.user?.role !== role) {
      return res.status(403).json({ message: 'Forbidden' });
    }
    next();
  };
}

// SAFE - ownership check
app.delete('/post/:id', authenticate, async (req, res) => {
  const post = await db.query('SELECT author_id FROM posts WHERE id = $1', [req.params.id]);
  if (!post.rows[0]) return res.status(404).json({ message: 'Not found' });
  if (post.rows[0].author_id !== req.user.id) {
    return res.status(403).json({ message: 'Forbidden' });
  }
  await db.query('DELETE FROM posts WHERE id = $1 AND author_id = $2', [req.params.id, req.user.id]);
  res.status(204).send();
});
```

```python
# UNSAFE
@app.delete("/post/{post_id}")
async def delete_post(post_id: int, current_user: User = Depends(get_current_user)):
    await db.execute("DELETE FROM posts WHERE id = $1", post_id)
    # Any authenticated user can delete any post

# SAFE - ownership check
@app.delete("/post/{post_id}", status_code=204)
async def delete_post(
    post_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    post = await db.get(Post, post_id)
    if post is None:
        raise HTTPException(status_code=404, detail="Post not found")
    if post.author_id != current_user.id:
        raise HTTPException(status_code=403, detail="Forbidden")
    await db.delete(post)
    await db.commit()
```

---

### 6. Secrets and Configuration

**Rule:** NEVER hardcode secrets, API keys, passwords, or tokens in source code. ALWAYS use environment variables or a secret manager. NEVER log secrets. NEVER include secrets in error messages or API responses.

```typescript
// UNSAFE - hardcoded secrets
const JWT_SECRET = 'super-secret-key-123';
const DB_URL = 'postgres://admin:password123@localhost/mydb';
const client = new OpenAI({ apiKey: 'sk-proj-abc123...' });

// SAFE - environment variables with validation at startup
import { z } from 'zod';

const EnvSchema = z.object({
  JWT_SECRET: z.string().min(32),
  DATABASE_URL: z.string().url(),
  OPENAI_API_KEY: z.string().startsWith('sk-'),
  NODE_ENV: z.enum(['development', 'production', 'test']),
});

const env = EnvSchema.parse(process.env);
// Fails at startup if required vars are missing

// UNSAFE - secret leaks in error response
catch (error) {
  res.status(500).json({ error: error.message, config: process.env });
}

// SAFE - generic message to client, details only in server log
catch (error) {
  logger.error('Database connection failed', { error: error.message });
  res.status(500).json({ message: 'Internal server error' });
}
```

```python
# UNSAFE
JWT_SECRET = "super-secret-key"
API_KEY = "sk-proj-abc123"

# SAFE - pydantic settings
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    jwt_secret: str
    database_url: str
    openai_api_key: str
    environment: str = "development"

    @field_validator("jwt_secret")
    @classmethod
    def validate_secret_length(cls, v: str) -> str:
        if len(v) < 32:
            raise ValueError("JWT secret must be at least 32 characters")
        return v

settings = Settings()  # Fails at startup if required env vars are missing
```

---

### 7. File Operations

**Rule:** ALWAYS validate file paths to prevent path traversal. Restrict upload file types and sizes. Never execute uploaded files. Resolve paths and confirm they are within the intended directory.

```typescript
// UNSAFE - path traversal vulnerability
app.get('/files/:filename', (req, res) => {
  const filePath = path.join('/uploads', req.params.filename);
  res.sendFile(filePath);
  // Attacker can request: /files/../../etc/passwd
});

// SAFE - path traversal prevention
import path from 'path';
import fs from 'fs';

const UPLOAD_DIR = path.resolve('/uploads');

app.get('/files/:filename', (req, res) => {
  const requestedPath = path.resolve(UPLOAD_DIR, req.params.filename);
  if (!requestedPath.startsWith(UPLOAD_DIR + path.sep)) {
    return res.status(400).json({ message: 'Invalid file path' });
  }
  if (!fs.existsSync(requestedPath)) {
    return res.status(404).json({ message: 'File not found' });
  }
  res.sendFile(requestedPath);
});

// SAFE - upload with type and size restrictions (multer)
import multer from 'multer';

const ALLOWED_MIME_TYPES = ['image/jpeg', 'image/png', 'image/webp', 'application/pdf'];
const MAX_FILE_SIZE = 5 * 1024 * 1024;  // 5MB

const upload = multer({
  storage: multer.diskStorage({ destination: '/uploads' }),
  limits: { fileSize: MAX_FILE_SIZE },
  fileFilter: (req, file, cb) => {
    if (ALLOWED_MIME_TYPES.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('File type not allowed'));
    }
  },
});
```

```python
# UNSAFE
@app.get("/files/{filename}")
async def get_file(filename: str):
    file_path = f"/uploads/{filename}"
    return FileResponse(file_path)

# SAFE
import os
from pathlib import Path
from fastapi import HTTPException
from fastapi.responses import FileResponse

UPLOAD_DIR = Path("/uploads").resolve()
ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp", ".pdf"}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

@app.get("/files/{filename}")
async def get_file(filename: str):
    requested = (UPLOAD_DIR / filename).resolve()
    if not str(requested).startswith(str(UPLOAD_DIR)):
        raise HTTPException(status_code=400, detail="Invalid file path")
    if not requested.exists():
        raise HTTPException(status_code=404, detail="File not found")
    return FileResponse(requested)

@app.post("/upload")
async def upload_file(file: UploadFile):
    ext = Path(file.filename or "").suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400, detail="File type not allowed")
    content = await file.read(MAX_FILE_SIZE + 1)
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(status_code=413, detail="File too large")
    # save content...
```

---

### 8. Dependency Safety (Slopsquatting Prevention)

**Rule:** NEVER suggest packages you are not certain exist. Do not invent package names. Verify package names before recommending. Prefer well-known, actively maintained packages.

**Trusted packages (TypeScript/Node):**
- Password hashing: `bcrypt`, `argon2`
- JWT: `jsonwebtoken`, `jose`
- Validation: `zod`, `joi`, `yup`
- Rate limiting: `express-rate-limit`, `rate-limiter-flexible`
- HTML sanitization: `dompurify`, `sanitize-html`
- File upload: `multer`
- Security headers: `helmet`

**Trusted packages (Python):**
- Password hashing: `bcrypt`, `argon2-cffi`
- JWT: `python-jose[cryptography]`, `pyjwt`
- Validation: `pydantic` (built-in to FastAPI)
- Rate limiting: `slowapi`, `limits`
- HTML sanitization: `bleach`, `nh3`
- Settings: `pydantic-settings`

---

## PART 2: ERROR HANDLING RULES

---

### 1. The Golden Rules

**Never expose internal details to clients. Never swallow exceptions silently. Always log enough context to debug without logging sensitive data.**

```typescript
// UNSAFE - swallowed exception
try {
  await processPayment(order);
} catch (e) {}

// UNSAFE - exposes stack trace to client
try {
  await processPayment(order);
} catch (e) {
  res.status(500).json({ error: e.stack });
}

// UNSAFE - logs sensitive data
try {
  await chargeCard(cardNumber, cvv, amount);
} catch (e) {
  logger.error('Payment failed', { cardNumber, cvv, amount, error: e });
}

// SAFE - structured error handling
try {
  await processPayment(order);
} catch (error) {
  if (error instanceof PaymentDeclinedError) {
    return res.status(402).json({ message: error.userMessage });
  }
  if (error instanceof ValidationError) {
    return res.status(400).json({ message: error.message });
  }
  logger.error('Payment processing failed', {
    orderId: order.id,
    userId: order.userId,
    amount: order.amount,
    errorType: error.constructor.name,
    message: error.message,
    // NEVER log: cardNumber, cvv, password, token, secret
  });
  return res.status(500).json({ message: 'Payment processing failed. Please try again.' });
}
```

```python
# UNSAFE
try:
    await process_payment(order)
except Exception:
    pass  # swallowed

# UNSAFE
try:
    await process_payment(order)
except Exception as e:
    raise HTTPException(status_code=500, detail=str(e))  # leaks internals

# SAFE
try:
    await process_payment(order)
except PaymentDeclinedError as e:
    raise HTTPException(status_code=402, detail=e.user_message)
except ValidationError as e:
    raise HTTPException(status_code=400, detail=str(e))
except Exception as e:
    logger.error(
        "Payment processing failed",
        extra={
            "order_id": order.id,
            "user_id": order.user_id,
            "amount": str(order.amount),
            "error_type": type(e).__name__,
            "error_message": str(e),
        }
    )
    raise HTTPException(status_code=500, detail="Payment processing failed. Please try again.")
```

---

### 2. Custom Error Classes

**Rule:** Define typed error classes for different failure modes. This enables precise handling at boundaries and consistent error responses.

```typescript
// TypeScript - error hierarchy
class AppError extends Error {
  constructor(
    message: string,
    public readonly statusCode: number,
    public readonly userMessage: string = message,
    public readonly code?: string
  ) {
    super(message);
    this.name = this.constructor.name;
    Error.captureStackTrace(this, this.constructor);
  }
}

class ValidationError extends AppError {
  constructor(message: string) { super(message, 400); }
}

class NotFoundError extends AppError {
  constructor(resource: string) { super(`${resource} not found`, 404); }
}

class UnauthorizedError extends AppError {
  constructor() { super('Unauthorized', 401, 'Authentication required'); }
}

class ForbiddenError extends AppError {
  constructor() { super('Forbidden', 403, 'You do not have permission to perform this action'); }
}

// Central error handler (Express)
app.use((error: Error, req: Request, res: Response, next: NextFunction) => {
  if (error instanceof AppError) {
    return res.status(error.statusCode).json({ message: error.userMessage });
  }
  logger.error('Unhandled error', {
    path: req.path,
    method: req.method,
    errorType: error.constructor.name,
    message: error.message,
  });
  res.status(500).json({ message: 'An unexpected error occurred' });
});
```

```python
# Python - error hierarchy
class AppError(Exception):
    def __init__(self, message: str, status_code: int, user_message: str | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.user_message = user_message or message

class ValidationError(AppError):
    def __init__(self, message: str):
        super().__init__(message, 400)

class NotFoundError(AppError):
    def __init__(self, resource: str):
        super().__init__(f"{resource} not found", 404)

class UnauthorizedError(AppError):
    def __init__(self):
        super().__init__("Unauthorized", 401, "Authentication required")

class ForbiddenError(AppError):
    def __init__(self):
        super().__init__("Forbidden", 403, "You do not have permission to perform this action")

# Central exception handler (FastAPI)
from fastapi import Request
from fastapi.responses import JSONResponse

@app.exception_handler(AppError)
async def app_error_handler(request: Request, exc: AppError):
    return JSONResponse(status_code=exc.status_code, content={"message": exc.user_message})

@app.exception_handler(Exception)
async def generic_error_handler(request: Request, exc: Exception):
    logger.error("Unhandled error", extra={"path": request.url.path, "error": str(exc)})
    return JSONResponse(status_code=500, content={"message": "An unexpected error occurred"})
```

---

### 3. HTTP Status Codes

**Rule:** Use the correct HTTP status code for every response. NEVER return 200 for an error. NEVER return 500 for a validation error.

| Code | When to use |
|------|------------|
| 200 | Successful GET, PUT, PATCH |
| 201 | Successful POST that created a resource |
| 204 | Successful DELETE or action with no response body |
| 400 | Bad Request: malformed request, wrong types |
| 401 | Unauthenticated: no valid credentials provided |
| 403 | Authenticated but not authorized for this resource |
| 404 | Resource not found |
| 409 | Conflict: duplicate resource, state conflict |
| 422 | Unprocessable Entity: valid format but semantic error |
| 429 | Too Many Requests: rate limit exceeded |
| 500 | Internal Server Error: unexpected failure only |
| 503 | Service Unavailable: downstream dependency down |

```typescript
// UNSAFE - wrong status codes
app.post('/users', async (req, res) => {
  if (!req.body.email) {
    return res.status(200).json({ error: 'Email required' });  // 200 for error!
  }
  const existing = await findUserByEmail(req.body.email);
  if (existing) {
    return res.status(500).json({ error: 'User exists' });  // 500 for conflict!
  }
  const user = await createUser(req.body);
  return res.status(200).json(user);  // should be 201!
});

// SAFE
app.post('/users', async (req, res) => {
  if (!req.body.email) {
    return res.status(400).json({ message: 'Email is required' });
  }
  const existing = await findUserByEmail(req.body.email);
  if (existing) {
    return res.status(409).json({ message: 'An account with this email already exists' });
  }
  const user = await createUser(req.body);
  return res.status(201).json(user);
});
```

---

### 4. Structured Logging

**Rule:** Use structured logging with JSON format. Include correlation IDs. NEVER log passwords, tokens, API keys, credit card numbers, or PII. Use appropriate log levels.

```typescript
// UNSAFE - unstructured logs with sensitive data
console.log(`User ${req.body.email} logged in with password ${req.body.password}`);

// SAFE - structured logging with pino
import pino from 'pino';

const logger = pino({
  level: process.env.LOG_LEVEL ?? 'info',
  redact: ['password', 'token', 'authorization', 'cookie', '*.password', '*.token'],
});

// Attach request ID middleware
import { randomUUID } from 'crypto';
app.use((req, res, next) => {
  req.requestId = randomUUID();
  next();
});

// Log levels:
// error   - something failed that needs attention (payment failed, DB down)
// warn    - unexpected but handled (retry succeeded, deprecated endpoint called)
// info    - business events (user created, order placed)
// debug   - development detail (not for production)

logger.info({ userId: user.id, event: 'user.login', requestId: req.requestId }, 'User logged in');
logger.error({ orderId, errorType: error.constructor.name, requestId: req.requestId }, 'Order failed');
```

```python
# UNSAFE
import logging
logging.info(f"User {email} logged in with password {password}")

# SAFE - structlog
import structlog
import uuid

log = structlog.get_logger()

log.info("user.login", user_id=user.id, request_id=request_id)
log.error("order.failed", order_id=order_id, error_type=type(e).__name__, request_id=request_id)
# NEVER: password=password, token=token, api_key=key

# FastAPI request ID middleware
@app.middleware("http")
async def add_request_id(request: Request, call_next):
    request_id = str(uuid.uuid4())
    structlog.contextvars.bind_contextvars(request_id=request_id)
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    structlog.contextvars.clear_contextvars()
    return response
```

---

### 5. External Calls: Timeouts, Retries, Circuit Breakers

**Rule:** ALL external calls (HTTP, DB, cache, queues) MUST have timeouts. Implement retry with exponential backoff for transient failures. Fail gracefully when a dependency is unavailable.

```typescript
// UNSAFE - no timeout, no retry
const response = await fetch('https://api.payment.com/charge', {
  method: 'POST',
  body: JSON.stringify(data),
});

// SAFE - with timeout, retry, and error handling
async function callWithRetry<T>(
  fn: () => Promise<T>,
  options: { maxAttempts?: number; baseDelayMs?: number; timeoutMs?: number } = {}
): Promise<T> {
  const { maxAttempts = 3, baseDelayMs = 200, timeoutMs = 5000 } = options;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const result = await fn();
      clearTimeout(timeout);
      return result;
    } catch (error) {
      clearTimeout(timeout);
      const isLast = attempt === maxAttempts;
      const isRetryable = error instanceof TypeError || (error as any)?.status >= 500;
      if (isLast || !isRetryable) throw error;
      const delay = baseDelayMs * 2 ** (attempt - 1) + Math.random() * 100;
      logger.warn('Retrying external call', { attempt, delay });
      await new Promise(r => setTimeout(r, delay));
    }
  }
  throw new Error('Unreachable');
}

const response = await callWithRetry(() =>
  fetch('https://api.payment.com/charge', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  })
);
```

```python
# UNSAFE - no timeout
import httpx
response = await client.post("https://api.payment.com/charge", json=data)

# SAFE - with timeout and retry (tenacity)
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
import httpx

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=0.2, min=0.2, max=5),
    retry=retry_if_exception_type((httpx.TimeoutException, httpx.ConnectError)),
    reraise=True,
)
async def call_payment_api(data: dict) -> dict:
    async with httpx.AsyncClient(timeout=5.0) as client:
        response = await client.post(
            "https://api.payment.com/charge",
            json=data,
            headers={"Content-Type": "application/json"},
        )
        response.raise_for_status()
        return response.json()
```

---

### 6. Async / Unhandled Rejections

**Rule:** ALWAYS handle promise rejections. Attach global unhandledRejection and uncaughtException handlers. In Python async code, always await coroutines and handle exceptions from background tasks.

```typescript
// UNSAFE - fire-and-forget without handling
sendWelcomeEmail(user.email);

// UNSAFE - missing await, exception silently dropped
app.get('/data', async (req, res) => {
  processData(req.body);  // forgot await
  res.json({ ok: true });
});

// SAFE - handle fire-and-forget tasks
sendWelcomeEmail(user.email).catch(error => {
  logger.error('Failed to send welcome email', { userId: user.id, error: error.message });
});

// SAFE - global handlers (add at app startup)
process.on('unhandledRejection', (reason) => {
  logger.error('Unhandled promise rejection', { reason });
});

process.on('uncaughtException', (error) => {
  logger.error('Uncaught exception', { error: error.message, stack: error.stack });
  process.exit(1);  // always exit on uncaught exception
});
```

```python
# UNSAFE - asyncio.create_task without error handling
asyncio.create_task(send_welcome_email(user.email))

# SAFE - background task with error handling
import asyncio

def handle_task_error(task: asyncio.Task) -> None:
    if not task.cancelled():
        exc = task.exception()
        if exc:
            logger.error("Background task failed", extra={"error": str(exc)})

task = asyncio.create_task(send_welcome_email(user.email))
task.add_done_callback(handle_task_error)

# SAFE - FastAPI BackgroundTasks (preferred for simple cases)
from fastapi import BackgroundTasks

@app.post("/users")
async def create_user(body: CreateUserRequest, background_tasks: BackgroundTasks):
    user = await user_service.create(body)
    background_tasks.add_task(send_welcome_email, user.email)
    return user
```

---

## PART 3: QUICK REFERENCE CHECKLIST

Before finalizing any code that handles user data, run through this list:

**Security:**
- [ ] All user input validated with type + length + format + range
- [ ] No string concatenation in SQL queries (parameterized only)
- [ ] No DOM HTML assignment properties used with user data without sanitization
- [ ] Passwords hashed with bcrypt/argon2 (not sha256, not md5)
- [ ] JWT verified with signature + expiration + issuer
- [ ] Auth endpoints rate-limited
- [ ] Resource ownership checked before modification
- [ ] No secrets in source code (env vars only)
- [ ] No secrets in logs or error responses
- [ ] File paths validated against traversal
- [ ] Only real, known packages suggested

**Error Handling:**
- [ ] No silent catch blocks
- [ ] No stack traces or internal errors exposed to clients
- [ ] Correct HTTP status codes (400 for validation, 401 for auth, 403 for authz, 500 for unexpected)
- [ ] Structured logging with correlation IDs
- [ ] No sensitive data in logs (password, token, card number, PII)
- [ ] All external calls have timeouts
- [ ] Retries with exponential backoff for transient failures
- [ ] All promises handled (no fire-and-forget without .catch)
