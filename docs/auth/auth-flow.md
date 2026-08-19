# Authentication Flow and Session Management

Scope: User registration, login lifecycles, password hashing, JWT session tokens, and CSRF protection.
Rendering context: Server
Project tier: 4
Last updated: auto

Overview
Montr Secure implements an on-premises authentication architecture combining Argon2 password hashing, JSON Web Tokens for stateless API authentication, HTTP-only session cookies for browser clients, and cryptographic CSRF tokens. Authentication middleware in apps/api/src/plugins/auth-plugin.ts inspects incoming HTTP requests to validate identity and attach authenticated user context to Fastify request objects.

User Registration and Password Hashing
Registration: The POST /api/v1/auth/register endpoint receives user email, password, and desired role. It creates a new Client tenant record and User account in packages/state-store.
Argon2 Hashing: Passwords are encrypted using Argon2id algorithm in apps/api/src/auth/password.ts with high memory and iteration parameters, ensuring resilient protection against brute-force and offline dictionary attacks. Raw password strings are never logged or stored.

Login Lifecycle and Token Issuance
Authentication: The POST /api/v1/auth/login endpoint validates incoming credentials against the User record in Postgres.
Session Token Issuance: Upon successful authentication, apps/api/src/auth/session.ts generates a signed JWT payload containing user ID, tenant client ID, and assigned role signed with JWT_SECRET.
Cookie and Header Delivery: The login handler sets an HTTP-only, secure, SameSite cookie named montr_session and returns the token in the JSON response body. Browser clients can authenticate via Authorization Bearer headers or session cookies.
Session Termination: The POST /api/v1/auth/logout endpoint clears the montr_session cookie and terminates the client session.

CSRF Protection and Mutating Requests
Token Generation: apps/api/src/auth/csrf.ts generates cryptographically secure CSRF tokens signed with CSRF_SECRET exposed via GET /api/v1/auth/csrf.
Verification Middleware: All state-mutating HTTP requests (POST, PATCH, DELETE) pass through app.verifyCsrf middleware in apps/api/src/plugins/auth-plugin.ts, verifying the X-CSRF-Token request header against the session context to prevent cross-site request forgery.

Protected Route Enforcement
Authentication Guard: Route handlers register app.authenticate pre-handler hooks. The middleware extracts credentials from Authorization headers or cookies, verifies token signatures, fetches the active user profile, and attaches the authUser object to the Fastify request. Unauthenticated requests are rejected with HTTP 401 Unauthorized.

Update Triggers
Update this file when authentication plugins change in apps/api/src/plugins/auth-plugin.ts, when session token generation evolves in apps/api/src/auth/session.ts, or when password hashing algorithms are updated in apps/api/src/auth/password.ts.

Related Docs
docs/auth/authorization.md — Role-based access control and permission enforcement.
docs/api/route-handlers.md — API endpoints managing authentication and registration.
