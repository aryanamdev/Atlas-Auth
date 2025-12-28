# Atlas Auth

## Overview

Atlas Auth is a **production-oriented authentication service** built with **Node.js and TypeScript**, designed to provide secure, scalable authentication for modern web applications. The project focuses on **clear token lifecycle management, strong type safety, and maintainable architecture**, rather than framework-specific tricks.

This system is intentionally designed as **infrastructure**, not a feature. It can be used as a standalone auth layer for product applications or extended toward multi-service environments.

---

## Problem Statement

Most applications need authentication that is:

* Secure by default
* Scalable without server-side sessions
* Easy to reason about and maintain

Atlas Auth addresses this by using **short-lived JWT access tokens** combined with **database-backed refresh tokens**, enabling stateless request authentication while retaining server-side control over session revocation.

---

## Core Architecture

**High-level flow**:

1. User authenticates via credentials
2. Server issues a short-lived access token and a long-lived refresh token
3. Access token is used for authenticated requests
4. Refresh token is validated against the database to issue new access tokens
5. Logout or token invalidation removes refresh token server-side

**Key architectural principles**:

* Stateless request authentication
* Explicit token lifecycle
* Clear separation between transport, auth logic, and persistence

---

## Token Strategy

* **Access Tokens**: Short-lived JWTs used to authenticate API requests
* **Refresh Tokens**: Long-lived tokens persisted in the database to allow controlled session renewal

Access tokens are intentionally **not stored** server-side to enable horizontal scaling. Refresh tokens act as the revocation and control mechanism.

---

## Type Safety & Boundaries

Authentication is security-critical, so TypeScript is used deliberately at system boundaries:

* Typed JWT payloads
* Typed auth middleware context
* Explicit request and response contracts

This reduces an entire class of runtime errors and makes auth behavior predictable as the system evolves.

---

## Middleware & Enforcement

Authentication is enforced at the middleware layer:

* Requests without valid tokens are rejected early
* Downstream handlers operate on a verified, typed user context

This keeps business logic free from repetitive auth checks.

---

## Failure Scenarios

Atlas Auth is designed with basic production failures in mind:

* Expired access tokens result in controlled unauthorized responses
* Invalid or missing refresh tokens prevent session renewal
* Logout explicitly invalidates server-side refresh tokens

The system favors **explicit failure over silent degradation**.

---

## Tradeoffs

* JWT-based auth was chosen over server sessions for scalability
* A single-service design was preferred over microservices for simplicity
* Advanced identity features (SSO, OAuth providers) are intentionally out of scope

These tradeoffs keep the system focused and understandable at product scale.

---

## Code Quality

The project enforces consistent quality standards using:

* TypeScript strict typing
* ESLint for unsafe patterns
* Prettier for consistent formatting

Auth code is treated as long-lived infrastructure, not experimental logic.

---

## Future Evolution

Potential extensions include:

* Refresh token rotation
* Multi-device session management
* OAuth / third-party identity providers
* Extraction into a dedicated auth service

---

## What This Project Demonstrates

* Ownership of a security-critical system
* Clear reasoning about auth tradeoffs
* Production-aware backend architecture
* Type safety used intentionally, not decoratively
