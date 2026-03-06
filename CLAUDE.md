# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Communication preferences

- Always respond in Spanish.
- The user is not a developer. Keep all explanations clear and simple.

## Commands

```bash
npm run dev                    # Dev server with hot reload (tsx watch)
npm run build                  # prisma generate + tsc
npm run start                  # Run compiled output (dist/index.js)
npm run seed                   # Run prisma/seed.ts

npm run prisma:generate        # Regenerate Prisma client after schema changes
npm run prisma:migrate:dev     # Create + apply a new migration (dev)
npm run prisma:migrate:deploy  # Apply pending migrations (production/CI)
```

No test runner is configured.

## Environment variables

Required in `.env`:

```
DATABASE_URL=postgresql://...
JWT_SECRET=<min 10 chars>

# Optional with defaults
PORT=3001
NODE_ENV=development
JWT_ISSUER=tptech
JWT_AUDIENCE=tptech-web
CORS_ORIGIN=              # comma-separated allowed origins (adds to hardcoded list)
APP_URL=http://localhost:5173  # used to build reset/invite links in emails

# Mail (one of three modes)
MAIL_MODE=preview         # preview | console | production
MAIL_FROM=no-reply@tptech.local
MAIL_APP_NAME=TPTech      # name shown in email templates
POSTMARK_API_TOKEN=       # required when MAIL_MODE=production

# R2 storage (Cloudflare) — optional, falls back to local /uploads/
R2_ENDPOINT=
R2_ACCESS_KEY_ID=
R2_SECRET_ACCESS_KEY=
R2_BUCKET=
R2_PUBLIC_BASE_URL=
```

## Architecture

### Boot sequence

`src/index.ts` → `src/server.ts` → `src/app.ts` (creates Express app and applies all middleware).

### Middleware stack (`src/app.ts`)

Applied in this order on every request:
1. `trust proxy 1` + `x-powered-by` disabled
2. Helmet (CSP, frameguard, HSTS, CORP) — `src/config/security.ts`
3. CORS with credentials — `src/config/cors.ts`
4. JSON + urlencoded body parsers (1mb limit)
5. cookie-parser
6. Prisma ALS request context (`src/lib/prisma.ts`)
7. Performance logger
8. Static file serving (`/uploads`, `/api/uploads`)
9. Global rate limiter (300 req/15min prod, 600 dev) — skips OPTIONS, /health, /uploads

### Route structure (`src/routes/index.ts`)

All routes are prefixed with `/api`:

| Path | Auth | Module |
|---|---|---|
| `/api/auth/*` | Public (some endpoints) | auth.routes.ts |
| `/api/users/*` | requireAuth | users.routes.ts |
| `/api/roles/*` | requireAuth | roles.routes.ts |
| `/api/permissions/*` | requireAuth | permissions.routes.ts |
| `/api/company/*` | requireAuth | company.routes.ts |
| `/api/warehouses/*` | requireAuth | warehouses.routes.ts |
| `/api/movimientos/*` | requireAuth | movimientos.routes.ts |
| `/api/valuation/*` | requireAuth (internal) | valuation.routes.ts |
| `/api/dashboard/*` | requireAuth | dashboard.routes.ts |
| `/api/storage/*` | — | storage.routes.ts |
| `/api/company/catalogs/*` | requireAuth | catalogs.routes.ts |

Dev-only: `GET /dev/mail/:id` — email preview (active when `MAIL_MODE !== production`).

### Multi-tenancy

Every table record is scoped to a `jewelryId` (the tenant). All queries MUST filter by `jewelryId`. The tenant ID comes from `req.tenantId` / `req.user.jewelryId` (set by `requireAuth`). Never trust the client to send a jewelryId — always use the one from the auth context.

### Authentication (`src/middlewares/requireAuth.ts`)

JWT stored in httpOnly cookie `tptech_session`. Bearer token is accepted as fallback for legacy compatibility.

On each request, `requireAuth`:
1. Verifies the JWT (cookie takes precedence over Bearer)
2. Loads the user from DB, checks `deletedAt`, checks `status === ACTIVE`
3. Validates `tokenVersion` (if present in JWT) — invalidated when password changes
4. Computes the effective permission set: role permissions + per-user overrides (ALLOW/DENY)
5. Sets `req.userId`, `req.tenantId`, `req.user`, `req.roles`, `req.isOwner`, `req.permissions`

### Permission system (`src/middlewares/requirePermission.ts`)

```ts
requirePermission("USERS_ROLES", "ADMIN")   // single
requireAnyPermission(["INVENTORY:VIEW", "INVENTORY:EDIT"]) // any
```

OWNER role bypasses all permission checks. Permissions are computed once in `requireAuth` and stored in `req.permissions` — no extra DB query in `requirePermission`.

Permission format: `MODULE:ACTION` (e.g. `USERS_ROLES:VIEW`, `INVENTORY:ADMIN`).

### Auth tokens (`src/lib/authTokens.ts`, `src/lib/authTokenStore.ts`)

Single-use tokens for password reset and user invitation. Stored in the `AuthToken` table with fields `jti` (unique), `expiresAt`, `usedAt`. Consuming a token marks `usedAt` atomically — a second use is rejected.

- `type: "reset"` — used for both password recovery (30min) and user invitations (7d)
- `signResetToken` + `buildResetLink` → `/reset-password?token=...`
- `signResetToken` + `buildInviteLink` → `/accept-invite?token=...`

### Mail system (`src/lib/mailer.ts`, `src/lib/mail.service.ts`)

`MAIL_MODE` controls behavior:
- `preview` (default dev) — stores email in memory, logs URL `/dev/mail/:id`
- `console` — prints to stdout only
- `production` — sends via Postmark (`src/lib/mail.provider.postmark.ts`)

All email functions are in `src/lib/mailer.ts`: `sendResetEmail`, `sendInviteEmail`.

### File uploads

Multer handles multipart uploads. Storage strategy:
- If R2 env vars are set → Cloudflare R2 (`src/lib/storage/r2.ts`)
- Otherwise → local `uploads/` directory (`src/lib/uploads/localUploads.ts`)

Uploaded files are served at `/uploads/*` and `/api/uploads/*`.

### Soft delete

All major models have `deletedAt DateTime?`. Always filter `deletedAt: null` in queries. Never use hard deletes on User, Role, Warehouse, Metal, or Jewelry records.

### Automatic short codes

- **Movement codes**: generated in `movimientos.service.ts` — `E-NNNN` (IN), `S-NNNN` (OUT), `T-NNNN` (TRANSFER), `A-NNNN` (ADJUST). Counter per tenant + kind (including voided movements).
- **Warehouse codes**: generated in `warehouses.service.ts` — first 3 letters of name (no accents) + 2-digit sequence (e.g. `ALM01`). Only generated if the user leaves the code field empty.

### Rate limiting (`src/config/rateLimit.ts`)

Per-endpoint limiters on auth routes (applied in `auth.routes.ts`):
- `authLoginLimiter` — login
- `authForgotLimiter` — forgot password
- `authResetLimiter` — reset password
- `authRegisterLimiter` — register (10/hour/IP)
