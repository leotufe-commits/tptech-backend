// tptech-backend/src/middlewares/requireAuth.ts
import type { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { UserStatus, OverrideEffect } from "@prisma/client";

import { prisma, setContextTenantId, setContextUserId } from "../lib/prisma.js";
import { getEnv } from "../config/env.js";

// mismo nombre que en auth.controller.ts
const AUTH_COOKIE = "tptech_session";

function isProd() {
  return process.env.NODE_ENV === "production";
}

function clearAuthCookie(res: Response) {
  try {
    res.clearCookie(AUTH_COOKIE, {
      httpOnly: true,
      secure: isProd(),
      sameSite: isProd() ? "none" : "lax",
      path: "/",
    });
  } catch {}
}

function unauthorized(res: Response, message = "Unauthorized") {
  clearAuthCookie(res);
  return res.status(401).json({ message });
}

/** Devuelve Bearer si existe (sin validar) */
function readBearer(req: Request): string | null {
  const h = req.headers.authorization;
  if (h && typeof h === "string") {
    const m = h.match(/^Bearer\s+(.+)$/i);
    if (m?.[1]) return m[1].trim();
  }
  return null;
}

/** Devuelve cookie si existe (sin validar) */
function readCookieToken(req: Request): string | null {
  const c = (req as any).cookies?.[AUTH_COOKIE];
  if (typeof c === "string" && c.trim().length > 0) return c.trim();
  return null;
}

/**
 * ✅ Política cookie-first:
 * - Si HAY cookie → SOLO cookie (si no valida, 401)
 * - Si NO hay cookie → usamos Bearer (útil para clients/API)
 */
function verifyAnyToken(req: Request): any | null {
  const env = getEnv();

  const cookie = readCookieToken(req);

  if (cookie) {
    try {
      // tolerancia por si alguna vez guardaste "Bearer xxx" dentro de la cookie
      const token = cookie.toLowerCase().startsWith("bearer ") ? cookie.slice(7).trim() : cookie;

      return jwt.verify(token, env.JWT_SECRET, {
        issuer: env.JWT_ISSUER,
        audience: env.JWT_AUDIENCE,
      }) as any;
    } catch {
      return null;
    }
  }

  const bearer = readBearer(req);
  if (!bearer) return null;

  try {
    return jwt.verify(bearer, env.JWT_SECRET, {
      issuer: env.JWT_ISSUER,
      audience: env.JWT_AUDIENCE,
    }) as any;
  } catch {
    return null;
  }
}

function toPermKey(module: any, action: any) {
  return `${String(module)}:${String(action)}`;
}

function readTokenVersion(payload: any): number | null {
  const raw = payload?.tokenVersion ?? payload?.tv ?? payload?.ver ?? payload?.token_ver;

  if (raw === undefined || raw === null || raw === "") return null;

  const n = Number(raw);
  if (!Number.isFinite(n)) return null;
  return Math.trunc(n);
}

export async function requireAuth(req: Request, res: Response, next: NextFunction) {
  try {
    const payload = verifyAnyToken(req);
    if (!payload) return unauthorized(res);

    const userId = String(payload?.sub || payload?.userId || "").trim();
    const tenantId = String(payload?.tenantId || payload?.jewelryId || payload?.tenant || "").trim();
    if (!userId || !tenantId) return unauthorized(res);

    const tokenVersion = readTokenVersion(payload);

    const user = await prisma.user.findFirst({
      where: {
        id: userId,
        jewelryId: tenantId,
        deletedAt: null,
      },
      select: {
        id: true,
        jewelryId: true,
        tokenVersion: true,
        status: true,
        roles: {
          select: {
            role: {
              select: {
                name: true,
                jewelryId: true,
                deletedAt: true,
                permissions: {
                  select: {
                    permission: { select: { module: true, action: true } },
                  },
                },
              },
            },
          },
        },
        permissionOverrides: {
          select: {
            effect: true,
            permission: { select: { module: true, action: true } },
          },
        },
      },
    });

    if (!user) return unauthorized(res);

    if (user.status !== UserStatus.ACTIVE) {
      return res.status(403).json({ message: "Usuario no habilitado." });
    }

    // ✅ SOLO validar tokenVersion si el JWT lo trae
    if (tokenVersion !== null && user.tokenVersion !== tokenVersion) {
      return unauthorized(res, "Sesión expirada");
    }

    // =========================
    // ✅ CONTEXTO REQ (compat)
    // =========================
    (req as any).userId = user.id;
    (req as any).tenantId = user.jewelryId;

    // ✅ Alias útiles (algunos módulos usan jewelryId)
    (req as any).jewelryId = user.jewelryId;

    // ✅ CLAVE: algunos handlers (attachments) leen req.user
    (req as any).user = {
      id: user.id,
      jewelryId: user.jewelryId,
    };

    const roleNames: string[] = [];
    for (const ur of user.roles ?? []) {
      const r = ur.role;
      if (!r) continue;
      if (r.jewelryId !== user.jewelryId) continue;
      if (r.deletedAt) continue;
      roleNames.push(String(r.name || "").trim().toUpperCase());
    }

    (req as any).roles = Array.from(new Set(roleNames));
    (req as any).isOwner = Boolean((req as any).roles?.includes?.("OWNER"));

    try {
      setContextUserId(user.id);
      setContextTenantId(user.jewelryId);
    } catch {}

    const base = new Set<string>();

    for (const ur of user.roles ?? []) {
      const role = ur.role;
      if (!role) continue;
      if (role.jewelryId !== user.jewelryId) continue;
      if (role.deletedAt) continue;

      for (const rp of role.permissions ?? []) {
        base.add(toPermKey(rp.permission.module, rp.permission.action));
      }
    }

    const deny = new Set<string>();
    const allow = new Set<string>();

    for (const ov of user.permissionOverrides ?? []) {
      const key = toPermKey(ov.permission.module, ov.permission.action);
      if (ov.effect === OverrideEffect.DENY) deny.add(key);
      if (ov.effect === OverrideEffect.ALLOW) allow.add(key);
    }

    for (const d of deny) base.delete(d);
    for (const a of allow) base.add(a);

    (req as any).permissions = Array.from(base);

    return next();
  } catch {
    return unauthorized(res);
  }
}
