import type { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { UserStatus, OverrideEffect } from "@prisma/client";

import { prisma, setContextTenantId, setContextUserId } from "../lib/prisma.js";

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) throw new Error("❌ JWT_SECRET no está configurado");
const JWT_SECRET_SAFE: string = JWT_SECRET;

const JWT_ISSUER = process.env.JWT_ISSUER || "tptech";
const JWT_AUDIENCE = process.env.JWT_AUDIENCE || "tptech-web";

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
  if (typeof c === "string" && c.trim()) return c.trim();
  return null;
}

/**
 * ✅ FIX:
 * - Si existe cookie, la priorizamos SIEMPRE.
 *   Motivo: en el frontend web puede quedar un Bearer legacy válido de firma,
 *   pero con tokenVersion viejo → disparaba "Sesión expirada" aunque la cookie sea válida.
 * - Si no hay cookie, usamos Bearer (útil para clientes/API).
 */
function verifyAnyToken(req: Request): any | null {
  const cookie = readCookieToken(req);
  const bearer = readBearer(req);

  const candidates = [cookie, bearer].filter(
    (t): t is string => typeof t === "string" && t.trim()
  );

  for (const token of candidates) {
    try {
      const payload = jwt.verify(token, JWT_SECRET_SAFE, {
        issuer: JWT_ISSUER,
        audience: JWT_AUDIENCE,
      }) as any;
      return payload;
    } catch {
      // probar siguiente candidato
    }
  }

  return null;
}

function toPermKey(module: any, action: any) {
  return `${String(module)}:${String(action)}`;
}

function readTokenVersion(payload: any): number | null {
  const raw =
    payload?.tokenVersion ??
    payload?.tv ??
    payload?.ver ??
    payload?.token_ver;

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
    const tenantId = String(
      payload?.tenantId || payload?.jewelryId || payload?.tenant || ""
    ).trim();
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

    // req context
    (req as any).userId = user.id;
    (req as any).tenantId = user.jewelryId;

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
    return unauthorized(r
  }
}
