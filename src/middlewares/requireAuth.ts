// tptech-backend/src/middlewares/requireAuth.ts
import type { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import PrismaPkg from "@prisma/client";
const { UserStatus, OverrideEffect } = PrismaPkg;

import { prisma, setContextTenantId, setContextUserId } from "../lib/prisma.js";


const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) throw new Error("❌ JWT_SECRET no está configurado");
const JWT_SECRET_SAFE: string = JWT_SECRET;

const JWT_ISSUER = process.env.JWT_ISSUER || "tptech";
const JWT_AUDIENCE = process.env.JWT_AUDIENCE || "tptech-web";

// mismo nombre que en auth.controller.ts
const AUTH_COOKIE = "tptech_session";

function getTokenFromReq(req: Request): string | null {
  // 1) Authorization: Bearer <token>
  const h = req.headers.authorization;
  if (h && typeof h === "string") {
    const m = h.match(/^Bearer\s+(.+)$/i);
    if (m?.[1]) return m[1].trim();
  }

  // 2) Cookie
  const c = (req as any).cookies?.[AUTH_COOKIE];
  if (typeof c === "string" && c.trim()) return c.trim();

  return null;
}

function toPermKey(module: any, action: any) {
  return `${String(module)}:${String(action)}`;
}

export async function requireAuth(req: Request, res: Response, next: NextFunction) {
  const token = getTokenFromReq(req);

  if (!token) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET_SAFE, {
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
    }) as any;

    // soporta payloads: tenantId o jewelryId
    const userId = String(payload?.sub || payload?.userId || "");
    const tenantId = String(payload?.tenantId || payload?.jewelryId || payload?.tenant || "");

    // soporta tokenVersion o tv
    const tokenVersion = Number(payload?.tokenVersion ?? payload?.tv ?? 0);

    if (!userId || !tenantId) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    /**
     * ✅ 1 sola query:
     * - valida que el user exista en ese tenant
     * - valida deletedAt null
     * - trae roles/overrides para req.permissions
     */
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

    if (!user) return res.status(401).json({ message: "Unauthorized" });

    // si está bloqueado / no activo, cortamos acá
    if (user.status !== UserStatus.ACTIVE) {
      return res.status(403).json({ message: "Usuario no habilitado." });
    }

    // tokenVersion mismatch => sesión inválida
    if (user.tokenVersion !== tokenVersion) {
      return res.status(401).json({ message: "Sesión expirada" });
    }

    // set req (tipado viene por express.d.ts)
    req.userId = user.id;
    req.tenantId = user.jewelryId;

    // ALS (multi-tenant)
    setContextUserId(user.id);
    setContextTenantId(user.jewelryId);

    // ✅ calcular permisos efectivos
    const base = new Set<string>();

    // roles -> base (solo roles del tenant + no borrados)
    for (const ur of user.roles ?? []) {
      const role = ur.role;
      if (!role) continue;
      if (role.jewelryId !== user.jewelryId) continue;
      if (role.deletedAt) continue;

      for (const rp of role.permissions ?? []) {
        base.add(toPermKey(rp.permission.module, rp.permission.action));
      }
    }

    // overrides: DENY pisa todo, ALLOW suma si no fue denegado
    const allow = new Set<string>();
    const deny = new Set<string>();

    for (const ov of user.permissionOverrides ?? []) {
      const key = toPermKey(ov.permission.module, ov.permission.action);
      if (ov.effect === OverrideEffect.DENY) deny.add(key);
      if (ov.effect === OverrideEffect.ALLOW) allow.add(key);
    }

    // aplicar deny primero
    for (const d of deny) base.delete(d);
    // luego allow
    for (const a of allow) base.add(a);
    // y deny vuelve a pisar por seguridad
    for (const d of deny) base.delete(d);

    req.permissions = Array.from(base);

    return next();
  } catch {
    return res.status(401).json({ message: "Unauthorized" });
  }
}
