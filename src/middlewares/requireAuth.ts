import type { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { prisma } from "../lib/prisma.js";
import { setContextTenantId, setContextUserId } from "../lib/prisma.js";

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) throw new Error("❌ JWT_SECRET no está configurado");

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

  // 2) Cookie (prod)
  const c = (req as any).cookies?.[AUTH_COOKIE];
  if (typeof c === "string" && c.trim()) return c.trim();

  return null;
}

export async function requireAuth(req: Request, res: Response, next: NextFunction) {
  const token = getTokenFromReq(req);

  if (!token) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET, {
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
    }) as any;

    const userId = String(payload?.sub || "");
    const tenantId = String(payload?.tenantId || "");
    const tokenVersion = Number(payload?.tokenVersion ?? 0);

    if (!userId || !tenantId) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    // Validación “extra” (opcional pero recomendada): tokenVersion
    const user = await prisma.user.findFirst({
      where: { id: userId, jewelryId: tenantId },
      select: { id: true, jewelryId: true, tokenVersion: true, status: true },
    });

    if (!user) return res.status(401).json({ message: "Unauthorized" });
    if ((user as any).tokenVersion !== tokenVersion) {
      return res.status(401).json({ message: "Sesión expirada" });
    }

    // set req
    (req as any).userId = user.id;
    (req as any).tenantId = user.jewelryId;

    // ALS (multi-tenant)
    setContextUserId(user.id);
    setContextTenantId(user.jewelryId);

    // permissions para requirePermission
    const full = await prisma.user.findFirst({
      where: { id: user.id, jewelryId: user.jewelryId },
      select: {
        roles: {
          select: {
            role: {
              select: {
                permissions: { select: { permission: { select: { module: true, action: true } } } },
              },
            },
          },
        },
        permissionOverrides: {
          select: { effect: true, permission: { select: { module: true, action: true } } },
        },
      },
    });

    const perms: string[] = [];

    // roles
    for (const ur of full?.roles ?? []) {
      for (const rp of ur.role?.permissions ?? []) {
        perms.push(`${rp.permission.module}:${rp.permission.action}`);
      }
    }

    // overrides
    const allow = new Set<string>();
    const deny = new Set<string>();
    for (const ov of full?.permissionOverrides ?? []) {
      const key = `${ov.permission.module}:${ov.permission.action}`;
      if (ov.effect === "ALLOW") allow.add(key);
      if (ov.effect === "DENY") deny.add(key);
    }

    const base = new Set(perms);
    for (const d of deny) base.delete(d);
    for (const a of allow) base.add(a);
    for (const d of deny) base.delete(d);

    (req as any).permissions = Array.from(base);

    return next();
  } catch {
    return res.status(401).json({ message: "Unauthorized" });
  }
}
