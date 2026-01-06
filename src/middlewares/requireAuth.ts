// tptech-backend/src/middlewares/requireAuth.ts
import type { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { prisma, setContextTenantId, setContextUserId, clearRequestContext } from "../lib/prisma.js";
import { UserStatus } from "@prisma/client";

/**
 * Extensión del Request de Express
 */
declare global {
  namespace Express {
    interface Request {
      userId?: string;
      tenantId?: string;
    }
  }
}

type AccessTokenPayload = {
  sub?: string;
  tenantId?: string;
  iat?: number;
  exp?: number;
  iss?: string;
  aud?: string | string[];
};

const JWT_ISSUER = process.env.JWT_ISSUER || "tptech";
const JWT_AUDIENCE = process.env.JWT_AUDIENCE || "tptech-web";

// nombre de la cookie (si existe)
const AUTH_COOKIE = "tptech_session";

/**
 * Obtiene el token desde:
 * 1) Authorization: Bearer <token>
 * 2) Cookie httpOnly (fallback)
 */
function getTokenFromRequest(req: Request): string | null {
  // 1) Bearer token (prioridad)
  const raw = req.headers.authorization;
  if (raw && typeof raw === "string") {
    const parts = raw.trim().split(/\s+/);
    if (parts.length >= 2) {
      const type = parts[0]?.toLowerCase();
      const token = parts[1];
      if (type === "bearer" && token) return token;
    }
  }

  // 2) Cookie (fallback)
  const anyReq = req as any;
  const cookieToken = anyReq?.cookies?.[AUTH_COOKIE];
  if (cookieToken) return String(cookieToken);

  return null;
}

export async function requireAuth(req: Request, res: Response, next: NextFunction) {
  const JWT_SECRET = process.env.JWT_SECRET;

  if (!JWT_SECRET) {
    return res.status(500).json({ message: "JWT_SECRET no está definido en el servidor" });
  }

  // ✅ Limpia el contexto ALS al finalizar el request
  res.on("finish", () => {
    try {
      clearRequestContext();
    } catch {}
  });

  try {
    const token = getTokenFromRequest(req);
    if (!token) {
      return res.status(401).json({ message: "No autorizado (sin token)" });
    }

    const payload = jwt.verify(token, JWT_SECRET, {
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
    }) as AccessTokenPayload;

    if (!payload?.sub || typeof payload.sub !== "string") {
      return res.status(401).json({ message: "Token inválido" });
    }

    if (!payload?.tenantId || typeof payload.tenantId !== "string") {
      return res.status(401).json({ message: "Token inválido (sin tenant)" });
    }

    const userId = payload.sub;
    const tokenTenantId = payload.tenantId;

    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { id: true, status: true, jewelryId: true },
    });

    if (!user) {
      return res.status(401).json({ message: "Usuario no encontrado" });
    }

    if (user.status !== UserStatus.ACTIVE) {
      return res.status(403).json({ message: "Usuario no habilitado" });
    }

    // 🔒 Multi-tenant: el tenant del token debe coincidir con el del usuario
    if (user.jewelryId !== tokenTenantId) {
      return res.status(401).json({ message: "Token inválido (tenant no coincide)" });
    }

    // Inyectamos contexto
    req.userId = user.id;
    req.tenantId = user.jewelryId;

    setContextUserId(user.id);
    setContextTenantId(user.jewelryId);

    return next();
  } catch {
    return res.status(401).json({ message: "Token inválido o expirado" });
  }
}
