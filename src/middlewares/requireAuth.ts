// tptech-backend/src/middlewares/requireAuth.ts
import type { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import {
  prisma,
  setContextTenantId,
  setContextUserId,
  clearRequestContext,
} from "../lib/prisma.js";
import { UserStatus } from "@prisma/client";

/**
 * Extensión del Request de Express
 */
declare global {
  namespace Express {
    interface Request {
      userId?: string;
      tenantId?: string;
      // ✅ para RBAC (cache por request desde requirePermission)
      permissions?: string[];
    }
  }
}

type AccessTokenPayload = {
  sub?: string;
  tenantId?: string;
  tokenVersion?: number;
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
  // 1) Bearer token
  const raw = req.headers.authorization;
  if (raw && typeof raw === "string") {
    const parts = raw.trim().split(/\s+/);
    if (parts.length === 2 && parts[0].toLowerCase() === "bearer") {
      return parts[1];
    }
  }

  // 2) Cookie
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

  // Limpia el contexto ALS al finalizar el request
  res.on("finish", () => {
    try {
      clearRequestContext();
    } catch {}
  });

  try {
    const token = getTokenFromRequest(req);
    if (!token) {
      return res.status(401).json({ code: "NO_TOKEN", message: "No autorizado" });
    }

    const payload = jwt.verify(token, JWT_SECRET, {
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
    }) as AccessTokenPayload;

    if (!payload.sub || !payload.tenantId) {
      return res.status(401).json({ code: "TOKEN_INVALID", message: "Token inválido" });
    }

    if (typeof payload.tokenVersion !== "number") {
      return res.status(401).json({ code: "TOKEN_INVALID", message: "Token inválido" });
    }

    const user = await prisma.user.findUnique({
      where: { id: payload.sub },
      select: {
        id: true,
        status: true,
        jewelryId: true,
        tokenVersion: true,
      },
    });

    if (!user) {
      return res.status(401).json({ code: "USER_NOT_FOUND", message: "Usuario no encontrado" });
    }

    if (user.status !== UserStatus.ACTIVE) {
      return res.status(403).json({ code: "USER_DISABLED", message: "Usuario no habilitado" });
    }

    // Multi-tenant
    if (user.jewelryId !== payload.tenantId) {
      return res.status(401).json({ code: "TOKEN_INVALID", message: "Token inválido" });
    }

    // Invalidación inmediata
    if (user.tokenVersion !== payload.tokenVersion) {
      return res.status(401).json({
        code: "SESSION_EXPIRED",
        message: "Sesión expirada. Iniciá sesión nuevamente.",
      });
    }

    // Inyectar contexto
    req.userId = user.id;
    req.tenantId = user.jewelryId;

    setContextUserId(user.id);
    setContextTenantId(user.jewelryId);

    return next();
  } catch (err: any) {
    // Token expirado por tiempo
    if (err?.name === "TokenExpiredError") {
      return res.status(401).json({
        code: "TOKEN_EXPIRED",
        message: "Token expirado",
      });
    }

    return res.status(401).json({
      code: "TOKEN_INVALID",
      message: "Token inválido",
    });
  }
}
