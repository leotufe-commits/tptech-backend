// src/config/security.ts
import rateLimit, { ipKeyGenerator } from "express-rate-limit";
import helmet from "helmet";
import type { RequestHandler } from "express";

const isProd = process.env.NODE_ENV === "production";

export function buildHelmetMiddleware(): RequestHandler {
  return helmet({
    contentSecurityPolicy: false,
    frameguard: { action: "deny" },
    referrerPolicy: { policy: "no-referrer" },
    hsts: isProd
      ? { maxAge: 15552000, includeSubDomains: true, preload: true } // ~180 días
      : false,
    crossOriginResourcePolicy: { policy: "cross-origin" },
  });
}

export function buildRateLimitMiddleware(): RequestHandler {
  return rateLimit({
    windowMs: 15 * 60 * 1000, // 15 min
    limit: isProd ? 300 : 600,

    standardHeaders: true,
    legacyHeaders: false,

    // ✅ helper oficial para soportar IPv6 correctamente
    keyGenerator: ipKeyGenerator,

    message: { message: "Demasiadas solicitudes. Intentá de nuevo más tarde." },
  });
}
