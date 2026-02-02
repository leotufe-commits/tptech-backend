// src/config/security.ts
import rateLimit, { ipKeyGenerator } from "express-rate-limit";
import helmet from "helmet";
import type { RequestHandler, Request } from "express";

const isProd = process.env.NODE_ENV === "production";

export function buildHelmetMiddleware(): RequestHandler {
  return helmet({
    contentSecurityPolicy: false,
    frameguard: { action: "deny" },
    referrerPolicy: { policy: "no-referrer" },
    hsts: isProd
      ? { maxAge: 15552000, includeSubDomains: true, preload: true } // ~180 días
      : false,

    // ✅ permite servir imágenes/recursos en cross-origin (frontend separado)
    crossOriginResourcePolicy: { policy: "cross-origin" },
  });
}

function getClientIp(req: Request) {
  // con app.set("trust proxy", 1) esto suele venir correcto
  return String(req.ip || "");
}

export function buildRateLimitMiddleware(): RequestHandler {
  return rateLimit({
    windowMs: 15 * 60 * 1000, // 15 min
    limit: isProd ? 300 : 600,

    standardHeaders: true,
    legacyHeaders: false,

    // ✅ NO rate-limit a preflights
    skip: (req) => {
      if (req.method === "OPTIONS") return true;

      // ✅ opcional: no limitar healthcheck ni archivos estáticos
      const p = String(req.path || "");
      if (p === "/health") return true;
      if (p.startsWith("/uploads/")) return true;

      return false;
    },

    // ✅ keyGenerator estable (IP) — evita problemas con proxies
    keyGenerator: (req) => ipKeyGenerator(getClientIp(req)),

    message: { message: "Demasiadas solicitudes. Intentá de nuevo más tarde." },
  });
}
