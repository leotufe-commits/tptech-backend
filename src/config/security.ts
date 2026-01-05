// src/config/security.ts
import rateLimit from "express-rate-limit";
import helmet from "helmet";
import type { RequestHandler } from "express";

export function buildHelmetMiddleware(): RequestHandler {
  return helmet({
    crossOriginResourcePolicy: { policy: "cross-origin" },
  });
}

export function buildRateLimitMiddleware(): RequestHandler {
  return rateLimit({
    windowMs: 15 * 60 * 1000, // 15 min
    limit: 600, // suave para no molestar en dev
    standardHeaders: true,
    legacyHeaders: false,
    message: { message: "Demasiadas solicitudes. Intentá de nuevo más tarde." },
  });
}
