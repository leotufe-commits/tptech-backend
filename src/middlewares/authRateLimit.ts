// src/middlewares/authRateLimit.ts
import rateLimit from "express-rate-limit";

/**
 * Rate limit estricto para endpoints sensibles de auth.
 * Ajustable más adelante según métricas reales.
 */
export const authRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 min
  limit: 20, // 20 intentos por IP cada 15 min
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: "Demasiados intentos. Probá nuevamente en unos minutos." },
});
