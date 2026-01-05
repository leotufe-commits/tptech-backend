// src/config/rateLimit.ts
import rateLimit from "express-rate-limit";

/**
 * Login: proteger contra brute force
 */
export const authLoginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: "Demasiados intentos de login. Intentá más tarde." },
});

/**
 * Forgot password
 */
export const authForgotLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: "Demasiadas solicitudes. Intentá más tarde." },
});

/**
 * Reset password
 */
export const authResetLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: "Demasiados intentos. Intentá más tarde." },
});
