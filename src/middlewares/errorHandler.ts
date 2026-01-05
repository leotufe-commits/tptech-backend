// src/middlewares/errorHandler.ts
import type { Request, Response, NextFunction } from "express";

export function errorHandler(err: any, _req: Request, res: Response, _next: NextFunction) {
  console.error("🔥 APP ERROR:", err);

  const msg = err?.message || "Error interno.";
  const status = String(msg).startsWith("CORS bloqueado") ? 403 : 500;

  return res.status(status).json({ message: msg });
}
