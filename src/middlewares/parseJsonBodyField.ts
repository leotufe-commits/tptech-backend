// src/middlewares/parseJsonBodyField.ts
import type { Request, Response, NextFunction } from "express";

/**
 * Si llega multipart/form-data con un campo string que contiene JSON
 * (por ejemplo: req.body.data = '{"name":"..."}'),
 * lo parsea y lo reemplaza como req.body.
 *
 * Mantiene compatibilidad total con requests JSON normales.
 */
export function parseJsonBodyField(fieldName: string) {
  return function (req: Request, res: Response, next: NextFunction) {
    const anyReq = req as any;

    // Si es JSON normal, no tocamos nada
    // (req.body ya viene como objeto)
    if (req.body && typeof req.body === "object" && !Array.isArray(req.body)) {
      // Pero en multipart, req.body suele ser objeto de strings,
      // y el JSON suele venir en req.body[fieldName]
    }

    const v = (req.body as any)?.[fieldName];

    if (typeof v !== "string") return next();

    try {
      const parsed = JSON.parse(v);

      // reemplazamos el body por el JSON parseado
      anyReq.body = parsed;

      return next();
    } catch {
      return res.status(400).json({ message: `Campo '${fieldName}' debe ser JSON válido.` });
    }
  };
}
