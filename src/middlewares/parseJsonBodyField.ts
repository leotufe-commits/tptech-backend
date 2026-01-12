// tptech-backend/src/middlewares/parseJsonBodyField.ts
import type { Request, Response, NextFunction } from "express";

/**
 * Middleware para soportar multipart/form-data con un campo JSON string.
 *
 * Ejemplo:
 *  - req.body.data = '{"name":"Mi Joyería","phoneCountry":"+54"}'
 *
 * 👉 Parse:
 *    - Convierte ese string en objeto
 *    - Reemplaza req.body por el JSON parseado
 *
 * Mantiene compatibilidad total con requests JSON normales.
 */
export function parseJsonBodyField(fieldName: string) {
  return function (req: Request, res: Response, next: NextFunction) {
    const anyReq = req as any;

    const value = (req.body as any)?.[fieldName];

    // Si no existe el campo o no es string → seguimos normal
    if (typeof value !== "string") {
      return next();
    }

    try {
      const parsed = JSON.parse(value);

      // Reemplazamos body por el objeto parseado
      anyReq.body = parsed;

      return next();
    } catch {
      return res.status(400).json({
        message: `Campo '${fieldName}' debe ser JSON válido.`,
      });
    }
  };
}
