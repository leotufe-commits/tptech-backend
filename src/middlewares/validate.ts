import type { Request, Response, NextFunction } from "express";
import type { ZodSchema, ZodError } from "zod";

/**
 * validateBody(schema)
 *
 * - Valida req.body contra un schema Zod
 * - Si falla → 400 con detalle de issues
 * - Si pasa → req.body queda tipado y sanitizado
 */
export function validateBody(schema: ZodSchema) {
  return (req: Request, res: Response, next: NextFunction) => {
    const parsed = schema.safeParse(req.body);

    if (!parsed.success) {
      const error = parsed.error as ZodError;

      return res.status(400).json({
        message: "Datos inválidos.",
        issues: error.issues.map((i) => ({
          path: i.path.join("."),
          message: i.message,
        })),
      });
    }

    // Body validado y normalizado
    req.body = parsed.data;
    return next();
  };
}
