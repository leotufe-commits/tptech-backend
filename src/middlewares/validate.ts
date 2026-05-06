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
      const issues = error.issues.map((i) => ({
        path: i.path.join("."),
        message: i.message,
        // code y received nos sirven para diagnosticar errores del cliente
        ...((i as any).code ? { code: (i as any).code } : {}),
        ...((i as any).received !== undefined ? { received: (i as any).received } : {}),
      }));

      // Log server-side para que el motivo del 400 quede visible en los logs.
      // Útil cuando el cliente solo ve "Datos inválidos." y necesita el detalle.
      // Mantiene cuerpo compacto: solo paths + mensaje, no el body completo.
      try {
        // eslint-disable-next-line no-console
        console.warn(`[validateBody] 400 en ${req.method} ${req.originalUrl}:`,
          JSON.stringify(issues));
      } catch { /* noop */ }

      return res.status(400).json({
        message: "Datos inválidos.",
        issues,
      });
    }

    // Body validado y normalizado
    req.body = parsed.data;
    return next();
  };
}
