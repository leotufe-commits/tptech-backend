// tptech-backend/src/middlewares/requirePermission.ts
import type { Request, Response, NextFunction } from "express";

/**
 * requirePermission(module, action)
 * ✅ Usa req.permissions (calculado por requireAuth)
 * ✅ NO consulta Prisma
 *
 * Regla:
 * - Si el permiso requerido no está en req.permissions => 403
 */
export function requirePermission(module: string, action: string) {
  const wanted = `${module}:${action}`;

  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.userId || !req.tenantId) {
      return res.status(401).json({ message: "No autenticado" });
    }

    const perms = req.permissions ?? [];
    if (!perms.includes(wanted)) {
      return res.status(403).json({
        message: "No tenés permisos para realizar esta acción.",
        required: wanted,
      });
    }

    return next();
  };
}

/**
 * ✅ EXTRA (opcional): si algún día querés permitir "cualquiera de estos permisos"
 * Ej: requireAnyPermission(["USERS_ROLES:ADMIN", "USERS_ROLES:EDIT"])
 */
export function requireAnyPermission(wanted: string[]) {
  const wantedList = Array.isArray(wanted) ? wanted : [];
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.userId || !req.tenantId) {
      return res.status(401).json({ message: "No autenticado" });
    }

    const perms = req.permissions ?? [];
    const ok = wantedList.some((w) => perms.includes(w));

    if (!ok) {
      return res.status(403).json({
        message: "No tenés permisos para realizar esta acción.",
        requiredAny: wantedList,
      });
    }

    return next();
  };
}
