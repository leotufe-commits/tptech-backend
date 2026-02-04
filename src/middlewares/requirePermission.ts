// tptech-backend/src/middlewares/requirePermission.ts
import type { Request, Response, NextFunction } from "express";

/**
 * Detecta si el request viene de un OWNER.
 * Soporta múltiples formas según cómo lo setee requireAuth:
 * - req.isOwner (boolean)
 * - req.role / req.userRole (string)
 * - req.roles (string[]) / req.userRoles (string[])
 */
function isOwnerReq(req: Request): boolean {
  const anyReq = req as any;

  if (anyReq?.isOwner === true) return true;

  const role = String(anyReq?.role ?? anyReq?.userRole ?? "")
    .trim()
    .toUpperCase();
  if (role === "OWNER") return true;

  const roles = (anyReq?.roles ?? anyReq?.userRoles) as unknown;
  if (Array.isArray(roles)) {
    return roles.map((x) => String(x).trim().toUpperCase()).includes("OWNER");
  }

  return false;
}

function isAuthed(req: Request) {
  return Boolean((req as any).userId && (req as any).tenantId);
}

/**
 * requirePermission(module, action)
 * ✅ Usa req.permissions (calculado por requireAuth)
 * ✅ NO consulta Prisma
 *
 * Regla:
 * - Si es OWNER => allow (bypass)
 * - Si el permiso requerido no está en req.permissions => 403
 */
export function requirePermission(module: string, action: string) {
  const wanted = `${String(module).trim()}:${String(action).trim()}`;

  return (req: Request, res: Response, next: NextFunction) => {
    if (!isAuthed(req)) return res.status(401).json({ message: "No autenticado" });

    // ✅ BYPASS OWNER
    if (isOwnerReq(req)) return next();

    const perms = ((req as any).permissions ?? []) as unknown;

    if (!Array.isArray(perms) || !perms.includes(wanted)) {
      return res.status(403).json({
        message: "No tenés permisos para realizar esta acción.",
        required: wanted,
      });
    }

    return next();
  };
}

/**
 * requireAnyPermission(["USERS_ROLES:ADMIN", "USERS_ROLES:EDIT"])
 * - Si es OWNER => allow (bypass)
 * - Si tiene cualquiera => allow
 */
export function requireAnyPermission(wanted: string[]) {
  const wantedList = Array.isArray(wanted)
    ? Array.from(
        new Set(
          wanted
            .map((x) => String(x ?? "").trim())
            .filter(Boolean)
        )
      )
    : [];

  return (req: Request, res: Response, next: NextFunction) => {
    if (!isAuthed(req)) return res.status(401).json({ message: "No autenticado" });

    // ✅ BYPASS OWNER
    if (isOwnerReq(req)) return next();

    const perms = ((req as any).permissions ?? []) as unknown;
    if (!Array.isArray(perms)) {
      return res.status(403).json({
        message: "No tenés permisos para realizar esta acción.",
        requiredAny: wantedList,
      });
    }

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
