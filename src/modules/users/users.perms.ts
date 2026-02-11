// tptech-backend/src/modules/users/users.perms.ts
import type { Request, Response } from "express";

/**
 * Detecta OWNER desde varios lugares posibles.
 * (depende de cómo tu requireAuth setea el request)
 */
export function isOwnerReq(req: Request): boolean {
  const anyReq = req as any;

  if (anyReq?.isOwner === true) return true;

  const role = String(anyReq?.role ?? anyReq?.userRole ?? "").trim().toUpperCase();
  if (role === "OWNER") return true;

  const roles = (anyReq?.roles ?? anyReq?.userRoles) as unknown;
  if (Array.isArray(roles)) {
    return roles.map((x) => String(x).trim().toUpperCase()).includes("OWNER");
  }

  return false;
}

/**
 * Verifica si el request trae permiso USERS_ROLES:ADMIN
 * Acepta string "USERS_ROLES:ADMIN" o objetos con module/action, etc.
 */
export function hasUsersRolesAdmin(perms: unknown[]): boolean {
  if (!Array.isArray(perms)) return false;

  for (const p of perms) {
    if (typeof p === "string") {
      if (p.trim() === "USERS_ROLES:ADMIN") return true;
      continue;
    }

    if (p && typeof p === "object") {
      const obj = p as any;

      const key =
        obj.key ??
        obj.code ??
        obj.slug ??
        obj.name ??
        (obj.module && obj.action ? `${obj.module}:${obj.action}` : undefined) ??
        (obj.permModule && obj.permAction ? `${obj.permModule}:${obj.permAction}` : undefined);

      if (typeof key === "string" && key.trim() === "USERS_ROLES:ADMIN") return true;

      const mod = String(obj.module ?? obj.permModule ?? "").trim();
      const act = String(obj.action ?? obj.permAction ?? "").trim();
      if (mod === "USERS_ROLES" && act === "ADMIN") return true;
    }
  }

  return false;
}

/**
 * Gate para endpoints ADMIN del módulo users/roles.
 * OWNER siempre pasa.
 */
export function requireAdminUsersRoles(req: Request, res: Response): boolean {
  if (isOwnerReq(req)) return true;

  const perms = ((req as any).permissions ?? []) as unknown[];
  if (!hasUsersRolesAdmin(perms)) {
    res.status(403).json({ message: "No tenés permisos para realizar esta acción." });
    return false;
  }
  return true;
}

/**
 * ✅ Alias defensivo por si en algún lado lo importaste con otro nombre (histórico)
 * (no molesta y evita roturas)
 */
export const requireUsersAdmin = requireAdminUsersRoles;

export default requireAdminUsersRoles;
