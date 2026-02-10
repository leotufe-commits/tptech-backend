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
 * Normaliza req.permissions a un Set<string> con claves "MODULE:ACTION"
 * Soporta:
 * - string[]: ["USERS_ROLES:ADMIN"]
 * - object[]: [{ module:"USERS_ROLES", action:"ADMIN" }]
 * - object[]: [{ permModule:"USERS_ROLES", permAction:"ADMIN" }]
 * - object[]: [{ key:"USERS_ROLES:ADMIN" }] / { code, slug, name }
 */
function permsToSet(perms: unknown): Set<string> {
  const out = new Set<string>();
  if (!Array.isArray(perms)) return out;

  for (const p of perms) {
    if (typeof p === "string") {
      const s = p.trim();
      if (s) out.add(s);
      continue;
    }

    if (p && typeof p === "object") {
      const obj = p as any;

      // si ya viene como string key
      const key =
        obj.key ??
        obj.code ??
        obj.slug ??
        obj.name ??
        obj.permission ??
        obj.perm ??
        (obj.module && obj.action ? `${obj.module}:${obj.action}` : undefined) ??
        (obj.permModule && obj.permAction ? `${obj.permModule}:${obj.permAction}` : undefined);

      if (typeof key === "string") {
        const s = key.trim();
        if (s) out.add(s);
      }

      // por si vienen separados
      const mod = String(obj.module ?? obj.permModule ?? "").trim();
      const act = String(obj.action ?? obj.permAction ?? "").trim();
      if (mod && act) out.add(`${mod}:${act}`);
    }
  }

  return out;
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

    const permsSet = permsToSet((req as any).permissions);

    if (!permsSet.has(wanted)) {
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

    const permsSet = permsToSet((req as any).permissions);

    const ok = wantedList.some((w) => permsSet.has(w));

    if (!ok) {
      return res.status(403).json({
        message: "No tenés permisos para realizar esta acción.",
        requiredAny: wantedList,
      });
    }

    return next();
  };
}
