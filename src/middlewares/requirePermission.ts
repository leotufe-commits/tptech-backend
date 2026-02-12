// tptech-backend/src/middlewares/requirePermission.ts
import type { Request, Response, NextFunction } from "express";

/**
 * Detecta si el request viene de un OWNER.
 * Soporta múltiples formas según cómo lo setee requireAuth:
 * - req.isOwner (boolean)
 * - req.role / req.userRole (string)
 * - req.roles (string[]) / req.userRoles (string[])
 * - req.user.role / req.user.roles
 */
function isOwnerReq(req: Request): boolean {
  const anyReq = req as any;

  if (anyReq?.isOwner === true) return true;

  const role = String(anyReq?.role ?? anyReq?.userRole ?? anyReq?.user?.role ?? "")
    .trim()
    .toUpperCase();
  if (role === "OWNER") return true;

  const roles = (anyReq?.roles ??
    anyReq?.userRoles ??
    anyReq?.user?.roles ??
    anyReq?.user?.roleCodes) as unknown;

  if (Array.isArray(roles)) {
    return roles.map((x) => String(x).trim().toUpperCase()).includes("OWNER");
  }

  return false;
}

/**
 * ✅ Authed si requireAuth setea:
 * - (legacy) req.userId + req.tenantId
 * - (tenant) req.userId + req.jewelryId
 * - (nuevo)  req.user.id + (req.user.tenantId || req.user.jewelryId)
 */
function isAuthed(req: Request) {
  const anyReq = req as any;

  const userId = anyReq?.userId ?? anyReq?.user?.id;
  const tenantId = anyReq?.tenantId ?? anyReq?.user?.tenantId;
  const jewelryId = anyReq?.jewelryId ?? anyReq?.user?.jewelryId;

  return Boolean(userId && (tenantId || jewelryId));
}

/**
 * Normaliza permisos a Set<string> con claves "MODULE:ACTION"
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
      if (s) out.add(s.toUpperCase());
      continue;
    }

    if (p && typeof p === "object") {
      const obj = p as any;

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
        if (s) out.add(s.toUpperCase());
      }

      const mod = String(obj.module ?? obj.permModule ?? "").trim();
      const act = String(obj.action ?? obj.permAction ?? "").trim();
      if (mod && act) out.add(`${mod}:${act}`.toUpperCase());
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
 * - Si no autenticado => 401
 * - Si es OWNER => allow (bypass)
 * - Si no tiene permiso => 403
 */
export function requirePermission(module: string, action: string) {
  const wanted = `${String(module).trim()}:${String(action).trim()}`.toUpperCase();

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
 * - Si no autenticado => 401
 * - Si es OWNER => allow (bypass)
 * - Si tiene cualquiera => allow
 */
export function requireAnyPermission(wanted: string[]) {
  const wantedList = Array.isArray(wanted)
    ? Array.from(
        new Set(
          wanted
            .map((x) => String(x ?? "").trim().toUpperCase())
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
