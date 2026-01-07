// src/services/permissions.ts
import type { OverrideEffect } from "@prisma/client";

/**
 * Normaliza un permiso al formato "MODULE:ACTION"
 */
export function formatPerm(module: string, action: string) {
  return `${module}:${action}`;
}

function uniq(arr: string[]) {
  return Array.from(new Set(arr));
}

/**
 * Calcula permisos efectivos combinando:
 * - permisos por roles
 * - overrides ALLOW/DENY
 *
 * Estructura esperada (compatible con tus includes):
 * user.roles[].role.permissions[].permission.{module,action}
 * user.permissionOverrides[].{effect, permission.{module,action}}
 */
export function computeEffectivePermissions(user: {
  roles?: Array<{
    role?: {
      permissions?: Array<{ permission?: { module: any; action: any } }>;
    };
  }>;
  permissionOverrides?: Array<{
    effect: OverrideEffect;
    permission?: { module: any; action: any };
  }>;
}) {
  // 1) permisos desde roles
  const fromRoles: string[] = [];
  for (const ur of user.roles ?? []) {
    const rps = ur.role?.permissions ?? [];
    for (const rp of rps) {
      const m = rp.permission?.module;
      const a = rp.permission?.action;
      if (m != null && a != null) {
        fromRoles.push(formatPerm(String(m), String(a)));
      }
    }
  }

  // 2) overrides
  const allow: string[] = [];
  const deny: string[] = [];
  for (const ov of user.permissionOverrides ?? []) {
    const m = ov.permission?.module;
    const a = ov.permission?.action;
    if (m == null || a == null) continue;

    const p = formatPerm(String(m), String(a));
    if (ov.effect === "ALLOW") allow.push(p);
    if (ov.effect === "DENY") deny.push(p);
  }

  // 3) aplicar (deny gana)
  const base = new Set<string>(uniq(fromRoles));
  for (const d of deny) base.delete(d);
  for (const a of allow) base.add(a);
  for (const d of deny) base.delete(d);

  return Array.from(base).sort();
}
