// tptech-backend/src/lib/authResponse.ts
import type { OverrideEffect } from "@prisma/client";

function uniq(arr: string[]) {
  return Array.from(new Set(arr));
}

function formatPerm(module: string, action: string) {
  return `${module}:${action}`;
}

export type ComputeUserShape = {
  roles: Array<{
    role: {
      permissions: Array<{ permission: { module: unknown; action: unknown } }>;
    };
  }>;
  permissionOverrides: Array<{
    effect: OverrideEffect;
    permission: { module: unknown; action: unknown };
  }>;
};

export function computeEffectivePermissions(user: ComputeUserShape) {
  // 1) permisos por roles
  const fromRoles: string[] = [];
  for (const ur of user.roles ?? []) {
    const rps = ur.role?.permissions ?? [];
    for (const rp of rps) {
      fromRoles.push(formatPerm(String(rp.permission.module), String(rp.permission.action)));
    }
  }

  // 2) overrides
  const allow: string[] = [];
  const deny: string[] = [];
  for (const ov of user.permissionOverrides ?? []) {
    const p = formatPerm(String(ov.permission.module), String(ov.permission.action));
    if (ov.effect === "ALLOW") allow.push(p);
    if (ov.effect === "DENY") deny.push(p);
  }

  // 3) aplicar deny sobre roles y allow
  const base = new Set(uniq(fromRoles));
  for (const d of deny) base.delete(d);
  for (const a of allow) base.add(a);
  for (const d of deny) base.delete(d);

  return Array.from(base).sort();
}

export function mapRoles(user: any) {
  return (user?.roles ?? []).map((ur: any) => ({
    id: ur.roleId,
    name: ur.role?.name,
    isSystem: ur.role?.isSystem ?? false,
  }));
}

export function normalizeJewelrySecurity(j: any) {
  if (!j) return null;
  return {
    ...j,
    pinLockEnabled: j.pinLockEnabled ?? true,
    pinLockTimeoutSec: j.pinLockTimeoutSec ?? 300,
    pinLockRequireOnUserSwitch: j.pinLockRequireOnUserSwitch ?? true,
    quickSwitchEnabled: j.quickSwitchEnabled ?? false,
  };
}

export function sanitizeUser(user: any) {
  const safeUser: any = { ...(user ?? {}) };
  delete safeUser.password;
  delete safeUser.quickPinHash; // nunca devolver hash
  delete safeUser.roles;
  delete safeUser.permissionOverrides;
  return safeUser;
}

export function buildAuthResponse(args: {
  user: any;
  token?: string;
  includeToken?: boolean;
}) {
  const { user, token, includeToken } = args;

  const roles = mapRoles(user);
  const permissions = computeEffectivePermissions(user as ComputeUserShape);

  return {
    user: sanitizeUser(user),
    jewelry: normalizeJewelrySecurity(user?.jewelry ?? null),
    roles,
    permissions,
    favoriteWarehouse: user?.favoriteWarehouse ?? null,
    ...(includeToken
      ? {
          token,
          accessToken: token,
        }
      : {}),
  };
}
