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
    roleId?: string;
    role: {
      id?: unknown;
      name?: unknown;
      displayName?: unknown;
      isSystem?: unknown;
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

function safeRoleLabel(r: any) {
  const dn = String(r?.displayName ?? "").trim();
  const n = String(r?.name ?? "").trim();
  return dn || n;
}

export function mapRoles(user: any) {
  const list = (user?.roles ?? []).map((ur: any) => {
    const role = ur?.role ?? {};
    const id = String(ur?.roleId ?? role?.id ?? "").trim();
    const name = String(role?.name ?? "").trim();
    const displayName = safeRoleLabel(role);
    const isSystem = Boolean(role?.isSystem ?? false);

    return { id, name, displayName, isSystem };
  });

  // ✅ limpia vacíos/duplicados por seguridad
  const seen = new Set<string>();
  return list.filter((r: any) => {
    const key = r.id || `${r.name}::${r.displayName}`;
    if (!key) return false;
    if (seen.has(key)) return false;
    seen.add(key);
    return Boolean(String(r.displayName || r.name || "").trim());
  });
}

export function normalizeJewelrySecurity(j: any) {
  if (!j) return null;

  return {
    ...j,

    // ✅ IMPORTANTE: default false (coincide con tu AuthContext)
    // si nunca se configuró el lock, NO debe bloquear por defecto
    pinLockEnabled: j.pinLockEnabled ?? false,

    // defaults “seguros” para UI/settings (solo si faltan)
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

export function buildAuthResponse(args: { user: any; token?: string; includeToken?: boolean }) {
  const { user, token, includeToken } = args;

  const roles = mapRoles(user);
  const permissions = computeEffectivePermissions(user as ComputeUserShape);

  // ✅ helpers listos para UI (Sidebar / LockScreen / Topbar)
  const roleNames = roles
    .map((r: any) => String(r?.displayName ?? r?.name ?? "").trim())
    .filter(Boolean);

  const roleLabel = roleNames.join(" • ");

  return {
    user: sanitizeUser(user),
    jewelry: normalizeJewelrySecurity(user?.jewelry ?? null),

    // ✅ roles con displayName
    roles,

    // ✅ extra para evitar hardcode en frontend
    roleNames,
    roleLabel,

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
