// tptech-backend/src/controllers/users.controller.ts
import type { Request, Response } from "express";
import type { Prisma } from "@prisma/client";
import bcrypt from "bcryptjs";
import { prisma } from "../lib/prisma.js";
import { auditLog } from "../lib/auditLogger.js";
import { UserStatus } from "@prisma/client";
import crypto from "node:crypto";
import path from "node:path";
import fs from "node:fs/promises";
import fsSync from "node:fs";

/* =========================
   HELPERS
========================= */
function requireTenantId(req: Request, res: Response): string | null {
  const tenantId = (req as any).tenantId as string | undefined;
  if (!tenantId) {
    res.status(400).json({ message: "Tenant no definido en el request." });
    return null;
  }
  return String(tenantId);
}

function uniqStrings(arr: string[]) {
  return Array.from(new Set(arr));
}

function normalizeEmail(raw: any) {
  return String(raw || "").toLowerCase().trim();
}

function normalizeName(raw: any) {
  const s = String(raw || "").trim();
  return s.length ? s : null;
}

/**
 * ✅ Opcional, pero SAFE para tu schema:
 * - undefined/null => undefined (no toca el campo)
 * - "" (o whitespace) => "" (string vacío, válido con @default(""))
 * - caso normal => string trim
 *
 * NUNCA devuelve null (para evitar Prisma error: "must not be null")
 */
function normOpt(raw: any): string | undefined {
  if (raw === undefined || raw === null) return undefined;
  const s = String(raw).trim();
  if (s.length === 0) return "";
  return s;
}

function normStr(raw: any) {
  return String(raw ?? "").trim();
}

function clampInt(v: any, def: number, min: number, max: number) {
  const n = Number(v);
  if (!Number.isFinite(n)) return def;
  return Math.max(min, Math.min(max, Math.trunc(n)));
}

function toPublicUrl(relativePath: string) {
  const base = String(process.env.PUBLIC_BASE_URL || "").replace(/\/+$/, "");
  if (!base) return relativePath;
  const p = relativePath.startsWith("/") ? relativePath : `/${relativePath}`;
  return `${base}${p}`;
}

function filenameFromAnyUrl(u: string) {
  try {
    if (u.startsWith("http://") || u.startsWith("https://")) {
      const url = new URL(u);
      return decodeURIComponent(url.pathname.split("/").pop() || "");
    }
  } catch {
    // ignore
  }
  const parts = String(u || "").split("/");
  return decodeURIComponent(parts[parts.length - 1] || "");
}

async function safeDeleteOldAvatar(avatarUrl: string | null) {
  if (!avatarUrl) return;

  const s = String(avatarUrl || "");
  if (!s.includes("/uploads/avatars/")) return;

  const filename = filenameFromAnyUrl(s);
  if (!filename) return;

  const safeName = path.basename(filename);
  if (!safeName) return;

  const abs = path.join(process.cwd(), "uploads", "avatars", safeName);

  try {
    await fs.unlink(abs);
  } catch {
    // ignore
  }
}

/** hash random para usuarios PENDING (evita guardar password vacío) */
async function randomPasswordHash() {
  const raw = crypto.randomBytes(24).toString("hex");
  return bcrypt.hash(raw, 10);
}

function isValidUserStatus(v: any): v is UserStatus {
  return v === "ACTIVE" || v === "PENDING" || v === "BLOCKED";
}

function isValidOverrideEffect(v: any): v is "ALLOW" | "DENY" {
  return v === "ALLOW" || v === "DENY";
}

/* =========================
   ✅ QUICK PIN HELPERS
   - hasQuickPin = (quickPinHash != null)
   - pinEnabled  = quickPinEnabled (solo tiene sentido si hay hash)
========================= */
function isValidPin4(v: any): v is string {
  const s = String(v ?? "").trim();
  return /^[0-9]{4}$/.test(s);
}

/**
 * ✅ FIX 403:
 * Soporta permisos en múltiples formatos:
 * - "USERS_ROLES:ADMIN"
 * - { module: "USERS_ROLES", action: "ADMIN" }
 * - { key: "USERS_ROLES:ADMIN" }
 * - { perm: "USERS_ROLES:ADMIN" }
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

function hasUsersRolesAdmin(perms: unknown[]): boolean {
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

function requireAdminUsersRoles(req: Request, res: Response): boolean {
  // ✅ BYPASS OWNER (igual que requirePermission)
  if (isOwnerReq(req)) return true;

  const perms = ((req as any).permissions ?? []) as unknown[];
  if (!hasUsersRolesAdmin(perms)) {
    res.status(403).json({ message: "No tenés permisos para realizar esta acción." });
    return false;
  }
  return true;
}

async function countUserOverrides(userId: string) {
  return prisma.userPermissionOverride.count({ where: { userId } });
}

/* =========================
   ✅ OWNER PIN FIX
   - Si el target es OWNER, permitir quitar/deshabilitar PIN
     SIN tocar permisos especiales (overrides).
========================= */
async function isTargetOwnerUser(tenantId: string, userId: string): Promise<boolean> {
  try {
    const ur = await prisma.userRole.findFirst({
      where: {
        userId,
        role: {
          jewelryId: tenantId,
          deletedAt: null,
          name: "OWNER",
        },
      },
      select: { userId: true },
    });
    return Boolean(ur);
  } catch {
    return false;
  }
}

/* =========================
   ✅ PIN LOCK RULE (tenant-level)
   - Si pinLockEnabled está activo, NO permitir dejar la joyería sin ningún PIN habilitado
========================= */
async function assertCanRemoveOrDisableQuickPinForTenant(tenantId: string, targetUserId: string): Promise<
  | { ok: true }
  | {
      ok: false;
      code: "LAST_PIN_LOCK_ACTIVE";
      message: string;
    }
> {
  const jewelry = await prisma.jewelry.findFirst({
    where: { id: tenantId },
    select: { pinLockEnabled: true },
  });

  if (!jewelry?.pinLockEnabled) return { ok: true };

  // Cantidad de usuarios con PIN "usable": hash + enabled + no deleted
  const countEnabled = await prisma.user.count({
    where: {
      jewelryId: tenantId,
      deletedAt: null,
      quickPinHash: { not: null },
      quickPinEnabled: true,
    },
  });

  if (countEnabled > 1) return { ok: true };

  // Si target es el último con PIN habilitado -> bloquear
  const target = await prisma.user.findFirst({
    where: { id: targetUserId, jewelryId: tenantId, deletedAt: null },
    select: { quickPinHash: true, quickPinEnabled: true },
  });

  const targetHasEnabledPin = Boolean(target?.quickPinHash) && Boolean(target?.quickPinEnabled);
  if (!targetHasEnabledPin) return { ok: true };

  return {
    ok: false,
    code: "LAST_PIN_LOCK_ACTIVE",
    message:
      "No podés eliminar o deshabilitar el último PIN mientras el bloqueo por PIN esté activo. Primero desactivá el bloqueo o asigná un PIN a otro usuario.",
  };
}

/* =========================
   ✅ QUICK PIN (ME)
   PUT /users/me/quick-pin
========================= */
export async function updateMyQuickPin(req: Request, res: Response) {
  const actorId = (req as any).userId as string;
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  const { pin, currentPin } = req.body as { pin?: string; currentPin?: string };

  if (!isValidPin4(pin)) {
    return res.status(400).json({ message: "El PIN debe tener exactamente 4 dígitos." });
  }

  const me = await prisma.user.findFirst({
    where: { id: actorId, jewelryId: tenantId, deletedAt: null },
    select: { id: true, quickPinHash: true, quickPinEnabled: true },
  });

  if (!me) return res.status(404).json({ message: "Usuario no encontrado." });

  if (me.quickPinHash) {
    if (!isValidPin4(currentPin)) {
      return res.status(400).json({ message: "Ingresá tu PIN actual (4 dígitos)." });
    }
    const ok = await bcrypt.compare(String(currentPin), me.quickPinHash);
    if (!ok) {
      auditLog(req, {
        action: "users.quick_pin.set_me",
        success: false,
        userId: actorId,
        tenantId,
        meta: { reason: "invalid_current_pin" },
      });
      return res.status(400).json({ message: "PIN actual incorrecto." });
    }
  }

  const hash = await bcrypt.hash(String(pin), 10);

  const updated = await prisma.user.update({
    where: { id: actorId },
    data: {
      quickPinHash: hash,
      quickPinEnabled: true,
      quickPinUpdatedAt: new Date(),
      quickPinFailedCount: 0,
      quickPinLockedUntil: null,
    },
    select: { id: true, quickPinHash: true, quickPinEnabled: true, quickPinUpdatedAt: true },
  });

  auditLog(req, {
    action: "users.quick_pin.set_me",
    success: true,
    userId: actorId,
    tenantId,
    meta: { hasPin: true },
  });

  return res.json({
    ok: true,
    hasQuickPin: Boolean(updated.quickPinHash),
    pinEnabled: Boolean(updated.quickPinEnabled),
    quickPinUpdatedAt: updated.quickPinUpdatedAt,
  });
}

/* =========================
   ✅ QUICK PIN (ME)
   DELETE /users/me/quick-pin
   ✅ FIX: currentPin opcional + regla último PIN si pinLockEnabled=true
========================= */
export async function removeMyQuickPin(req: Request, res: Response) {
  const actorId = (req as any).userId as string;
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  const { currentPin } = (req.body ?? {}) as { currentPin?: string };

  const me = await prisma.user.findFirst({
    where: { id: actorId, jewelryId: tenantId, deletedAt: null },
    select: { id: true, quickPinHash: true, quickPinEnabled: true },
  });

  if (!me) return res.status(404).json({ message: "Usuario no encontrado." });

  if (!me.quickPinHash) {
    return res.json({ ok: true, hasQuickPin: false, pinEnabled: false });
  }

  // ✅ regla “último PIN + pinLockEnabled”
  const gate = await assertCanRemoveOrDisableQuickPinForTenant(tenantId, actorId);
  if (!gate.ok) {
    return res.status(409).json({ code: gate.code, message: gate.message });
  }

  // ✅ Para MI CUENTA: currentPin es opcional. Si lo envía, lo validamos.
  if (currentPin !== undefined && String(currentPin).trim() !== "") {
    if (!isValidPin4(currentPin)) {
      return res.status(400).json({ message: "Ingresá tu PIN actual (4 dígitos)." });
    }

    const ok = await bcrypt.compare(String(currentPin), me.quickPinHash);
    if (!ok) {
      auditLog(req, {
        action: "users.quick_pin.remove_me",
        success: false,
        userId: actorId,
        tenantId,
        meta: { reason: "invalid_current_pin" },
      });
      return res.status(400).json({ message: "PIN actual incorrecto." });
    }
  }

  const updated = await prisma.user.update({
    where: { id: actorId },
    data: {
      quickPinHash: null,
      quickPinEnabled: false,
      quickPinUpdatedAt: new Date(),
      quickPinFailedCount: 0,
      quickPinLockedUntil: null,
    },
    select: { id: true, quickPinHash: true, quickPinEnabled: true, quickPinUpdatedAt: true },
  });

  auditLog(req, {
    action: "users.quick_pin.remove_me",
    success: true,
    userId: actorId,
    tenantId,
    meta: { hasPin: false },
  });

  return res.json({
    ok: true,
    hasQuickPin: Boolean(updated.quickPinHash),
    pinEnabled: Boolean(updated.quickPinEnabled),
    quickPinUpdatedAt: updated.quickPinUpdatedAt,
  });
}

/* =========================
   ✅ QUICK PIN (ADMIN) /users/:id/quick-pin
========================= */
export async function updateUserQuickPin(req: Request, res: Response) {
  const actorId = (req as any).userId as string;
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  if (!requireAdminUsersRoles(req, res)) return;

  const targetUserId = String(req.params.id || "").trim();
  if (!targetUserId) return res.status(400).json({ message: "ID inválido." });

  const { pin } = req.body as { pin?: string };

  if (!isValidPin4(pin)) {
    return res.status(400).json({ message: "El PIN debe tener exactamente 4 dígitos." });
  }

  const target = await prisma.user.findFirst({
    where: { id: targetUserId, jewelryId: tenantId, deletedAt: null },
    select: { id: true },
  });

  if (!target) return res.status(404).json({ message: "Usuario no encontrado." });

  const hash = await bcrypt.hash(String(pin), 10);

  const updated = await prisma.user.update({
    where: { id: targetUserId },
    data: {
      quickPinHash: hash,
      quickPinEnabled: true,
      quickPinUpdatedAt: new Date(),
      quickPinFailedCount: 0,
      quickPinLockedUntil: null,
    },
    select: { id: true, quickPinHash: true, quickPinEnabled: true, quickPinUpdatedAt: true },
  });

  auditLog(req, {
    action: "users.quick_pin.set_user",
    success: true,
    userId: actorId,
    tenantId,
    meta: { targetUserId, hasPin: true },
  });

  return res.json({
    ok: true,
    hasQuickPin: Boolean(updated.quickPinHash),
    pinEnabled: Boolean(updated.quickPinEnabled),
    quickPinUpdatedAt: updated.quickPinUpdatedAt,
  });
}

/* =========================
   ✅ QUICK PIN (ADMIN) DELETE /users/:id/quick-pin
========================= */
export async function removeUserQuickPin(req: Request, res: Response) {
  const actorId = (req as any).userId as string;
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  if (!requireAdminUsersRoles(req, res)) return;

  const targetUserId = String(req.params.id || "").trim();
  if (!targetUserId) return res.status(400).json({ message: "ID inválido." });

  const { confirmRemoveOverrides } = (req.body ?? {}) as { confirmRemoveOverrides?: boolean };

  const target = await prisma.user.findFirst({
    where: { id: targetUserId, jewelryId: tenantId, deletedAt: null },
    select: { id: true, quickPinHash: true, quickPinEnabled: true },
  });

  if (!target) return res.status(404).json({ message: "Usuario no encontrado." });

  // ✅ regla “último PIN + pinLockEnabled”
  const gate = await assertCanRemoveOrDisableQuickPinForTenant(tenantId, targetUserId);
  if (!gate.ok) {
    return res.status(409).json({ code: gate.code, message: gate.message, targetUserId });
  }

  // ✅ OWNER: permitir quitar PIN sin forzar borrado de overrides
  const targetIsOwner = await isTargetOwnerUser(tenantId, targetUserId);

  const overridesCount = await countUserOverrides(targetUserId);

  if (!targetIsOwner) {
    if (overridesCount > 0 && confirmRemoveOverrides !== true) {
      return res.status(409).json({
        code: "HAS_SPECIAL_PERMISSIONS",
        message: "Este usuario tiene permisos especiales asignados. Si continuás, se borrarán esos permisos.",
        overridesCount,
        requireConfirmRemoveOverrides: true,
      });
    }
  }

  const updated = await prisma.$transaction(async (tx: Prisma.TransactionClient) => {
    // Solo borrar overrides si NO es owner y el usuario confirmó
    if (!targetIsOwner && overridesCount > 0) {
      await tx.userPermissionOverride.deleteMany({ where: { userId: targetUserId } });
    }

    return tx.user.update({
      where: { id: targetUserId },
      data: {
        quickPinHash: null,
        quickPinEnabled: false,
        quickPinUpdatedAt: new Date(),
        quickPinFailedCount: 0,
        quickPinLockedUntil: null,
      },
      select: { id: true, quickPinHash: true, quickPinEnabled: true, quickPinUpdatedAt: true },
    });
  });

  auditLog(req, {
    action: "users.quick_pin.remove_user",
    success: true,
    userId: actorId,
    tenantId,
    meta: {
      targetUserId,
      hasPin: false,
      targetIsOwner,
      overridesCleared: !targetIsOwner && overridesCount > 0,
      overridesCount,
    },
  });

  return res.json({
    ok: true,
    hasQuickPin: Boolean(updated.quickPinHash),
    pinEnabled: Boolean(updated.quickPinEnabled),
    quickPinUpdatedAt: updated.quickPinUpdatedAt,
    overridesCleared: !targetIsOwner && overridesCount > 0,
    overridesCount,
    targetIsOwner,
  });
}

/* =========================
   ✅ QUICK PIN ENABLED (ADMIN)
========================= */
export async function updateUserQuickPinEnabled(req: Request, res: Response) {
  const actorId = (req as any).userId as string;
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  if (!requireAdminUsersRoles(req, res)) return;

  const targetUserId = String(req.params.id || "").trim();
  if (!targetUserId) return res.status(400).json({ message: "ID inválido." });

  const enabledRaw = (req.body as any)?.enabled;
  const confirmRemoveOverrides = Boolean((req.body as any)?.confirmRemoveOverrides);

  if (typeof enabledRaw !== "boolean") {
    return res.status(400).json({ message: "enabled debe ser boolean." });
  }

  const target = await prisma.user.findFirst({
    where: { id: targetUserId, jewelryId: tenantId, deletedAt: null },
    select: { id: true, quickPinHash: true, quickPinEnabled: true },
  });

  if (!target) return res.status(404).json({ message: "Usuario no encontrado." });

  if (enabledRaw === true && !target.quickPinHash) {
    return res.status(400).json({ message: "El usuario no tiene PIN definido. Definilo primero." });
  }

  // ✅ regla “último PIN + pinLockEnabled” también al DESHABILITAR
  if (enabledRaw === false) {
    const gate = await assertCanRemoveOrDisableQuickPinForTenant(tenantId, targetUserId);
    if (!gate.ok) {
      return res.status(409).json({ code: gate.code, message: gate.message, targetUserId });
    }
  }

  // ✅ OWNER: permitir deshabilitar sin forzar borrado de overrides
  const targetIsOwner = await isTargetOwnerUser(tenantId, targetUserId);

  let overridesCount = 0;
  if (enabledRaw === false) {
    overridesCount = await countUserOverrides(targetUserId);

    if (!targetIsOwner) {
      if (overridesCount > 0 && confirmRemoveOverrides !== true) {
        return res.status(409).json({
          code: "HAS_SPECIAL_PERMISSIONS",
          message: "Este usuario tiene permisos especiales asignados. Si continuás, se borrarán esos permisos.",
          overridesCount,
          requireConfirmRemoveOverrides: true,
        });
      }
    }
  }

  const updated = await prisma.$transaction(async (tx: Prisma.TransactionClient) => {
    // Solo borrar overrides si NO es owner y confirmó
    if (enabledRaw === false && !targetIsOwner && overridesCount > 0) {
      await tx.userPermissionOverride.deleteMany({ where: { userId: targetUserId } });
    }

    return tx.user.update({
      where: { id: targetUserId },
      data: { quickPinEnabled: enabledRaw },
      select: { id: true, quickPinHash: true, quickPinEnabled: true },
    });
  });

  auditLog(req, {
    action: "users.quick_pin.enabled",
    success: true,
    userId: actorId,
    tenantId,
    meta: {
      targetUserId,
      enabled: enabledRaw,
      targetIsOwner,
      overridesCleared: enabledRaw === false && !targetIsOwner && overridesCount > 0,
      overridesCount: enabledRaw === false ? overridesCount : undefined,
    },
  });

  return res.json({
    ok: true,
    hasQuickPin: Boolean(updated.quickPinHash),
    pinEnabled: Boolean(updated.quickPinHash) && Boolean(updated.quickPinEnabled),
    overridesCleared: enabledRaw === false && !targetIsOwner && overridesCount > 0,
    overridesCount: enabledRaw === false ? overridesCount : undefined,
    targetIsOwner,
  });
}

/* =========================
   POST /users (ADMIN)
========================= */
export async function createUser(req: Request, res: Response) {
  const actorId = (req as any).userId as string;
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  const body = req.body as {
    email: string;
    name?: string;
    password?: string;
    roleIds?: string[];
    status?: "ACTIVE" | "BLOCKED" | "PENDING";
  };

  const email = normalizeEmail(body.email);
  const name = normalizeName(body.name);

  if (!email) return res.status(400).json({ message: "Email inválido." });

  let roleIds = Array.isArray(body.roleIds) ? body.roleIds : [];
  roleIds = uniqStrings(roleIds.map((r: string) => String(r || "").trim()).filter(Boolean));

  const hasPassword = Boolean(String(body.password || "").trim());
  const desiredStatus = body.status ? String(body.status) : undefined;

  const status: UserStatus =
    desiredStatus === "BLOCKED"
      ? UserStatus.BLOCKED
      : desiredStatus === "PENDING"
        ? UserStatus.PENDING
        : hasPassword
          ? UserStatus.ACTIVE
          : UserStatus.PENDING;

  const existing = await prisma.user.findFirst({
    where: { jewelryId: tenantId, email },
    select: { id: true, deletedAt: true },
  });

  if (existing && existing.deletedAt == null) {
    auditLog(req, {
      action: "users.create",
      success: false,
      userId: actorId,
      tenantId,
      meta: { email, reason: "email_already_exists" },
    });
    return res.status(409).json({ message: "El email ya está registrado." });
  }

  if (roleIds.length) {
    const roles = await prisma.role.findMany({
      where: { id: { in: roleIds }, jewelryId: tenantId, deletedAt: null },
      select: { id: true },
    });

    if (roles.length !== roleIds.length) {
      return res.status(400).json({ message: "Uno o más roles no son válidos para esta joyería." });
    }
  }

  const passwordHash = hasPassword ? await bcrypt.hash(String(body.password), 10) : await randomPasswordHash();

  const created = await prisma.$transaction(async (tx: Prisma.TransactionClient) => {
    const user = await tx.user.create({
      data: {
        email,
        name,
        status,
        jewelryId: tenantId,
        password: passwordHash,
        tokenVersion: 0,
        deletedAt: null,

        quickPinHash: null,
        quickPinEnabled: false,
        quickPinUpdatedAt: null,
        quickPinFailedCount: 0,
        quickPinLockedUntil: null,
      },
      select: {
        id: true,
        email: true,
        name: true,
        status: true,
        avatarUrl: true,
        favoriteWarehouseId: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    if (roleIds.length) {
      await tx.userRole.createMany({
        data: roleIds.map((roleId: string) => ({ userId: user.id, roleId })),
        skipDuplicates: true,
      });
    }

    const roles = await tx.userRole.findMany({
      where: { userId: user.id },
      select: {
        role: { select: { id: true, name: true, isSystem: true, jewelryId: true, deletedAt: true } },
      },
    });

    type UR = (typeof roles)[number];
    type R = UR["role"];

    return {
      ...user,
      roles: roles
        .map((ur: UR) => ur.role as R)
        .filter((r: R) => r && r.jewelryId === tenantId && !r.deletedAt)
        .map((r: R) => ({ id: r.id, name: r.name, isSystem: r.isSystem })),
    };
  });

  auditLog(req, {
    action: "users.create",
    success: true,
    userId: actorId,
    tenantId,
    meta: { createdUserId: created.id, email, status, roleIds },
  });

  return res.status(201).json({ user: created });
}

/* =========================
   GET /users
   ✅ LIVIANO + PAGINADO + SEARCH
   ✅ incluye attachmentsCount + overridesCount (para UI instantánea)
========================= */
export async function listUsers(req: Request, res: Response) {
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  const q = String(req.query.q ?? "").trim();
  const status = String(req.query.status ?? "").trim().toUpperCase();
  const page = clampInt(req.query.page, 1, 1, 10_000);
  const limit = clampInt(req.query.limit, 30, 1, 100);
  const skip = (page - 1) * limit;

  const where: any = { jewelryId: tenantId, deletedAt: null };

  if (status === "ACTIVE" || status === "BLOCKED" || status === "PENDING") {
    where.status = status;
  }

  if (q) {
    where.OR = [
      { email: { contains: q, mode: "insensitive" } },
      { name: { contains: q, mode: "insensitive" } },
    ];
  }

  const [total, users] = await prisma.$transaction([
    prisma.user.count({ where }),
    prisma.user.findMany({
      where,
      select: {
        id: true,
        email: true,
        name: true,
        status: true,
        avatarUrl: true,
        favoriteWarehouseId: true,
        createdAt: true,
        updatedAt: true,

        quickPinHash: true,
        quickPinEnabled: true,

        roles: {
          select: {
            role: {
              select: { id: true, name: true, isSystem: true, jewelryId: true, deletedAt: true },
            },
          },
        },

        _count: {
          select: {
            attachments: true,
            permissionOverrides: true,
          },
        },
      },
      orderBy: { createdAt: "asc" },
      skip,
      take: limit,
    }),
  ]);

  type U = (typeof users)[number];
  type UR = U["roles"][number];
  type R = UR["role"];

  return res.json({
    page,
    limit,
    total,
    users: users.map((u: U) => ({
      id: u.id,
      email: u.email,
      name: u.name,
      status: u.status,
      avatarUrl: u.avatarUrl,
      favoriteWarehouseId: u.favoriteWarehouseId,
      createdAt: u.createdAt,
      updatedAt: u.updatedAt,

      hasQuickPin: Boolean(u.quickPinHash),
      pinEnabled: Boolean(u.quickPinHash) && Boolean(u.quickPinEnabled),

      roles: (u.roles ?? [])
        .map((ur: UR) => ur.role as R)
        .filter((r: R) => r && r.jewelryId === tenantId && !r.deletedAt)
        .map((r: R) => ({ id: r.id, name: r.name, isSystem: r.isSystem })),

      attachmentsCount: u._count?.attachments ?? 0,
      overridesCount: u._count?.permissionOverrides ?? 0,
      hasSpecialPermissions: (u._count?.permissionOverrides ?? 0) > 0,
    })),
  });
}

/* =========================
   GET /users/:id
========================= */
export async function getUser(req: Request, res: Response) {
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  const targetUserId = String(req.params.id || "").trim();
  if (!targetUserId) return res.status(400).json({ message: "ID inválido." });

  const user = await prisma.user.findFirst({
    where: { id: targetUserId, jewelryId: tenantId, deletedAt: null },
    select: {
      id: true,
      email: true,
      name: true,
      status: true,
      tokenVersion: true,
      avatarUrl: true,
      favoriteWarehouseId: true,

      phoneCountry: true,
      phoneNumber: true,
      documentType: true,
      documentNumber: true,

      street: true,
      number: true,
      city: true,
      province: true,
      postalCode: true,
      country: true,

      notes: true,

      createdAt: true,
      updatedAt: true,

      quickPinHash: true,
      quickPinEnabled: true,
      quickPinUpdatedAt: true,
      quickPinFailedCount: true,
      quickPinLockedUntil: true,

      roles: {
        select: {
          role: {
            select: { id: true, name: true, isSystem: true, jewelryId: true, deletedAt: true },
          },
        },
      },
      permissionOverrides: {
        select: {
          permissionId: true,
          effect: true,
        },
      },
      attachments: {
        select: { id: true, url: true, filename: true, mimeType: true, size: true, createdAt: true },
        orderBy: { createdAt: "desc" },
      },
    },
  });

  if (!user) return res.status(404).json({ message: "Usuario no encontrado." });

  type U = typeof user;
  type UR = U["roles"][number];
  type R = UR["role"];

  return res.json({
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
      status: user.status,
      tokenVersion: user.tokenVersion,
      avatarUrl: user.avatarUrl,
      favoriteWarehouseId: user.favoriteWarehouseId,

      phoneCountry: user.phoneCountry,
      phoneNumber: user.phoneNumber,
      documentType: user.documentType,
      documentNumber: user.documentNumber,

      street: user.street,
      number: user.number,
      city: user.city,
      province: user.province,
      postalCode: user.postalCode,
      country: user.country,

      notes: user.notes,

      createdAt: user.createdAt,
      updatedAt: user.updatedAt,

      hasQuickPin: Boolean(user.quickPinHash),
      pinEnabled: Boolean(user.quickPinHash) && Boolean(user.quickPinEnabled),
      quickPinUpdatedAt: user.quickPinUpdatedAt,
      quickPinFailedCount: user.quickPinFailedCount,
      quickPinLockedUntil: user.quickPinLockedUntil,

      roles: (user.roles ?? [])
        .map((ur: UR) => ur.role as R)
        .filter((r: R) => r && r.jewelryId === tenantId && !r.deletedAt)
        .map((r: R) => ({ id: r.id, name: r.name, isSystem: r.isSystem })),

      permissionOverrides: user.permissionOverrides ?? [],
      attachments: user.attachments ?? [],
    },
  });
}

/* =========================
   PATCH /users/:id
========================= */
export async function updateUserProfile(req: Request, res: Response) {
  const actorId = (req as any).userId as string;
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  const targetUserId = String(req.params.id || "").trim();
  if (!targetUserId) return res.status(400).json({ message: "ID inválido." });

  const body = req.body as {
    name?: string | null;

    phoneCountry?: string;
    phoneNumber?: string;
    documentType?: string;
    documentNumber?: string;

    street?: string;
    number?: string;
    city?: string;
    province?: string;
    postalCode?: string;
    country?: string;

    notes?: string;
  };

  const target = await prisma.user.findFirst({
    where: { id: targetUserId, jewelryId: tenantId, deletedAt: null },
    select: { id: true },
  });

  if (!target) return res.status(404).json({ message: "Usuario no encontrado." });

  const data: any = {};

  if ("name" in body) data.name = normalizeName(body.name);

  const setOpt = (key: string, value: any) => {
    const v = normOpt(value);
    if (v !== undefined) data[key] = v;
  };

  if ("phoneCountry" in body) setOpt("phoneCountry", body.phoneCountry);
  if ("phoneNumber" in body) setOpt("phoneNumber", body.phoneNumber);

  if ("documentType" in body) setOpt("documentType", body.documentType);
  if ("documentNumber" in body) setOpt("documentNumber", body.documentNumber);

  if ("street" in body) setOpt("street", body.street);
  if ("number" in body) setOpt("number", body.number);
  if ("city" in body) setOpt("city", body.city);
  if ("province" in body) setOpt("province", body.province);
  if ("postalCode" in body) setOpt("postalCode", body.postalCode);
  if ("country" in body) setOpt("country", body.country);

  if ("notes" in body) data.notes = normStr(body.notes);

  if (!Object.keys(data).length) {
    return res.status(400).json({ message: "No hay campos para actualizar." });
  }

  if (targetUserId !== actorId) {
    data.tokenVersion = { increment: 1 };
  }

  const updated = await prisma.user.update({
    where: { id: targetUserId },
    data,
    select: {
      id: true,
      email: true,
      name: true,
      status: true,
      tokenVersion: true,
      avatarUrl: true,
      favoriteWarehouseId: true,

      phoneCountry: true,
      phoneNumber: true,
      documentType: true,
      documentNumber: true,

      street: true,
      number: true,
      city: true,
      province: true,
      postalCode: true,
      country: true,

      notes: true,

      createdAt: true,
      updatedAt: true,
    },
  });

  auditLog(req, {
    action: "users.update_profile",
    success: true,
    userId: actorId,
    tenantId,
    meta: { targetUserId, fields: Object.keys(data).filter((k) => k !== "tokenVersion") },
  });

  return res.json({ user: updated });
}

/* =========================
   PATCH /users/:id/status
========================= */
export async function updateUserStatus(req: Request, res: Response) {
  const actorId = (req as any).userId as string;
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  const targetUserId = String(req.params.id || "").trim();
  const raw = (req.body as any)?.status;

  if (!targetUserId) return res.status(400).json({ message: "ID inválido." });

  if (targetUserId === actorId) {
    return res.status(400).json({ message: "No podés cambiar tu propio estado desde aquí." });
  }

  if (!isValidUserStatus(raw)) {
    return res.status(400).json({ message: "status inválido. Use: ACTIVE | PENDING | BLOCKED" });
  }

  const target = await prisma.user.findFirst({
    where: { id: targetUserId, jewelryId: tenantId, deletedAt: null },
    select: { id: true },
  });

  if (!target) return res.status(404).json({ message: "Usuario no encontrado." });

  const updated = await prisma.user.update({
    where: { id: targetUserId },
    data: {
      status: raw,
    },
    select: {
      id: true,
      email: true,
      name: true,
      status: true,
      tokenVersion: true,
      avatarUrl: true,
      favoriteWarehouseId: true,
      updatedAt: true,
      createdAt: true,
    },
  });

  auditLog(req, {
    action: "users.update_status",
    success: true,
    userId: actorId,
    tenantId,
    meta: { targetUserId, status: raw },
  });

  return res.json({ user: updated });
}

/* =========================
   PUT /users/:id/roles
========================= */
export async function assignRolesToUser(req: Request, res: Response) {
  const actorId = (req as any).userId as string;
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  const targetUserId = String(req.params.id || "").trim();
  let { roleIds } = req.body as { roleIds: string[] };

  if (!targetUserId) return res.status(400).json({ message: "ID inválido." });

  if (!Array.isArray(roleIds)) {
    return res.status(400).json({ message: "roleIds debe ser un array" });
  }

  roleIds = uniqStrings(roleIds.map((r: string) => String(r || "").trim()).filter(Boolean));

  if (targetUserId === actorId) {
    return res.status(400).json({ message: "No podés cambiar tus propios roles desde aquí." });
  }

  const target = await prisma.user.findFirst({
    where: { id: targetUserId, jewelryId: tenantId, deletedAt: null },
    select: { id: true },
  });

  if (!target) return res.status(404).json({ message: "Usuario no encontrado." });

  const roles = await prisma.role.findMany({
    where: {
      id: { in: roleIds },
      jewelryId: tenantId,
      deletedAt: null,
    },
    select: { id: true },
  });

  if (roles.length !== roleIds.length) {
    return res.status(400).json({ message: "Uno o más roles no son válidos para esta joyería." });
  }

  await prisma.$transaction(async (tx: Prisma.TransactionClient) => {
    await tx.userRole.deleteMany({ where: { userId: targetUserId } });

    if (roleIds.length) {
      await tx.userRole.createMany({
        data: roleIds.map((roleId: string) => ({ userId: targetUserId, roleId })),
        skipDuplicates: true,
      });
    }

    await tx.user.update({
      where: { id: targetUserId },
      data: { tokenVersion: { increment: 1 } },
      select: { id: true },
    });
  });

  auditLog(req, {
    action: "users.assign_roles",
    success: true,
    userId: actorId,
    tenantId,
    meta: { targetUserId, roleIds },
  });

  return res.json({ ok: true });
}

/* =========================
   POST /users/:id/overrides
========================= */
export async function setUserOverride(req: Request, res: Response) {
  const actorId = (req as any).userId as string;
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  const targetUserId = String(req.params.id || "").trim();
  const { permissionId, effect } = req.body as {
    permissionId: string;
    effect: "ALLOW" | "DENY";
  };

  if (!targetUserId) return res.status(400).json({ message: "ID inválido." });
  if (!permissionId) return res.status(400).json({ message: "permissionId requerido." });
  if (!isValidOverrideEffect(effect)) {
    return res.status(400).json({ message: "effect inválido. Use: ALLOW | DENY" });
  }

  const user = await prisma.user.findFirst({
    where: { id: targetUserId, jewelryId: tenantId, deletedAt: null },
    select: { id: true },
  });

  if (!user) return res.status(404).json({ message: "Usuario no encontrado." });

  const perm = await prisma.permission.findUnique({
    where: { id: permissionId },
    select: { id: true },
  });

  if (!perm) return res.status(404).json({ message: "Permiso no encontrado." });

  const override = await prisma.userPermissionOverride.upsert({
    where: {
      userId_permissionId: {
        userId: targetUserId,
        permissionId,
      },
    },
    create: {
      userId: targetUserId,
      permissionId,
      effect,
    },
    update: { effect },
  });

  await prisma.user.update({
    where: { id: targetUserId },
    data: { tokenVersion: { increment: 1 } },
    select: { id: true },
  });

  auditLog(req, {
    action: "users.set_override",
    success: true,
    userId: actorId,
    tenantId,
    meta: { targetUserId, permissionId, effect },
  });

  return res.json({ override });
}

/* =========================
   DELETE /users/:id/overrides/:permissionId
========================= */
export async function removeUserOverride(req: Request, res: Response) {
  const actorId = (req as any).userId as string;
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  const targetUserId = String(req.params.id || "").trim();
  const permissionId = String(req.params.permissionId || "").trim();

  if (!targetUserId) return res.status(400).json({ message: "ID inválido." });
  if (!permissionId) return res.status(400).json({ message: "permissionId inválido." });

  const target = await prisma.user.findFirst({
    where: { id: targetUserId, jewelryId: tenantId, deletedAt: null },
    select: { id: true },
  });

  if (!target) return res.status(404).json({ message: "Usuario no encontrado." });

  await prisma.userPermissionOverride.deleteMany({
    where: { userId: targetUserId, permissionId },
  });

  await prisma.user.update({
    where: { id: targetUserId },
    data: { tokenVersion: { increment: 1 } },
    select: { id: true },
  });

  auditLog(req, {
    action: "users.remove_override",
    success: true,
    userId: actorId,
    tenantId,
    meta: { targetUserId, permissionId },
  });

  return res.json({ ok: true });
}

/* =========================
   ⭐ FAVORITE WAREHOUSE (ME)
========================= */
export async function updateMyFavoriteWarehouse(req: Request, res: Response) {
  const actorId = (req as any).userId as string;
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  const { warehouseId } = req.body as { warehouseId?: string | null };

  if (warehouseId !== null && warehouseId !== undefined && typeof warehouseId !== "string") {
    return res.status(400).json({ message: "warehouseId inválido." });
  }

  const cleanId = typeof warehouseId === "string" ? warehouseId.trim() : warehouseId === null ? null : undefined;

  if (cleanId === "") {
    return res.status(400).json({ message: "warehouseId inválido." });
  }

  if (cleanId) {
    const wh = await prisma.warehouse.findFirst({
      where: { id: cleanId, jewelryId: tenantId, isActive: true },
      select: { id: true },
    });

    if (!wh) {
      return res.status(404).json({ message: "Almacén no encontrado (o no pertenece a esta joyería)." });
    }
  }

  const updated = await prisma.user.update({
    where: { id: actorId },
    data: { favoriteWarehouseId: cleanId ?? null },
    select: {
      id: true,
      email: true,
      name: true,
      status: true,
      avatarUrl: true,
      favoriteWarehouseId: true,
      createdAt: true,
      updatedAt: true,
    },
  });

  auditLog(req, {
    action: "users.favorite_warehouse.update_me",
    success: true,
    userId: actorId,
    tenantId,
    meta: { favoriteWarehouseId: updated.favoriteWarehouseId },
  });

  return res.json({ ok: true, user: updated });
}

/* =========================
   ⭐ FAVORITE WAREHOUSE (ADMIN)
========================= */
export async function updateUserFavoriteWarehouse(req: Request, res: Response) {
  const actorId = (req as any).userId as string;
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  const targetUserId = String(req.params.id || "").trim();
  if (!targetUserId) return res.status(400).json({ message: "ID inválido." });

  const { warehouseId } = req.body as { warehouseId?: string | null };

  if (warehouseId !== null && warehouseId !== undefined && typeof warehouseId !== "string") {
    return res.status(400).json({ message: "warehouseId inválido." });
  }

  const cleanId = typeof warehouseId === "string" ? warehouseId.trim() : warehouseId === null ? null : undefined;

  if (cleanId === "") {
    return res.status(400).json({ message: "warehouseId inválido." });
  }

  const target = await prisma.user.findFirst({
    where: { id: targetUserId, jewelryId: tenantId, deletedAt: null },
    select: { id: true },
  });

  if (!target) return res.status(404).json({ message: "Usuario no encontrado." });

  if (cleanId) {
    const wh = await prisma.warehouse.findFirst({
      where: { id: cleanId, jewelryId: tenantId, isActive: true },
      select: { id: true },
    });

    if (!wh) {
      return res.status(404).json({ message: "Almacén no encontrado (o no pertenece a esta joyería)." });
    }
  }

  const updated = await prisma.user.update({
    where: { id: targetUserId },
    data: { favoriteWarehouseId: cleanId ?? null, tokenVersion: { increment: 1 } },
    select: {
      id: true,
      email: true,
      name: true,
      status: true,
      avatarUrl: true,
      favoriteWarehouseId: true,
      createdAt: true,
      updatedAt: true,
    },
  });

  auditLog(req, {
    action: "users.favorite_warehouse.update_user",
    success: true,
    userId: actorId,
    tenantId,
    meta: { targetUserId, favoriteWarehouseId: updated.favoriteWarehouseId },
  });

  return res.json({ ok: true, user: updated });
}

/* =========================
   AVATAR (ME)
========================= */
export async function updateMyAvatar(req: Request, res: Response) {
  const actorId = (req as any).userId as string;
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  const file = (req as any).file as Express.Multer.File | undefined;
  if (!file) {
    return res.status(400).json({ message: "Falta archivo avatar (multipart field: avatar)." });
  }

  if (!file.mimetype?.startsWith("image/")) {
    return res.status(400).json({ message: "El archivo debe ser una imagen." });
  }

  const prev = await prisma.user.findFirst({
    where: { id: actorId, jewelryId: tenantId, deletedAt: null },
    select: { avatarUrl: true, id: true },
  });

  if (!prev) return res.status(404).json({ message: "Usuario no encontrado." });

  const avatarRelative = `/uploads/avatars/${file.filename}`;
  const avatarUrl = toPublicUrl(avatarRelative);

  const updated = await prisma.user.update({
    where: { id: actorId },
    data: { avatarUrl },
    select: {
      id: true,
      email: true,
      name: true,
      status: true,
      avatarUrl: true,
      favoriteWarehouseId: true,
      createdAt: true,
      updatedAt: true,
    },
  });

  await safeDeleteOldAvatar(prev.avatarUrl);

  auditLog(req, {
    action: "users.avatar.update_me",
    success: true,
    userId: actorId,
    tenantId,
    meta: { avatarUrl: updated.avatarUrl },
  });

  return res.json({ ok: true, avatarUrl: updated.avatarUrl, user: updated });
}

export async function removeMyAvatar(req: Request, res: Response) {
  const actorId = (req as any).userId as string;
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  const prev = await prisma.user.findFirst({
    where: { id: actorId, jewelryId: tenantId, deletedAt: null },
    select: { avatarUrl: true, id: true },
  });

  if (!prev) return res.status(404).json({ message: "Usuario no encontrado." });

  const updated = await prisma.user.update({
    where: { id: actorId },
    data: { avatarUrl: null },
    select: {
      id: true,
      email: true,
      name: true,
      status: true,
      avatarUrl: true,
      favoriteWarehouseId: true,
      createdAt: true,
      updatedAt: true,
    },
  });

  await safeDeleteOldAvatar(prev.avatarUrl);

  auditLog(req, {
    action: "users.avatar.remove_me",
    success: true,
    userId: actorId,
    tenantId,
    meta: {},
  });

  return res.json({ ok: true, avatarUrl: null, user: updated });
}

/* =========================
   AVATAR (ADMIN)
========================= */
export async function updateUserAvatarForUser(req: Request, res: Response) {
  const actorId = (req as any).userId as string;
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  const targetUserId = String(req.params.id || "").trim();
  if (!targetUserId) return res.status(400).json({ message: "ID inválido." });

  const file = (req as any).file as Express.Multer.File | undefined;
  if (!file) {
    return res.status(400).json({ message: "Falta archivo avatar (multipart field: avatar)." });
  }

  if (!file.mimetype?.startsWith("image/")) {
    return res.status(400).json({ message: "El archivo debe ser una imagen." });
  }

  const prev = await prisma.user.findFirst({
    where: { id: targetUserId, jewelryId: tenantId, deletedAt: null },
    select: { avatarUrl: true, id: true },
  });

  if (!prev) return res.status(404).json({ message: "Usuario no encontrado." });

  const avatarRelative = `/uploads/avatars/${file.filename}`;
  const avatarUrl = toPublicUrl(avatarRelative);

  const data: any = { avatarUrl };
  // ✅ NO invalidar tu propia sesión si te editás a vos mismo desde ADMIN
  if (targetUserId !== actorId) data.tokenVersion = { increment: 1 };

  const updated = await prisma.user.update({
    where: { id: targetUserId },
    data,
    select: {
      id: true,
      email: true,
      name: true,
      status: true,
      avatarUrl: true,
      favoriteWarehouseId: true,
      createdAt: true,
      updatedAt: true,
    },
  });

  await safeDeleteOldAvatar(prev.avatarUrl);

  auditLog(req, {
    action: "users.avatar.update_user",
    success: true,
    userId: actorId,
    tenantId,
    meta: { targetUserId, avatarUrl: updated.avatarUrl },
  });

  return res.json({ ok: true, avatarUrl: updated.avatarUrl, user: updated });
}


export async function removeUserAvatarForUser(req: Request, res: Response) {
  const actorId = (req as any).userId as string;
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  const targetUserId = String(req.params.id || "").trim();
  if (!targetUserId) return res.status(400).json({ message: "ID inválido." });

  const prev = await prisma.user.findFirst({
    where: { id: targetUserId, jewelryId: tenantId, deletedAt: null },
    select: { avatarUrl: true, id: true },
  });

  if (!prev) return res.status(404).json({ message: "Usuario no encontrado." });

  const data: any = { avatarUrl: null };
  // ✅ NO invalidar tu propia sesión si te editás a vos mismo desde ADMIN
  if (targetUserId !== actorId) data.tokenVersion = { increment: 1 };

  const updated = await prisma.user.update({
    where: { id: targetUserId },
    data,
    select: {
      id: true,
      email: true,
      name: true,
      status: true,
      avatarUrl: true,
      favoriteWarehouseId: true,
      createdAt: true,
      updatedAt: true,
    },
  });

  await safeDeleteOldAvatar(prev.avatarUrl);

  auditLog(req, {
    action: "users.avatar.remove_user",
    success: true,
    userId: actorId,
    tenantId,
    meta: { targetUserId },
  });

  return res.json({ ok: true, avatarUrl: null, user: updated });
}


/* =========================
   ✅ SOFT DELETE USER (ADMIN)
========================= */
export async function softDeleteUser(req: Request, res: Response) {
  const actorId = (req as any).userId as string;
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  const targetUserId = String(req.params.id || "").trim();
  if (!targetUserId) return res.status(400).json({ message: "ID inválido." });

  if (targetUserId === actorId) {
    return res.status(400).json({ message: "No podés eliminar tu propio usuario." });
  }

  const target = await prisma.user.findFirst({
    where: { id: targetUserId, jewelryId: tenantId, deletedAt: null },
    select: { id: true, email: true, avatarUrl: true },
  });

  if (!target) return res.status(404).json({ message: "Usuario no encontrado." });

  const now = new Date();
  const suffix = crypto.randomBytes(6).toString("hex");
  const freedEmail = `deleted__${target.id}__${now.getTime()}__${suffix}@deleted.local`;

  await prisma.$transaction(async (tx: Prisma.TransactionClient) => {
    await tx.userPermissionOverride.deleteMany({ where: { userId: targetUserId } });
    await tx.userRole.deleteMany({ where: { userId: targetUserId } });

    await tx.user.update({
      where: { id: targetUserId },
      data: {
        deletedAt: now,
        status: UserStatus.BLOCKED,
        tokenVersion: { increment: 1 },
        avatarUrl: null,
        email: freedEmail,
        name: null,

        quickPinHash: null,
        quickPinEnabled: false,
        quickPinUpdatedAt: new Date(),
        quickPinFailedCount: 0,
        quickPinLockedUntil: null,
      },
      select: { id: true },
    });
  });

  await safeDeleteOldAvatar(target.avatarUrl);

  auditLog(req, {
    action: "users.delete_soft",
    success: true,
    userId: actorId,
    tenantId,
    meta: { targetUserId },
  });

  return res.json({ ok: true });
}
/* =========================
   ✅ USER ATTACHMENTS (ADMIN)
========================= */

function publicBaseUrl(req: Request) {
  const envBase = String(process.env.PUBLIC_BASE_URL || "").replace(/\/+$/, "");
  if (envBase) return envBase;
  return `${req.protocol}://${req.get("host")}`;
}

function toPublicUrlFromReq(req: Request, relativePath: string) {
  const base = publicBaseUrl(req);
  const p = relativePath.startsWith("/") ? relativePath : `/${relativePath}`;
  return `${base}${p}`;
}

async function safeDeleteByUrlIfLocalUserAttachment(url: string | null) {
  if (!url) return;

  const s = String(url || "");
  if (!s.includes("/uploads/user-attachments/")) return;

  const filename = filenameFromAnyUrl(s);
  if (!filename) return;

  const safeName = path.basename(filename);
  if (!safeName) return;

  const abs = path.join(process.cwd(), "uploads", "user-attachments", safeName);

  try {
    await fs.unlink(abs);
  } catch {
    // ignore
  }
}

/**
 * Convierte una url pública local (…/uploads/user-attachments/FILE) en path absoluto.
 * Devuelve null si no parece un archivo local del backend.
 */
function absLocalUserAttachmentFromUrl(url: string) {
  const s = String(url || "");
  if (!s.includes("/uploads/user-attachments/")) return null;

  const filename = filenameFromAnyUrl(s);
  if (!filename) return null;

  const safeName = path.basename(filename);
  if (!safeName) return null;

  return path.join(process.cwd(), "uploads", "user-attachments", safeName);
}

/**
 * ✅ Normaliza req.files para soportar:
 * - multer.array("attachments") -> req.files = File[]
 * - multer.fields(...) -> req.files = { attachments?: File[], "attachments[]"? : File[] }
 */
function normalizeUploadedFiles(req: Request): Express.Multer.File[] {
  const anyReq = req as any;
  const rf = anyReq.files;

  if (!rf) return [];

  if (Array.isArray(rf)) return rf as Express.Multer.File[];

  if (rf && typeof rf === "object") {
    const out: Express.Multer.File[] = [];
    const obj = rf as Record<string, unknown>;

    const a = obj["attachments"];
    const b = obj["attachments[]"];

    if (Array.isArray(a)) out.push(...(a as Express.Multer.File[]));
    if (Array.isArray(b)) out.push(...(b as Express.Multer.File[]));

    return out;
  }

  return [];
}

/* =========================
   ✅ USER ATTACHMENTS (ME)
   PUT /users/me/attachments
========================= */
export async function uploadMyAttachments(req: Request, res: Response) {
  const actorId = (req as any).userId as string;
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  const me = await prisma.user.findFirst({
    where: { id: actorId, jewelryId: tenantId, deletedAt: null },
    select: { id: true },
  });

  if (!me) {
    return res.status(404).json({ message: "Usuario no encontrado." });
  }

  const files = normalizeUploadedFiles(req);

  if (!files.length) {
    return res.status(400).json({
      message: "No se recibieron archivos (field: attachments o attachments[]).",
    });
  }

  const created = await prisma.userAttachment.createMany({
    data: files.map((f) => {
      const rel = `/uploads/user-attachments/${f.filename}`;
      return {
        userId: actorId,
        url: toPublicUrlFromReq(req, rel),
        filename: f.originalname || f.filename,
        mimeType: f.mimetype || "application/octet-stream",
        size: f.size ?? 0,
      };
    }),
    skipDuplicates: true,
  });

  auditLog(req, {
    action: "users.attachments.upload_me",
    success: true,
    userId: actorId,
    tenantId,
    meta: { count: files.length },
  });

  const updated = await prisma.user.findFirst({
    where: { id: actorId, jewelryId: tenantId, deletedAt: null },
    select: {
      id: true,
      email: true,
      name: true,
      status: true,
      tokenVersion: true,
      avatarUrl: true,
      favoriteWarehouseId: true,

      phoneCountry: true,
      phoneNumber: true,
      documentType: true,
      documentNumber: true,
      street: true,
      number: true,
      city: true,
      province: true,
      postalCode: true,
      country: true,
      notes: true,

      createdAt: true,
      updatedAt: true,

      quickPinHash: true,
      quickPinEnabled: true,
      quickPinUpdatedAt: true,

      attachments: {
        select: { id: true, url: true, filename: true, mimeType: true, size: true, createdAt: true },
        orderBy: { createdAt: "desc" },
      },
      roles: {
        select: {
          role: {
            select: { id: true, name: true, isSystem: true, jewelryId: true, deletedAt: true },
          },
        },
      },
      permissionOverrides: { select: { permissionId: true, effect: true } },
    },
  });

  if (!updated) {
    return res.json({ ok: true, createdCount: created.count, user: null });
  }

  type U = typeof updated;
  type UR = U["roles"][number];
  type R = UR["role"];

  return res.json({
    ok: true,
    createdCount: created.count,
    user: {
      ...updated,
      hasQuickPin: Boolean(updated.quickPinHash),
      pinEnabled: Boolean(updated.quickPinHash) && Boolean(updated.quickPinEnabled),
      roles: (updated.roles ?? [])
        .map((ur: UR) => ur.role as R)
        .filter((r: R) => r && r.jewelryId === tenantId && !r.deletedAt)
        .map((r: R) => ({ id: r.id, name: r.name, isSystem: r.isSystem })),
      permissionOverrides: updated.permissionOverrides ?? [],
    },
  });
}


export async function uploadUserAttachments(req: Request, res: Response) {
  const actorId = (req as any).userId as string;
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  if (!requireAdminUsersRoles(req, res)) return;

  const targetUserId = String(req.params.id || "").trim();
  if (!targetUserId) return res.status(400).json({ message: "ID inválido." });

  const target = await prisma.user.findFirst({
    where: { id: targetUserId, jewelryId: tenantId, deletedAt: null },
    select: { id: true },
  });
  if (!target) return res.status(404).json({ message: "Usuario no encontrado." });

  const files = normalizeUploadedFiles(req);

  if (!files.length) {
    return res.status(400).json({
      message: "No se recibieron archivos (field: attachments o attachments[]).",
    });
  }

  const created = await prisma.userAttachment.createMany({
    data: files.map((f) => {
      const rel = `/uploads/user-attachments/${f.filename}`;
      return {
        userId: targetUserId,
        url: toPublicUrlFromReq(req, rel),
        filename: f.originalname || f.filename,
        mimeType: f.mimetype || "application/octet-stream",
        size: f.size ?? 0,
      };
    }),
    skipDuplicates: true,
  });

  if (targetUserId !== actorId) {
  await prisma.user.update({
    where: { id: targetUserId },
    data: { tokenVersion: { increment: 1 } },
    select: { id: true },
  });
}


  auditLog(req, {
    action: "users.attachments.upload",
    success: true,
    userId: actorId,
    tenantId,
    meta: { targetUserId, count: files.length },
  });

  const updated = await prisma.user.findFirst({
    where: { id: targetUserId, jewelryId: tenantId, deletedAt: null },
    select: {
      id: true,
      email: true,
      name: true,
      status: true,
      tokenVersion: true,
      avatarUrl: true,
      favoriteWarehouseId: true,

      phoneCountry: true,
      phoneNumber: true,
      documentType: true,
      documentNumber: true,
      street: true,
      number: true,
      city: true,
      province: true,
      postalCode: true,
      country: true,
      notes: true,

      createdAt: true,
      updatedAt: true,

      quickPinHash: true,
      quickPinEnabled: true,
      quickPinUpdatedAt: true,

      attachments: {
        select: { id: true, url: true, filename: true, mimeType: true, size: true, createdAt: true },
        orderBy: { createdAt: "desc" },
      },
      roles: {
        select: {
          role: {
            select: { id: true, name: true, isSystem: true, jewelryId: true, deletedAt: true },
          },
        },
      },
      permissionOverrides: { select: { permissionId: true, effect: true } },
    },
  });

  if (!updated) {
    return res.json({ ok: true, createdCount: created.count, user: null });
  }

  type U = typeof updated;
  type UR = U["roles"][number];
  type R = UR["role"];

  return res.json({
    ok: true,
    createdCount: created.count,
    user: {
      ...updated,
      hasQuickPin: Boolean(updated.quickPinHash),
      pinEnabled: Boolean(updated.quickPinHash) && Boolean(updated.quickPinEnabled),
      roles: (updated.roles ?? [])
        .map((ur: UR) => ur.role as R)
        .filter((r: R) => r && r.jewelryId === tenantId && !r.deletedAt)
        .map((r: R) => ({ id: r.id, name: r.name, isSystem: r.isSystem })),
      permissionOverrides: updated.permissionOverrides ?? [],
    },
  });
}
/* =========================
   ✅ GET /users/:id/attachments/:attachmentId/download
   - fuerza descarga (Content-Disposition)
   - valida tenant + ownership
   - ✅ permisos: que los controle la RUTA (VIEW o ADMIN), no acá
========================= */
function safeAsciiFilename(name: string) {
  // fallback simple para filename=""
  return (
    String(name || "archivo")
      .replace(/[\r\n"]/g, "") // evita header injection / comillas
      .replace(/[\/\\]/g, "_") // evita paths
      .trim() || "archivo"
  );
}

function contentDisposition(filename: string) {
  const fallback = safeAsciiFilename(filename);
  const utf8 = encodeURIComponent(String(filename || fallback));
  // filename* (RFC5987) + fallback ascii
  return `attachment; filename="${fallback}"; filename*=UTF-8''${utf8}`;
}

export async function downloadUserAttachment(req: Request, res: Response) {
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  const actorId = (req as any).userId as string | undefined;

  const targetUserId = String(req.params.id || "").trim();
  const attachmentId = String(req.params.attachmentId || "").trim();

  if (!targetUserId) return res.status(400).json({ message: "ID inválido." });
  if (!attachmentId) return res.status(400).json({ message: "attachmentId inválido." });

  const target = await prisma.user.findFirst({
    where: { id: targetUserId, jewelryId: tenantId, deletedAt: null },
    select: { id: true },
  });
  if (!target) return res.status(404).json({ message: "Usuario no encontrado." });

  const att = await prisma.userAttachment.findFirst({
    where: { id: attachmentId, userId: targetUserId },
    select: { id: true, url: true, filename: true, mimeType: true, size: true },
  });
  if (!att) return res.status(404).json({ message: "Adjunto no encontrado." });

  // Si es URL externa real y NO es un archivo local del backend -> redirect
  if (att.url.startsWith("http://") || att.url.startsWith("https://")) {
    const abs = absLocalUserAttachmentFromUrl(att.url);

    if (!abs) {
      auditLog(req, {
        action: "users.attachments.download",
        success: true,
        userId: actorId,
        tenantId,
        meta: { targetUserId, attachmentId, mode: "redirect" },
      });
      return res.redirect(att.url);
    }

    if (!fsSync.existsSync(abs)) {
      return res.status(404).json({ message: "Archivo no encontrado en disco." });
    }

    const stat = fsSync.statSync(abs);

    res.setHeader("Content-Type", att.mimeType || "application/octet-stream");
    res.setHeader("Content-Length", String(att.size || stat.size));
    res.setHeader("Content-Disposition", contentDisposition(att.filename || "archivo"));

    auditLog(req, {
      action: "users.attachments.download",
      success: true,
      userId: actorId,
      tenantId,
      meta: { targetUserId, attachmentId, mode: "local" },
    });

    return fsSync.createReadStream(abs).pipe(res);
  }

  // robustez por si algún día guardás path relativo
  const abs = absLocalUserAttachmentFromUrl(att.url);
  if (!abs) return res.status(400).json({ message: "URL de adjunto inválida." });
  if (!fsSync.existsSync(abs)) return res.status(404).json({ message: "Archivo no encontrado en disco." });

  const stat = fsSync.statSync(abs);

  res.setHeader("Content-Type", att.mimeType || "application/octet-stream");
  res.setHeader("Content-Length", String(att.size || stat.size));
  res.setHeader("Content-Disposition", contentDisposition(att.filename || "archivo"));

  auditLog(req, {
    action: "users.attachments.download",
    success: true,
    userId: actorId,
    tenantId,
    meta: { targetUserId, attachmentId, mode: "local" },
  });

  return fsSync.createReadStream(abs).pipe(res);
}

export async function deleteUserAttachment(req: Request, res: Response) {
  const actorId = (req as any).userId as string;
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  if (!requireAdminUsersRoles(req, res)) return;

  const targetUserId = String(req.params.id || "").trim();
  const attachmentId = String(req.params.attachmentId || "").trim();

  if (!targetUserId) return res.status(400).json({ message: "ID inválido." });
  if (!attachmentId) return res.status(400).json({ message: "attachmentId inválido." });

  const target = await prisma.user.findFirst({
    where: { id: targetUserId, jewelryId: tenantId, deletedAt: null },
    select: { id: true },
  });
  if (!target) return res.status(404).json({ message: "Usuario no encontrado." });

  const att = await prisma.userAttachment.findFirst({
    where: { id: attachmentId, userId: targetUserId },
    select: { id: true, url: true },
  });
  if (!att) return res.status(404).json({ message: "Adjunto no encontrado." });

  await prisma.userAttachment.delete({ where: { id: att.id } });

  if (targetUserId !== actorId) {
    await prisma.user.update({
      where: { id: targetUserId },
      data: { tokenVersion: { increment: 1 } },
    });
  }

  await safeDeleteByUrlIfLocalUserAttachment(att.url);

  auditLog(req, {
    action: "users.attachments.delete",
    success: true,
    userId: actorId,
    tenantId,
    meta: { targetUserId, attachmentId },
  });

  return res.json({ ok: true });
}
