// tptech-backend/src/modules/users/users.quickpin.ts
import type { Request, Response } from "express";
import type { Prisma } from "@prisma/client";
import bcrypt from "bcryptjs";
import { prisma } from "../../lib/prisma.js";
import { auditLog } from "../../lib/auditLogger.js";

import { requireTenantId, isValidPin4 } from "./users.helpers.js";
import { requireAdminUsersRoles } from "./users.perms.js";

async function countUserOverrides(userId: string) {
  return prisma.userPermissionOverride.count({ where: { userId } });
}

async function isTargetOwnerUser(tenantId: string, userId: string): Promise<boolean> {
  try {
    const ur = await prisma.userRole.findFirst({
      where: {
        userId,
        role: { jewelryId: tenantId, deletedAt: null, name: "OWNER" },
      },
      select: { userId: true },
    });
    return Boolean(ur);
  } catch {
    return false;
  }
}

async function assertCanRemoveOrDisableQuickPinForTenant(
  tenantId: string,
  targetUserId: string
): Promise<{ ok: true } | { ok: false; code: "LAST_PIN_LOCK_ACTIVE"; message: string }> {
  const jewelry = await prisma.jewelry.findFirst({
    where: { id: tenantId },
    select: { pinLockEnabled: true },
  });

  if (!jewelry?.pinLockEnabled) return { ok: true };

  const countEnabled = await prisma.user.count({
    where: {
      jewelryId: tenantId,
      deletedAt: null,
      quickPinHash: { not: null },
      quickPinEnabled: true,
    },
  });

  if (countEnabled > 1) return { ok: true };

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

/* ============ ME ============ */
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
    // ✅ FIX: pinEnabled debe depender de hash + enabled
    pinEnabled: Boolean(updated.quickPinHash) && Boolean(updated.quickPinEnabled),
    quickPinUpdatedAt: updated.quickPinUpdatedAt,
  });
}

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

  const gate = await assertCanRemoveOrDisableQuickPinForTenant(tenantId, actorId);
  if (!gate.ok) return res.status(409).json({ code: gate.code, message: gate.message });

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
    // ✅ FIX: pinEnabled debe depender de hash + enabled
    pinEnabled: Boolean(updated.quickPinHash) && Boolean(updated.quickPinEnabled),
    quickPinUpdatedAt: updated.quickPinUpdatedAt,
  });
}

/* ============ ADMIN ============ */
export async function updateUserQuickPin(req: Request, res: Response) {
  const actorId = (req as any).userId as string;
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;
  if (!requireAdminUsersRoles(req, res)) return;

  const targetUserId = String(req.params.id || "").trim();
  if (!targetUserId) return res.status(400).json({ message: "ID inválido." });

  const { pin } = req.body as { pin?: string };
  if (!isValidPin4(pin)) return res.status(400).json({ message: "El PIN debe tener exactamente 4 dígitos." });

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
    // ✅ FIX: pinEnabled debe depender de hash + enabled
    pinEnabled: Boolean(updated.quickPinHash) && Boolean(updated.quickPinEnabled),
    quickPinUpdatedAt: updated.quickPinUpdatedAt,
  });
}

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

  const gate = await assertCanRemoveOrDisableQuickPinForTenant(tenantId, targetUserId);
  if (!gate.ok) return res.status(409).json({ code: gate.code, message: gate.message, targetUserId });

  const targetIsOwner = await isTargetOwnerUser(tenantId, targetUserId);
  const overridesCount = await countUserOverrides(targetUserId);

  if (!targetIsOwner && overridesCount > 0 && confirmRemoveOverrides !== true) {
    return res.status(409).json({
      code: "HAS_SPECIAL_PERMISSIONS",
      message: "Este usuario tiene permisos especiales asignados. Si continuás, se borrarán esos permisos.",
      overridesCount,
      requireConfirmRemoveOverrides: true,
    });
  }

  const updated = await prisma.$transaction(async (tx: Prisma.TransactionClient) => {
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
    // ✅ FIX: pinEnabled debe depender de hash + enabled (aunque acá queda false igual)
    pinEnabled: Boolean(updated.quickPinHash) && Boolean(updated.quickPinEnabled),
    quickPinUpdatedAt: updated.quickPinUpdatedAt,
    overridesCleared: !targetIsOwner && overridesCount > 0,
    overridesCount,
    targetIsOwner,
  });
}

export async function updateUserQuickPinEnabled(req: Request, res: Response) {
  const actorId = (req as any).userId as string;
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;
  if (!requireAdminUsersRoles(req, res)) return;

  const targetUserId = String(req.params.id || "").trim();
  if (!targetUserId) return res.status(400).json({ message: "ID inválido." });

  const enabledRaw = (req.body as any)?.enabled;
  const confirmRemoveOverrides = Boolean((req.body as any)?.confirmRemoveOverrides);

  if (typeof enabledRaw !== "boolean") return res.status(400).json({ message: "enabled debe ser boolean." });

  const target = await prisma.user.findFirst({
    where: { id: targetUserId, jewelryId: tenantId, deletedAt: null },
    select: { id: true, quickPinHash: true, quickPinEnabled: true },
  });
  if (!target) return res.status(404).json({ message: "Usuario no encontrado." });

  if (enabledRaw === true && !target.quickPinHash) {
    return res.status(400).json({ message: "El usuario no tiene PIN definido. Definilo primero." });
  }

  if (enabledRaw === false) {
    const gate = await assertCanRemoveOrDisableQuickPinForTenant(tenantId, targetUserId);
    if (!gate.ok) return res.status(409).json({ code: gate.code, message: gate.message, targetUserId });
  }

  const targetIsOwner = await isTargetOwnerUser(tenantId, targetUserId);

  let overridesCount = 0;
  if (enabledRaw === false) {
    overridesCount = await countUserOverrides(targetUserId);

    if (!targetIsOwner && overridesCount > 0 && confirmRemoveOverrides !== true) {
      return res.status(409).json({
        code: "HAS_SPECIAL_PERMISSIONS",
        message: "Este usuario tiene permisos especiales asignados. Si continuás, se borrarán esos permisos.",
        overridesCount,
        requireConfirmRemoveOverrides: true,
      });
    }
  }

  const updated = await prisma.$transaction(async (tx: Prisma.TransactionClient) => {
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
