// tptech-backend/src/controllers/auth.pin.controller.ts
import type { Request, Response } from "express";
import bcrypt from "bcryptjs";

import { prisma } from "../lib/prisma.js";
import { auditLog } from "../lib/auditLogger.js";
import { buildAuthResponse } from "../lib/authResponse.js";
import { UserStatus } from "@prisma/client";

import { signToken, setAuthCookie, fetchUserForAuthById } from "./auth.base.controller.js";

/* =========================
   PIN / QUICK SWITCH
========================= */
const isValidPin = (pin: unknown) => /^\d{4}$/.test(String(pin ?? "").trim());

const PIN_MAX_FAILED = 5;
const PIN_LOCK_MINUTES = 5;

const lockUntilDate = () => new Date(Date.now() + PIN_LOCK_MINUTES * 60 * 1000);
const isLocked = (lockedUntil: Date | null | undefined) =>
  !!lockedUntil && lockedUntil.getTime() > Date.now();
const lockPayload = (lockedUntil: Date) => ({
  message: "PIN bloqueado. Intentá nuevamente más tarde.",
  code: "PIN_LOCKED",
  lockedUntil,
});

async function requireActiveMe(req: Request) {
  const userId = (req as any).userId as string | undefined;
  if (!userId) return null;

  const meUser = await prisma.user.findUnique({
    where: { id: userId },
    select: {
      id: true,
      status: true,
      jewelryId: true,
      quickPinHash: true,
      quickPinEnabled: true,
      quickPinUpdatedAt: true,
      quickPinFailedCount: true,
      quickPinLockedUntil: true,
      tokenVersion: true,
    },
  });

  if (!meUser) return null;
  if (meUser.status !== UserStatus.ACTIVE) return null;
  return meUser as any;
}

async function isQuickSwitchEnabled(jewelryId: string) {
  try {
    const j = await prisma.jewelry.findUnique({
      where: { id: jewelryId },
      select: { quickSwitchEnabled: true } as any,
    });
    return !!(j as any)?.quickSwitchEnabled;
  } catch {
    return false;
  }
}

async function recordPinFailure(args: {
  userId: string;
  tenantId: string;
  action: string;
  meta?: any;
}) {
  const u = await prisma.user.update({
    where: { id: args.userId },
    data: { quickPinFailedCount: { increment: 1 } },
    select: { quickPinFailedCount: true },
  });

  const failed = Number((u as any).quickPinFailedCount ?? 0);
  if (failed >= PIN_MAX_FAILED) {
    const lockedUntil = lockUntilDate();
    await prisma.user.update({
      where: { id: args.userId },
      data: { quickPinLockedUntil: lockedUntil, quickPinUpdatedAt: new Date() },
    });

    auditLog({} as any, {
      action: args.action,
      success: false,
      userId: args.userId,
      tenantId: args.tenantId,
      meta: { ...(args.meta ?? {}), reason: "pin_locked", lockedUntil, failed },
    });

    return { locked: true as const, lockedUntil };
  }

  return { locked: false as const, failed };
}

async function clearPinFailures(userId: string) {
  await prisma.user.update({
    where: { id: userId },
    data: {
      quickPinFailedCount: 0,
      quickPinLockedUntil: null,
      quickPinUpdatedAt: new Date(),
    },
  });
}

/* =========================
   ENDPOINTS
========================= */
export async function setMyPin(req: Request, res: Response) {
  const meUser = await requireActiveMe(req);
  if (!meUser) return res.status(401).json({ message: "Unauthorized" });

  const pin = String((req.body as any)?.pin ?? "").trim();
  if (!isValidPin(pin))
    return res.status(400).json({ message: "El PIN debe tener 4 dígitos." });

  const quickPinHash = await bcrypt.hash(pin, 10);

  const updated = await prisma.user.update({
    where: { id: meUser.id },
    data: {
      quickPinHash,
      quickPinEnabled: true,
      quickPinUpdatedAt: new Date(),
      quickPinFailedCount: 0,
      quickPinLockedUntil: null,
      tokenVersion: { increment: 1 },
    },
    select: { id: true, jewelryId: true, tokenVersion: true },
  });

  const token = signToken(updated.id, updated.jewelryId, updated.tokenVersion);
  setAuthCookie(req, res, token);

  auditLog(req, {
    action: "auth.pin_set",
    success: true,
    userId: updated.id,
    tenantId: updated.jewelryId,
  });
  return res.json({ ok: true });
}

export async function disableMyPin(req: Request, res: Response) {
  const meUser = await requireActiveMe(req);
  if (!meUser) return res.status(401).json({ message: "Unauthorized" });

  const pin = String((req.body as any)?.pin ?? "").trim();
  if (!isValidPin(pin)) return res.status(400).json({ message: "PIN inválido." });

  if (!meUser.quickPinEnabled || !meUser.quickPinHash)
    return res.status(400).json({ message: "El PIN no está habilitado." });
  if (isLocked(meUser.quickPinLockedUntil as any))
    return res.status(429).json(lockPayload(meUser.quickPinLockedUntil as any));

  const ok = await bcrypt.compare(pin, String(meUser.quickPinHash));
  if (!ok) {
    const r = await recordPinFailure({
      userId: meUser.id,
      tenantId: meUser.jewelryId,
      action: "auth.pin_disable",
      meta: { reason: "invalid_pin" },
    });
    if (r.locked) return res.status(429).json(lockPayload(r.lockedUntil));

    auditLog(req, {
      action: "auth.pin_disable",
      success: false,
      userId: meUser.id,
      tenantId: meUser.jewelryId,
      meta: { reason: "invalid_pin", failed: r.failed },
    });
    return res.status(401).json({ message: "PIN incorrecto." });
  }

  const updated = await prisma.user.update({
    where: { id: meUser.id },
    data: {
      quickPinHash: null,
      quickPinEnabled: false,
      quickPinUpdatedAt: new Date(),
      quickPinFailedCount: 0,
      quickPinLockedUntil: null,
      tokenVersion: { increment: 1 },
    },
    select: { id: true, jewelryId: true, tokenVersion: true },
  });

  const token = signToken(updated.id, updated.jewelryId, updated.tokenVersion);
  setAuthCookie(req, res, token);

  auditLog(req, {
    action: "auth.pin_disable",
    success: true,
    userId: updated.id,
    tenantId: updated.jewelryId,
  });
  return res.json({ ok: true });
}

export async function unlockWithPin(req: Request, res: Response) {
  const meUser = await requireActiveMe(req);
  if (!meUser) return res.status(401).json({ message: "Unauthorized" });

  const pin = String((req.body as any)?.pin ?? "").trim();
  if (!isValidPin(pin)) return res.status(400).json({ message: "PIN inválido." });

  if (!meUser.quickPinEnabled || !meUser.quickPinHash)
    return res.status(400).json({ message: "Este usuario no tiene PIN configurado." });
  if (isLocked(meUser.quickPinLockedUntil as any))
    return res.status(429).json(lockPayload(meUser.quickPinLockedUntil as any));

  const ok = await bcrypt.compare(pin, String(meUser.quickPinHash));
  if (!ok) {
    const r = await recordPinFailure({
      userId: meUser.id,
      tenantId: meUser.jewelryId,
      action: "auth.pin_unlock",
      meta: { reason: "invalid_pin" },
    });
    if (r.locked) return res.status(429).json(lockPayload(r.lockedUntil));

    auditLog(req, {
      action: "auth.pin_unlock",
      success: false,
      userId: meUser.id,
      tenantId: meUser.jewelryId,
      meta: { reason: "invalid_pin", failed: r.failed },
    });
    return res.status(401).json({ message: "PIN incorrecto." });
  }

  await clearPinFailures(meUser.id);

  auditLog(req, {
    action: "auth.pin_unlock",
    success: true,
    userId: meUser.id,
    tenantId: meUser.jewelryId,
  });
  return res.json({ ok: true });
}

export async function quickUsers(req: Request, res: Response) {
  const meUser = await requireActiveMe(req);
  if (!meUser) return res.status(401).json({ message: "Unauthorized" });

  const enabled = await isQuickSwitchEnabled(meUser.jewelryId);
  if (!enabled) return res.json({ enabled: false, users: [] });

  const users = await prisma.user.findMany({
    where: { jewelryId: meUser.jewelryId, status: UserStatus.ACTIVE, deletedAt: null },
    select: {
      id: true,
      email: true,
      name: true,
      avatarUrl: true,
      quickPinEnabled: true,
      quickPinHash: true,
      roles: { select: { roleId: true, role: { select: { name: true, isSystem: true } } } },
    },
    orderBy: { createdAt: "asc" },
  });

  return res.json({
    enabled: true,
    users: users.map((u: any) => {
      const roles = (u.roles ?? [])
        .map((ur: any) => ({
          id: ur.roleId,
          name: ur.role?.name,
          isSystem: ur.role?.isSystem ?? false,
        }))
        .filter((r: any) => typeof r?.name === "string" && r.name.trim());

      const roleNames = roles.map((r: any) => String(r.name).trim()).filter(Boolean);
      const roleLabel = roleNames.length ? roleNames.join(" • ") : "";

      const hasQuickPin = Boolean(u.quickPinEnabled && u.quickPinHash);
      const pinEnabled = Boolean(u.quickPinEnabled);

      return {
        id: u.id,
        email: u.email,
        name: u.name,
        avatarUrl: u.avatarUrl,
        hasQuickPin,
        pinEnabled,
        hasPin: hasQuickPin,
        roles,
        roleNames,
        roleLabel,
      };
    }),
  });
}

export async function switchUserWithPin(req: Request, res: Response) {
  const meUser = await requireActiveMe(req);
  if (!meUser) return res.status(401).json({ message: "Unauthorized" });

  const j = await prisma.jewelry.findUnique({
    where: { id: meUser.jewelryId },
    select: { quickSwitchEnabled: true, pinLockRequireOnUserSwitch: true } as any,
  });

  const enabled = Boolean((j as any)?.quickSwitchEnabled);
  if (!enabled) return res.status(403).json({ message: "Cambio rápido de usuario deshabilitado." });

  const requireOnUserSwitch =
    typeof (j as any)?.pinLockRequireOnUserSwitch === "boolean"
      ? Boolean((j as any)?.pinLockRequireOnUserSwitch)
      : true;

  const targetUserId = String((req.body as any)?.targetUserId ?? "").trim();
  const pin = String((req.body as any)?.pin ?? "").trim();

  if (!targetUserId) return res.status(400).json({ message: "targetUserId requerido." });
  if (requireOnUserSwitch && !isValidPin(pin))
    return res.status(400).json({ message: "PIN inválido." });

  const target = await fetchUserForAuthById(targetUserId);

  if (!target || target.jewelryId !== meUser.jewelryId || (target as any).deletedAt) {
    auditLog(req, {
      action: "auth.pin_switch",
      success: false,
      userId: meUser.id,
      tenantId: meUser.jewelryId,
      meta: { reason: "target_not_found_or_other_tenant", targetUserId },
    });
    return res.status(404).json({ message: "Usuario no encontrado." });
  }

  if (target.status !== UserStatus.ACTIVE) return res.status(403).json({ message: "Usuario no habilitado." });

  if (requireOnUserSwitch) {
    if (!(target as any).quickPinEnabled || !(target as any).quickPinHash)
      return res.status(400).json({ message: "El usuario seleccionado no tiene PIN configurado." });

    const lockedUntil = (target as any).quickPinLockedUntil as Date | null | undefined;
    if (isLocked(lockedUntil)) return res.status(429).json(lockPayload(lockedUntil as Date));

    const ok = await bcrypt.compare(pin, String((target as any).quickPinHash));
    if (!ok) {
      const r = await recordPinFailure({
        userId: target.id,
        tenantId: target.jewelryId,
        action: "auth.pin_switch",
        meta: { reason: "invalid_pin", targetUserId, fromUserId: meUser.id },
      });
      if (r.locked) return res.status(429).json(lockPayload(r.lockedUntil));

      auditLog(req, {
        action: "auth.pin_switch",
        success: false,
        userId: meUser.id,
        tenantId: meUser.jewelryId,
        meta: { reason: "invalid_pin", targetUserId, failed: r.failed },
      });
      return res.status(401).json({ message: "PIN incorrecto." });
    }

    await clearPinFailures(target.id);
  }

  const token = signToken(target.id, target.jewelryId, target.tokenVersion);
  setAuthCookie(req, res, token);

  auditLog(req, {
    action: "auth.pin_switch",
    success: true,
    userId: target.id,
    tenantId: target.jewelryId,
    meta: { fromUserId: meUser.id, requireOnUserSwitch },
  });

  return res.json(buildAuthResponse({ user: target, token, includeToken: true }));
}

export async function setQuickSwitchForJewelry(req: Request, res: Response) {
  const userId = (req as any).userId as string | undefined;
  const tenantId = (req as any).tenantId as string | undefined;

  if (!userId) return res.status(401).json({ message: "Unauthorized" });
  if (!tenantId) return res.status(400).json({ message: "Tenant no definido." });

  const enabledRaw = (req.body as any)?.enabled ?? (req.body as any)?.quickSwitchEnabled;
  const enabled = enabledRaw === true || enabledRaw === "true" || enabledRaw === 1 || enabledRaw === "1";

  await prisma.jewelry.update({ where: { id: tenantId }, data: { quickSwitchEnabled: enabled } as any });

  auditLog(req, {
    action: "company.security.quick_switch_set",
    success: true,
    userId,
    tenantId,
    meta: { enabled },
  });
  return res.json({ ok: true, enabled });
}

export async function setPinLockSettingsForJewelry(req: Request, res: Response) {
  const userId = (req as any).userId as string | undefined;
  const tenantId = (req as any).tenantId as string | undefined;

  if (!userId) return res.status(401).json({ message: "Unauthorized" });
  if (!tenantId) return res.status(400).json({ message: "Tenant no definido." });

  const body = (req.body ?? {}) as any;
  const data: any = {};
  if (typeof body.pinLockEnabled === "boolean") data.pinLockEnabled = body.pinLockEnabled;
  if (typeof body.pinLockTimeoutSec === "number") data.pinLockTimeoutSec = body.pinLockTimeoutSec;
  if (typeof body.pinLockRequireOnUserSwitch === "boolean")
    data.pinLockRequireOnUserSwitch = body.pinLockRequireOnUserSwitch;
  if (typeof body.quickSwitchEnabled === "boolean") data.quickSwitchEnabled = body.quickSwitchEnabled;

  if (!Object.keys(data).length)
    return res.status(400).json({ message: "No hay campos para actualizar." });

  const updated = await prisma.jewelry.update({
    where: { id: tenantId },
    data: data as any,
    select: {
      pinLockEnabled: true,
      pinLockTimeoutSec: true,
      pinLockRequireOnUserSwitch: true,
      quickSwitchEnabled: true,
    } as any,
  });

  auditLog(req, {
    action: "company.security.pin_lock_set",
    success: true,
    userId,
    tenantId,
    meta: data,
  });

  return res.json({
    ok: true,
    pinLockEnabled: Boolean((updated as any).pinLockEnabled),
    pinLockTimeoutSec: Number((updated as any).pinLockTimeoutSec ?? 300),
    pinLockRequireOnUserSwitch: Boolean((updated as any).pinLockRequireOnUserSwitch),
    quickSwitchEnabled: Boolean((updated as any).quickSwitchEnabled),
  });
}
