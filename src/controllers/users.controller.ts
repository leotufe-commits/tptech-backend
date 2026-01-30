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

function requireAdminUsersRoles(req: Request, res: Response): boolean {
  const perms = ((req as any).permissions ?? []) as unknown[];
  if (!Array.isArray(perms) || !perms.includes("USERS_ROLES:ADMIN")) {
    res.status(403).json({ message: "No tenés permisos para realizar esta acción." });
    return false;
  }
  return true;
}
async function countUserOverrides(userId: string) {
  return prisma.userPermissionOverride.count({ where: { userId } });
}


/* =========================
   ✅ QUICK PIN (ME)
   PUT /users/me/quick-pin
   body: { pin: "1234", currentPin?: "0000" }

   ⚠️ IMPORTANTE:
   Antes incrementabas tokenVersion acá => eso invalida el JWT/cookie y te “expira sesión”.
   El PIN no debería cerrar sesión, así que NO tocamos tokenVersion.
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

  // Si ya tenía PIN, validar currentPin antes de cambiarlo
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
   body: { currentPin: "1234" }

   ⚠️ NO tocamos tokenVersion (evita “sesión expirada”)
========================= */
export async function removeMyQuickPin(req: Request, res: Response) {
  const actorId = (req as any).userId as string;
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  const { currentPin } = req.body as { currentPin?: string };

  const me = await prisma.user.findFirst({
    where: { id: actorId, jewelryId: tenantId, deletedAt: null },
    select: { id: true, quickPinHash: true, quickPinEnabled: true },
  });

  if (!me) return res.status(404).json({ message: "Usuario no encontrado." });

  if (!me.quickPinHash) {
    return res.json({ ok: true, hasQuickPin: false, pinEnabled: false });
  }

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
   ✅ QUICK PIN (ADMIN)
   PUT /users/:id/quick-pin
   body: { pin: "1234" }

   ⚠️ NO tocamos tokenVersion (evita cerrar sesión del usuario por setear PIN)
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
   ✅ QUICK PIN (ADMIN)
   DELETE /users/:id/quick-pin

   ⚠️ NO tocamos tokenVersion
   ✅ Si tiene permisos especiales, exige confirmación y los borra
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

  const overridesCount = await countUserOverrides(targetUserId);

  if (overridesCount > 0 && confirmRemoveOverrides !== true) {
    return res.status(409).json({
      code: "HAS_SPECIAL_PERMISSIONS",
      message:
        "Este usuario tiene permisos especiales asignados. Si continuás, se borrarán esos permisos.",
      overridesCount,
      requireConfirmRemoveOverrides: true,
    });
  }

  const updated = await prisma.$transaction(async (tx: Prisma.TransactionClient) => {
    if (overridesCount > 0) {
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
      overridesCleared: overridesCount > 0,
      overridesCount,
    },
  });

  return res.json({
    ok: true,
    hasQuickPin: Boolean(updated.quickPinHash),
    pinEnabled: Boolean(updated.quickPinEnabled),
    quickPinUpdatedAt: updated.quickPinUpdatedAt,
    overridesCleared: overridesCount > 0,
    overridesCount,
  });
}


/* =========================
   ✅ QUICK PIN ENABLED (ADMIN)
   PATCH /users/:id/quick-pin/enabled
   body: { enabled: boolean }

   ⚠️ NO tocamos tokenVersion (evita “sesión expirada” por habilitar/deshabilitar)
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

  // ✅ Si se está DESHABILITANDO el PIN y hay permisos especiales -> exigir confirmación
  let overridesCount = 0;
  if (enabledRaw === false) {
    overridesCount = await countUserOverrides(targetUserId);

    if (overridesCount > 0 && confirmRemoveOverrides !== true) {
      return res.status(409).json({
        code: "HAS_SPECIAL_PERMISSIONS",
        message:
          "Este usuario tiene permisos especiales asignados. Si continuás, se borrarán esos permisos.",
        overridesCount,
        requireConfirmRemoveOverrides: true,
      });
    }
  }

  const updated = await prisma.$transaction(async (tx: Prisma.TransactionClient) => {
    if (enabledRaw === false && overridesCount > 0) {
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
      overridesCleared: enabledRaw === false && overridesCount > 0,
      overridesCount: enabledRaw === false ? overridesCount : undefined,
    },
  });

  return res.json({
    ok: true,
    hasQuickPin: Boolean(updated.quickPinHash),
    pinEnabled: Boolean(updated.quickPinHash) && Boolean(updated.quickPinEnabled),
    overridesCleared: enabledRaw === false && overridesCount > 0,
    overridesCount: enabledRaw === false ? overridesCount : undefined,
  });
}

/* =========================
   POST /users
   Crear usuario (ADMIN)
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
    where: {
      jewelryId: tenantId,
      email,
    },
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
      return res.status(400).json({
        message: "Uno o más roles no son válidos para esta joyería.",
      });
    }
  }

  const passwordHash = hasPassword
    ? await bcrypt.hash(String(body.password), 10)
    : await randomPasswordHash();

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
        role: {
          select: { id: true, name: true, isSystem: true, jewelryId: true, deletedAt: true },
        },
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

        // ✅ contadores livianos para la tabla
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

      // ✅ lo que necesita la tabla
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
   ⚠️ FIX: NO invalidar sesión del propio usuario por editar datos de perfil.
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

  // ✅ Solo invalidar sesiones si estoy editando a OTRA persona (opcional).
  // Para "mi usuario", NO tocamos tokenVersion (evita “sesión expirada”).
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
      tokenVersion: { increment: 1 },
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

  const cleanId =
    typeof warehouseId === "string" ? warehouseId.trim() : warehouseId === null ? null : undefined;

  if (cleanId === "") {
    return res.status(400).json({ message: "warehouseId inválido." });
  }

  if (cleanId) {
    const wh = await prisma.warehouse.findFirst({
      where: { id: cleanId, jewelryId: tenantId, isActive: true },
      select: { id: true },
    });

    if (!wh) {
      return res
        .status(404)
        .json({ message: "Almacén no encontrado (o no pertenece a esta joyería)." });
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

  const cleanId =
    typeof warehouseId === "string" ? warehouseId.trim() : warehouseId === null ? null : undefined;

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
      return res
        .status(404)
        .json({ message: "Almacén no encontrado (o no pertenece a esta joyería)." });
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

  const updated = await prisma.user.update({
    where: { id: targetUserId },
    data: { avatarUrl, tokenVersion: { increment: 1 } },
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

  const updated = await prisma.user.update({
    where: { id: targetUserId },
    data: { avatarUrl: null, tokenVersion: { increment: 1 } },
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

  const files = ((req as any).files ?? []) as Array<{
    filename: string;
    originalname?: string;
    mimetype?: string;
    size?: number;
  }>;

  if (!Array.isArray(files) || files.length === 0) {
    return res.status(400).json({ message: "No se recibieron archivos (field: attachments)." });
  }

  type F = (typeof files)[number];

  const created = await prisma.userAttachment.createMany({
    data: files.map((f: F) => {
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

  await prisma.user.update({
    where: { id: targetUserId },
    data: { tokenVersion: { increment: 1 } },
    select: { id: true },
  });

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

  await prisma.user.update({
    where: { id: targetUserId },
    data: { tokenVersion: { increment: 1 } },
    select: { id: true },
  });

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
