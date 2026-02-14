// tptech-backend/src/modules/users/users.core.ts
import type { Request, Response } from "express";
import type { Prisma } from "@prisma/client";
import { UserStatus } from "@prisma/client";
import bcrypt from "bcryptjs";
import crypto from "node:crypto";
import path from "node:path";
import fs from "node:fs/promises";

import { signResetToken, buildResetLink } from "../../lib/authTokens.js";
import { sendResetEmail } from "../../lib/mailer.js";

import { prisma } from "../../lib/prisma.js";
import { auditLog } from "../../lib/auditLogger.js";

import {
  requireTenantId,
  uniqStrings,
  normalizeEmail,
  normalizeName,
  normOpt,
  normStr,
  clampInt,
  toPublicUrl,
  filenameFromAnyUrl,
  isValidUserStatus,
  isValidOverrideEffect,
} from "./users.helpers.js";

/* =========================
   Helpers internos
========================= */

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

function mapRolesForTenant(tenantId: string, roles: any[] | undefined) {
  type UR = { role?: any };
  const rr = (roles ?? []) as UR[];

  return rr
    .map((ur) => ur.role)
    .filter((r) => r && r.jewelryId === tenantId && !r.deletedAt)
    .map((r) => ({ id: r.id, name: r.name, isSystem: r.isSystem }));
}

/* ✅ IP helper (proxy-friendly) */
function getReqIp(req: Request) {
  const xf = String(req.headers["x-forwarded-for"] || "").split(",")[0]?.trim();
  return xf || (req.socket?.remoteAddress ? String(req.socket.remoteAddress) : undefined);
}

/* ✅ Limpieza/higiene de tokens reset/invite */
async function cleanupResetAuthTokens() {
  try {
    await prisma.authToken.deleteMany({
      where: {
        type: "reset",
        OR: [{ expiresAt: { lt: new Date() } }, { usedAt: { not: null } }],
      },
    });
  } catch {
    // ignore
  }
}

/* =========================
   GET /users
   paginado + search
   incluye attachmentsCount + overridesCount
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

  return res.json({
    page,
    limit,
    total,
    users: users.map((u) => ({
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

      roles: mapRolesForTenant(tenantId, u.roles as any),

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

  return res.json({
    user: {
      ...user,
      hasQuickPin: Boolean(user.quickPinHash),
      pinEnabled: Boolean(user.quickPinHash) && Boolean(user.quickPinEnabled),
      roles: mapRolesForTenant(tenantId, user.roles as any),
      permissionOverrides: user.permissionOverrides ?? [],
      attachments: user.attachments ?? [],
    },
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
    name?: string | null;
    password?: string;
    roleIds?: string[];
    status?: "ACTIVE" | "BLOCKED" | "PENDING";
  };

  const email = normalizeEmail(body.email);
  const name = normalizeName(body.name);

  if (!email) return res.status(400).json({ message: "Email inválido." });

  let roleIds = Array.isArray(body.roleIds) ? body.roleIds : [];
  roleIds = uniqStrings(roleIds.map((r) => String(r || "").trim()).filter(Boolean));

  const hasPassword = Boolean(String(body.password || "").trim());
  const desiredStatus = body.status ? String(body.status) : undefined;

  const status: UserStatus =
    desiredStatus === "BLOCKED"
      ? UserStatus.BLOCKED
      : desiredStatus === "PENDING"
      ? UserStatus.PENDING
      : desiredStatus === "ACTIVE"
      ? UserStatus.ACTIVE
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
        data: roleIds.map((roleId) => ({ userId: user.id, roleId })),
        skipDuplicates: true,
      });
    }

    const roles = await tx.userRole.findMany({
      where: { userId: user.id },
      select: {
        role: { select: { id: true, name: true, isSystem: true, jewelryId: true, deletedAt: true } },
      },
    });

    return {
      ...user,
      roles: mapRolesForTenant(tenantId, roles as any),
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
   PATCH /users/:id (ADMIN)
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

  // ✅ invalidar tokens si editás a otro usuario
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
   PATCH /users/:id/status (ADMIN)
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
    data: { status: raw },
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
   PUT /users/:id/roles (ADMIN)
========================= */
export async function assignRolesToUser(req: Request, res: Response) {
  const actorId = (req as any).userId as string;
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  const targetUserId = String(req.params.id || "").trim();
  let { roleIds } = req.body as { roleIds: string[] };

  if (!targetUserId) return res.status(400).json({ message: "ID inválido." });
  if (!Array.isArray(roleIds)) return res.status(400).json({ message: "roleIds debe ser un array" });

  roleIds = uniqStrings(roleIds.map((r) => String(r || "").trim()).filter(Boolean));

  if (targetUserId === actorId) {
    return res.status(400).json({ message: "No podés cambiar tus propios roles desde aquí." });
  }

  const target = await prisma.user.findFirst({
    where: { id: targetUserId, jewelryId: tenantId, deletedAt: null },
    select: { id: true },
  });
  if (!target) return res.status(404).json({ message: "Usuario no encontrado." });

  const roles = await prisma.role.findMany({
    where: { id: { in: roleIds }, jewelryId: tenantId, deletedAt: null },
    select: { id: true },
  });

  if (roles.length !== roleIds.length) {
    return res.status(400).json({ message: "Uno o más roles no son válidos para esta joyería." });
  }

  await prisma.$transaction(async (tx: Prisma.TransactionClient) => {
    await tx.userRole.deleteMany({ where: { userId: targetUserId } });

    if (roleIds.length) {
      await tx.userRole.createMany({
        data: roleIds.map((roleId) => ({ userId: targetUserId, roleId })),
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
   POST /users/:id/overrides (ADMIN)
========================= */
export async function setUserOverride(req: Request, res: Response) {
  const actorId = (req as any).userId as string;
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  const targetUserId = String(req.params.id || "").trim();
  const { permissionId, effect } = req.body as { permissionId: string; effect: "ALLOW" | "DENY" };

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
    where: { userId_permissionId: { userId: targetUserId, permissionId } },
    create: { userId: targetUserId, permissionId, effect },
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
   DELETE /users/:id/overrides/:permissionId (ADMIN)
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
   PATCH /users/me/favorite-warehouse
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

  if (cleanId === "") return res.status(400).json({ message: "warehouseId inválido." });

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
   PATCH /users/:id/favorite-warehouse
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

  if (cleanId === "") return res.status(400).json({ message: "warehouseId inválido." });

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
   PUT /users/me/avatar
   DELETE /users/me/avatar
========================= */
export async function updateMyAvatar(req: Request, res: Response) {
  const actorId = (req as any).userId as string;
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  const file = (req as any).file as Express.Multer.File | undefined;
  if (!file) return res.status(400).json({ message: "Falta archivo avatar (multipart field: avatar)." });

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
   PUT /users/:id/avatar
   DELETE /users/:id/avatar
========================= */
export async function updateUserAvatarForUser(req: Request, res: Response) {
  const actorId = (req as any).userId as string;
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  const targetUserId = String(req.params.id || "").trim();
  if (!targetUserId) return res.status(400).json({ message: "ID inválido." });

  const file = (req as any).file as Express.Multer.File | undefined;
  if (!file) return res.status(400).json({ message: "Falta archivo avatar (multipart field: avatar)." });

  const prev = await prisma.user.findFirst({
    where: { id: targetUserId, jewelryId: tenantId, deletedAt: null },
    select: { avatarUrl: true, id: true },
  });
  if (!prev) return res.status(404).json({ message: "Usuario no encontrado." });

  const avatarRelative = `/uploads/avatars/${file.filename}`;
  const avatarUrl = toPublicUrl(avatarRelative);

  const data: any = { avatarUrl };
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
   DELETE /users/:id (ADMIN) - soft delete
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
    await tx.userAttachment.deleteMany({ where: { userId: targetUserId } });

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
   INVITE (ADMIN) - single-use real
   POST /users/:id/invite
========================= */
export async function sendUserInvite(req: Request, res: Response) {
  const actorId = (req as any).userId as string;
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  const targetUserId = String(req.params.id || "").trim();
  if (!targetUserId) return res.status(400).json({ message: "ID inválido." });

  const user = await prisma.user.findFirst({
    where: { id: targetUserId, jewelryId: tenantId, deletedAt: null },
    select: { id: true, email: true, status: true, jewelryId: true },
  });

  if (!user) return res.status(404).json({ message: "Usuario no encontrado." });

  // ✅ seguridad de negocio: invitación solo para PENDING (evita spam a activos / bloqueados)
  if (user.status !== UserStatus.PENDING) {
    auditLog(req, {
      action: "users.invite_send",
      success: false,
      userId: actorId,
      tenantId,
      meta: { targetUserId: user.id, email: user.email, status: user.status, reason: "not_pending" },
    });
    return res.status(400).json({ message: "La invitación solo está disponible para usuarios Pendiente." });
  }

  // higiene: limpiezas viejas
  await cleanupResetAuthTokens();

  const jti = crypto.randomUUID();
  const resetToken = signResetToken(user.id, jti, "7d"); // invitación válida 7 días
  const resetLink = buildResetLink(resetToken);

  // ✅ single-use real: guardamos registro en DB con expiración (7 días)
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

  try {
    await prisma.authToken.create({
      data: {
        type: "reset",
        jti,
        userId: user.id,
        expiresAt,
        emailSnapshot: user.email,
        ip: getReqIp(req),
        userAgent: String(req.headers["user-agent"] || ""),
      },
      select: { id: true },
    });
  } catch {
    auditLog(req, {
      action: "users.invite_send",
      success: false,
      userId: actorId,
      tenantId,
      meta: { targetUserId: user.id, email: user.email, status: user.status, jti, reason: "authtoken_create_failed" },
    });
    return res.status(500).json({ message: "No se pudo generar la invitación." });
  }

  try {
    await sendResetEmail(user.email, resetLink);
  } catch (e: any) {
    auditLog(req, {
      action: "users.invite_send",
      success: false,
      userId: actorId,
      tenantId,
      meta: { targetUserId: user.id, email: user.email, status: user.status, jti, reason: "mailer_failed" },
    });
    return res.status(500).json({ message: e?.message || "No se pudo enviar la invitación." });
  }

  auditLog(req, {
    action: "users.invite_send",
    success: true,
    userId: actorId,
    tenantId,
    meta: { targetUserId: user.id, email: user.email, status: user.status, jti },
  });

  // ✅ DEV: devolvemos link para test manual si querés (sin exponer en producción)
  const isDev = String(process.env.NODE_ENV || "").toLowerCase() !== "production";
  return res.json(isDev ? { ok: true, devLink: resetLink } : { ok: true });
}
