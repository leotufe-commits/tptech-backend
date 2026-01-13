// tptech-backend/src/controllers/users.controller.ts
import type { Request, Response } from "express";
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
  const tenantId = req.tenantId;
  if (!tenantId) {
    res.status(400).json({ message: "Tenant no definido en el request." });
    return null;
  }
  return tenantId;
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

async function safeDeleteOldAvatar(avatarUrl: string | null) {
  if (!avatarUrl) return;

  let pathname = avatarUrl;
  try {
    if (avatarUrl.startsWith("http://") || avatarUrl.startsWith("https://")) {
      pathname = new URL(avatarUrl).pathname;
    }
  } catch {
    pathname = avatarUrl;
  }

  if (!pathname.includes("/uploads/avatars/")) return;

  const local = pathname.replace(/^\/+/, "");
  try {
    await fs.unlink(local);
  } catch {
    // ignore
  }
}

/** hash random para usuarios PENDING (evita guardar password vacío) */
async function randomPasswordHash() {
  const raw = crypto.randomBytes(24).toString("hex");
  return bcrypt.hash(raw, 10);
}

/* =========================
   POST /users
   Crear usuario (ADMIN)
========================= */
export async function createUser(req: Request, res: Response) {
  const actorId = req.userId!;
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  const body = req.body as {
    email: string;
    name?: string;
    password?: string;
    roleIds?: string[];
    status?: "ACTIVE" | "BLOCKED";
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
      : hasPassword
        ? UserStatus.ACTIVE
        : UserStatus.PENDING;

  // email global único
  const existing = await prisma.user.findUnique({
    where: { email },
    select: { id: true },
  });

  if (existing) {
    auditLog(req, {
      action: "users.create",
      success: false,
      userId: actorId,
      tenantId,
      meta: { email, reason: "email_already_exists" },
    });
    return res.status(409).json({ message: "El email ya está registrado." });
  }

  // validar roles (tenant)
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

  const created = await prisma.$transaction(async (tx) => {
    const user = await tx.user.create({
      data: {
        email,
        name,
        status,
        jewelryId: tenantId,
        password: passwordHash,
        tokenVersion: 0,
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

    // roles (filtrados por tenant)
    const roles = await tx.userRole.findMany({
      where: { userId: user.id },
      select: {
        role: { select: { id: true, name: true, isSystem: true, jewelryId: true, deletedAt: true } },
      },
    });

    return {
      ...user,
      roles: roles
        .map((ur) => ur.role)
        .filter((r) => r && r.jewelryId === tenantId && !r.deletedAt)
        .map((r) => ({ id: r.id, name: r.name, isSystem: r.isSystem })),
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
   Query:
   - q (email/nombre)
   - status (ACTIVE/BLOCKED/PENDING)
   - page (1..)
   - limit (1..100)
========================= */
export async function listUsers(req: Request, res: Response) {
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  const q = String((req.query.q ?? "") as any).trim();
  const status = String((req.query.status ?? "") as any).trim().toUpperCase();
  const page = clampInt(req.query.page, 1, 1, 10_000);
  const limit = clampInt(req.query.limit, 30, 1, 100);
  const skip = (page - 1) * limit;

  const where: any = { jewelryId: tenantId };

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
        roles: {
          select: {
            role: {
              select: { id: true, name: true, isSystem: true, jewelryId: true, deletedAt: true },
            },
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
      roles: (u.roles ?? [])
        .map((ur) => ur.role)
        .filter((r) => r && r.jewelryId === tenantId && !r.deletedAt)
        .map((r) => ({ id: r.id, name: r.name, isSystem: r.isSystem })),
    })),
  });
}

/* =========================
   GET /users/:id
   ✅ DETALLE (incluye overrides)
========================= */
export async function getUser(req: Request, res: Response) {
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  const targetUserId = String(req.params.id || "").trim();
  if (!targetUserId) return res.status(400).json({ message: "ID inválido." });

  const user = await prisma.user.findFirst({
    where: { id: targetUserId, jewelryId: tenantId },
    select: {
      id: true,
      email: true,
      name: true,
      status: true,
      avatarUrl: true,
      favoriteWarehouseId: true,
      createdAt: true,
      updatedAt: true,
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
    },
  });

  if (!user) return res.status(404).json({ message: "Usuario no encontrado." });

  return res.json({
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
      status: user.status,
      avatarUrl: user.avatarUrl,
      favoriteWarehouseId: user.favoriteWarehouseId,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
      roles: (user.roles ?? [])
        .map((ur) => ur.role)
        .filter((r) => r && r.jewelryId === tenantId && !r.deletedAt)
        .map((r) => ({ id: r.id, name: r.name, isSystem: r.isSystem })),
      permissionOverrides: user.permissionOverrides ?? [],
    },
  });
}

/* =========================
   PATCH /users/:id/status
========================= */
export async function updateUserStatus(req: Request, res: Response) {
  const actorId = req.userId!;
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  const targetUserId = String(req.params.id || "").trim();
  const { status } = req.body as { status: UserStatus };

  if (!targetUserId) return res.status(400).json({ message: "ID inválido." });

  if (targetUserId === actorId) {
    return res.status(400).json({ message: "No podés cambiar tu propio estado desde aquí." });
  }

  const target = await prisma.user.findFirst({
    where: { id: targetUserId, jewelryId: tenantId },
    select: { id: true },
  });

  if (!target) return res.status(404).json({ message: "Usuario no encontrado." });

  const updated = await prisma.user.update({
    where: { id: targetUserId },
    data: {
      status,
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
    meta: { targetUserId, status },
  });

  return res.json({ user: updated });
}

/* =========================
   PUT /users/:id/roles
========================= */
export async function assignRolesToUser(req: Request, res: Response) {
  const actorId = req.userId!;
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  const targetUserId = String(req.params.id || "").trim();
  let { roleIds } = req.body as { roleIds: string[] };

  if (!targetUserId) return res.status(400).json({ message: "ID inválido." });

  if (!Array.isArray(roleIds)) {
    return res.status(400).json({ message: "roleIds debe ser un array" });
  }

  roleIds = uniqStrings(roleIds.map((r) => String(r || "").trim()).filter(Boolean));

  if (targetUserId === actorId) {
    return res.status(400).json({ message: "No podés cambiar tus propios roles desde aquí." });
  }

  const target = await prisma.user.findFirst({
    where: { id: targetUserId, jewelryId: tenantId },
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

  await prisma.$transaction(async (tx) => {
    await tx.userRole.deleteMany({ where: { userId: targetUserId } });

    if (roleIds.length) {
      await tx.userRole.createMany({
        data: roleIds.map((roleId) => ({ userId: targetUserId, roleId })),
        skipDuplicates: true,
      });
    }

    // invalidar sesión
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
  const actorId = req.userId!;
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  const targetUserId = String(req.params.id || "").trim();
  const { permissionId, effect } = req.body as {
    permissionId: string;
    effect: "ALLOW" | "DENY";
  };

  if (!targetUserId) return res.status(400).json({ message: "ID inválido." });
  if (!permissionId) return res.status(400).json({ message: "permissionId requerido." });

  const user = await prisma.user.findFirst({
    where: { id: targetUserId, jewelryId: tenantId },
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
  const actorId = req.userId!;
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  const targetUserId = String(req.params.id || "").trim();
  const permissionId = String(req.params.permissionId || "").trim();

  if (!targetUserId) return res.status(400).json({ message: "ID inválido." });
  if (!permissionId) return res.status(400).json({ message: "permissionId inválido." });

  const target = await prisma.user.findFirst({
    where: { id: targetUserId, jewelryId: tenantId },
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
   AVATAR (ME)
========================= */
export async function updateMyAvatar(req: Request, res: Response) {
  const actorId = req.userId!;
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  const file = (req as any).file as Express.Multer.File | undefined;
  if (!file) {
    return res.status(400).json({ message: "Falta archivo avatar (multipart field: avatar)." });
  }

  if (!file.mimetype?.startsWith("image/")) {
    return res.status(400).json({ message: "El archivo debe ser una imagen." });
  }

  const normalized = file.path.replace(/\\/g, "/");
  const idx = normalized.indexOf("uploads/");
  const publicRelative = idx >= 0 ? `/${normalized.slice(idx)}` : `/uploads/avatars/${file.filename}`;

  const ext = path.extname(file.originalname || "") || "";
  const ensureUniqueName =
    file.filename && file.filename.includes(".")
      ? null
      : `avatar_${actorId}_${Date.now()}_${crypto.randomBytes(4).toString("hex")}${ext}`;

  const avatarUrl = ensureUniqueName ? `/uploads/avatars/${ensureUniqueName}` : publicRelative;

  const prev = await prisma.user.findFirst({
    where: { id: actorId, jewelryId: tenantId },
    select: { avatarUrl: true, id: true },
  });

  if (!prev) return res.status(404).json({ message: "Usuario no encontrado." });

  if (ensureUniqueName) {
    const targetFsPath = `uploads/avatars/${ensureUniqueName}`;
    try {
      await fs.mkdir("uploads/avatars", { recursive: true });
      await fs.rename(file.path, targetFsPath);
    } catch {
      // ignore
    }
  }

  const updated = await prisma.user.update({
    where: { id: actorId },
    data: { avatarUrl: toPublicUrl(avatarUrl) },
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
  const actorId = req.userId!;
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  const prev = await prisma.user.findFirst({
    where: { id: actorId, jewelryId: tenantId },
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
