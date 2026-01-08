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

/**
 * Construye URL pública para archivos.
 * - Si tu avatarUrl se guarda como "/uploads/avatars/xxx.jpg", ya es suficiente para el frontend
 *   si tu backend sirve /uploads como estático.
 * - Si querés URL absoluta, seteá PUBLIC_BASE_URL (ej: https://tu-backend.onrender.com)
 */
function toPublicUrl(relativePath: string) {
  const base = String(process.env.PUBLIC_BASE_URL || "").replace(/\/+$/, "");
  if (!base) return relativePath; // devuelve relativa
  const p = relativePath.startsWith("/") ? relativePath : `/${relativePath}`;
  return `${base}${p}`;
}

/**
 * Intenta borrar un archivo anterior si es local y está en /uploads/avatars.
 * No rompe si falla.
 */
async function safeDeleteOldAvatar(avatarUrl: string | null) {
  if (!avatarUrl) return;

  // soporta URL absoluta o relativa
  // nos quedamos con el pathname
  let pathname = avatarUrl;
  try {
    if (avatarUrl.startsWith("http://") || avatarUrl.startsWith("https://")) {
      pathname = new URL(avatarUrl).pathname;
    }
  } catch {
    pathname = avatarUrl;
  }

  // solo borramos si está en /uploads/avatars/
  if (!pathname.includes("/uploads/avatars/")) return;

  // convertir a path local:
  // /uploads/avatars/abc.jpg -> uploads/avatars/abc.jpg
  const local = pathname.replace(/^\/+/, ""); // quita slash inicial
  try {
    await fs.unlink(local);
  } catch {
    // ignore
  }
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

  if (!email) {
    return res.status(400).json({ message: "Email inválido." });
  }

  // normalizar roles
  let roleIds = Array.isArray(body.roleIds) ? body.roleIds : [];
  roleIds = uniqStrings(roleIds.map((r) => String(r || "").trim()).filter(Boolean));

  const hasPassword = Boolean(String(body.password || "").trim());
  const desiredStatus = body.status ? String(body.status) : undefined;

  // status default: ACTIVE si hay password, sino PENDING
  const status: UserStatus =
    desiredStatus === "BLOCKED"
      ? UserStatus.BLOCKED
      : hasPassword
      ? UserStatus.ACTIVE
      : UserStatus.PENDING;

  // email único (global)
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

  // validar roles pertenecen al tenant (si mandan roleIds)
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

  const passwordHash = hasPassword ? await bcrypt.hash(String(body.password), 10) : null;

  const created = await prisma.$transaction(async (tx) => {
    const user = await tx.user.create({
      data: {
        email,
        name,
        status,
        jewelryId: tenantId,
        password: passwordHash ?? "", // ✅ compat con tu modelo (string requerido)
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
        data: roleIds.map((roleId) => ({
          userId: user.id,
          roleId,
        })),
        skipDuplicates: true,
      });
    }

    const roles = await tx.userRole.findMany({
      where: { userId: user.id },
      select: {
        role: { select: { id: true, name: true, isSystem: true } },
      },
    });

    return {
      ...user,
      roles: roles.map((ur) => ({
        id: ur.role.id,
        name: ur.role.name,
        isSystem: ur.role.isSystem,
      })),
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
   Listado (sin overrides)
========================= */
export async function listUsers(req: Request, res: Response) {
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  const users = await prisma.user.findMany({
    where: { jewelryId: tenantId },
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
          role: { select: { id: true, name: true, isSystem: true } },
        },
      },
    },
    orderBy: { createdAt: "asc" },
  });

  return res.json({
    users: users.map((u) => ({
      id: u.id,
      email: u.email,
      name: u.name,
      status: u.status,
      avatarUrl: u.avatarUrl,
      favoriteWarehouseId: u.favoriteWarehouseId,
      createdAt: u.createdAt,
      updatedAt: u.updatedAt,
      roles: (u.roles ?? []).map((ur) => ({
        id: ur.role.id,
        name: ur.role.name,
        isSystem: ur.role.isSystem,
      })),
    })),
  });
}

/* =========================
   GET /users/:id
   Detalle (con overrides)
========================= */
export async function getUser(req: Request, res: Response) {
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  const targetUserId = String(req.params.id);

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
          role: { select: { id: true, name: true, isSystem: true } },
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

  if (!user) {
    return res.status(404).json({ message: "Usuario no encontrado." });
  }

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
      roles: (user.roles ?? []).map((ur) => ({
        id: ur.role.id,
        name: ur.role.name,
        isSystem: ur.role.isSystem,
      })),
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

  const targetUserId = String(req.params.id);
  const { status } = req.body as { status: UserStatus };

  if (targetUserId === actorId) {
    return res.status(400).json({
      message: "No podés cambiar tu propio estado desde aquí.",
    });
  }

  const target = await prisma.user.findFirst({
    where: { id: targetUserId, jewelryId: tenantId },
    select: { id: true },
  });

  if (!target) {
    return res.status(404).json({ message: "Usuario no encontrado." });
  }

  const updated = await prisma.user.update({
    where: { id: targetUserId },
    data: {
      status,
      tokenVersion: { increment: 1 }, // invalida sesiones
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

  const targetUserId = String(req.params.id);
  let { roleIds } = req.body as { roleIds: string[] };

  if (!Array.isArray(roleIds)) {
    return res.status(400).json({ message: "roleIds debe ser un array" });
  }

  roleIds = uniqStrings(roleIds.map((r) => String(r || "").trim()).filter((r) => r.length > 0));

  if (targetUserId === actorId) {
    return res.status(400).json({
      message: "No podés cambiar tus propios roles desde aquí.",
    });
  }

  const target = await prisma.user.findFirst({
    where: { id: targetUserId, jewelryId: tenantId },
    select: { id: true },
  });

  if (!target) {
    return res.status(404).json({ message: "Usuario no encontrado." });
  }

  const roles = await prisma.role.findMany({
    where: {
      id: { in: roleIds },
      jewelryId: tenantId,
      deletedAt: null,
    },
    select: { id: true },
  });

  if (roles.length !== roleIds.length) {
    return res.status(400).json({
      message: "Uno o más roles no son válidos para esta joyería.",
    });
  }

  await prisma.userRole.deleteMany({
    where: { userId: targetUserId },
  });

  if (roleIds.length) {
    await prisma.userRole.createMany({
      data: roleIds.map((roleId) => ({
        userId: targetUserId,
        roleId,
      })),
      skipDuplicates: true,
    });
  }

  await prisma.user.update({
    where: { id: targetUserId },
    data: { tokenVersion: { increment: 1 } },
    select: { id: true },
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

  const targetUserId = String(req.params.id);
  const { permissionId, effect } = req.body as {
    permissionId: string;
    effect: "ALLOW" | "DENY";
  };

  const user = await prisma.user.findFirst({
    where: { id: targetUserId, jewelryId: tenantId },
    select: { id: true },
  });

  if (!user) {
    return res.status(404).json({ message: "Usuario no encontrado." });
  }

  const perm = await prisma.permission.findUnique({
    where: { id: permissionId },
    select: { id: true },
  });

  if (!perm) {
    return res.status(404).json({ message: "Permiso no encontrado." });
  }

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

  const targetUserId = String(req.params.id);
  const { permissionId } = req.params;

  const target = await prisma.user.findFirst({
    where: { id: targetUserId, jewelryId: tenantId },
    select: { id: true },
  });

  if (!target) {
    return res.status(404).json({ message: "Usuario no encontrado." });
  }

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
   PUT    /users/me/avatar   (multipart field: avatar)
   DELETE /users/me/avatar
========================= */

/**
 * PUT /users/me/avatar
 * Requiere middleware multer en la ruta: upload.single("avatar")
 * Espera: req.file
 */
export async function updateMyAvatar(req: Request, res: Response) {
  const actorId = req.userId!;
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  // Multer pone el archivo en req.file
  const file = (req as any).file as Express.Multer.File | undefined;
  if (!file) {
    return res.status(400).json({ message: "Falta archivo avatar (multipart field: avatar)." });
  }

  // Validación básica server-side
  if (!file.mimetype?.startsWith("image/")) {
    return res.status(400).json({ message: "El archivo debe ser una imagen." });
  }

  // ubicamos el path público (asumiendo /uploads estático)
  // Si tu storage ya define file.filename dentro de uploads/avatars, esto queda perfecto.
  // Ej: uploads/avatars/xxx.jpg -> /uploads/avatars/xxx.jpg
  const normalized = file.path.replace(/\\/g, "/"); // windows safe
  const idx = normalized.indexOf("uploads/");
  const publicRelative = idx >= 0 ? `/${normalized.slice(idx)}` : `/uploads/avatars/${file.filename}`;

  // usamos filename único real (si tu multer NO lo hace, te dejo fallback aquí)
  // Si tu multer ya genera nombres únicos, este fallback no se usa.
  const ext = path.extname(file.originalname || "") || "";
  const ensureUniqueName =
    file.filename && file.filename.includes(".")
      ? null
      : `avatar_${actorId}_${Date.now()}_${crypto.randomBytes(4).toString("hex")}${ext}`;

  const avatarUrl = ensureUniqueName ? `/uploads/avatars/${ensureUniqueName}` : publicRelative;

  // Traemos avatar previo para borrar el archivo local si corresponde
  const prev = await prisma.user.findFirst({
    where: { id: actorId, jewelryId: tenantId },
    select: { avatarUrl: true, id: true },
  });

  if (!prev) {
    return res.status(404).json({ message: "Usuario no encontrado." });
  }

  // Si el multer NO generó filename único, movemos/renombramos el archivo a nombre único
  // (esto evita cache y colisiones)
  if (ensureUniqueName) {
    const targetFsPath = `uploads/avatars/${ensureUniqueName}`;
    try {
      await fs.mkdir("uploads/avatars", { recursive: true });
      await fs.rename(file.path, targetFsPath);
    } catch {
      // si falla, no rompemos, pero el publicRelative podría apuntar a algo no ideal
      // en ese caso usamos publicRelative original
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

  // intentamos borrar avatar anterior si era local
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

/**
 * DELETE /users/me/avatar
 * Quita avatar del usuario logueado
 */
export async function removeMyAvatar(req: Request, res: Response) {
  const actorId = req.userId!;
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  const prev = await prisma.user.findFirst({
    where: { id: actorId, jewelryId: tenantId },
    select: { avatarUrl: true, id: true },
  });

  if (!prev) {
    return res.status(404).json({ message: "Usuario no encontrado." });
  }

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
