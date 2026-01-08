// tptech-backend/src/controllers/users.controller.ts
import type { Request, Response } from "express";
import bcrypt from "bcryptjs";
import { prisma } from "../lib/prisma.js";
import { auditLog } from "../lib/auditLogger.js";
import { UserStatus } from "@prisma/client";

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

/* =========================
   POST /users
   Crear usuario (ADMIN)
========================= */
/**
 * POST /users
 * Crea un usuario dentro del tenant.
 *
 * Body:
 * {
 *   email: string,
 *   name?: string,
 *   password?: string,
 *   roleIds?: string[],
 *   status?: "ACTIVE" | "BLOCKED"
 * }
 *
 * Notas:
 * - Si NO viene password => status default: PENDING (usuario creado pero sin acceso aún)
 * - Si viene password => status default: ACTIVE
 */
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
/**
 * GET /users
 * Devuelve usuarios del tenant + roles (para UI)
 * (Listado liviano: SIN overrides)
 */
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
/**
 * GET /users/:id
 * Detalle (incluye overrides)
 */
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
/**
 * PATCH /users/:id/status
 */
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
/**
 * PUT /users/:id/roles
 */
export async function assignRolesToUser(req: Request, res: Response) {
  const actorId = req.userId!;
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  const targetUserId = String(req.params.id);
  let { roleIds } = req.body as { roleIds: string[] };

  if (!Array.isArray(roleIds)) {
    return res.status(400).json({ message: "roleIds debe ser un array" });
  }

  // normalizar: trim + uniq
  roleIds = uniqStrings(roleIds.map((r) => String(r || "").trim()).filter((r) => r.length > 0));

  // ✅ no permitir auto-edición de roles (evita lock-out)
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

  // validar roles del tenant (evita asignar roles de otra joyería)
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

  // ✅ invalida sesiones/permisos cacheados
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
/**
 * POST /users/:id/overrides
 */
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

  // ✅ invalida sesiones/permisos cacheados
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
/**
 * DELETE /users/:id/overrides/:permissionId
 */
export async function removeUserOverride(req: Request, res: Response) {
  const actorId = req.userId!;
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  const targetUserId = String(req.params.id);
  const { permissionId } = req.params;

  // ✅ validar pertenencia al tenant (multi-tenant safety)
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

  // ✅ invalida sesiones/permisos cacheados
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
