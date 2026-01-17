// tptech-backend/src/controllers/roles.controller.ts
import type { Request, Response } from "express";
import type { Prisma } from "@prisma/client";
import { prisma } from "../lib/prisma.js";
import { auditLog } from "../lib/auditLogger.js";

/**
 * GET /roles
 * Lista roles del tenant (LIVIANO para performance).
 *
 * ✅ Opción B:
 * - name (respuesta) = displayName ?? name  -> nombre visible
 * - code (respuesta) = name                -> código técnico
 *
 * ⚡ PERF:
 * - NO incluimos permissions ni users (solo _count)
 */
export async function listRoles(req: Request, res: Response) {
  try {
    const tenantId = (req as any).tenantId as string | undefined;
    if (!tenantId) return res.status(401).json({ message: "Tenant no encontrado" });

    const roles = await prisma.role.findMany({
      where: { jewelryId: tenantId, deletedAt: null },
      select: {
        id: true,
        name: true,
        displayName: true,
        isSystem: true,
        createdAt: true,
        _count: { select: { users: true } },
      },
      orderBy: { createdAt: "asc" },
    });

    type Row = (typeof roles)[number];

    return res.json(
      roles.map((r: Row) => ({
        id: r.id,
        name: r.displayName ?? r.name, // visible
        code: r.name, // técnico
        isSystem: r.isSystem,
        usersCount: r._count.users,
      }))
    );
  } catch (e: any) {
    return res.status(500).json({ message: e?.message || "Error listando roles" });
  }
}

/**
 * GET /roles/:id
 * Detalle de un rol (para UI: precargar permissionIds).
 */
export async function getRole(req: Request, res: Response) {
  try {
    const tenantId = (req as any).tenantId as string | undefined;
    if (!tenantId) return res.status(401).json({ message: "Tenant no encontrado" });

    const roleId = String(req.params.id || "");
    if (!roleId) return res.status(400).json({ message: "roleId requerido" });

    const role = await prisma.role.findFirst({
      where: { id: roleId, jewelryId: tenantId, deletedAt: null },
      select: {
        id: true,
        name: true,
        displayName: true,
        isSystem: true,
        permissions: {
          select: {
            permissionId: true,
            permission: { select: { module: true, action: true } },
          },
        },
        _count: { select: { users: true } },
      },
    });

    if (!role) return res.status(404).json({ message: "Rol no encontrado" });

    type RP = (typeof role.permissions)[number];

    return res.json({
      role: {
        id: role.id,
        name: role.displayName ?? role.name,
        code: role.name,
        isSystem: role.isSystem,
        usersCount: role._count.users,
        permissionIds: role.permissions.map((rp: RP) => rp.permissionId),
        permissions: role.permissions.map((rp: RP) => ({
          id: rp.permissionId,
          module: rp.permission.module,
          action: rp.permission.action,
        })),
      },
    });
  } catch (e: any) {
    return res.status(500).json({ message: e?.message || "Error obteniendo rol" });
  }
}

/**
 * POST /roles
 */
export async function createRole(req: Request, res: Response) {
  try {
    const tenantId = (req as any).tenantId as string | undefined;
    const userId = (req as any).userId as string | undefined;
    if (!tenantId) return res.status(401).json({ message: "Tenant no encontrado" });

    const name = String((req as any).body?.name || "").trim();
    if (!name) return res.status(400).json({ message: "name requerido" });

    const existing = await prisma.role.findFirst({
      where: {
        jewelryId: tenantId,
        name: { equals: name, mode: "insensitive" },
      },
    });

    if (existing && existing.deletedAt === null) {
      return res.status(409).json({ message: "Ya existe un rol con ese nombre" });
    }

    if (existing && existing.deletedAt !== null) {
      const restored = await prisma.$transaction(async (tx: Prisma.TransactionClient) => {
        const role = await tx.role.update({
          where: { id: existing.id },
          data: {
            deletedAt: null,
            isSystem: false,
            name,
            displayName: name,
          },
        });

        await tx.rolePermission.deleteMany({ where: { roleId: role.id } });
        return role;
      });

      auditLog(req, {
        action: "roles.restore",
        success: true,
        userId,
        tenantId,
        meta: { roleId: restored.id, name },
      });

      return res.status(201).json(restored);
    }

    const role = await prisma.role.create({
      data: {
        name,
        displayName: name,
        jewelryId: tenantId,
        isSystem: false,
      },
    });

    auditLog(req, {
      action: "roles.create",
      success: true,
      userId,
      tenantId,
      meta: { roleId: role.id, name },
    });

    return res.status(201).json(role);
  } catch (e: any) {
    return res.status(500).json({ message: e?.message || "Error creando rol" });
  }
}

/**
 * PATCH /roles/:id
 */
export async function updateRole(req: Request, res: Response) {
  try {
    const tenantId = (req as any).tenantId as string | undefined;
    const userId = (req as any).userId as string | undefined;
    if (!tenantId) return res.status(401).json({ message: "Tenant no encontrado" });

    const roleId = String(req.params.id || "");
    if (!roleId) return res.status(400).json({ message: "roleId requerido" });

    const name = String((req as any).body?.name || "").trim();
    if (!name) return res.status(400).json({ message: "name requerido" });

    const role = await prisma.role.findFirst({
      where: { id: roleId, jewelryId: tenantId, deletedAt: null },
      select: { id: true, name: true, isSystem: true },
    });

    if (!role) return res.status(404).json({ message: "Rol no encontrado" });

    if (role.isSystem && role.name === "OWNER") {
      return res.status(403).json({ message: "No se puede renombrar el rol Propietario" });
    }

    if (role.isSystem) {
      const updated = await prisma.role.update({
        where: { id: roleId },
        data: { displayName: name },
      });

      auditLog(req, {
        action: "roles.rename_display",
        success: true,
        userId,
        tenantId,
        meta: { roleId, displayName: name },
      });

      return res.json(updated);
    }

    const exists = await prisma.role.findFirst({
      where: {
        jewelryId: tenantId,
        deletedAt: null,
        name: { equals: name, mode: "insensitive" },
        NOT: { id: roleId },
      },
      select: { id: true },
    });

    if (exists) {
      return res.status(409).json({ message: "Ya existe un rol con ese nombre" });
    }

    const updated = await prisma.role.update({
      where: { id: roleId },
      data: { name, displayName: name },
    });

    auditLog(req, {
      action: "roles.rename",
      success: true,
      userId,
      tenantId,
      meta: { roleId, name },
    });

    return res.json(updated);
  } catch (e: any) {
    return res.status(500).json({ message: e?.message || "Error renombrando rol" });
  }
}

/**
 * PATCH /roles/:id/permissions
 */
export async function updateRolePermissions(req: Request, res: Response) {
  try {
    const tenantId = (req as any).tenantId as string | undefined;
    const userId = (req as any).userId as string | undefined;
    if (!tenantId) return res.status(401).json({ message: "Tenant no encontrado" });

    const roleId = String(req.params.id || "");
    if (!roleId) return res.status(400).json({ message: "roleId requerido" });

    const permissionIds = Array.isArray((req as any).body?.permissionIds)
      ? (((req as any).body.permissionIds as unknown[]) as string[])
      : [];

    const role = await prisma.role.findFirst({
      where: { id: roleId, jewelryId: tenantId, deletedAt: null },
      select: { id: true, name: true, isSystem: true },
    });

    if (!role) return res.status(404).json({ message: "Rol no encontrado" });

    if (role.isSystem && role.name === "OWNER") {
      return res.status(403).json({ message: "No se pueden editar permisos del Propietario" });
    }

    await prisma.rolePermission.deleteMany({ where: { roleId } });

    if (permissionIds.length) {
      await prisma.rolePermission.createMany({
        data: permissionIds.map((pid: string) => ({ roleId, permissionId: pid })),
        skipDuplicates: true,
      });
    }

    auditLog(req, {
      action: "roles.update_permissions",
      success: true,
      userId,
      tenantId,
      meta: { roleId, permissionIds },
    });

    return res.json({ ok: true });
  } catch (e: any) {
    return res.status(500).json({ message: e?.message || "Error guardando permisos" });
  }
}

/**
 * DELETE /roles/:id
 */
export async function deleteRole(req: Request, res: Response) {
  try {
    const tenantId = (req as any).tenantId as string | undefined;
    const userId = (req as any).userId as string | undefined;
    if (!tenantId) return res.status(401).json({ message: "Tenant no encontrado" });

    const roleId = String(req.params.id || "");
    if (!roleId) return res.status(400).json({ message: "roleId requerido" });

    const role = await prisma.role.findFirst({
      where: { id: roleId, jewelryId: tenantId, deletedAt: null },
      select: { id: true, isSystem: true, users: { select: { userId: true } } },
    });

    if (!role) return res.status(404).json({ message: "Rol no encontrado" });

    if (role.isSystem) {
      return res.status(403).json({ message: "No se puede eliminar un rol del sistema" });
    }

    if ((role.users ?? []).length > 0) {
      return res.status(409).json({
        message: "No se puede eliminar el rol porque tiene usuarios asignados",
      });
    }

    await prisma.$transaction(async (tx: Prisma.TransactionClient) => {
      await tx.role.update({
        where: { id: roleId },
        data: { deletedAt: new Date() },
      });

      await tx.rolePermission.deleteMany({ where: { roleId } });
    });

    auditLog(req, {
      action: "roles.delete",
      success: true,
      userId,
      tenantId,
      meta: { roleId },
    });

    return res.status(204).send();
  } catch (e: any) {
    return res.status(500).json({ message: e?.message || "Error eliminando rol" });
  }
}
