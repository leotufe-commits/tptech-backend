import type { Request, Response } from "express";
import { prisma } from "../lib/prisma.js";
import { auditLog } from "../lib/auditLogger.js";

/**
 * GET /roles
 * Lista roles del tenant (incluye permisos para que el frontend pueda pre-marcar).
 */
export async function listRoles(req: Request, res: Response) {
  try {
    const tenantId = req.tenantId;
    if (!tenantId) return res.status(401).json({ message: "Tenant no encontrado" });

    const roles = await prisma.role.findMany({
      where: { jewelryId: tenantId, deletedAt: null },
      include: {
        permissions: { include: { permission: true } },
        users: true,
      },
      orderBy: { createdAt: "asc" },
    });

    return res.json(
      roles.map((r) => ({
        id: r.id,
        name: r.name,
        isSystem: r.isSystem,
        usersCount: r.users.length,
        // ✅ el frontend usa p.id para pre-marcar checkboxes
        permissions: r.permissions.map((rp) => ({
          id: rp.permissionId,
          module: rp.permission.module,
          action: rp.permission.action,
        })),
      }))
    );
  } catch (e: any) {
    return res.status(500).json({ message: e?.message || "Error listando roles" });
  }
}

/**
 * GET /roles/:id
 * Detalle de un rol (recomendado para UI prolija).
 */
export async function getRole(req: Request, res: Response) {
  try {
    const tenantId = req.tenantId;
    if (!tenantId) return res.status(401).json({ message: "Tenant no encontrado" });

    const roleId = String(req.params.id || "");
    if (!roleId) return res.status(400).json({ message: "roleId requerido" });

    const role = await prisma.role.findFirst({
      where: { id: roleId, jewelryId: tenantId, deletedAt: null },
      include: {
        permissions: { include: { permission: true } },
        users: true,
      },
    });

    if (!role) return res.status(404).json({ message: "Rol no encontrado" });

    return res.json({
      role: {
        id: role.id,
        name: role.name,
        isSystem: role.isSystem,
        usersCount: role.users.length,
        permissionIds: role.permissions.map((rp) => rp.permissionId),
        permissions: role.permissions.map((rp) => ({
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
 * Crear rol custom
 */
export async function createRole(req: Request, res: Response) {
  try {
    const tenantId = req.tenantId;
    if (!tenantId) return res.status(401).json({ message: "Tenant no encontrado" });

    const name = String(req.body?.name || "").trim();
    if (!name) return res.status(400).json({ message: "name requerido" });

    const role = await prisma.role.create({
      data: {
        name,
        jewelryId: tenantId,
        isSystem: false,
      },
    });

    auditLog(req, {
      action: "roles.create",
      success: true,
      userId: req.userId,
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
 * Renombrar rol
 */
export async function updateRole(req: Request, res: Response) {
  try {
    const tenantId = req.tenantId;
    if (!tenantId) return res.status(401).json({ message: "Tenant no encontrado" });

    const roleId = String(req.params.id || "");
    if (!roleId) return res.status(400).json({ message: "roleId requerido" });

    const name = String(req.body?.name || "").trim();
    if (!name) return res.status(400).json({ message: "name requerido" });

    const role = await prisma.role.findFirst({
      where: { id: roleId, jewelryId: tenantId, deletedAt: null },
    });

    if (!role) return res.status(404).json({ message: "Rol no encontrado" });
    if (role.isSystem) {
      return res.status(403).json({ message: "No se puede modificar un rol del sistema" });
    }

    const updated = await prisma.role.update({
      where: { id: roleId },
      data: { name },
    });

    auditLog(req, {
      action: "roles.rename",
      success: true,
      userId: req.userId,
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
 * Reemplaza permisos del rol
 * ✅ Opción C:
 * - OWNER (sistema) NO editable
 * - ADMIN/STAFF/READONLY (sistema) SÍ editable
 * - Custom SÍ editable
 */
export async function updateRolePermissions(req: Request, res: Response) {
  try {
    const tenantId = req.tenantId;
    if (!tenantId) return res.status(401).json({ message: "Tenant no encontrado" });

    const roleId = String(req.params.id || "");
    if (!roleId) return res.status(400).json({ message: "roleId requerido" });

    const permissionIds = Array.isArray(req.body?.permissionIds)
      ? (req.body.permissionIds as string[])
      : [];

    const role = await prisma.role.findFirst({
      where: { id: roleId, jewelryId: tenantId, deletedAt: null },
    });

    if (!role) return res.status(404).json({ message: "Rol no encontrado" });

    // ✅ Solo bloquear OWNER
    if (role.isSystem && role.name === "OWNER") {
      return res.status(403).json({ message: "No se pueden editar permisos del Propietario" });
    }

    await prisma.rolePermission.deleteMany({ where: { roleId } });

    if (permissionIds.length) {
      await prisma.rolePermission.createMany({
        data: permissionIds.map((pid) => ({
          roleId,
          permissionId: pid,
        })),
      });
    }

    auditLog(req, {
      action: "roles.update_permissions",
      success: true,
      userId: req.userId,
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
 * Elimina rol si no tiene usuarios asignados
 */
export async function deleteRole(req: Request, res: Response) {
  try {
    const tenantId = req.tenantId;
    if (!tenantId) return res.status(401).json({ message: "Tenant no encontrado" });

    const roleId = String(req.params.id || "");
    if (!roleId) return res.status(400).json({ message: "roleId requerido" });

    const role = await prisma.role.findFirst({
      where: { id: roleId, jewelryId: tenantId, deletedAt: null },
      include: { users: true },
    });

    if (!role) return res.status(404).json({ message: "Rol no encontrado" });
    if (role.isSystem) {
      return res.status(403).json({ message: "No se puede eliminar un rol del sistema" });
    }

    if (role.users.length > 0) {
      return res.status(409).json({
        message: "No se puede eliminar el rol porque tiene usuarios asignados",
      });
    }

    await prisma.role.update({
      where: { id: roleId },
      data: { deletedAt: new Date() },
    });

    auditLog(req, {
      action: "roles.delete",
      success: true,
      userId: req.userId,
      tenantId,
      meta: { roleId },
    });

    return res.status(204).send();
  } catch (e: any) {
    return res.status(500).json({ message: e?.message || "Error eliminando rol" });
  }
}
