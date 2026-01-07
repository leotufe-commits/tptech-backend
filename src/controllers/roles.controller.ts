import type { Request, Response } from "express";
import { prisma } from "../lib/prisma.js";
import { auditLog } from "../lib/auditLogger.js";

/**
 * GET /roles
 */
export async function listRoles(req: Request, res: Response) {
  const tenantId = req.tenantId!;

  const roles = await prisma.role.findMany({
    where: { jewelryId: tenantId, deletedAt: null },
    include: {
      permissions: {
        include: { permission: true },
      },
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
      permissions: r.permissions.map((rp) => ({
        id: rp.permissionId,
        module: rp.permission.module,
        action: rp.permission.action,
      })),
    }))
  );
}

/**
 * POST /roles
 */
export async function createRole(req: Request, res: Response) {
  const tenantId = req.tenantId!;
  const { name } = req.body;

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
}

/**
 * PATCH /roles/:id
 */
export async function updateRole(req: Request, res: Response) {
  const tenantId = req.tenantId!;
  const roleId = String(req.params.id);
  const { name } = req.body;

  const role = await prisma.role.findFirst({
    where: { id: roleId, jewelryId: tenantId, deletedAt: null },
  });

  if (!role) return res.status(404).json({ message: "Rol no encontrado" });
  if (role.isSystem)
    return res.status(403).json({ message: "No se puede modificar un rol del sistema" });

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
}

/**
 * PATCH /roles/:id/permissions
 */
export async function updateRolePermissions(req: Request, res: Response) {
  const tenantId = req.tenantId!;
  const roleId = String(req.params.id);
  const { permissionIds } = req.body as { permissionIds: string[] };

  const role = await prisma.role.findFirst({
    where: { id: roleId, jewelryId: tenantId, deletedAt: null },
  });

  if (!role) return res.status(404).json({ message: "Rol no encontrado" });
  if (role.isSystem)
    return res.status(403).json({ message: "No se pueden editar permisos de roles del sistema" });

  await prisma.rolePermission.deleteMany({
    where: { roleId },
  });

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
}

/**
 * DELETE /roles/:id
 */
export async function deleteRole(req: Request, res: Response) {
  const tenantId = req.tenantId!;
  const roleId = String(req.params.id);

  const role = await prisma.role.findFirst({
    where: { id: roleId, jewelryId: tenantId, deletedAt: null },
    include: { users: true },
  });

  if (!role) return res.status(404).json({ message: "Rol no encontrado" });
  if (role.isSystem)
    return res.status(403).json({ message: "No se puede eliminar un rol del sistema" });

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
}
