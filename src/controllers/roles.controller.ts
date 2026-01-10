import type { Request, Response } from "express";
import { prisma } from "../lib/prisma.js";
import { auditLog } from "../lib/auditLogger.js";

/**
 * GET /roles
 * Lista roles del tenant (incluye permisos para que el frontend pueda pre-marcar).
 *
 * ✅ Opción B:
 * - name (respuesta) = displayName ?? name  -> nombre visible
 * - code (respuesta) = name                -> código técnico
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
        name: r.displayName ?? r.name, // ✅ visible
        code: r.name, // ✅ técnico
        isSystem: r.isSystem,
        usersCount: r.users.length,
        permissions: r.permissions.map((rp) => ({
          id: rp.permissionId, // ✅ permissionId (lo que necesita el checkbox)
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
 * Detalle de un rol (para UI prolija).
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
        name: role.displayName ?? role.name, // ✅ visible
        code: role.name, // ✅ técnico
        isSystem: role.isSystem,
        usersCount: role.users.length,
        permissionIds: role.permissions.map((rp) => rp.permissionId), // ✅ clave
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
 * Crear rol custom (NO repetir nombre)
 *
 * ✅ FIX IMPORTANTE:
 * - Si existe un rol borrado (deletedAt != null) con el mismo nombre (case-insensitive),
 *   lo restauramos en vez de crear uno nuevo (evita error de unique).
 *
 * ✅ Opción B:
 * - para roles custom, usamos displayName = name (para que el nombre visible quede bien)
 */
export async function createRole(req: Request, res: Response) {
  try {
    const tenantId = req.tenantId;
    if (!tenantId) return res.status(401).json({ message: "Tenant no encontrado" });

    const name = String(req.body?.name || "").trim();
    if (!name) return res.status(400).json({ message: "name requerido" });

    // ✅ Buscar por nombre (case-insensitive) INCLUYENDO borrados
    const existing = await prisma.role.findFirst({
      where: {
        jewelryId: tenantId,
        name: { equals: name, mode: "insensitive" },
      },
    });

    // Si existe y NO está borrado → conflicto normal
    if (existing && existing.deletedAt === null) {
      return res.status(409).json({ message: "Ya existe un rol con ese nombre" });
    }

    // Si existe pero está borrado → RESTAURAR (y dejarlo "como nuevo")
    if (existing && existing.deletedAt !== null) {
      const restored = await prisma.$transaction(async (tx) => {
        // 1) restaurar
        const role = await tx.role.update({
          where: { id: existing.id },
          data: {
            deletedAt: null,
            isSystem: false,
            name, // normalizamos casing si querés
            displayName: name, // ✅ visible
          },
        });

        // 2) dejarlo limpio (como si fuera un rol nuevo)
        await tx.rolePermission.deleteMany({ where: { roleId: role.id } });

        return role;
      });

      auditLog(req, {
        action: "roles.restore",
        success: true,
        userId: req.userId,
        tenantId,
        meta: { roleId: restored.id, name },
      });

      // 201 porque para el usuario "se creó" de nuevo
      return res.status(201).json(restored);
    }

    // Si no existe → crear normal
    const role = await prisma.role.create({
      data: {
        name,
        displayName: name, // ✅ visible
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
 *
 * ✅ Opción B:
 * - OWNER (system) NO editable
 * - ADMIN/STAFF/READONLY (system) -> renombra displayName
 * - custom -> renombra name (y también displayName para mantener consistencia)
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

    // ✅ Bloquear únicamente OWNER
    if (role.isSystem && role.name === "OWNER") {
      return res.status(403).json({ message: "No se puede renombrar el rol Propietario" });
    }

    // ✅ Roles del sistema: renombrar displayName (NO tocar name/código)
    if (role.isSystem) {
      const updated = await prisma.role.update({
        where: { id: roleId },
        data: { displayName: name },
      });

      auditLog(req, {
        action: "roles.rename_display",
        success: true,
        userId: req.userId,
        tenantId,
        meta: { roleId, displayName: name },
      });

      return res.json(updated);
    }

    // ✅ Custom: no repetir nombre (solo entre activos)
    const exists = await prisma.role.findFirst({
      where: {
        jewelryId: tenantId,
        deletedAt: null,
        name: { equals: name, mode: "insensitive" },
        NOT: { id: roleId },
      },
    });
    if (exists) {
      return res.status(409).json({ message: "Ya existe un rol con ese nombre" });
    }

    const updated = await prisma.role.update({
      where: { id: roleId },
      data: {
        name,
        displayName: name, // ✅ mantenemos visible alineado
      },
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
 *
 * ✅ REGLA FINAL:
 * - OWNER NO editable
 * - ADMIN/STAFF/READONLY SÍ editables
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

    // ✅ Bloquear únicamente OWNER
    if (role.isSystem && role.name === "OWNER") {
      return res.status(403).json({ message: "No se pueden editar permisos del Propietario" });
    }

    await prisma.rolePermission.deleteMany({ where: { roleId } });

    if (permissionIds.length) {
      await prisma.rolePermission.createMany({
        data: permissionIds.map((pid) => ({ roleId, permissionId: pid })),
        skipDuplicates: true,
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
 * ✅ Solo roles custom
 *
 * ✅ Soft delete (deletedAt)
 * ✅ Limpia permisos del rol para que si se restaura, arranque limpio
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

    await prisma.$transaction(async (tx) => {
      // 1) soft delete
      await tx.role.update({
        where: { id: roleId },
        data: { deletedAt: new Date() },
      });

      // 2) limpiar permisos
      await tx.rolePermission.deleteMany({ where: { roleId } });
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
