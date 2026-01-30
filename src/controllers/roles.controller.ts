// tptech-backend/src/controllers/roles.controller.ts
import type { Request, Response } from "express";
import type { Prisma } from "@prisma/client";
import { prisma } from "../lib/prisma.js";
import { auditLog } from "../lib/auditLogger.js";

/* =========================
   Helpers
========================= */
function requireTenantId(req: Request, res: Response) {
  const tenantId = (req as any).tenantId as string | undefined;
  if (!tenantId) {
    res.status(401).json({ message: "Tenant no encontrado" });
    return null;
  }
  return String(tenantId);
}

function norm(s: any) {
  return String(s || "").trim();
}

function isOwnerRole(roleName: string) {
  // ✅ tolerante a DB: "OWNER" / "owner" / "Owner"
  return String(roleName || "").trim().toLowerCase() === "owner";
}

function uniqStrings(arr: string[]) {
  return Array.from(new Set((arr || []).map((x) => String(x)).filter(Boolean)));
}

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
    const tenantId = requireTenantId(req, res);
    if (!tenantId) return;

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
    const tenantId = requireTenantId(req, res);
    if (!tenantId) return;

    const roleId = norm(req.params.id);
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
 * (permissionIds opcional en schema; si lo mandás, lo aplicamos)
 */
export async function createRole(req: Request, res: Response) {
  try {
    const tenantId = requireTenantId(req, res);
    if (!tenantId) return;

    const userId = (req as any).userId as string | undefined;

    const name = norm((req as any).body?.name);
    if (!name) return res.status(400).json({ message: "name requerido" });

    const permissionIdsRaw = Array.isArray((req as any).body?.permissionIds)
      ? ((req as any).body.permissionIds as unknown[])
      : [];

    const permissionIds = uniqStrings(permissionIdsRaw as any);

    const existing = await prisma.role.findFirst({
      where: { jewelryId: tenantId, name: { equals: name, mode: "insensitive" } },
    });

    // ya existe activo
    if (existing && existing.deletedAt === null) {
      return res.status(409).json({ message: "Ya existe un rol con ese nombre" });
    }

    // restaurar soft deleted
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

        if (permissionIds.length) {
          // ✅ validar existencia de permisos
          const valid = await tx.permission.findMany({
            where: { id: { in: permissionIds } },
            select: { id: true },
          });
          const validIds = new Set(valid.map((p) => p.id));
          const safeIds = permissionIds.filter((id) => validIds.has(id));

          if (safeIds.length) {
            await tx.rolePermission.createMany({
              data: safeIds.map((pid) => ({ roleId: role.id, permissionId: pid })),
              skipDuplicates: true,
            });
          }
        }

        return role;
      });

      auditLog(req, {
        action: "roles.restore",
        success: true,
        userId,
        tenantId,
        meta: { roleId: restored.id, name, permissionIdsCount: permissionIds.length },
      });

      return res.status(201).json(restored);
    }

    const created = await prisma.$transaction(async (tx: Prisma.TransactionClient) => {
      const role = await tx.role.create({
        data: {
          name,
          displayName: name,
          jewelryId: tenantId,
          isSystem: false,
        },
      });

      if (permissionIds.length) {
        const valid = await tx.permission.findMany({
          where: { id: { in: permissionIds } },
          select: { id: true },
        });
        const validIds = new Set(valid.map((p) => p.id));
        const safeIds = permissionIds.filter((id) => validIds.has(id));

        if (safeIds.length) {
          await tx.rolePermission.createMany({
            data: safeIds.map((pid) => ({ roleId: role.id, permissionId: pid })),
            skipDuplicates: true,
          });
        }
      }

      return role;
    });

    auditLog(req, {
      action: "roles.create",
      success: true,
      userId,
      tenantId,
      meta: { roleId: created.id, name, permissionIdsCount: permissionIds.length },
    });

    return res.status(201).json(created);
  } catch (e: any) {
    return res.status(500).json({ message: e?.message || "Error creando rol" });
  }
}

/**
 * PATCH /roles/:id
 * - si isSystem: solo displayName
 * - si no isSystem: name + displayName
 */
export async function updateRole(req: Request, res: Response) {
  try {
    const tenantId = requireTenantId(req, res);
    if (!tenantId) return;

    const userId = (req as any).userId as string | undefined;

    const roleId = norm(req.params.id);
    if (!roleId) return res.status(400).json({ message: "roleId requerido" });

    const name = norm((req as any).body?.name);
    if (!name) return res.status(400).json({ message: "name requerido" });

    const role = await prisma.role.findFirst({
      where: { id: roleId, jewelryId: tenantId, deletedAt: null },
      select: { id: true, name: true, isSystem: true },
    });

    if (!role) return res.status(404).json({ message: "Rol no encontrado" });

    if (role.isSystem && isOwnerRole(role.name)) {
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
 * Reemplaza toda la lista de permisos del rol.
 */
export async function updateRolePermissions(req: Request, res: Response) {
  try {
    const tenantId = requireTenantId(req, res);
    if (!tenantId) return;

    const userId = (req as any).userId as string | undefined;

    const roleId = norm(req.params.id);
    if (!roleId) return res.status(400).json({ message: "roleId requerido" });

    const permissionIdsRaw = Array.isArray((req as any).body?.permissionIds)
      ? ((req as any).body.permissionIds as unknown[])
      : [];

    const permissionIds = uniqStrings(permissionIdsRaw as any);

    const role = await prisma.role.findFirst({
      where: { id: roleId, jewelryId: tenantId, deletedAt: null },
      select: { id: true, name: true, isSystem: true },
    });

    if (!role) return res.status(404).json({ message: "Rol no encontrado" });

    if (role.isSystem && isOwnerRole(role.name)) {
      return res.status(403).json({ message: "No se pueden editar permisos del Propietario" });
    }

    // ✅ validar existencia de permisos (catálogo global)
    let safeIds: string[] = [];
    if (permissionIds.length) {
      const valid = await prisma.permission.findMany({
        where: { id: { in: permissionIds } },
        select: { id: true },
      });
      const validIds = new Set(valid.map((p) => p.id));
      safeIds = permissionIds.filter((id) => validIds.has(id));
    }

    await prisma.$transaction(async (tx: Prisma.TransactionClient) => {
      await tx.rolePermission.deleteMany({ where: { roleId } });

      if (safeIds.length) {
        await tx.rolePermission.createMany({
          data: safeIds.map((pid) => ({ roleId, permissionId: pid })),
          skipDuplicates: true,
        });
      }
    });

    auditLog(req, {
      action: "roles.update_permissions",
      success: true,
      userId,
      tenantId,
      meta: { roleId, permissionIds: safeIds, dropped: permissionIds.length - safeIds.length },
    });

    // ✅ devolver algo útil para UI
    return res.json({ ok: true, roleId, permissionIds: safeIds });
  } catch (e: any) {
    return res.status(500).json({ message: e?.message || "Error guardando permisos" });
  }
}

/**
 * DELETE /roles/:id
 * Soft delete + limpia rolePermission.
 */
export async function deleteRole(req: Request, res: Response) {
  try {
    const tenantId = requireTenantId(req, res);
    if (!tenantId) return;

    const userId = (req as any).userId as string | undefined;

    const roleId = norm(req.params.id);
    if (!roleId) return res.status(400).json({ message: "roleId requerido" });

    const role = await prisma.role.findFirst({
      where: { id: roleId, jewelryId: tenantId, deletedAt: null },
      select: { id: true, name: true, isSystem: true, users: { select: { userId: true } } },
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
