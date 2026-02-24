// tptech-backend/src/modules/roles/roles.service.ts
import { Prisma } from "@prisma/client";
import { prisma } from "../../lib/prisma.js";
import { uniqStrings } from "../users/users.helpers.js";

function err(status: number, message: string) {
  const e: any = new Error(message);
  e.status = status;
  return e;
}

function s(v: any) {
  return String(v ?? "").trim();
}

function assertNonEmpty(v: any, msg: string) {
  const x = s(v);
  if (!x) throw err(400, msg);
  return x;
}

export async function listRoles(jewelryId: string) {
  const rows = await prisma.role.findMany({
    where: { jewelryId, deletedAt: null },
    orderBy: [{ isSystem: "desc" }, { name: "asc" }],
    select: {
      id: true,
      jewelryId: true,
      name: true,
      displayName: true,
      isSystem: true,
      createdAt: true,
      updatedAt: true,
      permissions: { select: { permissionId: true } },
      _count: { select: { users: true } },
    },
  });

  return rows.map((r) => ({
    id: r.id,
    jewelryId: r.jewelryId,
    name: r.name,
    displayName: r.displayName,
    isSystem: r.isSystem,
    createdAt: r.createdAt,
    updatedAt: r.updatedAt,
    permissionIds: (r.permissions ?? []).map((p) => p.permissionId),
    usersCount: (r as any)?._count?.users ?? 0,
  }));
}

export async function createRole(
  jewelryId: string,
  data: { name: string; permissionIds?: string[] }
) {
  const name = assertNonEmpty(data.name, "Nombre requerido.");
  const permissionIds = uniqStrings((data.permissionIds ?? []).map(String).filter(Boolean));

  // unique (jewelryId, name)
  const dup = await prisma.role.findFirst({
    where: { jewelryId, name, deletedAt: null },
    select: { id: true },
  });
  if (dup) throw err(409, `Ya existe un rol con nombre "${name}".`);

  const out = await prisma.$transaction(async (tx) => {
    const role = await tx.role.create({
      data: { jewelryId, name, isSystem: false },
      select: { id: true, jewelryId: true, name: true, displayName: true, isSystem: true, createdAt: true, updatedAt: true },
    });

    if (permissionIds.length) {
      // validamos que existan
      const exists = await tx.permission.findMany({
        where: { id: { in: permissionIds } },
        select: { id: true },
      });
      const okIds = new Set(exists.map((p) => p.id));
      const finalIds = permissionIds.filter((id) => okIds.has(id));

      if (finalIds.length) {
        await tx.rolePermission.createMany({
          data: finalIds.map((permissionId) => ({ roleId: role.id, permissionId })),
          skipDuplicates: true,
        });
      }
    }

    const perms = await tx.rolePermission.findMany({
      where: { roleId: role.id },
      select: { permissionId: true },
    });

    return { role, permissionIds: perms.map((p) => p.permissionId) };
  });

  return {
    ...out.role,
    permissionIds: out.permissionIds,
  };
}

export async function updateRole(
  jewelryId: string,
  roleId: string,
  data: { name?: string }
) {
  const nextName = data.name !== undefined ? assertNonEmpty(data.name, "Nombre requerido.") : undefined;

  const current = await prisma.role.findFirst({
    where: { id: roleId, jewelryId, deletedAt: null },
    select: { id: true, isSystem: true, name: true },
  });
  if (!current) throw err(404, "Rol no encontrado.");

  if (nextName && nextName !== current.name) {
    const dup = await prisma.role.findFirst({
      where: { jewelryId, name: nextName, deletedAt: null, id: { not: roleId } },
      select: { id: true },
    });
    if (dup) throw err(409, `Ya existe un rol con nombre "${nextName}".`);
  }

  const updated = await prisma.role.update({
    where: { id: roleId },
    data: { ...(nextName ? { name: nextName } : {}) },
    select: { id: true, jewelryId: true, name: true, displayName: true, isSystem: true, createdAt: true, updatedAt: true },
  });

  const perms = await prisma.rolePermission.findMany({
    where: { roleId },
    select: { permissionId: true },
  });

  return {
    ...updated,
    permissionIds: perms.map((p) => p.permissionId),
  };
}

/**
 * Reemplaza TODO el set de permisos del rol
 */
export async function updateRolePermissions(
  jewelryId: string,
  roleId: string,
  permissionIds: string[]
) {
  const role = await prisma.role.findFirst({
    where: { id: roleId, jewelryId, deletedAt: null },
    select: { id: true },
  });
  if (!role) throw err(404, "Rol no encontrado.");

  const ids = uniqStrings((permissionIds ?? []).map(String).filter(Boolean));

  // validamos que existan
  const exists = await prisma.permission.findMany({
    where: { id: { in: ids } },
    select: { id: true },
  });
  const okIds = new Set(exists.map((p) => p.id));
  const finalIds = ids.filter((id) => okIds.has(id));

  await prisma.$transaction(async (tx) => {
    await tx.rolePermission.deleteMany({ where: { roleId } });
    if (finalIds.length) {
      await tx.rolePermission.createMany({
        data: finalIds.map((permissionId) => ({ roleId, permissionId })),
        skipDuplicates: true,
      });
    }
  });

  return { ok: true, roleId, permissionIds: finalIds };
}

export async function deleteRole(jewelryId: string, roleId: string) {
  const role = await prisma.role.findFirst({
    where: { id: roleId, jewelryId, deletedAt: null },
    select: { id: true, isSystem: true, name: true, _count: { select: { users: true } } },
  });
  if (!role) throw err(404, "Rol no encontrado.");

  if (role.isSystem) throw err(409, "No se puede eliminar un rol del sistema.");
  const usersCount = (role as any)?._count?.users ?? 0;
  if (usersCount > 0) throw err(409, `No se puede eliminar: el rol está asignado a ${usersCount} usuario(s).`);

  await prisma.role.update({
    where: { id: roleId },
    data: {
      deletedAt: new Date(),
      name: `deleted__${role.name}__${Date.now()}`,
    } as any,
    select: { id: true },
  });

  return { ok: true };
}