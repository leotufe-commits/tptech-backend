import type { Request, Response } from "express";
import { requireTenantId } from "../users/users.helpers.js";
import { prisma } from "../../lib/prisma.js";

import * as Svc from "./roles.service.js";

/* =========================
   LIST
========================= */
export async function listRoles(req: Request, res: Response) {
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  const items = await Svc.listRoles(tenantId);
  return res.json({ items });
}

/* =========================
   GET BY ID 🔥 (nuevo)
========================= */
export async function getRoleById(req: Request, res: Response) {
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  const roleId = String(req.params.id || "").trim();
  if (!roleId) {
    return res.status(400).json({ message: "ID inválido." });
  }

  const role = await prisma.role.findFirst({
    where: {
      id: roleId,
      jewelryId: tenantId,
      deletedAt: null,
    },
    include: {
      permissions: {
        include: {
          permission: true,
        },
      },
      _count: {
        select: {
          users: true,
        },
      },
    },
  });

  if (!role) {
    return res.status(404).json({ message: "Rol no encontrado." });
  }

  return res.json({
    role: {
      id: role.id,
      name: role.name,
      code: role.name,
      isSystem: role.isSystem,
      usersCount: role._count.users,
      permissionIds: role.permissions.map((rp) => rp.permissionId),
      permissions: role.permissions.map((rp) => ({
        id: rp.permission.id,
        module: rp.permission.module,
        action: rp.permission.action,
      })),
    },
  });
}

/* =========================
   CREATE
========================= */
export async function createRole(req: Request, res: Response) {
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  const body = (req.body ?? {}) as any;

  const role = await Svc.createRole(tenantId, {
    name: body.name,
    permissionIds: body.permissionIds ?? [],
  });

  return res.status(201).json({ role });
}

/* =========================
   RENAME
========================= */
export async function updateRole(req: Request, res: Response) {
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  const roleId = String(req.params.id || "").trim();
  if (!roleId) {
    return res.status(400).json({ message: "ID inválido." });
  }

  const body = (req.body ?? {}) as any;
  const role = await Svc.updateRole(tenantId, roleId, {
    name: body.name,
  });

  return res.json({ role });
}

/* =========================
   UPDATE PERMISSIONS
========================= */
export async function updateRolePermissions(req: Request, res: Response) {
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  const roleId = String(req.params.id || "").trim();
  if (!roleId) {
    return res.status(400).json({ message: "ID inválido." });
  }

  const body = (req.body ?? {}) as any;
  const permissionIds = Array.isArray(body.permissionIds)
    ? body.permissionIds
    : [];

  const out = await Svc.updateRolePermissions(
    tenantId,
    roleId,
    permissionIds
  );

  return res.json(out);
}

/* =========================
   DELETE
========================= */
export async function deleteRole(req: Request, res: Response) {
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  const roleId = String(req.params.id || "").trim();
  if (!roleId) {
    return res.status(400).json({ message: "ID inválido." });
  }

  const out = await Svc.deleteRole(tenantId, roleId);
  return res.json(out);
}