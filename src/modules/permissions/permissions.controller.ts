// tptech-backend/src/modules/permissions/permissions.controller.ts
import type { Request, Response } from "express";
import { prisma } from "../../lib/prisma.js";

/**
 * GET /permissions
 * requireAuth ya está aplicado en routes/index.ts
 * requirePermission(...) ya está aplicado en permissions.routes.ts
 *
 * ✅ Compat response:
 * - { items: [...] }        (legacy)
 * - { permissions: [...] } (frontend roles modal)
 */
export async function listPermissions(_req: Request, res: Response) {
  const rows = await prisma.permission.findMany({
    orderBy: [{ module: "asc" }, { action: "asc" }],
    select: {
      id: true,
      module: true,
      action: true,
      createdAt: true,
    },
  });

  return res.json({
    items: rows,
    permissions: rows,
  });
}