import type { Request, Response } from "express";
import { prisma } from "../lib/prisma.js";

/**
 * GET /permissions
 * Lista el catálogo completo de permisos
 */
export async function listPermissions(req: Request, res: Response) {
  const permissions = await prisma.permission.findMany({
    select: {
      id: true,
      module: true,
      action: true,
    },
    orderBy: [
      { module: "asc" },
      { action: "asc" },
    ],
  });

  return res.json({ permissions });
}
