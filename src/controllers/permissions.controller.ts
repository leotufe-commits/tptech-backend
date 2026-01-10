import type { Request, Response } from "express";
import { prisma } from "../lib/prisma.js";

export async function listPermissions(req: Request, res: Response) {
  const permissions = await prisma.permission.findMany({
    orderBy: [{ module: "asc" }, { action: "asc" }],
  });

  return res.json(
    permissions.map((p) => ({
      id: p.id,
      module: p.module,
      action: p.action,
    }))
  );
}
