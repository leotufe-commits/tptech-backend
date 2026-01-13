// tptech-backend/src/controllers/permissions.controller.ts
import type { Request, Response } from "express";
import { prisma } from "../lib/prisma.js";

export async function listPermissions(_req: Request, res: Response) {
  try {
    // ✅ Cache: el catálogo de permisos casi nunca cambia
    // - private: por si hay proxies intermedios
    // - max-age: el navegador puede reutilizar 10 min
    res.setHeader("Cache-Control", "private, max-age=600");

    const permissions = await prisma.permission.findMany({
      select: {
        id: true,
        module: true,
        action: true,
      },
      orderBy: [{ module: "asc" }, { action: "asc" }],
    });

    return res.json(
      permissions.map((p) => ({
        id: p.id,
        module: p.module,
        action: p.action,
      }))
    );
  } catch (e: any) {
    return res.status(500).json({
      message: e?.message || "Error listando permisos",
    });
  }
}
