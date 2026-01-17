// tptech-backend/src/controllers/permissions.controller.ts
import type { Request, Response } from "express";
import { prisma } from "../lib/prisma.js";

export async function listPermissions(_req: Request, res: Response) {
  try {
    /**
     * ✅ Cache: el catálogo de permisos casi nunca cambia
     * - private: evita caches compartidas
     * - max-age: 10 min
     *
     * Si querés máxima seguridad (sin cache en browser):
     *   res.setHeader("Cache-Control", "no-store");
     */
    res.setHeader("Cache-Control", "private, max-age=600");

    const permissions = await prisma.permission.findMany({
      select: {
        id: true,
        module: true,
        action: true,
      },
      orderBy: [{ module: "asc" }, { action: "asc" }],
    });

    // Mantengo el formato actual (array) para no romper el frontend
    return res.json(
      permissions.map((p) => ({
        id: p.id,
        module: p.module,
        action: p.action,
      }))
    );

    // Alternativa (si algún día querés response envelope):
    // return res.json({ permissions });
  } catch (e: any) {
    return res.status(500).json({
      message: e?.message || "Error listando permisos",
    });
  }
}
