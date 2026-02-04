// tptech-backend/src/controllers/permissions.controller.ts
import type { Request, Response } from "express";
import { prisma } from "../lib/prisma.js";
import { auditLog } from "../lib/auditLogger.js";

export async function listPermissions(req: Request, res: Response) {
  try {
    /**
     * ✅ Cache: el catálogo de permisos casi nunca cambia
     * - private: evita caches compartidas
     * - max-age: 10 min
     *
     * Importante: Vary para que no se mezclen respuestas entre sesiones.
     */
    res.setHeader("Cache-Control", "private, max-age=600");
    res.setHeader("Vary", "Authorization, Cookie");

    const permissions = await prisma.permission.findMany({
      select: {
        id: true,
        module: true,
        action: true,
      },
      orderBy: [{ module: "asc" }, { action: "asc" }],
    });

    type Row = (typeof permissions)[number];

    auditLog(req, {
      action: "permissions.list",
      success: true,
      userId: (req as any).userId as string | undefined,
      tenantId: (req as any).tenantId as string | undefined,
      meta: { count: permissions.length },
    });

    // Mantengo el formato actual (array) para no romper el frontend
    return res.json(
      permissions.map((p: Row) => ({
        id: p.id,
        module: p.module,
        action: p.action,
      }))
    );
  } catch (e: any) {
    auditLog(req, {
      action: "permissions.list",
      success: false,
      userId: (req as any).userId as string | undefined,
      tenantId: (req as any).tenantId as string | undefined,
      meta: { error: String(e?.message ?? e) },
    });

    return res.status(500).json({
      message: e?.message || "Error listando permisos",
    });
  }
}
