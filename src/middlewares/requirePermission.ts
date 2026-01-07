// src/middlewares/requirePermission.ts
import type { Request, Response, NextFunction } from "express";
import { prisma } from "../lib/prisma.js";
import { OverrideEffect } from "@prisma/client";

/**
 * requirePermission(module, action)
 *
 * Regla:
 * - Permisos efectivos = roles + overrides
 * - DENY siempre gana sobre ALLOW
 * - Cache en req.permissions (por request)
 */
export function requirePermission(module: string, action: string) {
  const wanted = `${module}:${action}`;

  return async (req: Request, res: Response, next: NextFunction) => {
    const userId = req.userId;
    const tenantId = req.tenantId;

    if (!userId || !tenantId) {
      return res.status(401).json({ message: "No autenticado" });
    }

    // ✅ cache por request (siempre dejamos un array asignado)
    if (!req.permissions) {
      const user = await prisma.user.findFirst({
        where: { id: userId, jewelryId: tenantId },
        select: {
          roles: {
            include: {
              role: {
                select: {
                  deletedAt: true,
                  permissions: { include: { permission: true } },
                },
              },
            },
          },
          permissionOverrides: { include: { permission: true } },
        },
      });

      if (!user) {
        return res.status(401).json({ message: "Usuario no encontrado" });
      }

      const fromRoles: string[] = [];
      for (const ur of user.roles ?? []) {
        const role = ur.role;
        if (!role || role.deletedAt) continue;

        for (const rp of role.permissions ?? []) {
          fromRoles.push(`${rp.permission.module}:${rp.permission.action}`);
        }
      }

      const allow: string[] = [];
      const deny: string[] = [];
      for (const ov of user.permissionOverrides ?? []) {
        const p = `${ov.permission.module}:${ov.permission.action}`;
        if (ov.effect === OverrideEffect.ALLOW) allow.push(p);
        if (ov.effect === OverrideEffect.DENY) deny.push(p);
      }

      const effective = new Set<string>(fromRoles);
      for (const d of deny) effective.delete(d);
      for (const a of allow) effective.add(a);
      for (const d of deny) effective.delete(d);

      // ✅ SIEMPRE asignamos un array (evita TS18048)
      req.permissions = Array.from(effective);
    }

    // ✅ guard para TS (y por seguridad)
    const perms = req.permissions ?? [];

    if (!perms.includes(wanted)) {
      return res.status(403).json({
        message: "No tenés permisos para realizar esta acción.",
        required: wanted,
      });
    }

    return next();
  };
}
