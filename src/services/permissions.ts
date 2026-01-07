// src/middlewares/requirePermission.ts
import type { Request, Response, NextFunction } from "express";
import { prisma } from "../lib/prisma.js";
import { formatPerm, computeEffectivePermissions } from "../services/permissions.js";

declare global {
  namespace Express {
    interface Request {
      permissions?: string[];
    }
  }
}

export function requirePermission(module: string, action: string) {
  const needed = formatPerm(module, action);

  return async function (req: Request, res: Response, next: NextFunction) {
    const userId = req.userId;
    if (!userId) return res.status(401).json({ message: "Unauthorized" });

    // cache por request
    if (!req.permissions) {
      const user = await prisma.user.findUnique({
        where: { id: userId },
        include: {
          roles: {
            include: {
              role: {
                include: {
                  permissions: { include: { permission: true } },
                },
              },
            },
          },
          permissionOverrides: { include: { permission: true } },
        },
      });

      if (!user) return res.status(401).json({ message: "Unauthorized" });
      req.permissions = computeEffectivePermissions(user as any);
    }

    if (!req.permissions.includes(needed)) {
      return res.status(403).json({ message: "Forbidden" });
    }

    return next();
  };
}
