import type { Request, Response } from "express";
import { prisma } from "../lib/prisma.js";
import { auditLog } from "../lib/auditLogger.js";

/* =========================
   HELPERS
========================= */
function requireTenantId(req: Request, res: Response): string | null {
  const tenantId = (req as any).tenantId as string | undefined;
  if (!tenantId) {
    res.status(400).json({ message: "Tenant no definido en el request." });
    return null;
  }
  return String(tenantId);
}

function clampInt(v: any, def: number, min: number, max: number) {
  const n = Number(v);
  if (!Number.isFinite(n)) return def;
  return Math.max(min, Math.min(max, Math.trunc(n)));
}

/* =========================
   GET /company/settings/security
========================= */
export async function getSecuritySettings(req: Request, res: Response) {
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  const jewelry = await prisma.jewelry.findUnique({
    where: { id: tenantId },
    select: {
      id: true,
      quickSwitchEnabled: true,
      pinLockEnabled: true,
      pinLockTimeoutSec: true,
      pinLockRequireOnUserSwitch: true,
    },
  });

  if (!jewelry) {
    return res.status(404).json({ message: "Joyería no encontrada." });
  }

  return res.json({
    security: {
      quickSwitchEnabled: Boolean(jewelry.quickSwitchEnabled),
      pinLockEnabled: Boolean(jewelry.pinLockEnabled),
      pinLockTimeoutSec: Number(jewelry.pinLockTimeoutSec ?? 300),
      pinLockRequireOnUserSwitch: Boolean(jewelry.pinLockRequireOnUserSwitch),
    },
  });
}

/* =========================
   PATCH /company/settings/security
========================= */
export async function updateSecuritySettings(req: Request, res: Response) {
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  const actorId = (req as any).userId as string | undefined;

  const body = (req.body ?? {}) as Partial<{
    quickSwitchEnabled: boolean;
    pinLockEnabled: boolean;
    pinLockTimeoutSec: number;
    pinLockRequireOnUserSwitch: boolean;
  }>;

  const data: {
    quickSwitchEnabled?: boolean;
    pinLockEnabled?: boolean;
    pinLockTimeoutSec?: number;
    pinLockRequireOnUserSwitch?: boolean;
  } = {};

  if ("quickSwitchEnabled" in body) {
    if (typeof body.quickSwitchEnabled !== "boolean") {
      return res.status(400).json({ message: "quickSwitchEnabled debe ser boolean." });
    }
    data.quickSwitchEnabled = body.quickSwitchEnabled;
  }

  if ("pinLockEnabled" in body) {
    if (typeof body.pinLockEnabled !== "boolean") {
      return res.status(400).json({ message: "pinLockEnabled debe ser boolean." });
    }
    data.pinLockEnabled = body.pinLockEnabled;
  }

  if ("pinLockTimeoutSec" in body) {
    data.pinLockTimeoutSec = clampInt(body.pinLockTimeoutSec, 300, 10, 60 * 60 * 12);
  }

  if ("pinLockRequireOnUserSwitch" in body) {
    if (typeof body.pinLockRequireOnUserSwitch !== "boolean") {
      return res
        .status(400)
        .json({ message: "pinLockRequireOnUserSwitch debe ser boolean." });
    }
    data.pinLockRequireOnUserSwitch = body.pinLockRequireOnUserSwitch;
  }

  if (!Object.keys(data).length) {
    return res.status(400).json({ message: "No hay campos para actualizar." });
  }

  const updated = await prisma.jewelry.update({
    where: { id: tenantId },
    data,
    select: {
      id: true,
      quickSwitchEnabled: true,
      pinLockEnabled: true,
      pinLockTimeoutSec: true,
      pinLockRequireOnUserSwitch: true,
    },
  });

  auditLog(req, {
    action: "company.settings.security.update",
    success: true,
    userId: actorId,
    tenantId,
    meta: { fields: Object.keys(data) },
  });

  return res.json({
    ok: true,
    security: {
      quickSwitchEnabled: Boolean(updated.quickSwitchEnabled),
      pinLockEnabled: Boolean(updated.pinLockEnabled),
      pinLockTimeoutSec: Number(updated.pinLockTimeoutSec ?? 300),
      pinLockRequireOnUserSwitch: Boolean(updated.pinLockRequireOnUserSwitch),
    },
  });
}
