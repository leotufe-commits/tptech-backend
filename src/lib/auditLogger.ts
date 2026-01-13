import type { Request } from "express";

type AuditEventInput = {
  action: string;
  success: boolean;
  userId?: string | null;
  tenantId?: string | null;
  ip?: string | null;
  userAgent?: string | null;
  meta?: unknown;
};

type AuditEvent = AuditEventInput & {
  timestamp: string;
};

/**
 * Logger de auditoría de seguridad.
 * - Seguro para TypeScript
 * - Compatible con Prisma JsonValue
 * - No rompe consola ni DB
 */
export function auditLog(req: Request, event: AuditEventInput) {
  const log: AuditEvent = {
    timestamp: new Date().toISOString(),
    userId: req.userId ?? null,
    tenantId: req.tenantId ?? null,
    ip: req.ip ?? null,
    userAgent: req.headers["user-agent"] ?? null,
    ...event,
  };

  console.log("🧾 AUDIT LOG:", JSON.stringify(log));
}
