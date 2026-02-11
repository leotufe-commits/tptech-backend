// tptech-backend/src/lib/auditLogger.ts
import type { Request } from "express";

type AuditEventInput = {
  action: string;
  success: boolean;

  // opcionales → pueden venir del controller
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
 * - Permite override de userId/tenantId si se pasan manualmente
 */
export function auditLog(req: Request | null, event: AuditEventInput) {
  const log: AuditEvent = {
    timestamp: new Date().toISOString(),

    // prioridad:
    // 1) event.userId
    // 2) req.userId
    // 3) null
    userId:
      event.userId ??
      (req?.userId ?? null),

    tenantId:
      event.tenantId ??
      (req?.tenantId ?? null),

    ip:
      event.ip ??
      (req?.ip ?? null),

    userAgent:
      event.userAgent ??
      (req?.headers?.["user-agent"] ?? null),

    action: event.action,
    success: event.success,
    meta: event.meta ?? null,
  };

  console.log("🧾 AUDIT LOG:", JSON.stringify(log));
}
