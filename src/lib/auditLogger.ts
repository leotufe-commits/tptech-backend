// src/lib/auditLogger.ts
import type { Request } from "express";

type AuditEvent = {
  action: string;
  success: boolean;
  userId?: string;
  tenantId?: string;
  ip?: string;
  userAgent?: string;
  meta?: Record<string, any>;
  timestamp: string;
};

/**
 * Logger de auditoría de seguridad.
 * Por ahora escribe en consola, listo para:
 * - persistir en DB
 * - enviar a un servicio externo
 * - escribir a archivo
 */
export function auditLog(req: Request, event: Omit<AuditEvent, "timestamp">) {
  const log: AuditEvent = {
    timestamp: new Date().toISOString(),
    userId: req.userId,
    tenantId: req.tenantId,
    ip: req.ip,
    userAgent: req.headers["user-agent"],
    ...event,
  };

  console.log("🧾 AUDIT LOG:", JSON.stringify(log));
}
