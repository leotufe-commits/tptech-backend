// tptech-backend/src/lib/auditLogger.ts
import type { Request } from "express";

export type AuditEventInput = {
  action: string;
  success: boolean;

  /**
   * ✅ opcionales (desde controller/service)
   * Importante: evitamos "null" en el tipo para no propagar string|null a otros lados.
   * Si viene null desde algún lado viejo, lo normalizamos.
   */
  userId?: string;
  tenantId?: string; // (tenant = jewelry)
  jewelryId?: string; // alias opcional

  ip?: string;
  userAgent?: string;

  meta?: unknown;
};

type AuditEvent = {
  timestamp: string;
  action: string;
  success: boolean;

  userId: string | null;
  tenantId: string | null;

  ip: string | null;
  userAgent: string | null;

  meta: unknown | null;
};

function isReq(x: any): x is Request {
  return x && typeof x === "object" && typeof x.method === "string" && typeof x.get === "function";
}

function sOrNull(v: any): string | null {
  const s = typeof v === "string" ? v.trim() : "";
  return s ? s : null;
}

/**
 * ✅ Backward compatible:
 * - auditLog(req, event)   (nuevo)
 * - auditLog(event)        (viejo)
 */
export function auditLog(req: Request | null, event: AuditEventInput): void;
export function auditLog(event: AuditEventInput): void;
export function auditLog(a: Request | null | AuditEventInput, b?: AuditEventInput) {
  const req: Request | null = isReq(a) ? (a as Request) : null;
  const event: AuditEventInput = (isReq(a) ? b : a) as AuditEventInput;

  if (!event || typeof event !== "object") return;

  // ✅ Leemos user/tenant del req de forma segura (tu auth mete algo en req as any)
  const reqAny = req as any;

  const reqUserId = sOrNull(reqAny?.user?.id ?? reqAny?.userId);
  const reqTenantId =
    sOrNull(reqAny?.user?.jewelryId ?? reqAny?.tenantId ?? reqAny?.jewelryId);

  const tenantFromEvent = sOrNull((event as any).tenantId ?? (event as any).jewelryId);

  const log: AuditEvent = {
    timestamp: new Date().toISOString(),

    action: String(event.action || "").trim(),
    success: Boolean(event.success),

    // prioridad: event.userId -> req.userId -> null
    userId: sOrNull((event as any).userId) ?? reqUserId,

    // prioridad: event.tenantId/jewelryId -> req.tenantId/jewelryId -> null
    tenantId: tenantFromEvent ?? reqTenantId,

    ip:
      sOrNull((event as any).ip) ??
      sOrNull(reqAny?.headers?.["x-forwarded-for"]?.toString()?.split(",")?.[0]) ??
      sOrNull(reqAny?.ip),

    userAgent:
      sOrNull((event as any).userAgent) ??
      sOrNull(reqAny?.headers?.["user-agent"]),

    meta: (event as any).meta ?? null,
  };

  // ✅ Por ahora lo dejás en consola (como lo tenías)
  console.log("🧾 AUDIT LOG:", JSON.stringify(log));
}