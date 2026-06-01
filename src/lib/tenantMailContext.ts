// tptech-backend/src/lib/tenantMailContext.ts
// =============================================================================
// SSOT del contexto de mail por tenant — Etapa 1 (mail sender real).
//
// Centraliza la resolucion del HEADER del mail (`From` visible + `Reply-To`)
// desde la configuracion comercial del Jewelry. Todos los flujos de envio
// (factura, futuro presupuesto / orden / nota de credito / remito) usan
// esta funcion — NUNCA leen los campos del Jewelry por su cuenta.
//
// Reglas:
//   · `From` visible se compone como `"<senderName> <fromEmail>"` cuando
//     hay `emailSenderName` configurado. Sin sender name cae al
//     `MAIL_FROM` plano (env del backend).
//   · `Reply-To` toma de `emailReplyTo` (campo dedicado). Si esta vacio
//     cae a `email` (legacy / contacto general). Si ambos estan vacios
//     queda `undefined` → el mail no incluye ese header.
//   · `emailEnabled = false` queda registrado en el resultado para que
//     el caller decida bloquear o solo loggear. Esta capa NO bloquea
//     por si misma — la decision es del caller (por hoy: factura
//     ignora el flag; etapas futuras pueden hacer un hard-block).
//
// Cero acoplamiento al pricing-engine o al renderer del PDF. Solo lee
// 3 campos del Jewelry + el env `MAIL_FROM`.
// =============================================================================

import { prisma } from "./prisma.js";

/**
 * Contexto resuelto para componer un mail desde el tenant.
 *
 *   · `from` — header `From` ya compuesto (ej. `"Joyería Pérez <no-reply@tptech.local>"`).
 *             Si el tenant no tiene `emailSenderName` configurado vuelve
 *             solo el `fromEmail` (sin display name).
 *             Si tampoco hay `MAIL_FROM` env: `undefined` → el caller debe
 *             dejar que `mail.service` use su default interno.
 *   · `replyTo` — header `Reply-To`. `undefined` si el tenant no configuro
 *             ningun mail de contacto (caso muy raro, joyeria recien creada).
 *   · `senderName` — nombre visible aislado (util para logs / debug).
 *   · `fromEmail` — direccion-email del remitente sin display name
 *             (la base de `from`).
 *   · `emailEnabled` — flag tenant-wide. False = la joyeria pidio
 *             apagar el envio de mails. El caller decide si bloquea.
 */
export type TenantMailContext = {
  from:         string | undefined;
  replyTo:      string | undefined;
  senderName:   string | undefined;
  fromEmail:    string | undefined;
  emailEnabled: boolean;
};

/**
 * Compone el header `From` siguiendo la convencion RFC 5322 — display
 * name entre comillas si contiene caracteres especiales, y angle brackets
 * alrededor del email.
 *
 * Helper PURO — no toca DB ni env. Testeable directo.
 *
 * Ejemplos:
 *   composeFromHeader("Joyería Pérez", "no-reply@tptech.local")
 *     → '"Joyería Pérez" <no-reply@tptech.local>'
 *   composeFromHeader("",              "no-reply@tptech.local")
 *     → 'no-reply@tptech.local'
 *   composeFromHeader("Joyería",       undefined)
 *     → undefined
 */
export function composeFromHeader(
  senderName: string | undefined | null,
  fromEmail:  string | undefined | null,
): string | undefined {
  const email = (fromEmail ?? "").trim();
  if (!email) return undefined;
  const name = (senderName ?? "").trim();
  if (!name) return email;
  // Quotear si tiene caracteres "especiales" del header (espacios cuentan
  // como suficiente justificacion para quotear). Postmark acepta ambos
  // formatos pero el quoteado es mas robusto frente a parsers estrictos.
  const needsQuoting = /[\s",<>()@\\]/.test(name);
  const safeName = needsQuoting
    ? `"${name.replace(/"/g, '\\"')}"`
    : name;
  return `${safeName} <${email}>`;
}

/**
 * Resuelve el header `Reply-To` del tenant. Fallback chain:
 *   1. `emailReplyTo` (campo dedicado, configurado en Configuracion → Mails).
 *   2. `email` (legacy / contacto general de la joyeria).
 *   3. `undefined` (no header Reply-To en el mail).
 *
 * Helper PURO — no toca DB.
 */
export function resolveReplyTo(
  emailReplyTo: string | undefined | null,
  legacyEmail:  string | undefined | null,
): string | undefined {
  const dedicated = (emailReplyTo ?? "").trim();
  if (dedicated) return dedicated;
  const legacy = (legacyEmail ?? "").trim();
  if (legacy) return legacy;
  return undefined;
}

/**
 * Lee el `MAIL_FROM` del env y normaliza:
 *   · trim
 *   · vacio → undefined (para que `mail.service` use su default interno)
 */
function readEnvFromEmail(): string | undefined {
  const raw = (process.env.MAIL_FROM ?? "").trim();
  return raw.length > 0 ? raw : undefined;
}

/**
 * Resuelve el TenantMailContext completo leyendo de la DB.
 *
 * Lee SOLO los 4 campos minimos de `Jewelry` necesarios para componer
 * el mail (siguiendo la regla de performance movil: `select` explicito
 * sin payloads innecesarios). Si el jewelryId no existe (caso ya
 * cubierto por requireAuth antes), devuelve un contexto vacio
 * (`from=undefined, replyTo=undefined, emailEnabled=true`) — el caller
 * deberia haber tirado 404 antes.
 *
 * El `fromEmail` viene del env `MAIL_FROM` (configurado por DevOps en
 * el dominio del proveedor de mail, ej. Postmark) — NO se persiste
 * por joyeria porque depende de la infra. La joyeria solo configura
 * el nombre visible (`emailSenderName`) y el `Reply-To` (que apunta
 * a su propia casilla).
 */
export async function resolveTenantMailContext(
  jewelryId: string,
): Promise<TenantMailContext> {
  const tenant = await prisma.jewelry.findUnique({
    where:  { id: jewelryId },
    select: {
      emailEnabled:    true,
      emailSenderName: true,
      emailReplyTo:    true,
      email:           true, // legacy / fallback de replyTo
    },
  });

  const fromEmail   = readEnvFromEmail();
  const senderName  = tenant?.emailSenderName?.trim() || undefined;
  const from        = composeFromHeader(senderName, fromEmail);
  const replyTo     = resolveReplyTo(tenant?.emailReplyTo, tenant?.email);

  return {
    from,
    replyTo,
    senderName,
    fromEmail,
    emailEnabled: tenant?.emailEnabled ?? true,
  };
}
