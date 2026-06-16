// tptech-backend/src/lib/mail-branding.ts
// =============================================================================
// SSOT de la COMPOSICIÓN del cuerpo HTML de los mails de documentos del tenant.
// (Sprint 1 de Certificación — "Correos", alcance B-lite.)
//
// Un ÚNICO composer en el backend que ENVUELVE el mensaje del operador con el
// branding del tenant (firma, contacto, pie). Lo consumen los dos paths de
// envío de Factura (`sendSaleByEmail` y `sendSaleDraftByEmail`) para cumplir:
// "lo configurado en Configuración → Correos es lo que se envía".
//
// Reglas:
//   · El mensaje del operador se preserva INTACTO (escapado) dentro de un
//     <pre> — mismo comportamiento que antes de B-lite.
//   · Cada bloque de branding se agrega SOLO si tiene contenido. Sin branding
//     configurado → el HTML es exactamente el <pre> del mensaje (como antes).
//   · Función PURA: sin DB, sin env, sin React. La data de branding la provee
//     el SSOT `tenantMailContext.ts` (única lectura de la config del Jewelry).
//   · NO compone From/Reply-To (eso sigue siendo de tenantMailContext), NO
//     toca el PDF ni DocumentTemplate.
//
// NOTA (deuda conocida, fuera de alcance del Sprint 1): la equivalencia
// byte-a-byte entre este HTML y el "preview" del frontend (componente React de
// Correos) NO está garantizada. El preview es una maqueta visual; acá el
// contrato es "config = enviado" a nivel de datos. La paridad exacta de HTML
// requiere un composer compartido (tptech-shared) → futuro Sprint de Infra.
// =============================================================================

export type EmailBranding = {
  signature?:     string | null;
  contact?:       string | null;
  phone?:         string | null;
  whatsapp?:      string | null;
  addressLine?:   string | null;
  businessHours?: string | null;
  website?:       string | null;
  instagram?:     string | null;
  footer?:        string | null;
};

/** Escape HTML mínimo para interpolar texto del usuario/tenant en el mail. */
export function escapeHtmlForMail(s: string): string {
  return String(s ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

/**
 * Compone el cuerpo HTML del mail: mensaje del operador (intacto, escapado)
 * + branding del tenant (firma / contacto / pie) cuando está configurado.
 */
export function composeBrandedEmailHtml(opts: {
  message: string;
  branding?: EmailBranding | null;
}): string {
  const b = opts.branding ?? {};
  const t = (v?: string | null) => String(v ?? "").trim();

  const body =
    `<pre style="font-family:Arial,Helvetica,sans-serif;font-size:14px;line-height:1.5;white-space:pre-wrap;margin:0;">` +
    `${escapeHtmlForMail(opts.message ?? "")}</pre>`;

  const parts: string[] = [body];

  const signature = t(b.signature);
  if (signature) {
    parts.push(
      `<div style="margin-top:16px;padding-top:12px;border-top:1px solid #e5e7eb;` +
        `font-family:Arial,Helvetica,sans-serif;font-size:13px;color:#374151;` +
        `white-space:pre-wrap;">${escapeHtmlForMail(signature)}</div>`,
    );
  }

  const contactLine = [t(b.contact), t(b.phone), t(b.whatsapp)].filter(Boolean).join("  ·  ");
  const metaLine    = [t(b.addressLine), t(b.businessHours), t(b.website), t(b.instagram)].filter(Boolean).join("  ·  ");
  const footerText  = t(b.footer);

  if (contactLine || metaLine || footerText) {
    const foot: string[] = [];
    if (contactLine) foot.push(`<div>${escapeHtmlForMail(contactLine)}</div>`);
    if (metaLine)    foot.push(`<div>${escapeHtmlForMail(metaLine)}</div>`);
    if (footerText)  foot.push(`<div style="white-space:pre-wrap;">${escapeHtmlForMail(footerText)}</div>`);
    parts.push(
      `<div style="margin-top:16px;padding-top:12px;border-top:1px solid #e5e7eb;` +
        `font-family:Arial,Helvetica,sans-serif;font-size:11px;color:#6b7280;line-height:1.6;">` +
        `${foot.join("")}</div>`,
    );
  }

  return `<div style="font-family:Arial,Helvetica,sans-serif;font-size:14px;color:#111827;">${parts.join("")}</div>`;
}
