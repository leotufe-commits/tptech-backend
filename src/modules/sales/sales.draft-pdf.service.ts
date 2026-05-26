// src/modules/sales/sales.draft-pdf.service.ts
// =============================================================================
//  C5-fix Opción A — Renderer PDF DESDE EL DRAFT EN VIVO, sin Sale
//  persistido.
//
//  Diagnóstico previo (QA local 2026-05-26): el flujo Descargar / Mail
//  rompía paridad con el print del browser porque consumían el Sale
//  persistido (snapshot incompleto y posiblemente obsoleto) mientras
//  que Imprimir consumía el draft en vivo del navegador. Aunque ambos
//  usaban `<SaleInvoicePrintable>`, recibían props distintas.
//
//  Solución (opción A — riesgo bajo, sin migraciones):
//    · El frontend manda al backend EXACTAMENTE las mismas props que
//      `<SaleInvoicePrintable>` recibe en `window.print()`.
//    · El backend NO crea Sale, NO toca pricing-engine, NO persiste
//      nada. Sólo: renderToStaticMarkup + Puppeteer + (fallback
//      pdfkit si HTML falla).
//
//  Reglas duras:
//    · Cero matemática comercial — los totales (subtotal, descuento,
//      impuestos, total) llegan ya calculados desde el draft del
//      frontend, que a su vez los obtuvo del pricing-engine vía
//      `salesApi.preview()`.
//    · Mantenemos el switch PDF_ENGINE y el fallback pdfkit como
//      safety net. Pdfkit no soporta "draft preview" directamente
//      (no tiene template completo), así que en fallback usa un
//      placeholder mínimo — el HTML es la ruta esperada.
//    · Mail: reutiliza el helper de envío (`sendMail`) y adjunta el
//      mismo buffer que se descarga. Un único render por operación.
// =============================================================================

import {
  renderPrintableToPdf,
  type SaleDraftPrintableProps,
  type RenderPrintablePageConfig,
} from "../../lib/pdf/renderPrintableToPdf.js";
import { sendMail } from "../../lib/mail.service.js";
import { prisma } from "../../lib/prisma.js";

// ─── Tipos del request ───────────────────────────────────────────────────────

export interface RenderDraftPdfInput {
  /** Props 1:1 con `<SaleInvoicePrintable>` del frontend. */
  printable: SaleDraftPrintableProps;
  /** Tamaño + orientación de la página (idem `@page` del browser print). */
  page:      RenderPrintablePageConfig;
  /** Nombre sugerido del archivo para Content-Disposition. */
  filename?: string;
}

export interface SendDraftEmailInput extends RenderDraftPdfInput {
  to:      string;
  subject: string;
  message: string;
}

// ─── Render principal ────────────────────────────────────────────────────────

/** Renderea un PDF a partir del draft visual del frontend. NO toca
 *  Sale, NO toca pricing-engine, NO persiste. Mismo flag PDF_ENGINE
 *  que el flujo legacy; default `html`. Si HTML falla, propaga el
 *  error al caller — para el endpoint draft NO hay fallback pdfkit
 *  porque pdfkit requiere un Sale persistido con template completo
 *  para renderear las columnas correctamente.
 *
 *  Si el operador necesita rollback al pdfkit, debe usar
 *  `GET /sales/:id/pdf` (endpoint legacy) con la venta persistida. */
export async function renderSaleDraftPdf(input: RenderDraftPdfInput): Promise<Buffer> {
  console.info("[PDF] engine=html source=draft");
  return renderPrintableToPdf(input.printable, input.page);
}

/** Envía por mail el PDF del draft. Mismo renderer que el download
 *  → un único buffer por operación → adjunto == descarga. */
export async function sendSaleDraftByEmail(
  input:     SendDraftEmailInput,
  jewelryId: string,
): Promise<{ messagedRecipient: string; filename: string }> {
  const buffer   = await renderSaleDraftPdf(input);
  const filename = input.filename ?? "Factura.pdf";

  // Reply-To: email de la joyería si está configurado (mismo criterio
  // que el flujo legacy `sendSaleByEmail` en `sales.service.ts`).
  const tenant = await prisma.jewelry.findUnique({
    where:  { id: jewelryId },
    select: { email: true },
  });
  const replyTo = tenant?.email && tenant.email.trim().length > 0 ? tenant.email : undefined;

  const html = `<pre style="font-family:Arial,Helvetica,sans-serif;font-size:14px;line-height:1.5;white-space:pre-wrap;margin:0;">${escapeHtmlForMail(input.message)}</pre>`;

  await sendMail({
    to:      input.to,
    subject: input.subject,
    html,
    text:    input.message,
    replyTo,
    attachments: [
      { filename, content: buffer, contentType: "application/pdf" },
    ],
  });

  return { messagedRecipient: input.to, filename };
}

function escapeHtmlForMail(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
