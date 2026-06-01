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

import type {
  SaleDraftPrintableProps,
  RenderPrintablePageConfig,
} from "../../lib/pdf/renderPrintableToPdf.js";
import { sendMail } from "../../lib/mail.service.js";
// Etapa 1 (mail sender real) — SSOT del header de mail por tenant.
// Mismo modulo que usa `sendSaleByEmail` (sales.service.ts) — garantiza
// que ambos flujos componen From/Reply-To identicos.
import { resolveTenantMailContext } from "../../lib/tenantMailContext.js";
// Etapa 2 (PDF unico canonico) — provider fachada que sirve tanto al
// flujo legacy (Sale persistido) como al draft. Aca usamos solo el path
// `renderFromDraft`. Si en un futuro queremos consolidar ambos flujos en
// un endpoint unico, este es el unico lugar a tocar.
import { renderFromDraft } from "../../lib/saleInvoicePdfProvider.js";
// E2 — Log documental del envío. Inmutable, sin propagar errores —
// si el log falla, el envío sigue ok. El log NO impacta el flujo.
import { createDocumentEmailLog } from "../../lib/document-email-log.js";

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
  /** E2 — REQUERIDO. Anchor al Sale persistido para que el log
   *  documental tenga referencia trazable. El frontend persiste el
   *  draft via `ensurePersistedSaleDraft` antes de invocar este flujo
   *  → emails huérfanos sin documento ya no son aceptados. */
  saleId:  string;
}

// ─── Render principal ────────────────────────────────────────────────────────

/** Renderea un PDF a partir del draft visual del frontend. NO toca
 *  Sale, NO toca pricing-engine, NO persiste.
 *
 *  Etapa 2 — Esta funcion ahora es un wrapper delgado sobre el provider
 *  canonico (`saleInvoicePdfProvider.renderFromDraft`). Mantenemos la
 *  firma `(input) → Buffer` para back-compat con el controller
 *  (`renderDraftPdf`) y con los tests existentes. El log `[PDF] engine=
 *  html source=draft` se emite ahora dentro del provider — un unico
 *  punto de logging por origen de PDF. */
export async function renderSaleDraftPdf(input: RenderDraftPdfInput): Promise<Buffer> {
  const { buffer } = await renderFromDraft({
    printable: input.printable,
    page:      input.page,
    filename:  input.filename,
  });
  return buffer;
}

/** Envía por mail el PDF del draft. Mismo renderer que el download
 *  → un único buffer por operación → adjunto == descarga.
 *
 *  E2 — Después del envío (OK o no), persiste un log documental
 *  inmutable en `DocumentEmailLog`. El log NUNCA rompe el envío:
 *  el helper `createDocumentEmailLog` traga errores internamente. */
export async function sendSaleDraftByEmail(
  input:        SendDraftEmailInput,
  jewelryId:    string,
  sentByUserId?: string | null,
): Promise<{ messagedRecipient: string; filename: string }> {
  // Etapa 2 — Mismo provider canonico que `renderSaleDraftPdf` arriba.
  // El adjunto del mail draft sale del MISMO render que la descarga
  // draft → byte-equivalente. Devolvemos `filename` resuelto por el
  // provider en lugar de duplicarlo aca (default "Factura.pdf").
  const result   = await renderFromDraft({
    printable: input.printable,
    page:      input.page,
    filename:  input.filename,
  });
  const buffer   = result.buffer;
  const filename = result.filename;

  // Etapa 1 — From/Reply-To desde el SSOT del tenant (mismo helper que
  // `sendSaleByEmail` en `sales.service.ts`). Garantiza headers consistentes
  // entre ambos flujos (legacy y draft) y prepara el terreno para que
  // futuros documentos (presupuestos / ordenes / NC / remitos) usen la
  // misma resolucion de branding del tenant.
  const mailCtx = await resolveTenantMailContext(jewelryId);

  const html = `<pre style="font-family:Arial,Helvetica,sans-serif;font-size:14px;line-height:1.5;white-space:pre-wrap;margin:0;">${escapeHtmlForMail(input.message)}</pre>`;

  let mailResult: { messageId: string | null } = { messageId: null };
  let sendError:  Error | null = null;
  try {
    mailResult = await sendMail({
      to:      input.to,
      subject: input.subject,
      html,
      text:    input.message,
      from:    mailCtx.from,
      replyTo: mailCtx.replyTo,
      attachments: [
        { filename, content: buffer, contentType: "application/pdf" },
      ],
    });
  } catch (err) {
    sendError = err instanceof Error ? err : new Error(String(err));
  }

  // E2 — Log documental. Inmutable. NUNCA propaga errores (el helper
  // traga la excepción y devuelve null) → si la DB falla, el envío
  // sigue su curso (caller recibe el sendError si lo hubo, o el OK).
  await createDocumentEmailLog({
    jewelryId,
    documentKind:       "SALE_INVOICE",
    documentId:         input.saleId,
    saleId:             input.saleId,
    recipientEmail:     input.to,
    subjectSnapshot:    input.subject,
    bodySnapshot:       input.message,
    attachmentFilename: filename,
    provider:           "postmark",
    providerMessageId:  mailResult.messageId,
    status:             sendError ? "FAILED" : "SENT",
    sentByUserId:       sentByUserId ?? null,
  });

  // Si el envío falló, propagamos el error al caller DESPUÉS de
  // haber persistido el log FAILED — así el operador ve el toast
  // de error Y la auditoría queda registrada.
  if (sendError) throw sendError;

  return { messagedRecipient: input.to, filename };
}

function escapeHtmlForMail(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
