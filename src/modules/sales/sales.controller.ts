import type { Response } from "express";
import * as service from "./sales.service.js";
// C5-fix Opcion A — Endpoint render-only desde el draft del frontend.
// Vive en su propio service para no entrar en conflicto con cambios
// en curso de `sales.service.ts`.
import * as draftPdfService from "./sales.draft-pdf.service.js";

function s(v: any) { return String(v ?? "").trim(); }
function assert(cond: any, msg: string) {
  if (!cond) { const e: any = new Error(msg); e.status = 400; throw e; }
}

// P1: el motor de precios es la única fuente de verdad. Si el frontend manda
// estos campos en el body, los ignoramos y dejamos rastro en logs para
// detectar versiones de cliente desactualizadas o intentos de override.
const FORBIDDEN_TOTAL_FIELDS = ["subtotal", "discountAmount", "taxAmount", "total"] as const;
function warnIfTotalsInBody(scope: string, body: any) {
  if (!body || typeof body !== "object") return;
  const sent: Record<string, unknown> = {};
  for (const k of FORBIDDEN_TOTAL_FIELDS) {
    if (body[k] !== undefined) sent[k] = body[k];
  }
  if (Object.keys(sent).length > 0) {
    console.warn(
      `[${scope}] Cliente envió totales en el body — IGNORADOS. ` +
      `El backend recalcula desde el pricing-engine. Recibido: ${JSON.stringify(sent)}`,
    );
  }
}

export async function list(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  const skip = Math.max(0, parseInt(String(req.query.skip ?? "0"), 10) || 0);
  const take = Math.min(200, Math.max(1, parseInt(String(req.query.take ?? "50"), 10) || 50));
  return res.json(
    await service.listSales(req.user.jewelryId, {
      skip,
      take,
      status: s(req.query.status) || undefined,
      clientId: s(req.query.clientId) || undefined,
      sellerId: s(req.query.sellerId) || undefined,
      q: s(req.query.q) || undefined,
      dateFrom: s(req.query.dateFrom) || undefined,
      dateTo: s(req.query.dateTo) || undefined,
    })
  );
}

export async function getOne(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");
  return res.json(await service.getSale(id, req.user.jewelryId));
}

export async function create(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  const userId = s(req.userId || req.user?.id || "");
  warnIfTotalsInBody("sales.create", req.body);
  return res.status(201).json(await service.createSale(req.user.jewelryId, userId, req.body));
}

export async function update(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");
  warnIfTotalsInBody("sales.update", req.body);
  return res.json(await service.updateSale(id, req.user.jewelryId, req.body));
}

export async function confirm(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");
  const userId = s(req.userId || req.user?.id || "");
  warnIfTotalsInBody("sales.confirm", req.body);
  try {
    return res.json(await service.confirmSale(id, req.user.jewelryId, userId));
  } catch (e: any) {
    if (e.status === 422 && e.blockingAlerts) {
      return res.status(422).json({
        ok: false,
        message: e.message,
        blockingAlerts: e.blockingAlerts as string[],
      });
    }
    throw e;
  }
}

export async function addPayment(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");
  return res.json(await service.addPayment(id, req.user.jewelryId, req.body));
}

export async function cajaSummary(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  const date = s(req.query.date) || new Date().toISOString().slice(0, 10);
  return res.json(await service.cajaDaySummary(req.user.jewelryId, date));
}

export async function cancel(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");
  const userId = s(req.userId || req.user?.id || "");
  const note = s(req.body?.note ?? req.body?.cancelNote ?? "");
  return res.json(await service.cancelSale(id, req.user.jewelryId, userId, note));
}

// 1.B — Genera el PDF oficial de la factura. 409 si la venta no esta en un
// estado emitido (DRAFT o CANCELLED).
export async function downloadPdf(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");
  const { buffer, filename } = await service.generateSalePdf(id, req.user.jewelryId);
  res.setHeader("Content-Type",        "application/pdf");
  res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
  res.setHeader("Content-Length",      String(buffer.length));
  return res.send(buffer);
}

// 1.D — Envia el PDF oficial por mail al destinatario indicado.
// Validaciones inline (sin Zod para mantener simetria con los otros
// handlers del modulo). 409 SALE_NOT_CONFIRMED / SALE_CANCELLED /
// SALE_WITHOUT_RECEIPT_NUMBER segun el estado de la venta.
const EMAIL_RX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
export async function sendEmail(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");

  const to      = s(req.body?.to);
  const subject = s(req.body?.subject);
  const message = s(req.body?.message);
  assert(to,                "El destinatario (to) es requerido.");
  assert(EMAIL_RX.test(to), "El destinatario no es un email válido.");
  assert(subject,           "El asunto (subject) es requerido.");
  assert(message,           "El mensaje (message) es requerido.");

  await service.sendSaleByEmail(
    id,
    req.user.jewelryId,
    { to, subject, message },
    req.user?.id ?? null,
  );
  return res.json({ ok: true, message: "Factura enviada correctamente." });
}

// =============================================================================
// C5-fix Opción A — Endpoints render-only desde el draft del frontend.
//
// El frontend manda EXACTAMENTE las mismas props que pasa al
// `<SaleInvoicePrintable>` cuando hace `window.print()`. El backend
// solo renderea — no crea Sale, no toca pricing-engine, no persiste.
// Garantiza paridad visual Imprimir ↔ Descargar ↔ Mail.
// =============================================================================

/** Valida que el body tenga la forma mínima de `RenderDraftPdfInput`.
 *  No usa Zod para mantener el patrón inline del módulo. */
function validateRenderDraftBody(body: any): {
  printable: any;
  page:      { widthMm: number; heightMm: number; orientation?: "portrait" | "landscape" };
  filename?: string;
} {
  assert(body && typeof body === "object", "Body inválido.");
  assert(body.printable && typeof body.printable === "object", "Falta `printable` (props del componente).");
  assert(body.page && typeof body.page === "object", "Falta `page` (config de página).");
  const widthMm  = Number(body.page.widthMm);
  const heightMm = Number(body.page.heightMm);
  assert(widthMm > 0  && widthMm  < 2000, "`page.widthMm` inválido.");
  assert(heightMm > 0 && heightMm < 2000, "`page.heightMm` inválido.");

  const p = body.printable;
  assert(typeof p.documentNumber === "string", "Falta printable.documentNumber.");
  assert(typeof p.documentDate   === "string", "Falta printable.documentDate.");
  assert(typeof p.clientName     === "string", "Falta printable.clientName.");
  assert(Array.isArray(p.lines),                "Falta printable.lines (array).");
  assert(p.totals && typeof p.totals === "object", "Falta printable.totals.");
  assert(typeof p.totals.subtotal       === "number", "totals.subtotal debe ser numero.");
  assert(typeof p.totals.discountAmount === "number", "totals.discountAmount debe ser numero.");
  assert(typeof p.totals.taxAmount      === "number", "totals.taxAmount debe ser numero.");
  assert(typeof p.totals.total          === "number", "totals.total debe ser numero.");
  assert(typeof p.currencyCode === "string", "Falta printable.currencyCode.");

  return {
    printable: p,
    page: {
      widthMm,
      heightMm,
      orientation: body.page.orientation === "landscape" ? "landscape" : "portrait",
    },
    filename: typeof body.filename === "string" ? body.filename : undefined,
  };
}

export async function renderDraftPdf(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  const input    = validateRenderDraftBody(req.body);
  const buffer   = await draftPdfService.renderSaleDraftPdf(input);
  const filename = input.filename ?? "Factura.pdf";
  res.setHeader("Content-Type",        "application/pdf");
  res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
  res.setHeader("Content-Length",      String(buffer.length));
  return res.send(buffer);
}

export async function sendDraftEmail(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  const base = validateRenderDraftBody(req.body);

  const to      = s(req.body?.to);
  const subject = s(req.body?.subject);
  const message = s(req.body?.message);
  // E2 — `saleId` requerido. El frontend persiste el draft via
  // `ensurePersistedSaleDraft` antes de invocar este endpoint, y
  // manda el id resultante. Sin saleId no aceptamos el envío —
  // emails huérfanos rompen la trazabilidad documental.
  const saleId  = s(req.body?.saleId);

  assert(to,                "El destinatario (to) es requerido.");
  assert(EMAIL_RX.test(to), "El destinatario no es un email válido.");
  assert(subject,           "El asunto (subject) es requerido.");
  assert(message,           "El mensaje (message) es requerido.");
  assert(saleId,            "Falta `saleId` — el draft debe estar persistido antes de enviar el mail (E2).");

  await draftPdfService.sendSaleDraftByEmail(
    { ...base, to, subject, message, saleId },
    req.user.jewelryId,
    req.user?.id ?? null,
  );
  return res.json({ ok: true, message: "Factura enviada correctamente." });
}

// Preview — calcula precios + checkout sin crear la venta
export async function previewSale(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  const {
    lines, clientId, paymentMethodId, installmentsQty, channelId, couponCode,
    shippingAmount, globalDiscountAmount, globalDiscount,
    // Fase 2A.7 — override de lista de precios a nivel documento. Las líneas
    // pueden traer su propio `priceListIdOverride` con precedencia mayor.
    priceListId,
    // Fase MM — moneda en la que se quiere ver el response. SOLO afecta la
    // visualización del preview. Confirmación persiste en moneda base.
    currencyId,
    // Fase MM ext — cotización manual aplicada en el documento (`fxRate`
    // del frontend). Si viene válida, tiene precedencia sobre la última
    // tasa del catálogo `CurrencyRate`.
    currencyRate,
  } = req.body ?? {};
  assert(Array.isArray(lines) && lines.length > 0, "lines[] requerido.");
  const num = (v: any): number | undefined =>
    v == null ? undefined : (Number.isFinite(Number(v)) ? Number(v) : undefined);
  // Fase 5: resolver `globalDiscount` shape — frontend manda { type, value }.
  let gd: { type: "PERCENT" | "AMOUNT"; value: number } | null = null;
  if (globalDiscount && (globalDiscount.type === "PERCENT" || globalDiscount.type === "AMOUNT")) {
    const v = num(globalDiscount.value);
    if (v != null && v > 0) gd = { type: globalDiscount.type, value: v };
  }
  return res.json(
    await service.previewSale(req.user.jewelryId, {
      lines,
      clientId:             clientId        ?? null,
      paymentMethodId:      paymentMethodId ?? null,
      installmentsQty:      parseInt(String(installmentsQty ?? "0"), 10) || 0,
      channelId:            channelId       ?? null,
      couponCode:           couponCode      ?? null,
      shippingAmount:       num(shippingAmount),
      globalDiscountAmount: num(globalDiscountAmount),
      globalDiscount:       gd,
      priceListId:          priceListId     ?? null,
      currencyId:           currencyId      ?? null,
      currencyRate:         num(currencyRate) ?? null,
    }),
  );
}
