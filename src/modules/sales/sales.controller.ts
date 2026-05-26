import type { Response } from "express";
import * as service from "./sales.service.js";

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
