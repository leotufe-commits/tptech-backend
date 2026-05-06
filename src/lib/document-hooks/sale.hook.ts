// src/lib/document-hooks/sale.hook.ts
// ============================================================================
// onSaleConfirmed — hook transaccional que emite comprobante + movimiento de
// cuenta corriente a partir de una venta ya confirmada.
//
// Contrato transaccional (ver ARCHITECTURE-RECEIPTS-PAYMENTS.md §6.0):
//   - Recibe un Prisma.TransactionClient; NUNCA abre su propia transacción.
//   - Snapshot + Receipt + ReceiptLine + CurrentAccountMovement se crean en la
//     misma tx, o no se crea nada.
//   - El número de serie se incrementa atómicamente dentro de la misma tx.
//   - Las fallas aborta toda la tx (Postgres revierte el incremento).
//
// Reglas de signo de cuenta corriente (ver §4.1):
//   Factura emitida a cliente (OUTBOUND INVOICE) → DEBIT = aumenta deuda del cliente.
// ============================================================================

import { Prisma } from "@prisma/client";
import {
  buildDocumentPricingSnapshot,
  type BuildSnapshotInput,
  type DocumentLineInput,
  type DocumentLineSnapshot,
  type SnapshotTaxBreakdownItem,
  type PricingLineSnapshot,
} from "../pricing-engine/pricing-engine.js";

// ─────────────────────────────────────────────────────────────────────────────
// Tipos públicos
// ─────────────────────────────────────────────────────────────────────────────

export interface OnSaleConfirmedOpts {
  /** true = emite INVOICE automáticamente. Default true. */
  issueInvoice?: boolean;
  /** seriesId explícito para la factura. Si no se pasa se autoresuelve/provisiona. */
  invoiceSeriesId?: string;
  /** userId que emite el comprobante (se guarda en Receipt.issuedById) */
  issuedById?: string | null;
  /** Notas opcionales del comprobante */
  notes?: string;
}

export interface OnSaleConfirmedResult {
  receipts: Array<{ id: string; code: string; type: string; total: number }>;
  accountMovements: Array<{ id: string; kind: "DEBIT" | "CREDIT"; amountBase: number }>;
}

// ─────────────────────────────────────────────────────────────────────────────
// Entry point
// ─────────────────────────────────────────────────────────────────────────────

export async function onSaleConfirmed(
  tx: Prisma.TransactionClient,
  saleId: string,
  opts: OnSaleConfirmedOpts = {},
): Promise<OnSaleConfirmedResult> {
  const issueInvoice = opts.issueInvoice !== false;
  if (!issueInvoice) {
    return { receipts: [], accountMovements: [] };
  }

  // 1. Cargar la venta confirmada con todo el contexto necesario.
  const sale = await loadSale(tx, saleId);

  // 2. Construir el DocumentPricingSnapshot a partir de los datos persistidos.
  const snapshotInput = buildSnapshotInputFromSale(sale);
  const snapshot = buildDocumentPricingSnapshot(snapshotInput);

  // 3. Resolver o auto-provisionar la ReceiptSeries.
  const series = await resolveInvoiceSeries(tx, sale.jewelryId, opts.invoiceSeriesId ?? null);

  // 4. Incrementar atómicamente el número de la serie y reservarlo.
  const updatedSeries = await tx.receiptSeries.update({
    where: { id: series.id },
    data:  { nextNumber: { increment: 1 } },
    select: { nextNumber: true, prefix: true, pointOfSale: true },
  });
  const reservedNumber = updatedSeries.nextNumber - 1;
  const code = formatReceiptCode(updatedSeries.prefix, updatedSeries.pointOfSale, reservedNumber);

  // 5. Crear el Receipt (INVOICE).
  const receipt = await tx.receipt.create({
    data: {
      jewelryId:       sale.jewelryId,
      seriesId:        series.id,
      code,
      type:            "INVOICE",
      direction:       "OUTBOUND",
      status:          "ISSUED",
      saleId:          sale.id,
      purchaseId:      null,
      counterpartyId:  sale.clientId,
      pricingSnapshot: snapshot as unknown as Prisma.InputJsonValue,
      currencySnapshot: snapshot.currency as unknown as Prisma.InputJsonValue,
      currencyCode:    snapshot.currency.currencyCode,
      currencyRate:    new Prisma.Decimal(String(snapshot.currency.currencyRate)),
      subtotal:        new Prisma.Decimal(String(snapshot.totals.subtotal)),
      discountAmount:  new Prisma.Decimal(String(snapshot.totals.discountAmount)),
      taxAmount:       new Prisma.Decimal(String(snapshot.totals.taxAmount)),
      total:           new Prisma.Decimal(String(snapshot.totals.total)),
      totalBase:       new Prisma.Decimal(String(snapshot.totals.totalBase)),
      issueDate:       sale.saleDate ?? new Date(),
      issuedAt:        new Date(),
      issuedById:      opts.issuedById ?? null,
      notes:           opts.notes ?? "",
    },
    select: { id: true, code: true, type: true, total: true },
  });

  // 6. Crear ReceiptLine[] a partir del snapshot.
  if (snapshot.lines.length > 0) {
    await tx.receiptLine.createMany({
      data: snapshot.lines.map((l) => toReceiptLineRow(receipt.id, sale.jewelryId, l)),
    });
  }

  // 7. Crear CurrentAccountMovement (DEBIT = aumenta deuda del cliente) si hay
  //    contraparte identificada. Consumidor final sin FK de cliente no genera
  //    movimiento (el receipt queda pero fuera de cuenta corriente).
  const accountMovements: OnSaleConfirmedResult["accountMovements"] = [];
  if (sale.clientId) {
    const mov = await tx.currentAccountMovement.create({
      data: {
        jewelryId:        sale.jewelryId,
        entityId:         sale.clientId,
        kind:             "DEBIT",
        source:           "RECEIPT",
        receiptId:        receipt.id,
        amountBase:       new Prisma.Decimal(String(snapshot.totals.totalBase)),
        amountOriginal:   new Prisma.Decimal(String(snapshot.totals.total)),
        currencySnapshot: snapshot.currency as unknown as Prisma.InputJsonValue,
        currencyCode:     snapshot.currency.currencyCode,
        currencyRate:     new Prisma.Decimal(String(snapshot.currency.currencyRate)),
        movementDate:     sale.saleDate ?? new Date(),
        notes:            `Receipt ${code}`,
      },
      select: { id: true, kind: true, amountBase: true },
    });
    accountMovements.push({
      id:         mov.id,
      kind:       mov.kind,
      amountBase: parseFloat(mov.amountBase.toString()),
    });
  }

  return {
    receipts: [{
      id:    receipt.id,
      code:  receipt.code,
      type:  receipt.type,
      total: parseFloat(receipt.total.toString()),
    }],
    accountMovements,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Loaders & helpers
// ─────────────────────────────────────────────────────────────────────────────

type LoadedSale = Awaited<ReturnType<typeof loadSale>>;

async function loadSale(tx: Prisma.TransactionClient, saleId: string) {
  const sale = await tx.sale.findUnique({
    where: { id: saleId },
    select: {
      id: true,
      jewelryId: true,
      code: true,
      clientId: true,
      saleDate: true,
      subtotal: true,
      discountAmount: true,
      taxAmount: true,
      total: true,
      currencyId: true,
      currencySnapshot: true,
      clientSnapshot: true,
      channelSnapshot: true,
      couponSnapshot: true,
      issuerSnapshot: true,
      jewelry: {
        select: {
          id: true, name: true, cuit: true, ivaCondition: true,
        },
      },
      client: {
        select: {
          id: true, displayName: true, isClient: true, isSupplier: true,
          documentType: true, documentNumber: true, ivaCondition: true,
        },
      },
      channel: {
        select: { id: true, name: true, adjustmentType: true, adjustmentValue: true },
      },
      coupon: {
        select: { id: true, code: true, name: true, discountType: true, discountValue: true },
      },
      lines: {
        select: {
          id: true,
          articleId: true,
          variantId: true,
          articleName: true,
          variantName: true,
          sku: true,
          barcode: true,
          quantity: true,
          unitPrice: true,
          discountPct: true,
          lineTotal: true,
          priceSource: true,
          appliedPriceListId: true,
          appliedPromotionId: true,
          appliedDiscountId: true,
          unitCost: true,
          totalCost: true,
          unitMargin: true,
          totalMargin: true,
          marginPercent: true,
          taxAmount: true,
          breakdownSnapshot: true,
          taxSnapshot: true,
          pricingSnapshot: true,
          sortOrder: true,
          article: {
            select: { id: true, code: true, articleType: true, commercialMode: true },
          },
        },
        orderBy: { sortOrder: "asc" as const },
      },
    },
  });

  if (!sale) {
    const err: any = new Error(`Sale ${saleId} no encontrada.`);
    err.status = 404;
    throw err;
  }
  return sale;
}

/** Busca una serie INVOICE+OUTBOUND para el tenant; si no existe, la crea. */
async function resolveInvoiceSeries(
  tx: Prisma.TransactionClient,
  jewelryId: string,
  explicitSeriesId: string | null,
): Promise<{ id: string }> {
  if (explicitSeriesId) {
    const series = await tx.receiptSeries.findFirst({
      where: { id: explicitSeriesId, jewelryId, deletedAt: null },
      select: { id: true },
    });
    if (!series) {
      const err: any = new Error("ReceiptSeries no encontrada o inactiva.");
      err.status = 404;
      throw err;
    }
    return series;
  }

  const existing = await tx.receiptSeries.findFirst({
    where: {
      jewelryId,
      type:      "INVOICE",
      direction: "OUTBOUND",
      isActive:  true,
      deletedAt: null,
    },
    orderBy: { createdAt: "asc" as const },
    select: { id: true },
  });
  if (existing) return existing;

  // Auto-provision: tenant aún no configuró series. Crea una por defecto.
  const created = await tx.receiptSeries.create({
    data: {
      jewelryId,
      name:        "Factura A — Punto de venta 0001",
      type:        "INVOICE",
      direction:   "OUTBOUND",
      prefix:      "A",
      pointOfSale: "0001",
      nextNumber:  1,
    },
    select: { id: true },
  });
  return created;
}

function formatReceiptCode(prefix: string, pointOfSale: string, number: number): string {
  const numberPart = String(number).padStart(8, "0");
  const prefixPart = prefix ? `${prefix}-` : "";
  return `${prefixPart}${pointOfSale}-${numberPart}`;
}

// ─────────────────────────────────────────────────────────────────────────────
// Conversión Sale → BuildSnapshotInput
// ─────────────────────────────────────────────────────────────────────────────

function buildSnapshotInputFromSale(sale: LoadedSale): BuildSnapshotInput {
  const currency = extractCurrency(sale);

  const lines: DocumentLineInput[] = sale.lines.map((l) => {
    const itemKind = detectItemKind(l);
    const quantity  = toNum(l.quantity);
    const unitPrice = toNum(l.unitPrice);
    const subtotal  = quantity * unitPrice;
    const lineTotal = toNum(l.lineTotal);
    const discountLine = round2(subtotal - lineTotal);
    const lineTaxAmount = l.taxAmount != null ? toNum(l.taxAmount) : 0;

    // Intenta reusar el PricingLineSnapshot ya persistido; si no hay, arma uno mínimo.
    const linePricing: PricingLineSnapshot = (l.pricingSnapshot as any as PricingLineSnapshot | null)
      ?? buildFallbackLinePricing(l, unitPrice, lineTotal, discountLine, lineTaxAmount);

    // taxBreakdown por línea: si hay taxSnapshot lo usamos; si no, array vacío.
    const taxBreakdown = Array.isArray(l.taxSnapshot)
      ? (l.taxSnapshot as any as SnapshotTaxBreakdownItem[])
      : [];

    return {
      itemKind,
      articleId: l.articleId,
      variantId: l.variantId,
      code:      l.article?.code ?? "",
      sku:       l.sku ?? "",
      barcode:   l.barcode ?? "",
      name:      [l.articleName, l.variantName].filter(Boolean).join(" — ") || l.articleName || "",
      sortOrder: l.sortOrder ?? 0,

      linePricing,

      quantity,
      subtotal:        round2(subtotal),
      discountLine:    round2(discountLine),
      lineTotal:       round2(lineTotal),
      lineTaxAmount:   round2(lineTaxAmount),
      lineTotalWithTax: round2(lineTotal + lineTaxAmount),
      totalCost:       l.totalCost   != null ? toNum(l.totalCost)   : null,
      totalMargin:     l.totalMargin != null ? toNum(l.totalMargin) : null,

      taxBreakdown,
    };
  });

  const totals = computeTotalsFromLines(lines, sale, currency.currencyRate);
  const cost   = computeCostAggregates(lines, totals.subtotal);

  return {
    currency,
    issuer: extractIssuer(sale),
    counterparty: extractCounterparty(sale),
    channel: extractChannel(sale),
    coupon:  extractCoupon(sale),
    promotion: null,            // se detectará en Fase 6 cuando entre el flujo multi-línea
    quantityDiscount: null,     // idem
    paymentMethod: null,        // se poblará cuando llegue la capa de pago (Fase 6)
    rounding: {
      source:    "NONE",
      appliedOn: "NONE",
      mode:      "NONE",
      direction: "NONE",
      adjustment: 0,
    },
    taxBreakdown: aggregateTaxBreakdown(lines),
    totals,
    cost,
    lines,
  };
}

function detectItemKind(l: LoadedSale["lines"][number]): DocumentLineInput["itemKind"] {
  if (l.article?.commercialMode === "COMBO_COMMERCIAL") return "COMBO";
  if (l.article?.articleType === "SERVICE") return "SERVICE";
  if (l.variantId) return "ARTICLE_VARIANT";
  return "ARTICLE_SIMPLE";
}

function buildFallbackLinePricing(
  l: LoadedSale["lines"][number],
  unitPrice: number,
  lineTotal: number,
  discountAmount: number,
  taxAmount: number,
): PricingLineSnapshot {
  return {
    unitPrice,
    basePrice:      unitPrice,
    discountAmount,
    taxAmount,
    totalWithTax:   lineTotal + taxAmount,
    priceSource:    l.priceSource ?? "",
    baseSource:     "",
    unitCost:       l.unitCost     != null ? toNum(l.unitCost)     : null,
    unitMargin:     l.unitMargin   != null ? toNum(l.unitMargin)   : null,
    marginPercent:  l.marginPercent != null ? toNum(l.marginPercent) : null,
    costPartial:    false,
    costMode:       "",
    partial:        false,
    appliedPriceListId:   l.appliedPriceListId ?? null,
    appliedPriceListName: null,
    appliedPromotionId:   l.appliedPromotionId ?? null,
    appliedPromotionName: null,
    appliedDiscountId:    l.appliedDiscountId  ?? null,
    resolvedAt:     new Date().toISOString(),
  };
}

function extractCurrency(sale: LoadedSale): BuildSnapshotInput["currency"] {
  const snap = sale.currencySnapshot as any;
  if (snap && typeof snap === "object" && snap.currencyCode) {
    return {
      id:               snap.id ?? sale.currencyId ?? "",
      currencyCode:     snap.currencyCode ?? "",
      symbol:           snap.symbol ?? "",
      currencyRate:     toNum(snap.currencyRate ?? snap.rateToBase ?? 1),
      baseCurrencyCode: snap.baseCurrencyCode ?? snap.currencyCode ?? "",
    };
  }
  // Fallback: no hay snapshot de moneda. Usamos identidad (rate=1).
  return {
    id:               sale.currencyId ?? "",
    currencyCode:     "",
    symbol:           "",
    currencyRate:     1,
    baseCurrencyCode: "",
  };
}

function extractIssuer(sale: LoadedSale): BuildSnapshotInput["issuer"] {
  const snap = sale.issuerSnapshot as any;
  if (snap && typeof snap === "object") {
    return {
      jewelryId:    snap.jewelryId ?? sale.jewelryId,
      name:         snap.name ?? sale.jewelry.name,
      cuit:         snap.cuit ?? sale.jewelry.cuit ?? "",
      ivaCondition: snap.ivaCondition ?? sale.jewelry.ivaCondition ?? "",
    };
  }
  return {
    jewelryId:    sale.jewelryId,
    name:         sale.jewelry.name,
    cuit:         sale.jewelry.cuit ?? "",
    ivaCondition: sale.jewelry.ivaCondition ?? "",
  };
}

function extractCounterparty(sale: LoadedSale): BuildSnapshotInput["counterparty"] {
  const snap = sale.clientSnapshot as any;
  if (snap && typeof snap === "object" && (snap.displayName || snap.id)) {
    return {
      entityId:     snap.id ?? sale.clientId ?? null,
      kind:         "CLIENT",
      displayName:  snap.displayName ?? "",
      docType:      snap.documentType ?? "",
      docNumber:    snap.documentNumber ?? "",
      ivaCondition: snap.ivaCondition ?? "",
    };
  }
  if (sale.client) {
    return {
      entityId:     sale.clientId,
      kind:         "CLIENT",
      displayName:  sale.client.displayName,
      docType:      sale.client.documentType ?? "",
      docNumber:    sale.client.documentNumber ?? "",
      ivaCondition: sale.client.ivaCondition ?? "",
    };
  }
  return null; // consumidor final
}

function extractChannel(sale: LoadedSale): BuildSnapshotInput["channel"] {
  const snap = sale.channelSnapshot as any;
  if (snap && typeof snap === "object" && snap.id) {
    return {
      id:                snap.id,
      name:              snap.name ?? "",
      adjustmentPercent: snap.adjustmentType === "PERCENTAGE" ? toNum(snap.adjustmentValue) : null,
      adjustmentAmount:  toNum(snap.adjustmentAmount ?? 0),
    };
  }
  if (sale.channel) {
    return {
      id:                sale.channel.id,
      name:              sale.channel.name,
      adjustmentPercent: sale.channel.adjustmentType === "PERCENTAGE" ? toNum(sale.channel.adjustmentValue) : null,
      adjustmentAmount:  0,
    };
  }
  return null;
}

function extractCoupon(sale: LoadedSale): BuildSnapshotInput["coupon"] {
  const snap = sale.couponSnapshot as any;
  if (snap && typeof snap === "object" && snap.id) {
    return {
      id:             snap.id,
      code:           snap.code ?? "",
      name:           snap.name ?? "",
      discountType:   snap.discountType === "FIXED" ? "FIXED" : "PERCENTAGE",
      discountValue:  toNum(snap.discountValue ?? 0),
      discountAmount: toNum(snap.discountAmount ?? 0),
    };
  }
  if (sale.coupon) {
    return {
      id:             sale.coupon.id,
      code:           sale.coupon.code,
      name:           sale.coupon.name,
      discountType:   sale.coupon.discountType === "FIXED_AMOUNT" ? "FIXED" : "PERCENTAGE",
      discountValue:  toNum(sale.coupon.discountValue ?? 0),
      discountAmount: 0,
    };
  }
  return null;
}

function computeTotalsFromLines(
  lines: DocumentLineInput[],
  sale: LoadedSale,
  currencyRate: number,
): BuildSnapshotInput["totals"] {
  const subtotal = lines.reduce((s, l) => s + l.subtotal, 0);
  const discountLines = lines.reduce((s, l) => s + l.discountLine, 0);
  const taxAmount = lines.reduce((s, l) => s + l.lineTaxAmount, 0);
  const total = toNum(sale.total);

  return {
    subtotal:               round2(subtotal),
    channelAmount:          0,
    couponAmount:           round2(toNum(sale.discountAmount)),
    quantityDiscountAmount: 0,
    promotionAmount:        0,
    paymentSurcharge:       0,
    discountAmount:         round2(discountLines + toNum(sale.discountAmount)),
    taxAmount:              round2(taxAmount),
    roundingAdjustment:     0,
    total:                  round2(total),
    totalBase:              round2(total * currencyRate),
  };
}

function computeCostAggregates(
  lines: DocumentLineInput[],
  subtotal: number,
): BuildSnapshotInput["cost"] {
  let totalCost = 0;
  let partial = false;
  let anyCost = false;
  for (const l of lines) {
    if (l.totalCost == null) { partial = true; continue; }
    totalCost += l.totalCost;
    anyCost = true;
  }
  if (!anyCost) {
    return { totalCost: null, totalMargin: null, marginPercent: null, costPartial: true };
  }
  const totalMargin = subtotal - totalCost;
  const marginPercent = subtotal > 0 ? round2((totalMargin / subtotal) * 100) : null;
  return {
    totalCost:     round2(totalCost),
    totalMargin:   round2(totalMargin),
    marginPercent,
    costPartial:   partial,
  };
}

function aggregateTaxBreakdown(lines: DocumentLineInput[]): SnapshotTaxBreakdownItem[] {
  const byTaxId = new Map<string, SnapshotTaxBreakdownItem>();
  for (const l of lines) {
    for (const t of l.taxBreakdown) {
      const existing = byTaxId.get(t.taxId);
      if (existing) {
        existing.baseAmount = round2(existing.baseAmount + t.baseAmount);
        existing.taxAmount  = round2(existing.taxAmount  + t.taxAmount);
      } else {
        byTaxId.set(t.taxId, { ...t });
      }
    }
  }
  return Array.from(byTaxId.values());
}

function toReceiptLineRow(
  receiptId: string,
  jewelryId: string,
  l: DocumentLineSnapshot,
): Prisma.ReceiptLineCreateManyInput {
  return {
    receiptId,
    jewelryId,
    pricingSnapshot: l as unknown as Prisma.InputJsonValue,
    articleId:       l.articleId,
    variantId:       l.variantId,
    itemKind:        l.itemKind,
    name:            l.name,
    code:            l.code,
    sku:             l.sku,
    barcode:         l.barcode,
    quantity:        new Prisma.Decimal(String(l.quantity)),
    unitPrice:       new Prisma.Decimal(String(l.unitPrice ?? 0)),
    subtotal:        new Prisma.Decimal(String(l.subtotal)),
    discountAmount:  new Prisma.Decimal(String(l.discountLine)),
    lineTotal:       new Prisma.Decimal(String(l.lineTotal)),
    taxAmount:       new Prisma.Decimal(String(l.lineTaxAmount)),
    totalWithTax:    new Prisma.Decimal(String(l.lineTotalWithTax)),
    totalCost:       l.totalCost   != null ? new Prisma.Decimal(String(l.totalCost))   : null,
    totalMargin:     l.totalMargin != null ? new Prisma.Decimal(String(l.totalMargin)) : null,
    sortOrder:       l.sortOrder,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Utils numéricos
// ─────────────────────────────────────────────────────────────────────────────

function toNum(v: Prisma.Decimal | number | string | null | undefined): number {
  if (v == null) return 0;
  if (typeof v === "number") return v;
  if (typeof v === "string") return parseFloat(v) || 0;
  return parseFloat(v.toString()) || 0;
}

function round2(v: number): number {
  return Math.round(v * 100) / 100;
}
