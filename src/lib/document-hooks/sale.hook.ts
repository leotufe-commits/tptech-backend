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
  type BalanceMode,
  type DocumentBalanceBreakdown,
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
  // ── Fase 3B.5 — Balance Mode passthrough (POLICY.md §11) ────────────────
  /** Modo de balance ya resuelto/congelado por confirmSale (R11.4).
   *  Si no se provee, el snapshot v3 cae a `UNIFIED` + `FALLBACK_UNIFIED`. */
  balanceMode?: BalanceMode;
  /** Origen del modo (auditoría). String libre coherente con
   *  `BalanceModeSource`: DOCUMENT_OVERRIDE / ENTITY_DEFAULT / etc. */
  balanceModeSource?: string;
  /** Breakdown canónico construido por confirmSale. Si no se provee, el
   *  snapshot v3 lo deriva como UNIFIED implícito (`monetary.amount=total`). */
  balanceBreakdown?: DocumentBalanceBreakdown;
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
  //    Fase 3B.5: incorpora Balance Mode + breakdown si el caller los provee.
  //    Si no, el builder defaultea a UNIFIED implícito (back-compat).
  const snapshotInput = buildSnapshotInputFromSale(sale);
  if (opts.balanceMode) {
    (snapshotInput as any).balanceMode = opts.balanceMode;
  }
  if (opts.balanceModeSource) {
    (snapshotInput as any).balanceModeSource = opts.balanceModeSource;
  }
  if (opts.balanceBreakdown) {
    (snapshotInput as any).balanceBreakdown = opts.balanceBreakdown;
  }
  // Trazabilidad: el snapshot del receipt apunta de vuelta al Sale origen.
  (snapshotInput as any).sourceDocument = { kind: "SALE", id: sale.id, number: sale.code };
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
  //
  //  ── Fase 3B.6 (POLICY.md §11) ──────────────────────────────────────────
  //  Reglas que se aplican acá:
  //    · `balanceMode` SIEMPRE se persiste (UNIFIED por defecto si el caller
  //      no lo provee — preserva back-compat exacta para flujos legacy).
  //    · `sourceDocumentType = "SALE"` / `sourceDocumentId = sale.id` siempre
  //      (R11.7 — trazabilidad inversa universal).
  //    · UNIFIED: amountBase/Original/currency desde `snapshot.totals` (igual
  //      que pre-3B.6). NO se crean `AccountMovementMetalEntry`.
  //    · BREAKDOWN: amountBase/Original/currency desde
  //      `opts.balanceBreakdown.monetaryBalance` (la fuente de verdad es el
  //      breakdown confirmado, NO se reconstruye nada). Se crea una
  //      `AccountMovementMetalEntry` por cada metal padre con `gramsPure > 0`.
  //    · BREAKDOWN sin breakdown válido → falla controladamente (R11.5):
  //      mejor abortar la confirmación que persistir una cuenta corriente
  //      inconsistente.
  const accountMovements: OnSaleConfirmedResult["accountMovements"] = [];

  // Validación temprana del breakdown cuando el modo es BREAKDOWN. Si falta o
  // está corrupto, abortamos la transacción — Postgres revierte el receipt,
  // los receiptLines y los movimientos de stock que se hicieron arriba.
  if (
    opts.balanceMode === "BREAKDOWN" &&
    !isValidBalanceBreakdownForPersistence(opts.balanceBreakdown)
  ) {
    const e: any = new Error(
      "balanceMode=BREAKDOWN pero opts.balanceBreakdown ausente/inválido. " +
      "No se puede persistir cuenta corriente sin un breakdown válido.",
    );
    e.status = 422;
    e.code   = "BALANCE_BREAKDOWN_REQUIRED";
    throw e;
  }

  if (sale.clientId) {
    const effectiveMode: "UNIFIED" | "BREAKDOWN" = opts.balanceMode ?? "UNIFIED";
    const mb = (effectiveMode === "BREAKDOWN" && opts.balanceBreakdown)
      ? opts.balanceBreakdown.monetaryBalance
      : null;

    // amountBase / amountOriginal / currency según el modo.
    const movAmountBase     = mb != null
      ? new Prisma.Decimal(String(mb.amountBase))
      : new Prisma.Decimal(String(snapshot.totals.totalBase));
    const movAmountOriginal = mb != null
      ? new Prisma.Decimal(String(mb.amount))
      : new Prisma.Decimal(String(snapshot.totals.total));
    // Si el breakdown trae currencyCode vacío (preview sin conversión),
    // caemos al code del snapshot para no perder la moneda.
    const movCurrencyCode = mb?.currencyCode && mb.currencyCode.length > 0
      ? mb.currencyCode
      : snapshot.currency.currencyCode;
    const movCurrencyRate = mb != null
      ? new Prisma.Decimal(String(mb.currencyRate))
      : new Prisma.Decimal(String(snapshot.currency.currencyRate));

    const mov = await tx.currentAccountMovement.create({
      data: {
        jewelryId:          sale.jewelryId,
        entityId:           sale.clientId,
        kind:               "DEBIT",
        source:             "RECEIPT",
        receiptId:          receipt.id,
        amountBase:         movAmountBase,
        amountOriginal:     movAmountOriginal,
        currencySnapshot:   snapshot.currency as unknown as Prisma.InputJsonValue,
        currencyCode:       movCurrencyCode,
        currencyRate:       movCurrencyRate,
        movementDate:       sale.saleDate ?? new Date(),
        notes:              `Receipt ${code}`,
        // Fase 3B.6 — modo + trazabilidad inversa al documento origen.
        balanceMode:        effectiveMode,
        sourceDocumentType: "SALE",
        sourceDocumentId:   sale.id,
      },
      select: { id: true, kind: true, amountBase: true },
    });
    accountMovements.push({
      id:         mov.id,
      kind:       mov.kind,
      amountBase: parseFloat(mov.amountBase.toString()),
    });

    // 7b. AccountMovementMetalEntry (sólo en BREAKDOWN con metales reales).
    //     Cada metal padre del breakdown se proyecta a una fila. Los metales
    //     son GRAMOS — no se convierten de moneda. Las filas inválidas
    //     (gramsPure≤0) se descartan defensivamente (no rompen el flujo).
    if (effectiveMode === "BREAKDOWN" && opts.balanceBreakdown) {
      const entryRows = buildAccountMovementMetalEntryRows({
        movementId: mov.id,
        jewelryId:  sale.jewelryId,
        breakdown:  opts.balanceBreakdown,
      });
      if (entryRows.length > 0) {
        await tx.accountMovementMetalEntry.createMany({ data: entryRows });
      }
    }
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

/** Busca una serie CREDIT_NOTE+OUTBOUND para el tenant; si no existe, la
 *  auto-provisiona con defaults (`NC` / `0001` / `nextNumber=1`).
 *  Etapa 1.2 — usado por `onSaleCancelled`. */
async function resolveCreditNoteSeries(
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
      const err: any = new Error("ReceiptSeries (CREDIT_NOTE) no encontrada o inactiva.");
      err.status = 404;
      throw err;
    }
    return series;
  }

  const existing = await tx.receiptSeries.findFirst({
    where: {
      jewelryId,
      type:      "CREDIT_NOTE",
      direction: "OUTBOUND",
      isActive:  true,
      deletedAt: null,
    },
    orderBy: { createdAt: "asc" as const },
    select: { id: true },
  });
  if (existing) return existing;

  const created = await tx.receiptSeries.create({
    data: {
      jewelryId,
      name:        "Nota de crédito — Punto de venta 0001",
      type:        "CREDIT_NOTE",
      direction:   "OUTBOUND",
      prefix:      "NC",
      pointOfSale: "0001",
      nextNumber:  1,
    },
    select: { id: true },
  });
  return created;
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

// ─────────────────────────────────────────────────────────────────────────────
// T56 (Fase 3B.6) — Helpers de proyección Balance Mode → cuenta corriente
// ─────────────────────────────────────────────────────────────────────────────

/** Valida la forma del breakdown para persistir cuenta corriente. NO valida
 *  semántica (gramos, valuaciones, etc.) — sólo que el shape mínimo esté
 *  presente para no escribir movimientos truncos. */
export function isValidBalanceBreakdownForPersistence(
  bd: DocumentBalanceBreakdown | undefined | null,
): bd is DocumentBalanceBreakdown {
  if (!bd || typeof bd !== "object") return false;
  if (!Array.isArray(bd.metals)) return false;
  const mb = bd.monetaryBalance;
  if (!mb || typeof mb !== "object") return false;
  if (typeof mb.amount !== "number")     return false;
  if (typeof mb.amountBase !== "number") return false;
  // T58 (Fase 3B.8) — hardening: rechazar NaN / Infinity. Sin esto, persistir
  // un BREAKDOWN con `amount = NaN` crashearía el `Prisma.Decimal(NaN)` con
  // un error oscuro y dejaría la tx a medio aplicar (Receipt sí, mov no).
  if (!Number.isFinite(mb.amount))     return false;
  if (!Number.isFinite(mb.amountBase)) return false;
  return true;
}

/** Input del builder de rows de `AccountMovementMetalEntry`. */
export interface BuildMetalEntryRowsArgs {
  movementId: string;
  jewelryId:  string;
  breakdown:  DocumentBalanceBreakdown;
}

/** Proyecta `balanceBreakdown.metals[]` al shape de `AccountMovementMetalEntry`.
 *  Reglas:
 *    · Una fila por metal padre.
 *    · `gramsPure <= 0` (y gramsOriginal <= 0) → fila descartada (no se
 *      bloquea, sólo se ignora — defensiva).
 *    · `sourceLineId` se toma del primer entry de `sourceLineIds[]` cuando
 *      hay exactamente uno — sin esa unicidad queda null (más de una línea
 *      aportó al mismo padre y persistir un solo id distorsionaría la
 *      trazabilidad).
 *    · No convierte gramos a moneda. Son gramos físicos / pureza. */
export function buildAccountMovementMetalEntryRows(
  args: BuildMetalEntryRowsArgs,
): Prisma.AccountMovementMetalEntryCreateManyInput[] {
  // T58 (Fase 3B.8) — hardening:
  //   · Rechazar gramsPure / gramsOriginal NaN, Infinity, negativos o ≤ 0.
  //   · Dedup defensivo por `metalParentId`: si el breakdown trajera dos
  //     entradas para el mismo padre (no debería, pero defendemos), las
  //     sumamos en lugar de crear duplicados (que viola la unicidad lógica
  //     "1 fila por metal padre por movimiento").
  //   · `purity` se preserva null si todas las entradas duplicadas trajeran
  //     null; si alguna trae número, se sigue ponderando.
  const accByParent = new Map<string, {
    metalParentId:   string | null;
    metalParentName: string;
    gramsOriginal:   number;
    gramsPure:       number;
    purity:          number | null;   // ponderada interna
    sourceLineIds:   Set<string>;
  }>();

  for (const m of args.breakdown.metals) {
    const gramsOriginal = Number(m.gramsOriginal ?? 0);
    const gramsPure     = Number(m.gramsPure ?? 0);
    // Filtrado defensivo: NaN/Infinity/≤0 quedan fuera.
    if (!Number.isFinite(gramsOriginal) || !Number.isFinite(gramsPure)) continue;
    if (gramsOriginal <= 1e-9 || gramsPure <= 1e-9)                    continue;
    // Clave de dedup: metalParentId (o "__null__" si no hay padre — edge).
    const key = m.metalParentId ?? "__null__";
    const existing = accByParent.get(key);
    if (existing) {
      existing.gramsOriginal += gramsOriginal;
      existing.gramsPure     += gramsPure;
      // Re-pondera la pureza si los nuevos gramos suman.
      existing.purity = existing.gramsOriginal > 1e-9
        ? existing.gramsPure / existing.gramsOriginal
        : null;
      for (const id of m.sourceLineIds ?? []) existing.sourceLineIds.add(id);
    } else {
      const purity = m.purity != null && Number.isFinite(Number(m.purity))
        ? Number(m.purity)
        : null;
      accByParent.set(key, {
        metalParentId:   m.metalParentId || null,
        metalParentName: m.metalParentName ?? "",
        gramsOriginal,
        gramsPure,
        purity,
        sourceLineIds:   new Set(m.sourceLineIds ?? []),
      });
    }
  }

  const out: Prisma.AccountMovementMetalEntryCreateManyInput[] = [];
  for (const acc of accByParent.values()) {
    // sourceLineId único cuando exactamente UNA línea aportó al padre.
    const sourceLineId =
      acc.sourceLineIds.size === 1
        ? Array.from(acc.sourceLineIds)[0]
        : null;
    out.push({
      movementId:      args.movementId,
      jewelryId:       args.jewelryId,
      metalParentId:   acc.metalParentId,
      metalParentName: acc.metalParentName,
      gramsOriginal:   new Prisma.Decimal(String(acc.gramsOriginal)),
      purity:          acc.purity != null
        ? new Prisma.Decimal(String(acc.purity))
        : null,
      gramsPure:       new Prisma.Decimal(String(acc.gramsPure)),
      sourceLineId,
    });
  }
  return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// Etapa 1.2 — onSaleCancelled
// ─────────────────────────────────────────────────────────────────────────────
//
// Hook transaccional que se invoca desde `cancelSale` cuando una venta
// CONFIRMED se anula. Emite la Nota de Crédito de reversa + movimiento de
// cuenta corriente espejo. Mismo contrato transaccional que `onSaleConfirmed`:
// recibe `Prisma.TransactionClient`, no abre TX propia, falla aborta toda
// la cancelación.
//
// Regla "nada se pisa, todo se encadena":
//   · El Receipt INVOICE original queda intacto (`status` sigue ISSUED).
//   · El CurrentAccountMovement DEBIT original queda intacto.
//   · La NC apunta al original via `Receipt.correctedReceiptId`.
//   · El movimiento CREDIT reverso apunta a la NC via `receiptId` y al
//     documento origen via `sourceDocumentType="SALE_CANCEL"` /
//     `sourceDocumentId=sale.id`.
//
// Convención de signos: todos los montos POSITIVOS. El signo contable lo
// determina el `type` (CREDIT_NOTE) y el `kind` (CREDIT) del movimiento.
//
// Si la sale era DRAFT (no había Receipt original) o no se encuentra el
// Receipt original, el hook devuelve `{ creditNote: null, ... }` y no
// emite nada — el flujo del service sigue su curso (solo stock revertido).
// ─────────────────────────────────────────────────────────────────────────────

export interface OnSaleCancelledOpts {
  /** userId que ejecuta la cancelación (se guarda en `Receipt.issuedById`). */
  issuedById?: string | null;
  /** Nota libre del usuario (se incluye en notes del Receipt y del movimiento). */
  note?: string;
  /** seriesId explícito para la NC. Si no se pasa se autoresuelve/provisiona. */
  creditNoteSeriesId?: string;
}

export interface OnSaleCancelledResult {
  creditNote: {
    id: string;
    code: string;
    correctedReceiptId: string;
    total: number;
  } | null;
  reverseMovement: {
    id: string;
    kind: "CREDIT";
    amountBase: number;
  } | null;
}

export async function onSaleCancelled(
  tx: Prisma.TransactionClient,
  saleId: string,
  opts: OnSaleCancelledOpts = {},
): Promise<OnSaleCancelledResult> {
  // 1. Cargar el Receipt INVOICE original asociado a la sale (ISSUED).
  //    Si no existe → la sale era DRAFT o el hook anterior nunca corrió.
  //    No hay nada que revertir contablemente.
  const originalReceipt = await tx.receipt.findFirst({
    where: {
      saleId,
      type:      "INVOICE",
      direction: "OUTBOUND",
      status:    "ISSUED",
    },
    select: {
      id:               true,
      jewelryId:        true,
      code:             true,
      counterpartyId:   true,
      pricingSnapshot:  true,
      currencySnapshot: true,
      currencyCode:     true,
      currencyRate:     true,
      subtotal:         true,
      discountAmount:   true,
      taxAmount:        true,
      total:            true,
      totalBase:        true,
      issueDate:        true,
      lines: {
        orderBy: { sortOrder: "asc" as const },
        select: {
          articleId:       true,
          variantId:       true,
          itemKind:        true,
          name:            true,
          code:            true,
          sku:             true,
          barcode:         true,
          quantity:        true,
          unitPrice:       true,
          subtotal:        true,
          discountAmount:  true,
          lineTotal:       true,
          taxAmount:       true,
          totalWithTax:    true,
          totalCost:       true,
          totalMargin:     true,
          pricingSnapshot: true,
          sortOrder:       true,
        },
      },
    },
  });

  if (!originalReceipt) {
    return { creditNote: null, reverseMovement: null };
  }

  // 2. Cargar el CurrentAccountMovement DEBIT original (si existe — el cliente
  //    pudo ser consumidor final). Con sus metal entries.
  const originalMov = await tx.currentAccountMovement.findFirst({
    where: { receiptId: originalReceipt.id, kind: "DEBIT" },
    select: {
      id:                 true,
      entityId:           true,
      amountOriginal:     true,
      amountBase:         true,
      currencySnapshot:   true,
      currencyCode:       true,
      currencyRate:       true,
      balanceMode:        true,
      metalEntries: {
        select: {
          metalParentId:   true,
          metalParentName: true,
          gramsOriginal:   true,
          purity:          true,
          gramsPure:       true,
          sourceLineId:    true,
        },
      },
    },
  });

  // 3. Resolver/auto-provisionar serie CREDIT_NOTE OUTBOUND.
  const series = await resolveCreditNoteSeries(
    tx,
    originalReceipt.jewelryId,
    opts.creditNoteSeriesId ?? null,
  );

  // 4. Incrementar atómicamente el número de la serie y reservarlo.
  const updatedSeries = await tx.receiptSeries.update({
    where: { id: series.id },
    data:  { nextNumber: { increment: 1 } },
    select: { nextNumber: true, prefix: true, pointOfSale: true },
  });
  const reservedNumber = updatedSeries.nextNumber - 1;
  const ncCode = formatReceiptCode(updatedSeries.prefix, updatedSeries.pointOfSale, reservedNumber);

  // 5. Crear Receipt CREDIT_NOTE con `correctedReceiptId` apuntando al
  //    original. Snapshots y totales se copian tal cual (positivos); el
  //    signo contable lo da `type=CREDIT_NOTE`. NO se recalcula nada.
  const noteText = opts.note?.trim()
    ? `Anulación de ${originalReceipt.code} — ${opts.note.trim()}`
    : `Anulación de ${originalReceipt.code}`;

  const creditNote = await tx.receipt.create({
    data: {
      jewelryId:          originalReceipt.jewelryId,
      seriesId:           series.id,
      code:               ncCode,
      type:               "CREDIT_NOTE",
      direction:          "OUTBOUND",
      status:             "ISSUED",
      saleId,
      purchaseId:         null,
      counterpartyId:     originalReceipt.counterpartyId,
      correctedReceiptId: originalReceipt.id,
      pricingSnapshot:    originalReceipt.pricingSnapshot as unknown as Prisma.InputJsonValue,
      currencySnapshot:   originalReceipt.currencySnapshot as unknown as Prisma.InputJsonValue,
      currencyCode:       originalReceipt.currencyCode,
      currencyRate:       originalReceipt.currencyRate,
      subtotal:           originalReceipt.subtotal,
      discountAmount:     originalReceipt.discountAmount,
      taxAmount:          originalReceipt.taxAmount,
      total:              originalReceipt.total,
      totalBase:          originalReceipt.totalBase,
      issueDate:          new Date(),
      issuedAt:           new Date(),
      issuedById:         opts.issuedById ?? null,
      notes:              noteText,
    },
    select: { id: true, code: true, total: true, correctedReceiptId: true },
  });

  // 6. Crear ReceiptLine[] espejo desde las líneas originales (mismos
  //    snapshots, misma qty, mismo unitPrice). Solo cambia `receiptId`.
  if (originalReceipt.lines.length > 0) {
    await tx.receiptLine.createMany({
      data: originalReceipt.lines.map((l): Prisma.ReceiptLineCreateManyInput => ({
        receiptId:       creditNote.id,
        jewelryId:       originalReceipt.jewelryId,
        articleId:       l.articleId,
        variantId:       l.variantId,
        itemKind:        l.itemKind,
        name:            l.name,
        code:            l.code,
        sku:             l.sku,
        barcode:         l.barcode,
        quantity:        l.quantity,
        unitPrice:       l.unitPrice,
        subtotal:        l.subtotal,
        discountAmount:  l.discountAmount,
        lineTotal:       l.lineTotal,
        taxAmount:       l.taxAmount,
        totalWithTax:    l.totalWithTax,
        totalCost:       l.totalCost,
        totalMargin:     l.totalMargin,
        pricingSnapshot: l.pricingSnapshot as unknown as Prisma.InputJsonValue,
        sortOrder:       l.sortOrder,
      })),
    });
  }

  // 7. CurrentAccountMovement CREDIT reverso (solo si había DEBIT original
  //    — consumidor final sin entityId no genera movimiento, igual que en
  //    onSaleConfirmed).
  if (!originalMov) {
    return {
      creditNote: {
        id: creditNote.id,
        code: creditNote.code,
        correctedReceiptId: creditNote.correctedReceiptId!,
        total: parseFloat(creditNote.total.toString()),
      },
      reverseMovement: null,
    };
  }

  const reverseMov = await tx.currentAccountMovement.create({
    data: {
      jewelryId:          originalReceipt.jewelryId,
      entityId:           originalMov.entityId,
      kind:               "CREDIT",
      source:             "RECEIPT",
      receiptId:          creditNote.id,
      amountBase:         originalMov.amountBase,
      amountOriginal:     originalMov.amountOriginal,
      currencySnapshot:   originalMov.currencySnapshot as unknown as Prisma.InputJsonValue,
      currencyCode:       originalMov.currencyCode,
      currencyRate:       originalMov.currencyRate,
      movementDate:       new Date(),
      notes:              noteText,
      balanceMode:        originalMov.balanceMode ?? "UNIFIED",
      sourceDocumentType: "SALE_CANCEL",
      sourceDocumentId:   saleId,
    },
    select: { id: true, kind: true, amountBase: true },
  });

  // 7b. AccountMovementMetalEntry reversas (solo si el original era BREAKDOWN
  //     con metales reales). Misma convención de positivos.
  if (originalMov.metalEntries.length > 0) {
    await tx.accountMovementMetalEntry.createMany({
      data: originalMov.metalEntries.map((e): Prisma.AccountMovementMetalEntryCreateManyInput => ({
        movementId:      reverseMov.id,
        jewelryId:       originalReceipt.jewelryId,
        metalParentId:   e.metalParentId,
        metalParentName: e.metalParentName,
        gramsOriginal:   e.gramsOriginal,
        purity:          e.purity,
        gramsPure:       e.gramsPure,
        sourceLineId:    e.sourceLineId,
      })),
    });
  }

  return {
    creditNote: {
      id: creditNote.id,
      code: creditNote.code,
      correctedReceiptId: creditNote.correctedReceiptId!,
      total: parseFloat(creditNote.total.toString()),
    },
    reverseMovement: {
      id:         reverseMov.id,
      kind:       "CREDIT",
      amountBase: parseFloat(reverseMov.amountBase.toString()),
    },
  };
}
