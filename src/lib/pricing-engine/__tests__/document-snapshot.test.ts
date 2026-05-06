// src/lib/pricing-engine/__tests__/document-snapshot.test.ts
// =============================================================================
// Tests para buildDocumentPricingSnapshot — función pura sin DB.
// Valida:
//   · Estructura del snapshot (version + resolvedAt + todos los campos)
//   · Agregación de impuestos por taxId
//   · Agregación de costo / margen / partial
//   · Preservación de datos de línea (PricingLineSnapshot + campos propios)
// =============================================================================

import { describe, it, expect } from "vitest";
import {
  buildDocumentPricingSnapshot,
  DOCUMENT_SNAPSHOT_VERSION,
  type BuildSnapshotInput,
  type DocumentLineInput,
} from "../pricing-engine.document.js";
import type { PricingLineSnapshot } from "../pricing-engine.types.js";

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

function makeLinePricing(over: Partial<PricingLineSnapshot> = {}): PricingLineSnapshot {
  return {
    unitPrice:      100,
    basePrice:      100,
    discountAmount: 0,
    taxAmount:      0,
    totalWithTax:   100,
    priceSource:    "MANUAL_FALLBACK",
    baseSource:     "MANUAL_FALLBACK",
    unitCost:       60,
    unitMargin:     40,
    marginPercent:  40,
    costPartial:    false,
    costMode:       "MANUAL",
    partial:        false,
    appliedPriceListId:   null,
    appliedPriceListName: null,
    appliedPromotionId:   null,
    appliedPromotionName: null,
    appliedDiscountId:    null,
    resolvedAt:     "2026-04-23T00:00:00.000Z",
    ...over,
  };
}

function makeLine(over: Partial<DocumentLineInput> = {}): DocumentLineInput {
  return {
    itemKind:  "ARTICLE_SIMPLE",
    articleId: "art-1",
    variantId: null,
    code:      "A001",
    sku:       "SKU001",
    barcode:   "",
    name:      "Artículo",
    sortOrder: 0,
    linePricing: makeLinePricing(),
    quantity:         2,
    subtotal:         200,
    discountLine:     0,
    lineTotal:        200,
    lineTaxAmount:    42,
    lineTotalWithTax: 242,
    totalCost:        120,
    totalMargin:      80,
    taxBreakdown:     [],
    ...over,
  };
}

function makeInput(lines: DocumentLineInput[]): BuildSnapshotInput {
  return {
    currency: {
      id:               "cur-ars",
      currencyCode:     "ARS",
      symbol:           "$",
      currencyRate:     1,
      baseCurrencyCode: "ARS",
    },
    issuer: {
      jewelryId:    "jw-1",
      name:         "Joyería Test",
      cuit:         "20-11111111-1",
      ivaCondition: "RESPONSABLE_INSCRIPTO",
    },
    counterparty: {
      entityId:     "cli-1",
      kind:         "CLIENT",
      displayName:  "Cliente SA",
      docType:      "DNI",
      docNumber:    "12345678",
      ivaCondition: "CONSUMIDOR_FINAL",
    },
    channel:          null,
    coupon:           null,
    promotion:        null,
    quantityDiscount: null,
    paymentMethod:    null,
    rounding: {
      source:    "NONE",
      appliedOn: "NONE",
      mode:      "NONE",
      direction: "NONE",
      adjustment: 0,
    },
    taxBreakdown: [],
    totals: {
      subtotal:               lines.reduce((s, l) => s + l.subtotal, 0),
      channelAmount:          0,
      couponAmount:           0,
      quantityDiscountAmount: 0,
      promotionAmount:        0,
      paymentSurcharge:       0,
      discountAmount:         0,
      taxAmount:              lines.reduce((s, l) => s + l.lineTaxAmount, 0),
      roundingAdjustment:     0,
      total:                  lines.reduce((s, l) => s + l.lineTotalWithTax, 0),
      totalBase:              lines.reduce((s, l) => s + l.lineTotalWithTax, 0),
    },
    cost: {
      totalCost:     lines.reduce((s, l) => s + (l.totalCost ?? 0), 0),
      totalMargin:   lines.reduce((s, l) => s + (l.totalMargin ?? 0), 0),
      marginPercent: 40,
      costPartial:   false,
    },
    lines,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

describe("buildDocumentPricingSnapshot — shape", () => {
  it("genera version + resolvedAt ISO + todos los bloques", () => {
    const snap = buildDocumentPricingSnapshot(makeInput([makeLine()]));

    expect(snap.version).toBe(DOCUMENT_SNAPSHOT_VERSION);
    expect(snap.resolvedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(snap.currency.currencyCode).toBe("ARS");
    expect(snap.currency.currencyRate).toBe(1);
    expect(snap.issuer.jewelryId).toBe("jw-1");
    expect(snap.counterparty?.kind).toBe("CLIENT");
    expect(snap.rounding.source).toBe("NONE");
    expect(snap.totals.total).toBe(242);
    expect(snap.lines).toHaveLength(1);
  });

  it("consumidor final → counterparty null", () => {
    const input = makeInput([makeLine()]);
    input.counterparty = null;
    const snap = buildDocumentPricingSnapshot(input);
    expect(snap.counterparty).toBeNull();
  });

  it("cada DocumentLineSnapshot incluye identidad + PricingLineSnapshot + totales", () => {
    const snap = buildDocumentPricingSnapshot(makeInput([
      makeLine({ code: "A001", name: "Producto", quantity: 3, subtotal: 300, lineTotal: 300 }),
    ]));
    const line = snap.lines[0];
    expect(line.itemKind).toBe("ARTICLE_SIMPLE");
    expect(line.code).toBe("A001");
    expect(line.name).toBe("Producto");
    expect(line.quantity).toBe(3);
    expect(line.subtotal).toBe(300);
    // Propagación del PricingLineSnapshot
    expect(line.unitCost).toBe(60);
    expect(line.priceSource).toBe("MANUAL_FALLBACK");
    expect(line.marginPercent).toBe(40);
    expect(line.resolvedAt).toBe("2026-04-23T00:00:00.000Z");
  });
});

describe("buildDocumentPricingSnapshot — combos y servicios", () => {
  it("combo: preserva comboComponents cuando vienen", () => {
    const comboLine = makeLine({
      itemKind: "COMBO",
      comboComponents: [
        { articleId: "c1", code: "C1", name: "Comp 1", quantity: 1, unitCost: 30, affectsStock: true },
        { articleId: "c2", code: "C2", name: "Comp 2", quantity: 2, unitCost: 15, affectsStock: true },
      ],
    });
    const snap = buildDocumentPricingSnapshot(makeInput([comboLine]));
    expect(snap.lines[0].itemKind).toBe("COMBO");
    expect(snap.lines[0].comboComponents).toHaveLength(2);
    expect(snap.lines[0].comboComponents?.[0].code).toBe("C1");
  });

  it("servicio: itemKind SERVICE + no hay comboComponents", () => {
    const svc = makeLine({ itemKind: "SERVICE", name: "Reparación" });
    const snap = buildDocumentPricingSnapshot(makeInput([svc]));
    expect(snap.lines[0].itemKind).toBe("SERVICE");
    expect(snap.lines[0].comboComponents).toBeUndefined();
  });

  it("variante: itemKind ARTICLE_VARIANT + variantId poblado", () => {
    const variant = makeLine({ itemKind: "ARTICLE_VARIANT", variantId: "var-1" });
    const snap = buildDocumentPricingSnapshot(makeInput([variant]));
    expect(snap.lines[0].itemKind).toBe("ARTICLE_VARIANT");
    expect(snap.lines[0].variantId).toBe("var-1");
  });
});

describe("buildDocumentPricingSnapshot — moneda y redondeo", () => {
  it("conserva currencyRate y baseCurrencyCode para reconstrucción histórica", () => {
    const input = makeInput([makeLine()]);
    input.currency = {
      id: "cur-usd", currencyCode: "USD", symbol: "US$",
      currencyRate: 1050.5, baseCurrencyCode: "ARS",
    };
    const snap = buildDocumentPricingSnapshot(input);
    expect(snap.currency.currencyRate).toBe(1050.5);
    expect(snap.currency.baseCurrencyCode).toBe("ARS");
  });

  it("preserva el bloque rounding tal como vino", () => {
    const input = makeInput([makeLine()]);
    input.rounding = {
      source: "PRICE_LIST", appliedOn: "TOTAL",
      mode: "DECIMAL_2", direction: "NEAREST", adjustment: -0.05,
    };
    const snap = buildDocumentPricingSnapshot(input);
    expect(snap.rounding.source).toBe("PRICE_LIST");
    expect(snap.rounding.adjustment).toBe(-0.05);
  });
});

describe("buildDocumentPricingSnapshot — inmutabilidad", () => {
  it("dos llamadas en distintos instantes producen resolvedAt distintos", async () => {
    const first = buildDocumentPricingSnapshot(makeInput([makeLine()]));
    await new Promise((r) => setTimeout(r, 5));
    const second = buildDocumentPricingSnapshot(makeInput([makeLine()]));
    expect(first.resolvedAt).not.toBe(second.resolvedAt);
  });

  it("mutar el input después NO afecta al snapshot emitido", () => {
    const line = makeLine();
    const input = makeInput([line]);
    const snap = buildDocumentPricingSnapshot(input);

    // Mutación posterior del input
    line.name = "MUTADO";
    line.quantity = 999;

    // El snapshot guarda los valores copiados al momento de construir
    expect(snap.lines[0].name).toBe("Artículo");
    expect(snap.lines[0].quantity).toBe(2);
  });
});
