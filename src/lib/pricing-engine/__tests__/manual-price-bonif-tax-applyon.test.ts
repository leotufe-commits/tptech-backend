// src/lib/pricing-engine/__tests__/manual-price-bonif-tax-applyon.test.ts
// =============================================================================
// T43.1-3 — Blindaje del comportamiento de `manualPriceOverride` combinado con
// `manualDiscountOverride` (applyOn METAL/HECHURA/TOTAL) y con `taxOverride`
// + `entityTaxExempt`.
//
// REGLAS QUE ESTE TEST CONGELA (POLICY R6 — passthrough motor):
//
//   1. Con `manualPriceOverride`, el motor decide el modo de derivación del
//      breakdown metal/hechura según los componentes del costo. Cuando el
//      cost se reporta como un único bucket (type=MANUAL en `costComposition`,
//      sin metal+hechura desglosados), el motor cae en modo
//      `MANUAL_AS_HECHURA`: `metalSale = 0`, `hechuraSale = basePrice` —
//      todo el precio manual se imputa al bucket HECHURA.
//
//   2. En modo MANUAL_AS_HECHURA con `manualDiscountOverride`:
//        · `applyOn=TOTAL`   → descuenta sobre el precio manual completo.
//        · `applyOn=HECHURA` → equivale a applyOn=TOTAL (toda la base está
//                              en hechura, no hay porción metal a excluir).
//        · `applyOn=METAL`   → descuenta sobre la porción METAL (= 0) →
//                              EFECTO NULO. El motor preserva el precio
//                              manual tal cual. Coherente: no se puede
//                              descontar lo que no existe en el bucket.
//
//      ⚠️ Cuando el cost del artículo tenga buckets metal+hechura reales
//      (camino `PROPORTIONAL_COST` del motor en `pricing-engine.sale.ts`
//      línea 2890-2896), applyOn=METAL/HECHURA SÍ distribuirá el descuento
//      proporcionalmente. Ese caso requiere setup de DB más complejo
//      (metalVariantId con quote, articleGroupItem, etc.) y se cubrirá en
//      un test de integración posterior con fixtures completos.
//
//   3. `taxOverride` GANA sobre `entityTaxExempt` cuando el operador
//      ingresa impuesto manual explícito, incluso si hay
//      `manualPriceOverride`. La exención del cliente es un default de
//      hidratación, no un candado.
//
// Estos tests NO modifican lógica del motor — solo blindan el comportamiento
// observado para detectar regresiones futuras.
// =============================================================================

import { describe, it, expect, vi, beforeEach } from "vitest";
import { Prisma } from "@prisma/client";

const mockPrisma = vi.hoisted(() => ({
  currency:             { findFirst:  vi.fn() },
  currencyRate:         { findFirst:  vi.fn() },
  metalQuote:           { findFirst:  vi.fn(), findMany: vi.fn() },
  metalVariant:         { findMany:   vi.fn() },
  jewelry:              { findUnique: vi.fn() },
  article:              { findFirst:  vi.fn() },
  articleVariant:       { findFirst:  vi.fn() },
  articleGroupItem:     { findFirst:  vi.fn() },
  promotion:            { findMany:   vi.fn() },
  quantityDiscount:     { findMany:   vi.fn() },
  commercialEntity:     { findFirst:  vi.fn() },
  articleCategory:      { findFirst:  vi.fn() },
  priceList:            { findFirst:  vi.fn() },
  tax:                  { findMany:   vi.fn() },
  entityMermaOverride:  { findMany:   vi.fn() },
}));

vi.mock("../../prisma.js", () => ({ prisma: mockPrisma }));

import { resolveFinalSalePrice } from "../pricing-engine.sale.js";

const D = Prisma.Decimal;

function makeDbArticle(overrides: Record<string, any> = {}) {
  return {
    categoryId:            null,
    brand:                 null,
    groupId:               null,
    salePrice:             null,
    useManualSalePrice:    false,
    manualAdjustmentKind:  null,
    manualAdjustmentType:  null,
    manualAdjustmentValue: null,
    // Cost crudo 1000 (bucket único). Sin desglose metal+hechura → con
    // manualPrice el motor entra en `MANUAL_AS_HECHURA`.
    costComposition:       [
      { type: "MANUAL", quantity: new D("1"), unitValue: new D("1000"),
        currencyId: null, mermaPercent: null, metalVariantId: null },
    ],
    manualTaxIds:          [],
    ...overrides,
  };
}

function makePriceList(overrides: Record<string, any> = {}) {
  return {
    id:               "pl-test",
    name:             "Lista Test",
    mode:             "MARGIN_TOTAL",
    marginTotal:      new D("100"),
    marginMetal:      null,
    marginHechura:    null,
    costPerGram:      null,
    surcharge:        null,
    minimumPrice:     null,
    roundingTarget:   "NONE",
    roundingMode:     "NONE",
    roundingDirection:"NEAREST",
    roundingApplyOn:  "PRICE",
    validFrom:        null,
    validTo:          null,
    isActive:         true,
    scope:            "GENERAL",
    isFavorite:       true,
    deletedAt:        null,
    sortOrder:        0,
    ...overrides,
  };
}

function defaultPolicy() {
  return {
    defaultMermaPercent:             null,
    pricingLowMarginWarningPercent:  null,
    pricingLowMarginBlockPercent:    null,
    pricingBlockLossSale:            false,
    pricingBlockZeroOrNegativePrice: true,
    pricingBlockPartialData:         false,
  };
}

function makeExemptClient(taxExempt: boolean) {
  return {
    taxExempt,
    taxApplyOnOverride:  null,
    commercialRuleType:  null,
    commercialValueType: null,
    commercialValue:     null,
    commercialApplyOn:   null,
    taxOverrides:        [],
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  mockPrisma.article.findFirst.mockResolvedValue(makeDbArticle());
  mockPrisma.articleVariant.findFirst.mockResolvedValue(null);
  mockPrisma.promotion.findMany.mockResolvedValue([]);
  mockPrisma.quantityDiscount.findMany.mockResolvedValue([]);
  mockPrisma.commercialEntity.findFirst.mockResolvedValue(null);
  mockPrisma.articleCategory.findFirst.mockResolvedValue(null);
  mockPrisma.priceList.findFirst.mockResolvedValue(makePriceList());
  mockPrisma.jewelry.findUnique.mockResolvedValue(defaultPolicy());
  mockPrisma.currency.findFirst.mockResolvedValue({ id: "ARS" });
  mockPrisma.metalVariant.findMany.mockResolvedValue([]);
  mockPrisma.metalQuote.findMany.mockResolvedValue([]);
  mockPrisma.tax.findMany.mockResolvedValue([]);
  mockPrisma.entityMermaOverride.findMany.mockResolvedValue([]);
});

// ─────────────────────────────────────────────────────────────────────────────
// PUNTO 1 — manualPrice + manualDiscount applyOn=METAL
// ─────────────────────────────────────────────────────────────────────────────

describe("T43.1 — manualPrice + manualDiscount applyOn=METAL (rama MANUAL_AS_HECHURA)", () => {
  it("manualPrice 1500 (sin cost desglosado) → metalSale=0, hechuraSale=basePrice de lista (MANUAL_AS_HECHURA)", async () => {
    const res = await resolveFinalSalePrice("j1", {
      articleId:           "a1",
      manualPriceOverride:  1500,
    });
    const br = res.metalHechuraBreakdown!;
    // En MANUAL_AS_HECHURA el motor expone el desglose del BASE PRICE de
    // lista (2000 = cost 1000 × 2 por marginTotal=100), NO del manualPrice.
    // El `unitPrice` final SÍ es el manualPrice; el breakdown sigue
    // mostrando el "subtotal natural" pre-override.
    expect(Number(br.metalSale)  ).toBeCloseTo(0,    2);
    expect(Number(br.hechuraSale)).toBeCloseTo(2000, 2); // basePrice lista
    expect(res.unitPrice!.toNumber()).toBeCloseTo(1500, 2); // manualPrice
  });

  it("manualPrice 1500 + discount 10% applyOn=METAL → SIN EFECTO (metal=0, nada que descontar)", async () => {
    // Comportamiento congelado: con MANUAL_AS_HECHURA, applyOn=METAL no
    // tiene base sobre la que aplicar el descuento → unitPrice = 1500
    // (intacto). Coherente: no se descuenta lo que no existe.
    const res = await resolveFinalSalePrice("j1", {
      articleId:              "a1",
      manualPriceOverride:     1500,
      manualDiscountOverride: {
        mode:      "PERCENT",
        value:     10,
        appliesTo: "METAL",
        kind:      "BONUS",
      },
    });
    expect(res.unitPrice!.toNumber()).toBeCloseTo(1500, 2);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// PUNTO 2 — manualPrice + manualDiscount applyOn=HECHURA / TOTAL
// ─────────────────────────────────────────────────────────────────────────────

describe("T43.2 — manualPrice + manualDiscount applyOn=HECHURA / TOTAL", () => {
  it("descuento 10% applyOn=HECHURA sobre manualPrice 1500 → descuenta 150 (toda la base es hechura)", async () => {
    // En MANUAL_AS_HECHURA, hechuraSale = manualPrice = 1500. Descuento 10%
    // = 150 → unitPrice 1350. Equivalente a applyOn=TOTAL en este modo.
    const res = await resolveFinalSalePrice("j1", {
      articleId:              "a1",
      manualPriceOverride:     1500,
      manualDiscountOverride: {
        mode:      "PERCENT",
        value:     10,
        appliesTo: "HECHURA",
        kind:      "BONUS",
      },
    });
    expect(res.unitPrice!.toNumber()).toBeCloseTo(1350, 2);
  });

  it("RECARGO 10% applyOn=HECHURA + manualPrice 1500 → suma 150 (1500 + 150 = 1650)", async () => {
    const res = await resolveFinalSalePrice("j1", {
      articleId:              "a1",
      manualPriceOverride:     1500,
      manualDiscountOverride: {
        mode:      "PERCENT",
        value:     10,
        appliesTo: "HECHURA",
        kind:      "SURCHARGE",
      },
    });
    expect(res.unitPrice!.toNumber()).toBeCloseTo(1650, 2);
  });

  it("descuento 10% applyOn=TOTAL sobre manualPrice 1500 → unitPrice 1350 (baseline)", async () => {
    // Control: applyOn=TOTAL aplica sobre el manualPrice completo.
    const res = await resolveFinalSalePrice("j1", {
      articleId:              "a1",
      manualPriceOverride:     1500,
      manualDiscountOverride: {
        mode:      "PERCENT",
        value:     10,
        appliesTo: "TOTAL",
        kind:      "BONUS",
      },
    });
    expect(res.unitPrice!.toNumber()).toBeCloseTo(1350, 2);
  });

  it("descuento AMOUNT 200 applyOn=TOTAL → unitPrice 1300", async () => {
    const res = await resolveFinalSalePrice("j1", {
      articleId:              "a1",
      manualPriceOverride:     1500,
      manualDiscountOverride: {
        mode:      "AMOUNT",
        value:     200,
        appliesTo: "TOTAL",
        kind:      "BONUS",
      },
    });
    expect(res.unitPrice!.toNumber()).toBeCloseTo(1300, 2);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// PUNTO 3 — manualPrice + entityTaxExempt + manualTaxOverride
// ─────────────────────────────────────────────────────────────────────────────

describe("T43.3 — manualPrice + entityTaxExempt + manualTaxOverride", () => {
  it("Cliente EXENTO + manualPrice 1500 (sin taxOverride) → tax 0, taxExemptByEntity=true", async () => {
    mockPrisma.commercialEntity.findFirst.mockResolvedValue(makeExemptClient(true));
    const res = await resolveFinalSalePrice("j1", {
      articleId:           "a1",
      clientId:             "c1",
      manualPriceOverride:  1500,
    });
    expect(res.unitPrice!.toNumber()).toBeCloseTo(1500, 2);
    expect(res.taxAmount.toNumber()).toBe(0);
    expect(res.taxExemptByEntity).toBe(true);
  });

  it("Cliente EXENTO + manualPrice 1500 + taxOverride PERCENT 21 → tax 21% × 1500 = 315 (override gana)", async () => {
    // REGLA T43: el override manual de impuesto GANA sobre la exención
    // del cliente. La exención es default de hidratación; cuando el
    // operador ingresa impuesto manual explícito, su intención supera la
    // herencia. Documentado en POLICY.md.
    mockPrisma.commercialEntity.findFirst.mockResolvedValue(makeExemptClient(true));
    const res = await resolveFinalSalePrice("j1", {
      articleId:           "a1",
      clientId:             "c1",
      manualPriceOverride:  1500,
      taxOverride:          { mode: "PERCENT", value: 21, appliesTo: "TOTAL" },
    });
    expect(res.unitPrice!.toNumber()).toBeCloseTo(1500, 2);
    expect(res.taxAmount.toNumber()).toBeCloseTo(315, 2);
    expect(res.taxExemptByEntity).toBe(false);
    expect(res.taxBreakdown.some((t: any) => t.taxId === "OVERRIDE_MANUAL")).toBe(true);
  });

  it("Cliente EXENTO + manualPrice 1500 + taxOverride AMOUNT 100 → tax = 100", async () => {
    mockPrisma.commercialEntity.findFirst.mockResolvedValue(makeExemptClient(true));
    const res = await resolveFinalSalePrice("j1", {
      articleId:           "a1",
      clientId:             "c1",
      manualPriceOverride:  1500,
      taxOverride:          { mode: "AMOUNT", value: 100, appliesTo: "TOTAL" },
    });
    expect(res.taxAmount.toNumber()).toBeCloseTo(100, 2);
    expect(res.taxExemptByEntity).toBe(false);
  });

  it("Cliente NO exento + manualPrice + taxOverride PERCENT 21 (regresión intacta)", async () => {
    mockPrisma.commercialEntity.findFirst.mockResolvedValue(makeExemptClient(false));
    const res = await resolveFinalSalePrice("j1", {
      articleId:           "a1",
      clientId:             "c1",
      manualPriceOverride:  1500,
      taxOverride:          { mode: "PERCENT", value: 21, appliesTo: "TOTAL" },
    });
    expect(res.taxAmount.toNumber()).toBeCloseTo(315, 2);
    expect(res.taxExemptByEntity).toBe(false);
  });

  it("manualPrice + manualDiscount + taxOverride: orden = price → discount → tax", async () => {
    // Caso compuesto: precio manual 1500, descuento 10% TOTAL (= 150),
    // tax override 21% sobre subtotal post-descuento.
    // → subtotal post-descuento = 1500 − 150 = 1350.
    // → tax = 1350 × 21% = 283.5.
    mockPrisma.commercialEntity.findFirst.mockResolvedValue(makeExemptClient(false));
    const res = await resolveFinalSalePrice("j1", {
      articleId:              "a1",
      clientId:                "c1",
      manualPriceOverride:     1500,
      manualDiscountOverride: {
        mode: "PERCENT", value: 10, appliesTo: "TOTAL", kind: "BONUS",
      },
      taxOverride:             { mode: "PERCENT", value: 21, appliesTo: "TOTAL" },
    });
    expect(res.unitPrice!.toNumber()).toBeCloseTo(1350, 2);
    expect(res.taxAmount.toNumber()).toBeCloseTo(283.5, 2);
  });
});
