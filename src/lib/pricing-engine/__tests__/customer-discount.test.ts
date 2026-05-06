// src/lib/pricing-engine/__tests__/customer-discount.test.ts
// =============================================================================
// SPRINT 3 — customerDiscountAmount expuesto como campo singular.
//
// POLICY.md §8 — el motor expone el monto del descuento por regla de cliente
// (capa 5) independientemente del applyOn. Antes solo se exponía como
// adjustment dentro de componentSaleBreakdown cuando applyOn=METAL/HECHURA.
//
// Casos:
//   1. rule applyOn=TOTAL DISCOUNT → customerDiscountAmount > 0.
//   2. rule applyOn=METAL DISCOUNT → customerDiscountAmount > 0.
//   3. rule SURCHARGE → customerDiscountAmount = null (recargo, no descuento).
//   4. Sin cliente o sin rule → customerDiscountAmount = null.
//
// Alcance EXCLUSIVO del campo (POLICY.md §8):
//   · NO incluye quantityDiscountAmount.
//   · NO incluye promotionDiscountAmount.
//   · NO incluye SURCHARGE.
//   · NO incluye descuentos manuales (manualDiscountOverride).
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

import { resolveFinalSalePrice, buildPricingSnapshot } from "../pricing-engine.sale.js";

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
    costComposition:       [],
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

function makeClient(commercial: {
  ruleType?:  "DISCOUNT" | "BONUS" | "SURCHARGE" | null;
  valueType?: "PERCENTAGE" | "FIXED_AMOUNT" | null;
  value?:     string | null;
  applyOn?:   "TOTAL" | "METAL" | "HECHURA" | "METAL_Y_HECHURA" | "PRODUCT" | "SERVICE" | null;
}) {
  return {
    taxExempt:           false,
    taxApplyOnOverride:  null,
    commercialRuleType:  commercial.ruleType  ?? null,
    commercialValueType: commercial.valueType ?? null,
    commercialValue:     commercial.value ? new D(commercial.value) : null,
    commercialApplyOn:   commercial.applyOn   ?? null,
    taxOverrides:        [],
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  mockPrisma.article.findFirst.mockResolvedValue(makeDbArticle({
    costComposition: [
      { type: "MANUAL", quantity: new D("1"), unitValue: new D("1000"),
        currencyId: null, mermaPercent: null, metalVariantId: null },
    ],
  }));
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

// =============================================================================
// 1. rule applyOn=TOTAL → customerDiscountAmount expuesto
// =============================================================================

describe("customerDiscountAmount — rule applyOn=TOTAL (capa 5)", () => {
  it("DISCOUNT 10% sobre TOTAL → expone monto en customerDiscountAmount", async () => {
    // basePrice (lista MARGIN_TOTAL margen 100% sobre cost=1000) = 2000
    // Descuento 10% sobre TOTAL: 200
    mockPrisma.commercialEntity.findFirst.mockResolvedValue(makeClient({
      ruleType:  "DISCOUNT",
      valueType: "PERCENTAGE",
      value:     "10",
      applyOn:   "TOTAL",
    }));

    const res = await resolveFinalSalePrice("j1", { articleId: "a1", clientId: "c1" });
    expect(res.customerDiscountAmount).not.toBeNull();
    expect(res.customerDiscountAmount!.toNumber()).toBeCloseTo(200, 2);
    // unitPrice debería estar reducido
    expect(res.unitPrice!.toNumber()).toBeCloseTo(1800, 2);
  });

  it("BONUS aplyOn=TOTAL FIXED_AMOUNT 150 → customerDiscountAmount = 150", async () => {
    mockPrisma.commercialEntity.findFirst.mockResolvedValue(makeClient({
      ruleType:  "BONUS",
      valueType: "FIXED_AMOUNT",
      value:     "150",
      applyOn:   "TOTAL",
    }));

    const res = await resolveFinalSalePrice("j1", { articleId: "a1", clientId: "c1" });
    expect(res.customerDiscountAmount!.toNumber()).toBeCloseTo(150, 2);
  });

  it("snapshot persiste el valor", async () => {
    mockPrisma.commercialEntity.findFirst.mockResolvedValue(makeClient({
      ruleType:  "DISCOUNT",
      valueType: "PERCENTAGE",
      value:     "5",
      applyOn:   "TOTAL",
    }));

    const res = await resolveFinalSalePrice("j1", { articleId: "a1", clientId: "c1" });
    const snap = buildPricingSnapshot(res);
    expect(snap.customerDiscountAmount).not.toBeNull();
    expect(snap.customerDiscountAmount).toBeCloseTo(100, 2);  // 5% de 2000
  });
});

// =============================================================================
// 2. rule applyOn=METAL → customerDiscountAmount también expuesto
// =============================================================================

describe("customerDiscountAmount — rule applyOn=METAL (capa 5)", () => {
  it("DISCOUNT applyOn=METAL → expone monto agregado en customerDiscountAmount", async () => {
    // Setup con metal/hechura para que applyOn=METAL aplique
    mockPrisma.metalVariant.findMany.mockResolvedValue([
      { id: "v1", saleFactor: new D("1"), purity: null },
    ]);
    mockPrisma.metalQuote.findMany.mockResolvedValue([
      { variantId: "v1", price: new D("500") },
    ]);
    mockPrisma.article.findFirst.mockResolvedValue(makeDbArticle({
      costComposition: [
        { type: "METAL",   quantity: new D("4"), unitValue: new D("0"),   currencyId: null, mermaPercent: new D("0"), metalVariantId: "v1" },
        { type: "HECHURA", quantity: new D("1"), unitValue: new D("500"), currencyId: null, mermaPercent: null,        metalVariantId: null },
      ],
    }));
    mockPrisma.priceList.findFirst.mockResolvedValue(makePriceList({
      mode:           "METAL_HECHURA",
      marginTotal:    null,
      marginMetal:    new D("20"),  // metal: 2000 → metalSale 2400
      marginHechura:  new D("10"),  // hechura: 500 → hechuraSale 550
    }));
    mockPrisma.commercialEntity.findFirst.mockResolvedValue(makeClient({
      ruleType:  "DISCOUNT",
      valueType: "PERCENTAGE",
      value:     "5",
      applyOn:   "METAL",
    }));

    const res = await resolveFinalSalePrice("j1", { articleId: "a1", clientId: "c1" });
    // Descuento 5% sobre metalSale 2400 = 120
    expect(res.customerDiscountAmount).not.toBeNull();
    expect(res.customerDiscountAmount!.toNumber()).toBeCloseTo(120, 2);
  });
});

// =============================================================================
// 3. SURCHARGE no se incluye
// =============================================================================

describe("customerDiscountAmount — SURCHARGE no entra", () => {
  it("rule SURCHARGE applyOn=TOTAL → customerDiscountAmount = null", async () => {
    mockPrisma.commercialEntity.findFirst.mockResolvedValue(makeClient({
      ruleType:  "SURCHARGE",
      valueType: "PERCENTAGE",
      value:     "10",
      applyOn:   "TOTAL",
    }));

    const res = await resolveFinalSalePrice("j1", { articleId: "a1", clientId: "c1" });
    expect(res.customerDiscountAmount).toBeNull();
    // El recargo SÍ se aplica (precio sube), pero no entra al campo
    expect(res.unitPrice!.toNumber()).toBeGreaterThan(2000);
  });
});

// =============================================================================
// 4. Sin rule → null
// =============================================================================

describe("customerDiscountAmount — sin rule aplicada", () => {
  it("sin clientId → customerDiscountAmount = null", async () => {
    const res = await resolveFinalSalePrice("j1", { articleId: "a1" });
    expect(res.customerDiscountAmount).toBeNull();
  });

  it("clientId sin rule comercial → customerDiscountAmount = null", async () => {
    mockPrisma.commercialEntity.findFirst.mockResolvedValue(makeClient({}));
    const res = await resolveFinalSalePrice("j1", { articleId: "a1", clientId: "c1" });
    expect(res.customerDiscountAmount).toBeNull();
  });

  it("clientId con rule pero value=0 → customerDiscountAmount = null", async () => {
    mockPrisma.commercialEntity.findFirst.mockResolvedValue(makeClient({
      ruleType:  "DISCOUNT",
      valueType: "PERCENTAGE",
      value:     "0",
      applyOn:   "TOTAL",
    }));
    const res = await resolveFinalSalePrice("j1", { articleId: "a1", clientId: "c1" });
    expect(res.customerDiscountAmount).toBeNull();
  });
});

// =============================================================================
// 5. Alcance del campo (POLICY.md §8)
// =============================================================================

describe("customerDiscountAmount — alcance del campo", () => {
  it("NO incluye quantityDiscountAmount (descuento por cantidad)", async () => {
    mockPrisma.quantityDiscount.findMany.mockResolvedValue([{
      id: "qd1",
      articleId: "a1", variantId: null, categoryId: null, brand: null, groupId: null,
      isStackable: false, evaluationMode: "LINE",
      tiers: [{ minQty: new D("1"), type: "PERCENTAGE", value: new D("10") }],
    }]);
    // NO hay rule de cliente
    const res = await resolveFinalSalePrice("j1", { articleId: "a1", quantity: 2 });
    expect(res.quantityDiscountAmount).not.toBeNull();
    expect(res.quantityDiscountAmount!.toNumber()).toBeGreaterThan(0);
    expect(res.customerDiscountAmount).toBeNull();
  });

  it("quantityDiscount + rule de cliente activa → ambos coexisten, customerDiscountAmount aislado", async () => {
    mockPrisma.quantityDiscount.findMany.mockResolvedValue([{
      id: "qd1",
      articleId: "a1", variantId: null, categoryId: null, brand: null, groupId: null,
      isStackable: false, evaluationMode: "LINE",
      tiers: [{ minQty: new D("1"), type: "PERCENTAGE", value: new D("10") }],
    }]);
    mockPrisma.commercialEntity.findFirst.mockResolvedValue(makeClient({
      ruleType:  "DISCOUNT",
      valueType: "PERCENTAGE",
      value:     "5",
      applyOn:   "TOTAL",
    }));
    const res = await resolveFinalSalePrice("j1", { articleId: "a1", clientId: "c1", quantity: 2 });
    expect(res.quantityDiscountAmount).not.toBeNull();
    expect(res.customerDiscountAmount).not.toBeNull();
    // Los dos campos son independientes
    expect(res.quantityDiscountAmount!.toNumber()).not.toBe(res.customerDiscountAmount!.toNumber());
  });
});
