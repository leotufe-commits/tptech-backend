// src/lib/pricing-engine/__tests__/pure-grams.test.ts
// =============================================================================
// SPRINT 3 — pureGramsBase / pureGramsSale en metalHechuraBreakdown
//
// POLICY.md §8 — el motor expone gramos puros cuando hay una purity única
// en la composición. El frontend ya no los reconstruye (Sprint 2).
//
// Fórmulas:
//   pureGramsBase = metalGramsBase × purity
//   pureGramsSale = pureGramsBase × (1 + metalMarginPct/100)
//
// Casos:
//   1. Una variante con purity → pureGrams* > 0.
//   2. Variante sin purity → pureGrams* = null.
//   3. Mezcla de purity (heterogéneo) → pureGrams* = null.
// =============================================================================

import { describe, it, expect, vi, beforeEach } from "vitest";
import { Prisma } from "@prisma/client";

const mockPrisma = vi.hoisted(() => ({
  currency:         { findFirst:  vi.fn() },
  currencyRate:     { findFirst:  vi.fn() },
  metalQuote:       { findFirst:  vi.fn(), findMany: vi.fn() },
  metalVariant:     { findMany:   vi.fn() },
  jewelry:          { findUnique: vi.fn() },
  article:          { findFirst:  vi.fn() },
  articleVariant:   { findFirst:  vi.fn() },
  articleGroupItem: { findFirst:  vi.fn() },
  promotion:        { findMany:   vi.fn() },
  quantityDiscount: { findMany:   vi.fn() },
  commercialEntity: { findFirst:  vi.fn() },
  articleCategory:  { findFirst:  vi.fn() },
  priceList:        { findFirst:  vi.fn() },
  tax:              { findMany:   vi.fn() },
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
    costComposition:       [],
    manualTaxIds:          [],
    ...overrides,
  };
}

function makePriceList(overrides: Record<string, any> = {}) {
  return {
    id:               "pl-test",
    name:             "Lista Test",
    mode:             "METAL_HECHURA",
    marginTotal:      null,
    marginMetal:      new D("20"),
    marginHechura:    new D("30"),
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

beforeEach(() => {
  vi.clearAllMocks();
  mockPrisma.article.findFirst.mockResolvedValue(null);
  mockPrisma.articleVariant.findFirst.mockResolvedValue(null);
  mockPrisma.promotion.findMany.mockResolvedValue([]);
  mockPrisma.quantityDiscount.findMany.mockResolvedValue([]);
  mockPrisma.commercialEntity.findFirst.mockResolvedValue(null);
  mockPrisma.articleCategory.findFirst.mockResolvedValue(null);
  mockPrisma.priceList.findFirst.mockResolvedValue(null);
  mockPrisma.jewelry.findUnique.mockResolvedValue(defaultPolicy());
  mockPrisma.currency.findFirst.mockResolvedValue({ id: "ARS" });
  mockPrisma.metalVariant.findMany.mockResolvedValue([]);
  mockPrisma.metalQuote.findMany.mockResolvedValue([]);
  mockPrisma.tax.findMany.mockResolvedValue([]);
});

// =============================================================================
// 1. Una variante con purity → pureGrams* poblados
// =============================================================================

describe("pureGrams — caso una variante con purity definida", () => {
  it("pureGramsBase = metalGramsBase × purity, pureGramsSale aplica margen", async () => {
    // Setup: 5g de oro 18K (purity=0.750), merma=0%, precio=1000/g
    // metalGramsBase = 5g (con merma 0% sigue siendo 5)
    // metalCost = 5 × 1000 = 5000
    // marginMetal = 20% → metalSale = 6000
    // pureGramsBase = 5 × 0.750 = 3.750
    // pureGramsSale = 3.750 × 1.20 = 4.500
    mockPrisma.metalVariant.findMany.mockResolvedValue([
      { id: "v18k", saleFactor: new D("1"), purity: new D("0.750") },
    ]);
    mockPrisma.metalQuote.findMany.mockResolvedValue([
      { variantId: "v18k", price: new D("1000") },
    ]);
    mockPrisma.article.findFirst.mockResolvedValue(makeDbArticle({
      costComposition: [
        { type: "METAL",   quantity: new D("5"), unitValue: new D("0"),   currencyId: null, mermaPercent: new D("0"),   metalVariantId: "v18k" },
        { type: "HECHURA", quantity: new D("1"), unitValue: new D("200"), currencyId: null, mermaPercent: null,         metalVariantId: null },
      ],
    }));
    mockPrisma.priceList.findFirst.mockResolvedValue(makePriceList());

    const res = await resolveFinalSalePrice("j1", { articleId: "a1" });

    expect(res.metalHechuraBreakdown).not.toBeNull();
    // Sprint 3 — focus: pureGramsBase / pureGramsSale (campos nuevos).
    // (`metalGramsBase` puede venir con purity ya aplicada por
    //  `enrichCostMetalSteps` — inconsistencia pre-existente fuera de scope).
    expect(res.metalHechuraBreakdown!.pureGramsBase).toBeCloseTo(3.750, 4);
    expect(res.metalHechuraBreakdown!.pureGramsSale).toBeCloseTo(4.500, 4);
  });

  it("pureGramsSale aplica margen Y merma del costo", async () => {
    // Setup: 4g oro 22K (purity=0.916), merma=10%, margen=25%
    // metalGramsBase = 4 × 1.10 = 4.4
    // pureGramsBase  = 4.4 × 0.916 = 4.0304
    // pureGramsSale  = 4.0304 × 1.25 = 5.038
    mockPrisma.metalVariant.findMany.mockResolvedValue([
      { id: "v22k", saleFactor: new D("1"), purity: new D("0.916") },
    ]);
    mockPrisma.metalQuote.findMany.mockResolvedValue([
      { variantId: "v22k", price: new D("2000") },
    ]);
    mockPrisma.article.findFirst.mockResolvedValue(makeDbArticle({
      costComposition: [
        { type: "METAL",   quantity: new D("4"), unitValue: new D("0"),   currencyId: null, mermaPercent: new D("10"),  metalVariantId: "v22k" },
        { type: "HECHURA", quantity: new D("1"), unitValue: new D("500"), currencyId: null, mermaPercent: null,         metalVariantId: null },
      ],
    }));
    mockPrisma.priceList.findFirst.mockResolvedValue(makePriceList({
      marginMetal:   new D("25"),
      marginHechura: new D("30"),
    }));

    const res = await resolveFinalSalePrice("j1", { articleId: "a1" });
    // Sprint 3 — campos nuevos. metalGramsBase queda fuera del foco.
    expect(res.metalHechuraBreakdown!.pureGramsBase).toBeCloseTo(4.0304, 3);
    expect(res.metalHechuraBreakdown!.pureGramsSale).toBeCloseTo(5.038,  3);
  });
});

// =============================================================================
// 2. Variante sin purity → pureGrams* null
// =============================================================================

describe("pureGrams — variante sin purity definida", () => {
  it("variante con purity null → pureGramsBase y pureGramsSale = null", async () => {
    mockPrisma.metalVariant.findMany.mockResolvedValue([
      { id: "vsin", saleFactor: new D("1"), purity: null },
    ]);
    mockPrisma.metalQuote.findMany.mockResolvedValue([
      { variantId: "vsin", price: new D("1000") },
    ]);
    mockPrisma.article.findFirst.mockResolvedValue(makeDbArticle({
      costComposition: [
        { type: "METAL", quantity: new D("3"), unitValue: new D("0"), currencyId: null, mermaPercent: new D("0"), metalVariantId: "vsin" },
      ],
    }));
    mockPrisma.priceList.findFirst.mockResolvedValue(makePriceList());

    const res = await resolveFinalSalePrice("j1", { articleId: "a1" });
    // metalGramsBase debería existir (no depende de purity)
    expect(res.metalHechuraBreakdown!.metalGramsBase).toBeCloseTo(3, 4);
    // pureGrams* debería quedar null por falta de purity
    expect(res.metalHechuraBreakdown!.pureGramsBase).toBeNull();
    expect(res.metalHechuraBreakdown!.pureGramsSale).toBeNull();
  });
});

// =============================================================================
// 3. Mezcla de variantes con purity heterogénea → null (POLICY.md §8)
// =============================================================================

describe("pureGrams — mezcla de variantes (purity heterogénea)", () => {
  it("dos variantes METAL con purity distinta → pureGrams* null", async () => {
    // 18K (0.750) + 22K (0.916) en la misma composición → ambiguo
    mockPrisma.metalVariant.findMany.mockResolvedValue([
      { id: "v18k", saleFactor: new D("1"), purity: new D("0.750") },
      { id: "v22k", saleFactor: new D("1"), purity: new D("0.916") },
    ]);
    mockPrisma.metalQuote.findMany.mockResolvedValue([
      { variantId: "v18k", price: new D("1000") },
      { variantId: "v22k", price: new D("2000") },
    ]);
    mockPrisma.article.findFirst.mockResolvedValue(makeDbArticle({
      costComposition: [
        { type: "METAL", quantity: new D("3"), unitValue: new D("0"), currencyId: null, mermaPercent: new D("0"), metalVariantId: "v18k" },
        { type: "METAL", quantity: new D("2"), unitValue: new D("0"), currencyId: null, mermaPercent: new D("0"), metalVariantId: "v22k" },
      ],
    }));
    mockPrisma.priceList.findFirst.mockResolvedValue(makePriceList());

    const res = await resolveFinalSalePrice("j1", { articleId: "a1" });
    expect(res.metalHechuraBreakdown!.pureGramsBase).toBeNull();
    expect(res.metalHechuraBreakdown!.pureGramsSale).toBeNull();
  });

  it("una variante con purity y otra sin purity → null (heterogéneo)", async () => {
    mockPrisma.metalVariant.findMany.mockResolvedValue([
      { id: "v18k", saleFactor: new D("1"), purity: new D("0.750") },
      { id: "vsin", saleFactor: new D("1"), purity: null },
    ]);
    mockPrisma.metalQuote.findMany.mockResolvedValue([
      { variantId: "v18k", price: new D("1000") },
      { variantId: "vsin", price: new D("500") },
    ]);
    mockPrisma.article.findFirst.mockResolvedValue(makeDbArticle({
      costComposition: [
        { type: "METAL", quantity: new D("2"), unitValue: new D("0"), currencyId: null, mermaPercent: new D("0"), metalVariantId: "v18k" },
        { type: "METAL", quantity: new D("1"), unitValue: new D("0"), currencyId: null, mermaPercent: new D("0"), metalVariantId: "vsin" },
      ],
    }));
    mockPrisma.priceList.findFirst.mockResolvedValue(makePriceList());

    const res = await resolveFinalSalePrice("j1", { articleId: "a1" });
    expect(res.metalHechuraBreakdown!.pureGramsBase).toBeNull();
    expect(res.metalHechuraBreakdown!.pureGramsSale).toBeNull();
  });
});
