// src/lib/pricing-engine/__tests__/tax-exempt-manual-override.test.ts
// =============================================================================
// Exención de cliente = DEFAULT (hidratación), NO un candado.
//
// Bug: con cliente exento, un `taxOverride` MANUAL de la línea se descartaba
// (`entityTaxExempt ? null : opts.taxOverride`). El operador no podía cargar
// impuesto manual sobre un cliente exento.
//
// Regla:
//   · exento sin override   → tax 0, taxExemptByEntity = true  (default).
//   · exento + override      → se aplica el override, taxExemptByEntity = false
//                              (decisión explícita del operador SUPERA la
//                              exención heredada).
//   · NO exento + override   → se aplica el override (regresión: intacto).
//   · NO exento sin nada     → 0 (sin impuestos heredados configurados).
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
    categoryId: null, brand: null, groupId: null, salePrice: null,
    useManualSalePrice: false, manualAdjustmentKind: null,
    manualAdjustmentType: null, manualAdjustmentValue: null,
    costComposition: [
      { type: "MANUAL", quantity: new D("1"), unitValue: new D("1000"),
        currencyId: null, mermaPercent: null, metalVariantId: null },
    ],
    manualTaxIds: [],
    ...overrides,
  };
}

function makePriceList(overrides: Record<string, any> = {}) {
  return {
    id: "pl-test", name: "Lista Test", mode: "MARGIN_TOTAL",
    marginTotal: new D("100"), marginMetal: null, marginHechura: null,
    costPerGram: null, surcharge: null, minimumPrice: null,
    roundingTarget: "NONE", roundingMode: "NONE", roundingDirection: "NEAREST",
    roundingApplyOn: "PRICE", validFrom: null, validTo: null, isActive: true,
    scope: "GENERAL", isFavorite: true, deletedAt: null, sortOrder: 0,
    ...overrides,
  };
}

function defaultPolicy() {
  return {
    defaultMermaPercent: null, pricingLowMarginWarningPercent: null,
    pricingLowMarginBlockPercent: null, pricingBlockLossSale: false,
    pricingBlockZeroOrNegativePrice: true, pricingBlockPartialData: false,
  };
}

/** Cliente exento (sin regla comercial). */
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

// basePrice = cost 1000 × (1 + margen 100%) = 2000. Sin descuento → fp = 2000.

describe("Exención cliente = default, no candado (taxOverride manual)", () => {
  it("exento SIN override → tax 0 y taxExemptByEntity = true (hidratación)", async () => {
    mockPrisma.commercialEntity.findFirst.mockResolvedValue(makeExemptClient(true));
    const res = await resolveFinalSalePrice("j1", { articleId: "a1", clientId: "c1" });
    expect(res.taxAmount.toNumber()).toBe(0);
    expect(res.taxExemptByEntity).toBe(true);
  });

  it("exento + taxOverride PERCENT 21 (TOTAL) → se aplica; taxExemptByEntity = false", async () => {
    mockPrisma.commercialEntity.findFirst.mockResolvedValue(makeExemptClient(true));
    const res = await resolveFinalSalePrice("j1", {
      articleId: "a1", clientId: "c1",
      taxOverride: { mode: "PERCENT", value: 21, appliesTo: "TOTAL" },
    });
    // 21% sobre fp 2000 = 420 — NO se descarta por exención.
    expect(res.taxAmount.toNumber()).toBeCloseTo(420, 2);
    expect(res.taxExemptByEntity).toBe(false);
    expect(res.taxBreakdown.some((t: any) => t.taxId === "OVERRIDE_MANUAL")).toBe(true);
  });

  it("exento + taxOverride AMOUNT 50 → tax = 50; taxExemptByEntity = false", async () => {
    mockPrisma.commercialEntity.findFirst.mockResolvedValue(makeExemptClient(true));
    const res = await resolveFinalSalePrice("j1", {
      articleId: "a1", clientId: "c1",
      taxOverride: { mode: "AMOUNT", value: 50, appliesTo: "TOTAL" },
    });
    expect(res.taxAmount.toNumber()).toBeCloseTo(50, 2);
    expect(res.taxExemptByEntity).toBe(false);
  });

  it("NO exento + taxOverride AMOUNT 50 → se aplica (regresión intacta)", async () => {
    mockPrisma.commercialEntity.findFirst.mockResolvedValue(makeExemptClient(false));
    const res = await resolveFinalSalePrice("j1", {
      articleId: "a1", clientId: "c1",
      taxOverride: { mode: "AMOUNT", value: 50, appliesTo: "TOTAL" },
    });
    expect(res.taxAmount.toNumber()).toBeCloseTo(50, 2);
    expect(res.taxExemptByEntity).toBe(false);
  });

  it("NO exento, sin override ni impuestos heredados → tax 0, no exento", async () => {
    mockPrisma.commercialEntity.findFirst.mockResolvedValue(makeExemptClient(false));
    const res = await resolveFinalSalePrice("j1", { articleId: "a1", clientId: "c1" });
    expect(res.taxAmount.toNumber()).toBe(0);
    expect(res.taxExemptByEntity).toBe(false);
  });
});
