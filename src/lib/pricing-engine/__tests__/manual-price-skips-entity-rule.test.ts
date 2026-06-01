// src/lib/pricing-engine/__tests__/manual-price-skips-entity-rule.test.ts
// =============================================================================
// T22 — `manualPriceOverride` debe SALTEAR la condición comercial automática
// del cliente (`EntityCommercialRule`). Misma semántica que ya aplica el motor
// para `qty discount` y `promotion`: precio manual = precio final neto que el
// operador fijó; aplicar ajustes automáticos encima genera comportamiento
// "fantasma" no esperado por el usuario.
//
// Casos cubiertos:
//   1. Cliente recargo 15% + precio manual → total = manualPrice (sin recargo).
//   2. Cliente recargo 15% + precio LISTA → total CON recargo (no regresión).
//   3. Cliente descuento 10% + precio manual → total = manualPrice (sin desc.).
//   4. Cliente descuento 10% + precio LISTA → total CON descuento (no regresión).
//   5. Precio manual + manualDiscountOverride → manual override SE APLICA
//      (intención explícita del operador, distinta de la regla del cliente).
//   6. Restaurar precio automático (sin manualPriceOverride) → vuelven las
//      reglas automáticas del cliente.
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
    marginTotal:      new D("100"),  // basePrice = cost × 2 = 2000
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

describe("T22 — manualPriceOverride saltea la condición comercial del cliente", () => {
  it("Cliente RECARGO 15% + precio manual 400 → total = 400 (sin recargo encima)", async () => {
    mockPrisma.commercialEntity.findFirst.mockResolvedValue(makeClient({
      ruleType:  "SURCHARGE",
      valueType: "PERCENTAGE",
      value:     "15",
      applyOn:   "TOTAL",
    }));

    const res = await resolveFinalSalePrice("j1", {
      articleId:           "a1",
      clientId:             "c1",
      manualPriceOverride:  400,
    });
    // El precio manual gana — sin +15% del cliente.
    expect(res.unitPrice!.toNumber()).toBeCloseTo(400, 2);
    // customerDiscountAmount NO se acumula cuando el manual saltea la regla.
    expect(res.customerDiscountAmount).toBeNull();
  });

  it("Cliente RECARGO 15% + precio LISTA (sin manual) → total = lista × 1.15 (no regresión)", async () => {
    mockPrisma.commercialEntity.findFirst.mockResolvedValue(makeClient({
      ruleType:  "SURCHARGE",
      valueType: "PERCENTAGE",
      value:     "15",
      applyOn:   "TOTAL",
    }));
    // SIN manualPriceOverride → la regla del cliente se aplica normal.
    const res = await resolveFinalSalePrice("j1", { articleId: "a1", clientId: "c1" });
    // base 2000 × 1.15 = 2300.
    expect(res.unitPrice!.toNumber()).toBeCloseTo(2300, 2);
  });

  it("Cliente DESCUENTO 10% + precio manual 400 → total = 400 (sin descuento)", async () => {
    mockPrisma.commercialEntity.findFirst.mockResolvedValue(makeClient({
      ruleType:  "DISCOUNT",
      valueType: "PERCENTAGE",
      value:     "10",
      applyOn:   "TOTAL",
    }));

    const res = await resolveFinalSalePrice("j1", {
      articleId:           "a1",
      clientId:             "c1",
      manualPriceOverride:  400,
    });
    expect(res.unitPrice!.toNumber()).toBeCloseTo(400, 2);
    expect(res.customerDiscountAmount).toBeNull();
  });

  it("Cliente DESCUENTO 10% + precio LISTA → total = 1800 (no regresión)", async () => {
    mockPrisma.commercialEntity.findFirst.mockResolvedValue(makeClient({
      ruleType:  "DISCOUNT",
      valueType: "PERCENTAGE",
      value:     "10",
      applyOn:   "TOTAL",
    }));
    const res = await resolveFinalSalePrice("j1", { articleId: "a1", clientId: "c1" });
    // base 2000 − 10% = 1800.
    expect(res.unitPrice!.toNumber()).toBeCloseTo(1800, 2);
    expect(res.customerDiscountAmount!.toNumber()).toBeCloseTo(200, 2);
  });

  it("Precio manual + manualDiscountOverride (BONUS 10%) → el manual SÍ aplica encima del precio manual", async () => {
    // Manual price saltea la regla AUTO del cliente, pero el override
    // manual del operador (`manualDiscountOverride`) ES explícito y se aplica.
    mockPrisma.commercialEntity.findFirst.mockResolvedValue(makeClient({
      ruleType:  "SURCHARGE",
      valueType: "PERCENTAGE",
      value:     "15",
      applyOn:   "TOTAL",
    }));

    const res = await resolveFinalSalePrice("j1", {
      articleId:              "a1",
      clientId:                "c1",
      manualPriceOverride:     400,
      manualDiscountOverride: {
        mode:      "PERCENT",
        value:     10,
        appliesTo: "TOTAL",
        kind:      "BONUS",
      },
    });
    // 400 − 10% = 360. La regla del cliente (recargo 15%) NO se aplicó.
    expect(res.unitPrice!.toNumber()).toBeCloseTo(360, 2);
  });

  it("Precio manual + manualDiscountOverride (SURCHARGE 10%) → manual sube el precio sobre el manual", async () => {
    mockPrisma.commercialEntity.findFirst.mockResolvedValue(makeClient({
      ruleType:  "DISCOUNT",
      valueType: "PERCENTAGE",
      value:     "10",
      applyOn:   "TOTAL",
    }));

    const res = await resolveFinalSalePrice("j1", {
      articleId:              "a1",
      clientId:                "c1",
      manualPriceOverride:     400,
      manualDiscountOverride: {
        mode:      "PERCENT",
        value:     10,
        appliesTo: "TOTAL",
        kind:      "SURCHARGE",
      },
    });
    // 400 + 10% = 440. Descuento auto del cliente (10%) saltea-do.
    expect(res.unitPrice!.toNumber()).toBeCloseTo(440, 2);
  });

  it("Sin manualPriceOverride (restaurar automático) → cliente vuelve a aplicar normal", async () => {
    mockPrisma.commercialEntity.findFirst.mockResolvedValue(makeClient({
      ruleType:  "SURCHARGE",
      valueType: "PERCENTAGE",
      value:     "15",
      applyOn:   "TOTAL",
    }));
    const res = await resolveFinalSalePrice("j1", { articleId: "a1", clientId: "c1" });
    // Sin manual → vuelve a aplicar +15%.
    expect(res.unitPrice!.toNumber()).toBeCloseTo(2300, 2);
  });
});
