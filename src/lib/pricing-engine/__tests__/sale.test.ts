// src/lib/pricing-engine/__tests__/sale.test.ts
// Tests unitarios para resolveFinalSalePrice().
// Se mockea: prisma, resolveArticleCost, resolvePriceList/applyPriceList.

import { describe, it, expect, vi, beforeEach } from "vitest";
import { Prisma } from "@prisma/client";

// ── Mocks (vi.hoisted garantiza disponibilidad en las factories) ─────────────

const mockPrisma = vi.hoisted(() => ({
  article:          { findFirst:  vi.fn() },
  articleVariant:   { findFirst:  vi.fn() },
  promotion:        { findMany:   vi.fn() },
  quantityDiscount: { findMany:   vi.fn() },
  currency:         { findFirst:  vi.fn() },
  currencyRate:     { findFirst:  vi.fn() },
  metalQuote:       { findFirst:  vi.fn() },
  jewelry:          { findUnique: vi.fn() },
}));
vi.mock("../../prisma.js", () => ({ prisma: mockPrisma }));

const mockResolveArticleCost = vi.hoisted(() => vi.fn());
vi.mock("../pricing-engine.cost.js", () => ({
  resolveArticleCost: (...args: any[]) => mockResolveArticleCost(...args),
}));

const mockResolvePriceList = vi.hoisted(() => vi.fn());
const mockApplyPriceList   = vi.hoisted(() => vi.fn());
vi.mock("../../pricing.utils.js", () => ({
  resolvePriceList: (...args: any[]) => mockResolvePriceList(...args),
  applyPriceList:   (...args: any[]) => mockApplyPriceList(...args),
}));

// Import DESPUÉS de los mocks
import { resolveFinalSalePrice } from "../pricing-engine.sale.js";

// ── Helpers ──────────────────────────────────────────────────────────────────

const D = Prisma.Decimal;

/** Artículo mínimo para el select que hace la función */
function makeDbArticle(overrides: Record<string, any> = {}) {
  return {
    categoryId:           null,
    brand:                null,
    salePrice:            null,
    useManualSalePrice:   false,
    costCalculationMode:  "MANUAL",
    costPrice:            null,
    manualCurrencyId:     null,
    manualBaseCost:       null,
    manualAdjustmentKind:  null,
    manualAdjustmentType:  null,
    manualAdjustmentValue: null,
    multiplierBase:       null,
    multiplierValue:      null,
    multiplierQuantity:   null,
    multiplierCurrencyId: null,
    hechuraPrice:         null,
    hechuraPriceMode:     "FIXED",
    mermaPercent:         null,
    category:             null,
    costComposition:      [],
    compositions:         [],
    ...overrides,
  };
}

/** CostResult vacío — sin costo */
function noCost() {
  return {
    value: null,
    mode:  "MANUAL",
    partial: true,
    steps: [],
  };
}

/** CostResult con valor fijo */
function costOf(amount: number) {
  return {
    value:   new D(String(amount)),
    mode:    "MANUAL",
    partial: false,
    steps:   [],
    metalCost:   new D("0"),
    hechuraCost: new D("0"),
    totalGrams:  new D("0"),
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  // Por defecto: artículo no encontrado
  mockPrisma.article.findFirst.mockResolvedValue(null);
  mockPrisma.articleVariant.findFirst.mockResolvedValue(null);
  mockPrisma.promotion.findMany.mockResolvedValue([]);
  mockPrisma.quantityDiscount.findMany.mockResolvedValue([]);
  mockResolveArticleCost.mockResolvedValue(noCost());
  mockResolvePriceList.mockResolvedValue(null);
});

// ─────────────────────────────────────────────────────────────────────────────
// ARTÍCULO NO ENCONTRADO
// ─────────────────────────────────────────────────────────────────────────────

describe("Artículo no encontrado", () => {
  it("Devuelve todo null si el artículo no existe", async () => {
    const res = await resolveFinalSalePrice("j1", { articleId: "x" });
    expect(res.unitPrice).toBeNull();
    expect(res.basePrice).toBeNull();
    expect(res.priceSource).toBe("NONE");
    expect(res.partial).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// MANUAL_OVERRIDE
// ─────────────────────────────────────────────────────────────────────────────

describe("MANUAL_OVERRIDE", () => {
  it("useManualSalePrice=true + salePrice=3000 → finalPrice=3000", async () => {
    mockPrisma.article.findFirst.mockResolvedValue(
      makeDbArticle({ useManualSalePrice: true, salePrice: new D("3000") })
    );
    mockResolveArticleCost.mockResolvedValue(noCost());

    const res = await resolveFinalSalePrice("j1", { articleId: "a1" });
    expect(res.unitPrice?.toNumber()).toBe(3000);
    expect(res.baseSource).toBe("MANUAL_OVERRIDE");
    expect(res.priceSource).toBe("MANUAL_OVERRIDE");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// MANUAL_FALLBACK
// ─────────────────────────────────────────────────────────────────────────────

describe("MANUAL_FALLBACK", () => {
  it("salePrice=2500 (sin override) → fallback con 2500", async () => {
    mockPrisma.article.findFirst.mockResolvedValue(
      makeDbArticle({ salePrice: new D("2500") })
    );
    mockResolveArticleCost.mockResolvedValue(noCost());

    const res = await resolveFinalSalePrice("j1", { articleId: "a1" });
    expect(res.unitPrice?.toNumber()).toBe(2500);
    expect(res.baseSource).toBe("MANUAL_FALLBACK");
  });

  it("Sin salePrice ni lista → unitPrice=null", async () => {
    mockPrisma.article.findFirst.mockResolvedValue(makeDbArticle());
    mockResolveArticleCost.mockResolvedValue(noCost());

    const res = await resolveFinalSalePrice("j1", { articleId: "a1" });
    expect(res.unitPrice).toBeNull();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// VARIANT OVERRIDE
// ─────────────────────────────────────────────────────────────────────────────

describe("VARIANT_OVERRIDE", () => {
  it("variant.priceOverride=5000 → finalPrice=5000", async () => {
    mockPrisma.article.findFirst.mockResolvedValue(makeDbArticle());
    mockPrisma.articleVariant.findFirst.mockResolvedValue({
      priceOverride: new D("5000"),
    });
    mockResolveArticleCost.mockResolvedValue(noCost());

    const res = await resolveFinalSalePrice("j1", {
      articleId: "a1",
      variantId: "v1",
    });
    expect(res.unitPrice?.toNumber()).toBe(5000);
    expect(res.steps.some(s => s.key === "VARIANT_OVERRIDE")).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// PRICE_LIST
// ─────────────────────────────────────────────────────────────────────────────

describe("PRICE_LIST", () => {
  it("Lista MARGIN_TOTAL 100% sobre costo=1000 → precio=2000", async () => {
    mockPrisma.article.findFirst.mockResolvedValue(makeDbArticle());
    mockResolveArticleCost.mockResolvedValue(costOf(1000));

    const fakePriceList = {
      id: "pl1", name: "Lista General",
      mode: "MARGIN_TOTAL", marginTotal: "100",
      marginMetal: null, marginHechura: null,
      costPerGram: null, surcharge: null, minimumPrice: null,
      roundingTarget: "NONE", roundingMode: "NONE", roundingDirection: "NEAREST",
      validFrom: null, validTo: null, isActive: true,
    };
    mockResolvePriceList.mockResolvedValue({ priceList: fakePriceList, source: "GENERAL" });
    mockApplyPriceList.mockReturnValue({ value: new D("2000"), partial: false });

    const res = await resolveFinalSalePrice("j1", { articleId: "a1" });
    expect(res.unitPrice?.toNumber()).toBe(2000);
    expect(res.baseSource).toBe("PRICE_LIST");
    expect(res.appliedPriceListId).toBe("pl1");
    expect(res.appliedPriceListName).toBe("Lista General");
    expect(res.steps.some(s => s.key === "PRICE_LIST" && s.status === "ok")).toBe(true);
  });

  it("Lista encontrada pero sin datos de costo → step missing, cae a fallback", async () => {
    mockPrisma.article.findFirst.mockResolvedValue(
      makeDbArticle({ salePrice: new D("999") })
    );
    mockResolveArticleCost.mockResolvedValue(noCost());
    mockResolvePriceList.mockResolvedValue({
      priceList: { id: "pl1", name: "L", mode: "MARGIN_TOTAL", isActive: true, validFrom: null, validTo: null },
      source: "GENERAL",
    });
    mockApplyPriceList.mockReturnValue({ value: null, partial: true });

    const res = await resolveFinalSalePrice("j1", { articleId: "a1" });
    // Sin precio de lista → usa fallback
    expect(res.unitPrice?.toNumber()).toBe(999);
    expect(res.baseSource).toBe("MANUAL_FALLBACK");
    expect(res.steps.some(s => s.key === "PRICE_LIST" && s.status === "missing")).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// QUANTITY DISCOUNT
// ─────────────────────────────────────────────────────────────────────────────

describe("QUANTITY_DISCOUNT", () => {
  beforeEach(() => {
    mockPrisma.article.findFirst.mockResolvedValue(
      makeDbArticle({ salePrice: new D("1000") })
    );
    mockResolveArticleCost.mockResolvedValue(noCost());
  });

  it("10% de descuento sobre base=1000 → 900", async () => {
    mockPrisma.quantityDiscount.findMany.mockResolvedValue([{
      id: "qd1",
      articleId: "a1", variantId: null, categoryId: null, brand: null,
      tiers: [{ minQty: new D("1"), type: "PERCENTAGE", value: new D("10") }],
    }]);

    const res = await resolveFinalSalePrice("j1", { articleId: "a1", quantity: 5 });
    expect(res.unitPrice?.toNumber()).toBeCloseTo(900, 4);
    expect(res.quantityDiscountAmount?.toNumber()).toBeCloseTo(100, 4);
    expect(res.priceSource).toBe("QUANTITY_DISCOUNT");
    expect(res.appliedDiscountId).toBe("qd1");
  });

  it("Descuento FIXED -150 sobre base=1000 → 850", async () => {
    mockPrisma.quantityDiscount.findMany.mockResolvedValue([{
      id: "qd2",
      articleId: "a1", variantId: null, categoryId: null, brand: null,
      tiers: [{ minQty: new D("1"), type: "FIXED", value: new D("150") }],
    }]);

    const res = await resolveFinalSalePrice("j1", { articleId: "a1", quantity: 3 });
    expect(res.unitPrice?.toNumber()).toBeCloseTo(850, 4);
  });

  it("Descuento mayor que precio → precio nunca negativo (queda en 0)", async () => {
    mockPrisma.quantityDiscount.findMany.mockResolvedValue([{
      id: "qd3",
      articleId: "a1", variantId: null, categoryId: null, brand: null,
      tiers: [{ minQty: new D("1"), type: "FIXED", value: new D("9999") }],
    }]);

    const res = await resolveFinalSalePrice("j1", { articleId: "a1", quantity: 1 });
    expect(res.unitPrice?.toNumber()).toBeGreaterThanOrEqual(0);
  });

  it("Sin descuento aplicable → priceSource no es QUANTITY_DISCOUNT", async () => {
    const res = await resolveFinalSalePrice("j1", { articleId: "a1", quantity: 1 });
    expect(res.priceSource).not.toBe("QUANTITY_DISCOUNT");
    expect(res.quantityDiscountAmount).toBeNull();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// PROMOTION
// ─────────────────────────────────────────────────────────────────────────────

describe("PROMOTION", () => {
  beforeEach(() => {
    mockPrisma.article.findFirst.mockResolvedValue(
      makeDbArticle({ salePrice: new D("1000") })
    );
    mockResolveArticleCost.mockResolvedValue(noCost());
  });

  it("Promo FIXED -100 sobre base=1000 → 900", async () => {
    mockPrisma.promotion.findMany.mockResolvedValue([{
      id: "promo1", name: "Promo verano",
      type: "FIXED", value: new D("100"),
      scope: "ALL",
      validFrom: null, validTo: null,
      isActive: true, deletedAt: null, priority: 1,
    }]);

    const res = await resolveFinalSalePrice("j1", { articleId: "a1" });
    expect(res.unitPrice?.toNumber()).toBeCloseTo(900, 4);
    expect(res.promotionDiscountAmount?.toNumber()).toBeCloseTo(100, 4);
    expect(res.priceSource).toBe("PROMOTION");
    expect(res.appliedPromotionId).toBe("promo1");
    expect(res.appliedPromotionName).toBe("Promo verano");
  });

  it("Promo PERCENTAGE 20% sobre base=1000 → 800", async () => {
    mockPrisma.promotion.findMany.mockResolvedValue([{
      id: "promo2", name: "20% OFF",
      type: "PERCENTAGE", value: new D("20"),
      scope: "ALL",
      validFrom: null, validTo: null,
      isActive: true, deletedAt: null, priority: 1,
    }]);

    const res = await resolveFinalSalePrice("j1", { articleId: "a1" });
    expect(res.unitPrice?.toNumber()).toBeCloseTo(800, 4);
  });

  it("Promo con fecha vencida → se ignora", async () => {
    const yesterday = new Date(Date.now() - 86_400_000);
    mockPrisma.promotion.findMany.mockResolvedValue([{
      id: "promo3", name: "Expirada",
      type: "FIXED", value: new D("500"),
      scope: "ALL",
      validFrom: null, validTo: yesterday,
      isActive: true, deletedAt: null, priority: 1,
    }]);

    const res = await resolveFinalSalePrice("j1", { articleId: "a1" });
    expect(res.unitPrice?.toNumber()).toBe(1000); // sin descuento
    expect(res.priceSource).not.toBe("PROMOTION");
  });

  it("Promo isActive=false → se ignora", async () => {
    mockPrisma.promotion.findMany.mockResolvedValue([{
      id: "promo4", name: "Inactiva",
      type: "FIXED", value: new D("500"),
      scope: "ALL",
      validFrom: null, validTo: null,
      isActive: false, deletedAt: null, priority: 1,
    }]);

    const res = await resolveFinalSalePrice("j1", { articleId: "a1" });
    expect(res.unitPrice?.toNumber()).toBe(1000);
    expect(res.appliedPromotionId).toBeNull();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// QTY + PROMO combinadas
// ─────────────────────────────────────────────────────────────────────────────

describe("QTY + PROMO combinadas", () => {
  it("base=1000 → qty -10% → 900 → promo -100 → 800", async () => {
    mockPrisma.article.findFirst.mockResolvedValue(
      makeDbArticle({ salePrice: new D("1000") })
    );
    mockResolveArticleCost.mockResolvedValue(noCost());

    mockPrisma.quantityDiscount.findMany.mockResolvedValue([{
      id: "qd1",
      articleId: "a1", variantId: null, categoryId: null, brand: null,
      tiers: [{ minQty: new D("1"), type: "PERCENTAGE", value: new D("10") }],
    }]);
    mockPrisma.promotion.findMany.mockResolvedValue([{
      id: "promo1", name: "P",
      type: "FIXED", value: new D("100"),
      scope: "ALL",
      validFrom: null, validTo: null,
      isActive: true, deletedAt: null, priority: 1,
    }]);

    const res = await resolveFinalSalePrice("j1", { articleId: "a1", quantity: 5 });
    expect(res.basePrice?.toNumber()).toBe(1000);
    expect(res.quantityDiscountAmount?.toNumber()).toBeCloseTo(100, 4);
    expect(res.promotionDiscountAmount?.toNumber()).toBeCloseTo(100, 4);
    expect(res.unitPrice?.toNumber()).toBeCloseTo(800, 4);
    expect(res.discountAmount.toNumber()).toBeCloseTo(200, 4);
    expect(res.priceSource).toBe("PROMOTION");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// MARGEN
// ─────────────────────────────────────────────────────────────────────────────

describe("Margen", () => {
  it("costo=500, precio=1000 → margen=50%", async () => {
    mockPrisma.article.findFirst.mockResolvedValue(
      makeDbArticle({ salePrice: new D("1000") })
    );
    mockResolveArticleCost.mockResolvedValue(costOf(500));

    const res = await resolveFinalSalePrice("j1", { articleId: "a1" });
    expect(res.unitCost?.toNumber()).toBe(500);
    expect(res.unitMargin?.toNumber()).toBe(500);
    expect(res.marginPercent?.toNumber()).toBeCloseTo(50, 4);
    expect(res.steps.some(s => s.key === "MARGIN" && s.status === "ok")).toBe(true);
  });

  it("Sin costo → margen=null", async () => {
    mockPrisma.article.findFirst.mockResolvedValue(
      makeDbArticle({ salePrice: new D("1000") })
    );
    mockResolveArticleCost.mockResolvedValue(noCost());

    const res = await resolveFinalSalePrice("j1", { articleId: "a1" });
    expect(res.unitCost).toBeNull();
    expect(res.marginPercent).toBeNull();
  });

  it("Steps siempre incluyen PRECIO_FINAL al final", async () => {
    mockPrisma.article.findFirst.mockResolvedValue(
      makeDbArticle({ salePrice: new D("1000") })
    );
    const res = await resolveFinalSalePrice("j1", { articleId: "a1" });
    const lastStep = res.steps[res.steps.length - 1];
    expect(lastStep?.key).toBe("PRECIO_FINAL");
  });
});
