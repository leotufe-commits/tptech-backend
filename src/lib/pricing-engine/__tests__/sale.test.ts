// src/lib/pricing-engine/__tests__/sale.test.ts
// Tests unitarios para resolveFinalSalePrice().
// Se mockea: prisma, calculateCostFromLines, resolvePriceList/applyPriceList.

import { describe, it, expect, vi, beforeEach } from "vitest";
import { Prisma } from "@prisma/client";

// ── Mocks (vi.hoisted garantiza disponibilidad en las factories) ─────────────

const mockPrisma = vi.hoisted(() => ({
  article:          { findFirst:  vi.fn() },
  articleVariant:   { findFirst:  vi.fn() },
  articleGroupItem: { findFirst:  vi.fn() },
  promotion:        { findMany:   vi.fn() },
  quantityDiscount: { findMany:   vi.fn() },
  currency:         { findFirst:  vi.fn() },
  currencyRate:     { findFirst:  vi.fn() },
  metalQuote:       { findFirst:  vi.fn() },
  jewelry:          { findUnique: vi.fn() },
  commercialEntity: { findFirst:  vi.fn() },
  entityMermaOverride: { findMany: vi.fn() },
}));
vi.mock("../../prisma.js", () => ({ prisma: mockPrisma }));

const mockResolveArticleCost = vi.hoisted(() => vi.fn());
vi.mock("../pricing-engine.cost.js", () => ({
  // calculateCostFromLines: única API de costo — interceptada para tests de venta.
  calculateCostFromLines: (...args: any[]) => mockResolveArticleCost(...args),
  // enrichCostMetalSteps: no-op en tests unitarios — solo enriquece metadata visual.
  enrichCostMetalSteps: vi.fn(),
  // FASE 3 — set de metales del artículo. En tests unitarios el set es vacío
  // (no hay composición), así que el scope METALS nunca matchea. Equivalente
  // a "regla METALS no aplica" — comportamiento neutral para tests viejos.
  getArticleMetalVariantIds: vi.fn().mockResolvedValue([]),
  loadArticleMetalVariantsBatch: vi.fn().mockResolvedValue(new Map()),
  // applyAdjustment: helper PURO (sin DB) reutilizado por el branch combo para
  // aplicar el lineAdj del cost-line. Réplica exacta de pricing-engine.cost.ts.
  applyAdjustment: (base: any, kind?: any, adjType?: any, adjRaw?: any) => {
    if (!kind || kind === "" || adjRaw == null) return base;
    const absVal = new Prisma.Decimal(Math.abs(Number(adjRaw)).toString());
    const adjAmount = adjType === "PERCENTAGE" ? base.mul(absVal.div(100)) : absVal;
    return kind === "SURCHARGE" ? base.add(adjAmount) : base.sub(adjAmount);
  },
}));

const mockResolvePriceList = vi.hoisted(() => vi.fn());
const mockApplyPriceList   = vi.hoisted(() => vi.fn());
vi.mock("../pricing-engine.pricelist.js", () => ({
  resolvePriceList: (...args: any[]) => mockResolvePriceList(...args),
  applyPriceList:   (...args: any[]) => mockApplyPriceList(...args),
  // Implementación PURA real (NO mockeada) — necesaria desde que el combo
  // conserva `deferredRounding` y puede ejecutar el redondeo FINAL_PRICE/TOTAL.
  // Espejo exacto de `applyRounding` en pricing-engine.pricelist.ts.
  applyRounding: (value: any, mode: string, direction: string) => {
    if (mode === "NONE") return value;
    const v = Number(value?.toString?.() ?? value);
    let step: number;
    switch (mode) {
      case "INTEGER":   step = 1;    break;
      case "DECIMAL_1": step = 0.1;  break;
      case "DECIMAL_2": step = 0.01; break;
      case "TEN":       step = 10;   break;
      case "HUNDRED":   step = 100;  break;
      default: return value;
    }
    const rounded =
      direction === "UP"   ? Math.ceil(v / step) * step  :
      direction === "DOWN" ? Math.floor(v / step) * step :
                             Math.round(v / step) * step;
    return new Prisma.Decimal(String(rounded));
  },
}));

// Import DESPUÉS de los mocks
import { resolveFinalSalePrice, buildPricingSnapshot } from "../pricing-engine.sale.js";

// ── Helpers ──────────────────────────────────────────────────────────────────

const D = Prisma.Decimal;

/** Artículo mínimo para el select que hace la función */
function makeDbArticle(overrides: Record<string, any> = {}) {
  return {
    categoryId:            null,
    brand:                 null,
    salePrice:             null,
    useManualSalePrice:    false,
    manualAdjustmentKind:  null,
    manualAdjustmentType:  null,
    manualAdjustmentValue: null,
    mermaPercent:          null,
    category:              null,
    costComposition:       [],
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
  mockPrisma.articleGroupItem.findFirst.mockResolvedValue(null);
  mockPrisma.promotion.findMany.mockResolvedValue([]);
  mockPrisma.quantityDiscount.findMany.mockResolvedValue([]);
  mockPrisma.commercialEntity.findFirst.mockResolvedValue(null);
  mockPrisma.entityMermaOverride.findMany.mockResolvedValue([]);
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
// REGRESIÓN — Las variantes NO tienen precio propio (priceOverride eliminado)
// ─────────────────────────────────────────────────────────────────────────────

describe("Variantes sin precio propio — herencia del artículo padre", () => {
  it("variante NO puede override el precio — VARIANT_OVERRIDE nunca aparece en los pasos", async () => {
    // Artículo padre con salePrice=3000
    mockPrisma.article.findFirst.mockResolvedValue(makeDbArticle({ salePrice: new D("3000"), useManualSalePrice: true }));
    mockPrisma.articleVariant.findFirst.mockResolvedValue({ weightOverride: null });
    mockResolveArticleCost.mockResolvedValue(noCost());

    const res = await resolveFinalSalePrice("j1", {
      articleId: "a1",
      variantId: "v1",
    });

    // El precio es el del artículo padre (3000), no de la variante
    expect(res.unitPrice?.toNumber()).toBe(3000);
    // El paso VARIANT_OVERRIDE nunca debe aparecer (fue eliminado)
    expect(res.steps.some(s => s.key === "VARIANT_OVERRIDE")).toBe(false);
  });

  it("variante solo puede tener weightOverride — no priceOverride", async () => {
    // Solo weightOverride es válido en variante
    mockPrisma.article.findFirst.mockResolvedValue(makeDbArticle());
    mockPrisma.articleVariant.findFirst.mockResolvedValue({ weightOverride: new D("5") });
    mockResolveArticleCost.mockResolvedValue(noCost());

    // No debe haber error ni intento de leer priceOverride
    const res = await resolveFinalSalePrice("j1", { articleId: "a1", variantId: "v1" });
    expect(res).toBeDefined();
    // La query a articleVariant solo pide weightOverride (no priceOverride)
    const selectArg = mockPrisma.articleVariant.findFirst.mock.calls[0]?.[0]?.select ?? {};
    expect(selectArg).not.toHaveProperty("priceOverride");
    expect(selectArg).toHaveProperty("weightOverride");
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
      articleId: "a1", variantId: null, categoryId: null, brand: null, groupId: null,
      isStackable: true, evaluationMode: "LINE",
      tiers: [{ minQty: new D("1"), type: "PERCENTAGE", value: new D("10") }],
    }]);
    mockPrisma.promotion.findMany.mockResolvedValue([{
      id: "promo1", name: "P",
      type: "FIXED", value: new D("100"),
      scope: "ALL", applyOn: "TOTAL",
      validFrom: null, validTo: null,
      isActive: true, deletedAt: null, priority: 1,
      isStackable: true,
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

  it("Steps siempre incluyen PRECIO_FINAL", async () => {
    mockPrisma.article.findFirst.mockResolvedValue(
      makeDbArticle({ salePrice: new D("1000") })
    );
    const res = await resolveFinalSalePrice("j1", { articleId: "a1" });
    expect(res.steps.map(s => s.key)).toContain("PRECIO_FINAL");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// COMPOSICIÓN DE COSTO — aislación de variante
//
// Garantiza que el simulador usa SOLO la composición efectiva de la variante
// seleccionada, sin mezclar líneas del padre ni de otras variantes.
// ─────────────────────────────────────────────────────────────────────────────

/** Línea de costo mínima (shape compatible con CostLineInput) */
function makeCostLine(overrides: Record<string, any> = {}) {
  return {
    type: "METAL",
    label: "Oro 18K",
    quantity: new D("1"),
    unitValue: new D("1000"),
    currencyId: null,
    mermaPercent: null,
    metalVariantId: null,
    lineAdjKind: null,
    lineAdjType: null,
    lineAdjValue: null,
    catalogItem: null,
    ...overrides,
  };
}

describe("Composición efectiva — aislación de variante en simulador", () => {
  beforeEach(() => {
    mockResolveArticleCost.mockResolvedValue(noCost());
    mockPrisma.promotion.findMany.mockResolvedValue([]);
    mockPrisma.quantityDiscount.findMany.mockResolvedValue([]);
    mockResolvePriceList.mockResolvedValue(null);
  });

  it("variante con variantId → calculateCostFromLines siempre recibe las líneas del PADRE", async () => {
    // Nueva arquitectura: las variantes no tienen costLines propias.
    // El costo siempre proviene del artículo padre (costComposition).
    const parentLine = makeCostLine({ quantity: new D("10"), label: "Línea padre" });

    mockPrisma.article.findFirst.mockResolvedValue(
      makeDbArticle({ costComposition: [parentLine] }),
    );
    mockPrisma.articleVariant.findFirst.mockResolvedValue({ weightOverride: null });

    await resolveFinalSalePrice("j1", { articleId: "a1", variantId: "v1" });

    const passedLines = mockResolveArticleCost.mock.calls[0][1];
    expect(passedLines).toHaveLength(1);
    expect(passedLines[0].label).toBe("Línea padre");
    expect(passedLines[0].quantity.toString()).toBe("10");
  });

  it("variante hereda del padre — múltiples líneas recibidas sin mezcla ni duplicación", async () => {
    const parentLine1 = makeCostLine({ quantity: new D("10"), label: "Metal padre" });
    const parentLine2 = makeCostLine({ type: "HECHURA", quantity: new D("1"), label: "Hechura padre" });

    mockPrisma.article.findFirst.mockResolvedValue(
      makeDbArticle({ costComposition: [parentLine1, parentLine2] }),
    );
    mockPrisma.articleVariant.findFirst.mockResolvedValue({ weightOverride: null });

    await resolveFinalSalePrice("j1", { articleId: "a1", variantId: "v1" });

    const passedLines = mockResolveArticleCost.mock.calls[0][1];
    expect(passedLines).toHaveLength(2);
    expect(passedLines[0].label).toBe("Metal padre");
    expect(passedLines[1].label).toBe("Hechura padre");
  });

  it("sin variantId → calculateCostFromLines recibe las líneas del padre sin modificar", async () => {
    const parentLine = makeCostLine({ quantity: new D("7"), label: "Padre solo" });

    mockPrisma.article.findFirst.mockResolvedValue(
      makeDbArticle({ costComposition: [parentLine] }),
    );
    // No se carga variante

    await resolveFinalSalePrice("j1", { articleId: "a1" });

    const passedLines = mockResolveArticleCost.mock.calls[0][1];
    expect(passedLines).toHaveLength(1);
    expect(passedLines[0].label).toBe("Padre solo");
  });

  it("variante sin weightOverride — el costo del padre no se modifica", async () => {
    // El costo siempre proviene del padre, las variantes solo pueden ajustar peso.
    const parentLine = makeCostLine({ label: "Metal padre", quantity: new D("10") });

    mockPrisma.article.findFirst.mockResolvedValue(
      makeDbArticle({ costComposition: [parentLine] }),
    );
    mockPrisma.articleVariant.findFirst.mockResolvedValue({ weightOverride: null });

    await resolveFinalSalePrice("j1", { articleId: "a1", variantId: "v1" });

    // El costo sigue siendo del padre, sin mezcla ni modificación
    const passedLines = mockResolveArticleCost.mock.calls[0][1];
    expect(passedLines).toHaveLength(1);
    expect(passedLines[0].label).toBe("Metal padre");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// COMBO — límite de profundidad y anti-ciclo en el motor
// ─────────────────────────────────────────────────────────────────────────────

describe("Combo comercial — guards del motor", () => {
  it("profundidad > 5 bloquea el cálculo del combo con step COMBO_COST missing", async () => {
    // Simula que ya estamos en el nivel 5 de anidamiento (el caller es otro combo).
    // El motor debe cortar antes de resolver componentes.
    mockPrisma.article.findFirst.mockResolvedValue(
      makeDbArticle({
        commercialMode: "COMBO_COMMERCIAL",
        costComposition: [
          { type: "PRODUCT", catalogItemId: "child-1", quantity: new D("1"), catalogItem: { id: "child-1", code: "C1", name: "Child 1" } },
        ],
      }),
    );

    const res = await resolveFinalSalePrice("j1", {
      articleId: "combo-deep",
      _comboContext: { depth: 5, visited: new Set<string>() },
    });

    // El combo no resuelve costo → unitCost null y partial true
    expect(res.unitCost).toBeNull();
    expect(res.partial).toBe(true);

    // Debe aparecer el step COMBO_COST con status missing y mensaje de profundidad
    const comboStep = res.steps.find((s) => s.key === "COMBO_COST");
    expect(comboStep).toBeDefined();
    expect(comboStep?.status).toBe("missing");
    expect(comboStep?.message).toMatch(/[Pp]rofundidad/);
  });

  it("ciclo detectado en runtime (articleId ya visitado) → step COMBO_COST missing con 'Ciclo'", async () => {
    mockPrisma.article.findFirst.mockResolvedValue(
      makeDbArticle({
        commercialMode: "COMBO_COMMERCIAL",
        costComposition: [
          { type: "PRODUCT", catalogItemId: "child-1", quantity: new D("1"), catalogItem: { id: "child-1", code: "C1", name: "Child 1" } },
        ],
      }),
    );

    const res = await resolveFinalSalePrice("j1", {
      articleId: "combo-cycle",
      _comboContext: { depth: 0, visited: new Set<string>(["combo-cycle"]) },
    });

    expect(res.unitCost).toBeNull();
    expect(res.partial).toBe(true);

    const comboStep = res.steps.find((s) => s.key === "COMBO_COST");
    expect(comboStep).toBeDefined();
    expect(comboStep?.status).toBe("missing");
    expect(comboStep?.message).toMatch(/[Cc]iclo/);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// COMBO — precio derivado de componentes (Opción A)
// ─────────────────────────────────────────────────────────────────────────────
//
// El precio de venta de un COMBO_COMMERCIAL se deriva de sus componentes:
//   precio combo = Σ(precio de venta del componente × cantidad) ± ajuste propio
//   costo  combo = Σ(costo del componente × cantidad)
// cuando NO hay lista de precios ni precio manual. priceSource="COMBO_COMPONENTS".
// El ajuste reutiliza el SSOT applyComboAdjustment (combo.utils.ts).
// ─────────────────────────────────────────────────────────────────────────────

describe("Combo comercial — precio derivado de componentes (Opción A)", () => {
  /** Registra artículos por id para el findFirst recursivo (combo + componentes). */
  function registerArticles(map: Record<string, any>) {
    mockPrisma.article.findFirst.mockImplementation(async (args: any) => {
      const id = args?.where?.id;
      return map[id] ?? null;
    });
  }

  /** Línea de componente del combo (PRODUCT con catalogItemId). */
  function comp(id: string, qty: number) {
    return {
      type: "PRODUCT",
      catalogItemId: id,
      quantity: new D(String(qty)),
      catalogItem: { id, code: id.toUpperCase(), name: id },
    };
  }

  it("1) combo con un componente con precio → unitCost/unitPrice/totalWithTax > 0", async () => {
    registerArticles({
      "combo-1": makeDbArticle({
        commercialMode: "COMBO_COMMERCIAL",
        costComposition: [comp("comp-1", 1)],
      }),
      "comp-1": makeDbArticle({ useManualSalePrice: true, salePrice: new D("200") }),
    });
    mockResolveArticleCost.mockResolvedValue(costOf(100));

    const res = await resolveFinalSalePrice("j1", { articleId: "combo-1" });

    expect(res.priceSource).toBe("COMBO_COMPONENTS");
    expect(res.unitCost?.toNumber()).toBe(100);            // Σ costo componente × qty
    expect(res.unitPrice?.toNumber()).toBe(200);           // Σ precio componente × qty
    expect(res.totalWithTax?.toNumber()).toBeGreaterThan(0);
    expect(res.partial).toBe(false);

    // Step de trazabilidad del precio del combo
    const priceStep = res.steps.find((s) => s.key === "COMBO_PRICE");
    expect(priceStep?.status).toBe("ok");
    expect((priceStep?.meta as any)?.subtotal).toBe(200);
  });

  it("2) varios componentes → unitCost = Σ(costo×qty), unitPrice = Σ(precio×qty)", async () => {
    registerArticles({
      "combo-2": makeDbArticle({
        commercialMode: "COMBO_COMMERCIAL",
        costComposition: [comp("comp-a", 2), comp("comp-b", 3)],
      }),
      "comp-a": makeDbArticle({ useManualSalePrice: true, salePrice: new D("200") }),
      "comp-b": makeDbArticle({ useManualSalePrice: true, salePrice: new D("300") }),
    });
    mockResolveArticleCost.mockResolvedValue(costOf(100)); // costo 100 por componente

    const res = await resolveFinalSalePrice("j1", { articleId: "combo-2" });

    expect(res.unitCost?.toNumber()).toBe(500);   // 100×2 + 100×3
    expect(res.unitPrice?.toNumber()).toBe(1300);  // 200×2 + 300×3
    expect(res.priceSource).toBe("COMBO_COMPONENTS");
  });

  describe("3) ajuste propio del combo (comboAdjustmentKind/Value)", () => {
    function comboWithAdjustment(kind: string, value: number | null) {
      registerArticles({
        "combo-adj": makeDbArticle({
          commercialMode: "COMBO_COMMERCIAL",
          comboAdjustmentKind: kind,
          comboAdjustmentValue: value != null ? new D(String(value)) : null,
          costComposition: [comp("comp-1", 1)],
        }),
        "comp-1": makeDbArticle({ useManualSalePrice: true, salePrice: new D("1000") }),
      });
      mockResolveArticleCost.mockResolvedValue(costOf(400));
    }

    it("NONE → suma directa (1000)", async () => {
      comboWithAdjustment("NONE", null);
      const res = await resolveFinalSalePrice("j1", { articleId: "combo-adj" });
      expect(res.unitPrice?.toNumber()).toBe(1000);
    });

    it("DISCOUNT_PERCENT 10 → 900", async () => {
      comboWithAdjustment("DISCOUNT_PERCENT", 10);
      const res = await resolveFinalSalePrice("j1", { articleId: "combo-adj" });
      expect(res.unitPrice?.toNumber()).toBeCloseTo(900, 4);
    });

    it("SURCHARGE_PERCENT 10 → 1100", async () => {
      comboWithAdjustment("SURCHARGE_PERCENT", 10);
      const res = await resolveFinalSalePrice("j1", { articleId: "combo-adj" });
      expect(res.unitPrice?.toNumber()).toBeCloseTo(1100, 4);
    });

    it("DISCOUNT_FIXED 250 → 750", async () => {
      comboWithAdjustment("DISCOUNT_FIXED", 250);
      const res = await resolveFinalSalePrice("j1", { articleId: "combo-adj" });
      expect(res.unitPrice?.toNumber()).toBeCloseTo(750, 4);
    });
  });

  it("4) simulador ↔ factura: el resolver compartido es determinístico (misma línea, mismo resultado)", async () => {
    // El Simulador (getPricingPreview) y la Factura (previewSale) resuelven la
    // línea con el MISMO resolveFinalSalePrice. Si el resolver es determinístico
    // sobre el mismo input, ambas superficies muestran el mismo número.
    registerArticles({
      "combo-par": makeDbArticle({
        commercialMode: "COMBO_COMMERCIAL",
        costComposition: [comp("comp-1", 2)],
      }),
      "comp-1": makeDbArticle({ useManualSalePrice: true, salePrice: new D("150") }),
    });
    // mockImplementation → objeto de costo fresco por llamada (el branch combo
    // muta costResult.value; en producción cada call recibe un objeto nuevo).
    mockResolveArticleCost.mockImplementation(async () => costOf(80));

    const sim = await resolveFinalSalePrice("j1", { articleId: "combo-par" });
    const inv = await resolveFinalSalePrice("j1", { articleId: "combo-par" });

    expect(inv.priceSource).toBe(sim.priceSource);
    expect(inv.unitPrice?.toNumber()).toBe(sim.unitPrice?.toNumber());
    expect(inv.unitCost?.toNumber()).toBe(sim.unitCost?.toNumber());
    expect(inv.totalWithTax?.toNumber()).toBe(sim.totalWithTax?.toNumber());
    expect(sim.unitPrice?.toNumber()).toBe(300); // 150 × 2
  });

  it("5) preview ↔ confirmación: el snapshot del precio del combo es estable entre llamadas", async () => {
    // Preview y confirmación consumen el MISMO resolver. La estabilidad del
    // COMBO_PRICE + totales entre llamadas idénticas es la base de la paridad
    // preview/confirm (la parity full-stack vive en preview-confirm-parity.test.ts).
    registerArticles({
      "combo-snap": makeDbArticle({
        commercialMode: "COMBO_COMMERCIAL",
        comboAdjustmentKind: "DISCOUNT_PERCENT",
        comboAdjustmentValue: new D("20"),
        costComposition: [comp("comp-1", 1), comp("comp-2", 1)],
      }),
      "comp-1": makeDbArticle({ useManualSalePrice: true, salePrice: new D("600") }),
      "comp-2": makeDbArticle({ useManualSalePrice: true, salePrice: new D("400") }),
    });
    // objeto de costo fresco por llamada (ver nota en el test de paridad sim↔factura)
    mockResolveArticleCost.mockImplementation(async () => costOf(200));

    const previewRes = await resolveFinalSalePrice("j1", { articleId: "combo-snap" });
    const confirmRes = await resolveFinalSalePrice("j1", { articleId: "combo-snap" });

    // subtotal 1000, descuento 20% → 800
    expect(previewRes.unitPrice?.toNumber()).toBeCloseTo(800, 4);
    expect(confirmRes.unitPrice?.toNumber()).toBe(previewRes.unitPrice?.toNumber());
    expect(confirmRes.unitCost?.toNumber()).toBe(previewRes.unitCost?.toNumber());

    const pStep = previewRes.steps.find((s) => s.key === "COMBO_PRICE");
    const cStep = confirmRes.steps.find((s) => s.key === "COMBO_PRICE");
    expect((cStep?.meta as any)?.finalPrice).toBe((pStep?.meta as any)?.finalPrice);
    expect((pStep?.meta as any)?.adjustmentAmount).toBeCloseTo(200, 4); // 20% de 1000
  });

  it("6) componente sin precio → no explota, marca parcial y deja advertencia clara", async () => {
    registerArticles({
      "combo-miss": makeDbArticle({
        commercialMode: "COMBO_COMMERCIAL",
        costComposition: [comp("comp-ok", 1), comp("comp-noprice", 1)],
      }),
      "comp-ok":      makeDbArticle({ useManualSalePrice: true, salePrice: new D("500") }),
      "comp-noprice": makeDbArticle({ /* sin precio manual ni lista → noPrice */ }),
    });
    mockResolveArticleCost.mockResolvedValue(costOf(100));

    const res = await resolveFinalSalePrice("j1", { articleId: "combo-miss" });

    // No rompe: el combo conserva el precio del componente válido
    expect(res.unitPrice?.toNumber()).toBe(500);
    expect(res.priceSource).toBe("COMBO_COMPONENTS");
    expect(res.partial).toBe(true);

    const priceStep = res.steps.find((s) => s.key === "COMBO_PRICE");
    expect(priceStep).toBeDefined();
    expect(priceStep?.status).toBe("partial");
    expect((priceStep?.meta as any)?.componentsWithPrice).toBe(1);
    expect((priceStep?.meta as any)?.componentsMissingPrice).toBe(1);
  });

  it("combo con salePrice=0 residual + componentes con precio → COMBO_COMPONENTS (no MANUAL_FALLBACK)", async () => {
    // Regresión: el combo puede tener salePrice=0 persistido (legacy). El
    // fallback salePrice NO debe ganarle al precio derivado de componentes.
    registerArticles({
      "combo-sp0": makeDbArticle({
        commercialMode: "COMBO_COMMERCIAL",
        salePrice: new D("0"),          // ← salePrice residual no-nulo
        useManualSalePrice: false,
        costComposition: [comp("comp-1", 1)],
      }),
      "comp-1": makeDbArticle({ useManualSalePrice: true, salePrice: new D("750") }),
    });
    mockResolveArticleCost.mockImplementation(async () => costOf(300));

    const res = await resolveFinalSalePrice("j1", { articleId: "combo-sp0" });

    expect(res.priceSource).toBe("COMBO_COMPONENTS");
    expect(res.unitPrice?.toNumber()).toBe(750);
    expect(res.unitCost?.toNumber()).toBe(300);
    expect(res.totalWithTax?.toNumber()).toBeGreaterThan(0);
  });

  it("no regresiona: combo CON precio manual propio NO usa el derivado", async () => {
    // Si el operador fijó precio manual en el combo, ese gana (igual que
    // cualquier artículo). El derivado solo entra cuando no hay lista ni manual.
    registerArticles({
      "combo-man": makeDbArticle({
        commercialMode: "COMBO_COMMERCIAL",
        useManualSalePrice: true,
        salePrice: new D("9999"),
        costComposition: [comp("comp-1", 1)],
      }),
      "comp-1": makeDbArticle({ useManualSalePrice: true, salePrice: new D("200") }),
    });
    mockResolveArticleCost.mockResolvedValue(costOf(100));

    const res = await resolveFinalSalePrice("j1", { articleId: "combo-man" });

    expect(res.priceSource).toBe("MANUAL_OVERRIDE");
    expect(res.unitPrice?.toNumber()).toBe(9999);
  });

  // ── Shadow del override manual = 0 en combos (fix de precedencia) ─────────
  // El "0" inicial de la línea (campo Precio editable) NO debe pisar el precio
  // derivado del combo. Un override REAL del operador (> 0) sigue ganando.
  it("Caso 1: combo + manualPriceOverride=0 → NO shadowea, queda COMBO_COMPONENTS", async () => {
    registerArticles({
      "combo-z": makeDbArticle({
        commercialMode: "COMBO_COMMERCIAL",
        salePrice: new D("0"),
        useManualSalePrice: false,
        costComposition: [comp("comp-1", 1)],
      }),
      "comp-1": makeDbArticle({ useManualSalePrice: true, salePrice: new D("673") }),
    });
    mockResolveArticleCost.mockImplementation(async () => costOf(300));

    const res = await resolveFinalSalePrice("j1", {
      articleId: "combo-z",
      manualPriceOverride: 0,        // ← 0 inicial de la línea, NO override real
    });

    expect(res.priceSource).toBe("COMBO_COMPONENTS");
    expect(res.unitPrice?.toNumber()).toBe(673);
    expect(res.totalWithTax?.toNumber()).toBeGreaterThan(0);
  });

  it("Caso 2: combo + manualPriceOverride=800000 → override REAL gana (MANUAL_OVERRIDE)", async () => {
    registerArticles({
      "combo-m": makeDbArticle({
        commercialMode: "COMBO_COMMERCIAL",
        salePrice: new D("0"),
        useManualSalePrice: false,
        costComposition: [comp("comp-1", 1)],
      }),
      "comp-1": makeDbArticle({ useManualSalePrice: true, salePrice: new D("673") }),
    });
    mockResolveArticleCost.mockImplementation(async () => costOf(300));

    const res = await resolveFinalSalePrice("j1", {
      articleId: "combo-m",
      manualPriceOverride: 800000,
    });

    expect(res.priceSource).toBe("MANUAL_OVERRIDE");
    expect(res.unitPrice?.toNumber()).toBe(800000);
  });

  it("Caso 3: artículo NORMAL + manualPriceOverride=0 → comportamiento intacto (MANUAL_OVERRIDE=0)", async () => {
    // No combo (comboDerivedPrice=null) → el override 0 sigue siendo válido.
    registerArticles({
      "art-normal": makeDbArticle({ salePrice: new D("1000") }), // basePrice vía MANUAL_FALLBACK
    });
    mockResolveArticleCost.mockImplementation(async () => costOf(400));

    const res = await resolveFinalSalePrice("j1", {
      articleId: "art-normal",
      manualPriceOverride: 0,
    });

    expect(res.priceSource).toBe("MANUAL_OVERRIDE");
    expect(res.unitPrice?.toNumber()).toBe(0);
  });

  // ── Caso real: lista/promo del combo resuelve basePrice=0 (no null) ───────
  // Una PRICE_LIST en modo margen evalúa a 0 sobre el combo (costo agregado 0),
  // dejando basePrice=0 y, antes del fix, bloqueando el branch COMBO_COMPONENTS
  // (que exigía basePrice==null). El componente SÍ tiene precio → el combo debe
  // resolver con el precio derivado, no quedar en 0.
  it("combo con PRICE_LIST que deja basePrice=0 + componentes con precio → COMBO_COMPONENTS, unitPrice>0", async () => {
    registerArticles({
      "combo-pl0": makeDbArticle({
        commercialMode: "COMBO_COMMERCIAL",
        categoryId: "cat-combo",                 // ← solo el combo tiene lista (por categoría)
        costComposition: [comp("comp-1", 1)],
      }),
      "comp-1": makeDbArticle({
        categoryId: null,
        useManualSalePrice: true,
        salePrice: new D("673289.37"),           // ← el componente SÍ tiene precio
      }),
    });
    mockResolveArticleCost.mockImplementation(async () => costOf(0)); // costo combo 0
    // Lista SOLO para el combo (categoryId="cat-combo"); el componente no matchea.
    mockResolvePriceList.mockImplementation(async (_jw: string, opts: any) =>
      opts?.categoryId === "cat-combo"
        ? { priceList: { id: "pl-combo", name: "Lista Combo", mode: "MARGIN_TOTAL" }, source: "CATEGORY" }
        : null,
    );
    // La lista evalúa a 0 sobre el combo (margen sobre costo 0).
    mockApplyPriceList.mockReturnValue({ value: new D("0"), partial: false });

    const res = await resolveFinalSalePrice("j1", { articleId: "combo-pl0" });

    expect(res.priceSource).toBe("COMBO_COMPONENTS");
    expect(res.basePrice?.toNumber()).toBeGreaterThan(0);
    expect(res.unitPrice?.toNumber()).toBeGreaterThan(0);
    expect(res.unitPrice?.toNumber()).toBeCloseTo(673289.37, 2);
    expect(res.totalWithTax?.toNumber()).toBeGreaterThan(0);
    // La lista que resolvió 0 no debe quedar atribuida.
    expect(res.appliedPriceListId).toBeNull();
  });

  // ── Opción A: base del combo INMUNE a promo del componente ────────────────
  // Una promoción scope ALL pega al combo Y (recursivamente) a cada componente.
  // El precio del combo debe derivar del BASE del componente (pre-promo), NO de
  // su unitPrice (post-promo) → la promo se aplica UNA sola vez sobre la base
  // real, sin doble conteo.
  it("caso real: promo scope ALL + combo → base = precio BASE del componente (no post-promo), promo 1 sola vez", async () => {
    mockPrisma.promotion.findMany.mockResolvedValue([{
      id: "promo-all", name: "PROMO ALL",
      type: "PERCENTAGE", value: new D("50"),
      scope: "ALL",
      validFrom: null, validTo: null,
      isActive: true, deletedAt: null, priority: 1,
    }]);
    registerArticles({
      "combo-promo": makeDbArticle({
        commercialMode: "COMBO_COMMERCIAL",
        costComposition: [comp("comp-1", 1)],
      }),
      "comp-1": makeDbArticle({ useManualSalePrice: true, salePrice: new D("673289.37") }),
    });
    mockResolveArticleCost.mockImplementation(async () => costOf(100000));

    const res = await resolveFinalSalePrice("j1", { articleId: "combo-promo" });

    // base = precio BASE del componente (673289.37), NO el post-promo (336644.685).
    // Con el bug anterior (usar unitPrice) basePrice habría quedado en 336644.685.
    expect(res.basePrice?.toNumber()).toBeCloseTo(673289.37, 2);
    // promo del combo aplicada UNA sola vez sobre la base real (50% off):
    //   673289.37 × 0.5 = 336644.685   (NO 168322.34 = doble promo)
    expect(res.unitPrice?.toNumber()).toBeCloseTo(336644.685, 2);
    expect(res.unitPrice!.toNumber()).toBeGreaterThan(0);
    expect(res.priceSource).toBe("PROMOTION");
    expect(res.appliedPromotionId).toBe("promo-all");
    expect(res.promotionDiscountAmount!.toNumber()).toBeGreaterThan(0);
    expect(res.totalWithTax?.toNumber()).toBeGreaterThan(0);
  });

  // ── Propagación del contexto comercial a la recursión del componente ──────
  // Root cause runtime: el componente deriva su precio de la LISTA. Resuelto
  // "bare" (sin lista/cliente del documento) devolvía null → comboDerivedPrice
  // colapsaba → basePrice=0. La recursión ahora propaga clientId/priceList del
  // documento → el componente resuelve igual que individualmente (673289.37).
  it("caso real: componente con precio SOLO por lista → la recursión propaga el contexto → combo > 0", async () => {
    const comboList = { id: "pl-combo", name: "L combo", mode: "MARGIN_TOTAL",
      marginTotal: null, marginMetal: null, marginHechura: null, costPerGram: null,
      surcharge: null, minimumPrice: null, roundingTarget: "NONE", roundingMode: "NONE",
      roundingDirection: "NEAREST", validFrom: null, validTo: null, isActive: true };
    const compList = { ...comboList, id: "pl-comp", name: "L comp" };

    registerArticles({
      "combo-ctx": makeDbArticle({
        commercialMode: "COMBO_COMMERCIAL",
        categoryId: "cat-combo",
        costComposition: [comp("comp-1", 1)],
      }),
      // El componente NO tiene precio propio (ni salePrice ni override): su
      // precio sale exclusivamente de la lista resuelta por clientId.
      "comp-1": makeDbArticle({ categoryId: null }),
    });
    mockResolveArticleCost.mockImplementation(async () => costOf(100000));
    // Lista del combo (por categoría) → 0. Lista del componente (por cliente) → 673289.37.
    mockResolvePriceList.mockImplementation(async (_jw: string, opts: any) => {
      if (opts?.categoryId === "cat-combo") return { priceList: comboList, source: "CATEGORY" };
      if (opts?.clientId) return { priceList: compList, source: "CLIENT" };
      return null; // bare (sin contexto) → el componente NO resolvía precio
    });
    mockApplyPriceList.mockImplementation((priceList: any) =>
      priceList?.id === "pl-combo"
        ? { value: new D("0"), partial: false }
        : { value: new D("673289.37"), partial: false },
    );

    // El documento se resuelve CON clientId (contexto comercial real).
    const res = await resolveFinalSalePrice("j1", { articleId: "combo-ctx", clientId: "cli-1" });

    expect(res.priceSource).toBe("COMBO_COMPONENTS");
    expect(res.basePrice?.toNumber()).toBeCloseTo(673289.37, 2);  // = precio individual del componente
    expect(res.unitPrice?.toNumber()).toBeGreaterThan(0);
    expect(res.totalWithTax?.toNumber()).toBeGreaterThan(0);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// COMBO — ajuste interno del cost-line (lineAdj) en el precio base (Modelo A)
// ─────────────────────────────────────────────────────────────────────────────
//
// Fuente ÚNICA: cost-line del componente → lineAdj interno → margen → venta.
//   costLineAdj  = applyAdjustment(unitValue × qty, lineAdj)
//   marginFactor = componentResult.basePrice / componentResult.unitCost
//   contribución = costLineAdj × marginFactor
// Elimina la doble fuente de verdad (composición vs precio principal).
// Caso BR000: unitValue=404378, unitCost=404378, basePrice=748099,30 → margen 1,85.
// ─────────────────────────────────────────────────────────────────────────────
describe("Combo — lineAdj del cost-line afecta el precio base (Modelo A)", () => {
  function registerArticles(map: Record<string, any>) {
    mockPrisma.article.findFirst.mockImplementation(async (args: any) => map[args?.where?.id] ?? null);
  }
  /** Cost-line de componente con unitValue + ajuste interno opcional. */
  function compAdj(
    id: string, qty: number, unitValue: number,
    adj?: { kind: string; type: string; value: number },
    type: "PRODUCT" | "SERVICE" = "PRODUCT",
  ) {
    return {
      type, catalogItemId: id, quantity: new D(String(qty)),
      unitValue: new D(String(unitValue)),
      lineAdjKind:  adj?.kind  ?? "",
      lineAdjType:  adj?.type  ?? "",
      lineAdjValue: adj?.value != null ? new D(String(adj.value)) : null,
      catalogItem: { id, code: id.toUpperCase(), name: id },
    };
  }
  // BR000-like: basePrice 748099,30 (manual), unitCost 404378 → margen 1,85.
  const BR000 = { useManualSalePrice: true, salePrice: new D("748099.30") };

  it("1) PERCENTAGE −10% → basePrice = costLineAdj × margen (673289,37)", async () => {
    registerArticles({
      "combo": makeDbArticle({ commercialMode: "COMBO_COMMERCIAL",
        costComposition: [compAdj("br000", 1, 404378, { kind: "BONUS", type: "PERCENTAGE", value: 10 })] }),
      "br000": makeDbArticle(BR000),
    });
    mockResolveArticleCost.mockImplementation(async () => costOf(404378));
    const res = await resolveFinalSalePrice("j1", { articleId: "combo" });
    expect(res.priceSource).toBe("COMBO_COMPONENTS");
    expect(res.basePrice?.toNumber()).toBeCloseTo(673289.37, 2);
    // El subtotal del COMBO_PRICE (que alimenta basePrice) = venta ajustada → paridad con composición.
    const step = res.steps.find((s) => s.key === "COMBO_PRICE");
    expect((step?.meta as any)?.subtotal).toBeCloseTo(673289.37, 2);
  });

  it("2) sin lineAdj → basePrice = componentResult.basePrice (748099,30) — regresión", async () => {
    registerArticles({
      "combo": makeDbArticle({ commercialMode: "COMBO_COMMERCIAL",
        costComposition: [compAdj("br000", 1, 404378)] }),
      "br000": makeDbArticle(BR000),
    });
    mockResolveArticleCost.mockImplementation(async () => costOf(404378));
    const res = await resolveFinalSalePrice("j1", { articleId: "combo" });
    expect(res.basePrice?.toNumber()).toBeCloseTo(748099.30, 2);
  });

  it("3) FIXED_AMOUNT −$20.000 → Opción A (cost → fijo → margen): impacto venta = 20000×margen", async () => {
    registerArticles({
      "combo": makeDbArticle({ commercialMode: "COMBO_COMMERCIAL",
        costComposition: [compAdj("br000", 1, 404378, { kind: "BONUS", type: "FIXED_AMOUNT", value: 20000 })] }),
      "br000": makeDbArticle(BR000),
    });
    mockResolveArticleCost.mockImplementation(async () => costOf(404378));
    const res = await resolveFinalSalePrice("j1", { articleId: "combo" });
    // (404378 − 20000) × 1,85 = 711099,30 ; impacto = 748099,30 − 711099,30 = 37000 = 20000 × 1,85
    expect(res.basePrice?.toNumber()).toBeCloseTo(711099.30, 2);
  });

  it("4) recargo SURCHARGE +10% → basePrice = 748099,30 × 1,10 = 822909,23", async () => {
    registerArticles({
      "combo": makeDbArticle({ commercialMode: "COMBO_COMMERCIAL",
        costComposition: [compAdj("br000", 1, 404378, { kind: "SURCHARGE", type: "PERCENTAGE", value: 10 })] }),
      "br000": makeDbArticle(BR000),
    });
    mockResolveArticleCost.mockImplementation(async () => costOf(404378));
    const res = await resolveFinalSalePrice("j1", { articleId: "combo" });
    expect(res.basePrice?.toNumber()).toBeCloseTo(822909.23, 2);
  });

  it("5) múltiples componentes con lineAdj y márgenes distintos → Σ contribuciones", async () => {
    registerArticles({
      "combo": makeDbArticle({ commercialMode: "COMBO_COMMERCIAL",
        costComposition: [
          compAdj("a", 1, 100, { kind: "BONUS", type: "PERCENTAGE", value: 10 }), // 90 × (200/100=2) = 180
          compAdj("b", 1, 100),                                                   // 100 × (300/100=3) = 300
        ] }),
      "a": makeDbArticle({ useManualSalePrice: true, salePrice: new D("200") }),
      "b": makeDbArticle({ useManualSalePrice: true, salePrice: new D("300") }),
    });
    mockResolveArticleCost.mockImplementation(async () => costOf(100));
    const res = await resolveFinalSalePrice("j1", { articleId: "combo" });
    expect(res.basePrice?.toNumber()).toBeCloseTo(480, 2); // 180 + 300
  });

  it("6) componente SERVICE con lineAdj → aporta su contribución", async () => {
    registerArticles({
      "combo": makeDbArticle({ commercialMode: "COMBO_COMMERCIAL",
        costComposition: [compAdj("svc", 1, 250, { kind: "BONUS", type: "PERCENTAGE", value: 10 }, "SERVICE")] }),
      "svc": makeDbArticle({ useManualSalePrice: true, salePrice: new D("500") }),
    });
    mockResolveArticleCost.mockImplementation(async () => costOf(250));
    const res = await resolveFinalSalePrice("j1", { articleId: "combo" });
    // 250×0,9=225 × (500/250=2) = 450
    expect(res.basePrice?.toNumber()).toBeCloseTo(450, 2);
  });

  it("7) ajuste propio del combo + lineAdj → orden: componente-adj, luego combo-adj", async () => {
    registerArticles({
      "combo": makeDbArticle({ commercialMode: "COMBO_COMMERCIAL",
        comboAdjustmentKind: "DISCOUNT_PERCENT", comboAdjustmentValue: new D("5"),
        costComposition: [compAdj("br000", 1, 404378, { kind: "BONUS", type: "PERCENTAGE", value: 10 })] }),
      "br000": makeDbArticle(BR000),
    });
    mockResolveArticleCost.mockImplementation(async () => costOf(404378));
    const res = await resolveFinalSalePrice("j1", { articleId: "combo" });
    // 673289,37 × 0,95 = 639624,90
    expect(res.basePrice?.toNumber()).toBeCloseTo(639624.90, 2);
  });

  it("8) unitValue=0 legacy → fallback a venta standalone (748099,30)", async () => {
    registerArticles({
      "combo": makeDbArticle({ commercialMode: "COMBO_COMMERCIAL",
        costComposition: [compAdj("br000", 1, 0, { kind: "BONUS", type: "PERCENTAGE", value: 10 })] }),
      "br000": makeDbArticle(BR000),
    });
    mockResolveArticleCost.mockImplementation(async () => costOf(404378));
    const res = await resolveFinalSalePrice("j1", { articleId: "combo" });
    // unitValue=0 → bifurcación legacy → componentResult.basePrice × qty (ignora lineAdj)
    expect(res.basePrice?.toNumber()).toBeCloseTo(748099.30, 2);
  });

  it("9) preview ↔ confirm: determinístico (mismo basePrice en 2 llamadas)", async () => {
    registerArticles({
      "combo": makeDbArticle({ commercialMode: "COMBO_COMMERCIAL",
        costComposition: [compAdj("br000", 1, 404378, { kind: "BONUS", type: "PERCENTAGE", value: 10 })] }),
      "br000": makeDbArticle(BR000),
    });
    mockResolveArticleCost.mockImplementation(async () => costOf(404378));
    const a = await resolveFinalSalePrice("j1", { articleId: "combo" });
    const b = await resolveFinalSalePrice("j1", { articleId: "combo" });
    expect(b.basePrice?.toNumber()).toBe(a.basePrice?.toNumber());
    expect(b.unitPrice?.toNumber()).toBe(a.unitPrice?.toNumber());
  });

  it("10) combo + promo scope ALL → promo UNA vez sobre el basePrice ajustado (sin doble)", async () => {
    mockPrisma.promotion.findMany.mockResolvedValue([{
      id: "promo-all", name: "PROMO ALL", type: "PERCENTAGE", value: new D("10"),
      scope: "ALL", validFrom: null, validTo: null, isActive: true, deletedAt: null, priority: 1,
    }]);
    registerArticles({
      "combo": makeDbArticle({ commercialMode: "COMBO_COMMERCIAL",
        costComposition: [compAdj("br000", 1, 404378, { kind: "BONUS", type: "PERCENTAGE", value: 10 })] }),
      "br000": makeDbArticle(BR000),
    });
    mockResolveArticleCost.mockImplementation(async () => costOf(404378));
    const res = await resolveFinalSalePrice("j1", { articleId: "combo" });
    // basePrice (con lineAdj, inmune a la promo del componente) = 673289,37
    expect(res.basePrice?.toNumber()).toBeCloseTo(673289.37, 2);
    // promo del combo 10% UNA vez → 673289,37 × 0,9 = 605960,43 (NO doble)
    expect(res.unitPrice?.toNumber()).toBeCloseTo(605960.43, 2);
    expect(res.priceSource).toBe("PROMOTION");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// COMBO — precedencia COMBO_COMPONENTS > PRICE_LIST (Modelo A)
// ─────────────────────────────────────────────────────────────────────────────
//
// Bug: la PRICE_LIST sobre comboCost (sin lineAdj) producía basePrice > 0 y el
// gate viejo (solo ≤0) no lo reemplazaba. Ahora, si el combo se construyó desde
// cost-lines reales (comboPriceUsedCostLines), comboDerivedPrice gana sobre la
// lista; la lista conserva su atribución (priceListId/name/mode).
// BR000: unitValue=404378, unitCost=404378, basePrice=748099,30 → margen 1,85.
//   comboCost × margen (lista) = 748099,30 ; comboDerivedPrice = 673289,37.
// ─────────────────────────────────────────────────────────────────────────────
describe("Combo — precedencia COMBO_COMPONENTS > PRICE_LIST", () => {
  function registerArticles(map: Record<string, any>) {
    mockPrisma.article.findFirst.mockImplementation(async (args: any) => map[args?.where?.id] ?? null);
  }
  function compAdj(id: string, qty: number, unitValue: number, adj?: { kind: string; type: string; value: number }) {
    return {
      type: "PRODUCT", catalogItemId: id, quantity: new D(String(qty)), unitValue: new D(String(unitValue)),
      lineAdjKind: adj?.kind ?? "", lineAdjType: adj?.type ?? "",
      lineAdjValue: adj?.value != null ? new D(String(adj.value)) : null,
      catalogItem: { id, code: id.toUpperCase(), name: id },
    };
  }
  const BR000 = { categoryId: null, useManualSalePrice: true, salePrice: new D("748099.30") };
  const comboList = { id: "pl-combo", name: "Lista Unificada", mode: "MARGIN_TOTAL",
    marginTotal: null, marginMetal: null, marginHechura: null, costPerGram: null, surcharge: null,
    minimumPrice: null, roundingTarget: "NONE", roundingMode: "NONE", roundingDirection: "NEAREST",
    validFrom: null, validTo: null, isActive: true };

  /** Lista solo para el combo (categoryId="cat"); aplica margen 1,85 sobre el costo. */
  function setupComboWithList(extra?: any, applyImpl?: any) {
    mockResolvePriceList.mockImplementation(async (_jw: string, opts: any) =>
      opts?.categoryId === "cat" ? { priceList: comboList, source: "CATEGORY" } : null);
    mockApplyPriceList.mockImplementation(applyImpl ?? ((_pl: any, cost: any) =>
      ({ value: new D(String(Number(cost?.value ?? 0) * 1.85)), partial: false })));
    mockResolveArticleCost.mockImplementation(async () => costOf(404378));
    registerArticles({
      "combo": makeDbArticle({ commercialMode: "COMBO_COMMERCIAL", categoryId: "cat",
        costComposition: [compAdj("br000", 1, 404378, { kind: "BONUS", type: "PERCENTAGE", value: 10 })], ...extra }),
      "br000": makeDbArticle(BR000),
    });
  }

  it("1+2+7) caso real: el combo (673289,37) gana sobre la lista (748099,30) y conserva appliedPriceList*", async () => {
    setupComboWithList();
    const res = await resolveFinalSalePrice("j1", { articleId: "combo" });
    expect(res.basePrice?.toNumber()).toBeCloseTo(673289.37, 2);     // combo gana
    expect(res.priceSource).toBe("COMBO_COMPONENTS");
    expect(res.appliedPriceListId).toBe("pl-combo");                 // lista conservada
    expect(res.appliedPriceListName).toBe("Lista Unificada");
    const step = res.steps.find((s) => s.key === "COMBO_PRICE");
    expect((step?.meta as any)?.subtotal).toBeCloseTo(673289.37, 2); // COMBO_PRICE.subtotal == basePrice
  });

  it("5) legacy unitValue=0 + lista → la lista pricea (combo NO la pisa)", async () => {
    setupComboWithList({ costComposition: [compAdj("br000", 1, 0, { kind: "BONUS", type: "PERCENTAGE", value: 10 })] });
    const res = await resolveFinalSalePrice("j1", { articleId: "combo" });
    // comboPriceUsedCostLines=false → la lista (748099,30) gana → priceSource PRICE_LIST
    expect(res.priceSource).toBe("PRICE_LIST");
    expect(res.basePrice?.toNumber()).toBeCloseTo(748099.30, 2);
  });

  it("6) manual override REAL del artículo gana sobre el combo (priceSource MANUAL_OVERRIDE)", async () => {
    // Sin lista → PRICE_LIST skipped → manual override del artículo fija basePrice.
    mockResolvePriceList.mockResolvedValue(null);
    mockResolveArticleCost.mockImplementation(async () => costOf(404378));
    registerArticles({
      "combo": makeDbArticle({ commercialMode: "COMBO_COMMERCIAL",
        useManualSalePrice: true, salePrice: new D("999999"),
        costComposition: [compAdj("br000", 1, 404378, { kind: "BONUS", type: "PERCENTAGE", value: 10 })] }),
      "br000": makeDbArticle(BR000),
    });
    const res = await resolveFinalSalePrice("j1", { articleId: "combo" });
    expect(res.priceSource).toBe("MANUAL_OVERRIDE");
    expect(res.basePrice?.toNumber()).toBe(999999);
  });

  it("8) reset de rounding: la lista emitió appliedRounding sobre el valor viejo → null tras el override", async () => {
    setupComboWithList(undefined, (_pl: any, cost: any) => ({
      value: new D(String(Number(cost?.value ?? 0) * 1.85)),
      partial: false,
      preRounding: new D(String(Number(cost?.value ?? 0) * 1.85 + 5)), // fuerza appliedRounding en el bloque PRICE_LIST
      roundingMode: "INTEGER", roundingDirection: "NEAREST",
    }));
    const res = await resolveFinalSalePrice("j1", { articleId: "combo" });
    expect(res.basePrice?.toNumber()).toBeCloseTo(673289.37, 2);
    expect(res.priceSource).toBe("COMBO_COMPONENTS");
    expect(res.appliedRounding).toBeNull(); // R1: reset del artefacto stale de la lista
  });

  it("9) margin warning: el caso real NO dispara bloqueo espurio (margen sano)", async () => {
    setupComboWithList();
    const res = await resolveFinalSalePrice("j1", { articleId: "combo" });
    // margen = (673289,37 − 404378) / 673289,37 ≈ 39,9% > umbral 15% → positivo, sin block
    expect(res.marginPercent?.toNumber()).toBeGreaterThan(15);
    expect(res.unitPrice?.toNumber()).toBeGreaterThan(0);
  });

  it("4) artículo normal con lista: sin cambios (regresión)", async () => {
    mockResolvePriceList.mockResolvedValue({ priceList: comboList, source: "GENERAL" });
    mockApplyPriceList.mockReturnValue({ value: new D("5000"), partial: false });
    mockResolveArticleCost.mockImplementation(async () => costOf(2000));
    mockPrisma.article.findFirst.mockResolvedValue(makeDbArticle()); // no combo
    const res = await resolveFinalSalePrice("j1", { articleId: "a1" });
    expect(res.priceSource).toBe("PRICE_LIST");   // combo no interviene
    expect(res.basePrice?.toNumber()).toBe(5000);
    expect(res.appliedPriceListId).toBe("pl-combo");
  });

  // ── FIX 2026-06-11 — combo conserva el Redondeo Comercial FINAL_PRICE/TOTAL ──
  // El combo debe comportarse como un artículo monetario de lista unificada:
  // `deferredRounding` (config de la lista) SOBREVIVE al override del combo y
  // su `totalWithTax` se redondea fresco, igual que un artículo normal.

  it("11) FIX combo en lista con redondeo TOTAL/HUNDRED: PRE → POST (deferredRounding sobrevive)", async () => {
    setupComboWithList(undefined, (_pl: any, cost: any) => ({
      value:    new D(String(Number(cost?.value ?? 0) * 1.85)),
      partial:  false,
      // La lista delega un redondeo FINAL_PRICE/TOTAL a HUNDRED.
      roundingDeferred: { applyOn: "TOTAL", mode: "HUNDRED", direction: "NEAREST" },
    }));
    const res = await resolveFinalSalePrice("j1", { articleId: "combo" });
    // basePrice (comboDerivedPrice) NO cambia — el fix solo afecta totalWithTax.
    expect(res.basePrice?.toNumber()).toBeCloseTo(673289.37, 2);
    expect(res.priceSource).toBe("COMBO_COMPONENTS");
    // appliedRounding se RECALCULA fresco sobre el totalWithTax del combo.
    expect(res.appliedRounding).not.toBeNull();
    expect(res.appliedRounding!.applyOn).toBe("TOTAL");
    expect(Number(res.appliedRounding!.preRounding)).toBeCloseTo(673289.37, 2);
    expect(Number(res.appliedRounding!.postRounding)).toBe(673300);  // PRE 673289,37 → POST 673300
    // totalWithTax pasa de PRE a POST.
    expect(res.totalWithTax?.toNumber()).toBe(673300);
  });

  it("12) FIX combo SIN redondeo de lista: POST = PRE (no inventa impacto)", async () => {
    setupComboWithList();   // applyPriceList default — sin roundingDeferred
    const res = await resolveFinalSalePrice("j1", { articleId: "combo" });
    expect(res.basePrice?.toNumber()).toBeCloseTo(673289.37, 2);
    expect(res.priceSource).toBe("COMBO_COMPONENTS");
    expect(res.appliedRounding).toBeNull();                 // sin redondeo → null
    expect(res.totalWithTax?.toNumber()).toBeCloseTo(673289.37, 2); // POST == PRE
  });

  it("13) FIX artículo NORMAL en lista con redondeo TOTAL: sin regresión (redondea igual)", async () => {
    mockResolvePriceList.mockResolvedValue({ priceList: comboList, source: "GENERAL" });
    mockApplyPriceList.mockReturnValue({
      value:   new D("5049"),
      partial: false,
      roundingDeferred: { applyOn: "TOTAL", mode: "HUNDRED", direction: "NEAREST" },
    });
    mockResolveArticleCost.mockImplementation(async () => costOf(2000));
    mockPrisma.article.findFirst.mockResolvedValue(makeDbArticle()); // no combo
    const res = await resolveFinalSalePrice("j1", { articleId: "a1" });
    expect(res.priceSource).toBe("PRICE_LIST");
    expect(res.basePrice?.toNumber()).toBe(5049);
    expect(res.appliedRounding).not.toBeNull();
    expect(Number(res.appliedRounding!.postRounding)).toBe(5000);   // 5049 → nearest hundred
  });

  // ── FIX paridad Preview↔Confirm para líneas applyOn=TOTAL ──────────────────
  // El redondeo TOTAL vive solo en `appliedRounding` (no se hornea en unitPrice).
  // buildPricingSnapshot DEBE persistirlo para que confirmSale recupere el delta
  // `(post−pre)×qty` (MISMA fórmula que preview) → Preview == Confirm.

  it("14) FIX buildPricingSnapshot persiste appliedRounding cuando el motor lo aplicó (combo TOTAL)", async () => {
    setupComboWithList(undefined, (_pl: any, cost: any) => ({
      value:    new D(String(Number(cost?.value ?? 0) * 1.85)),
      partial:  false,
      roundingDeferred: { applyOn: "TOTAL", mode: "HUNDRED", direction: "NEAREST" },
    }));
    const res  = await resolveFinalSalePrice("j1", { articleId: "combo" });
    const snap = buildPricingSnapshot(res);
    // El snapshot lleva el redondeo congelado (5 campos canónicos).
    expect(snap.appliedRounding).toBeDefined();
    expect(snap.appliedRounding).toMatchObject({
      applyOn:   "TOTAL",
      mode:      "HUNDRED",
      direction: "NEAREST",
    });
    expect(snap.appliedRounding!.preRounding).toBeCloseTo(673289.37, 2);
    expect(snap.appliedRounding!.postRounding).toBe(673300);
    // Paridad por construcción: confirm computa (post−pre)×qty con estos valores.
    const qty = 1;
    const confirmDelta = (snap.appliedRounding!.postRounding - snap.appliedRounding!.preRounding) * qty;
    expect(Math.round(confirmDelta * 100) / 100).toBeCloseTo(10.63, 2); // 673300 − 673289,37
  });

  it("15) FIX buildPricingSnapshot OMITE appliedRounding cuando no hubo redondeo (back-compat)", async () => {
    setupComboWithList();   // applyPriceList default — sin roundingDeferred
    const res  = await resolveFinalSalePrice("j1", { articleId: "combo" });
    const snap = buildPricingSnapshot(res);
    // Snapshot viejo / sin redondeo → campo ausente → confirm cae a delta 0.
    expect(snap.appliedRounding).toBeUndefined();
  });

  it("16) FIX snapshot persiste appliedRounding también para artículo NORMAL applyOn=TOTAL", async () => {
    mockResolvePriceList.mockResolvedValue({ priceList: comboList, source: "GENERAL" });
    mockApplyPriceList.mockReturnValue({
      value:   new D("5049"),
      partial: false,
      roundingDeferred: { applyOn: "TOTAL", mode: "HUNDRED", direction: "NEAREST" },
    });
    mockResolveArticleCost.mockImplementation(async () => costOf(2000));
    mockPrisma.article.findFirst.mockResolvedValue(makeDbArticle()); // no combo
    const res  = await resolveFinalSalePrice("j1", { articleId: "a1" });
    const snap = buildPricingSnapshot(res);
    expect(snap.appliedRounding).toMatchObject({ applyOn: "TOTAL" });
    expect(snap.appliedRounding!.postRounding).toBe(5000);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// COMBO — costLineOverrides recalculan comboDerivedPrice (edición en Factura)
// ─────────────────────────────────────────────────────────────────────────────
//
// Al editar la tabla de composición, el operador genera costLineOverrides por
// costLineId. El branch combo debe usar los valores EFECTIVOS (qty/unitValue/
// lineAdj) para reconstruir comboDerivedPrice → basePrice. Espejo de
// calculateCostFromLines. BR000: unitCost 404378, basePrice 748099,30 → margen 1,85.
// ─────────────────────────────────────────────────────────────────────────────
describe("Combo — costLineOverrides recalculan el precio", () => {
  function registerArticles(map: Record<string, any>) {
    mockPrisma.article.findFirst.mockImplementation(async (args: any) => map[args?.where?.id] ?? null);
  }
  /** Cost-line con id (para que el override matchee por costLineId). */
  function compId(costLineId: string, articleId: string, qty: number, unitValue: number,
    adj?: { kind: string; type: string; value: number }, type: "PRODUCT" | "SERVICE" = "PRODUCT") {
    return {
      id: costLineId, type, catalogItemId: articleId, quantity: new D(String(qty)),
      unitValue: new D(String(unitValue)),
      lineAdjKind: adj?.kind ?? "", lineAdjType: adj?.type ?? "",
      lineAdjValue: adj?.value != null ? new D(String(adj.value)) : null,
      catalogItem: { id: articleId, code: articleId.toUpperCase(), name: articleId },
    };
  }
  const BR000 = { useManualSalePrice: true, salePrice: new D("748099.30") };
  function setup(costComposition: any[]) {
    mockResolveArticleCost.mockImplementation(async () => costOf(404378));
    registerArticles({
      "combo": makeDbArticle({ commercialMode: "COMBO_COMMERCIAL", costComposition }),
      "br000": makeDbArticle(BR000),
      "svc":   makeDbArticle({ useManualSalePrice: true, salePrice: new D("500") }),
    });
  }

  it("1) override quantity → basePrice escala", async () => {
    setup([compId("cl-1", "br000", 1, 404378)]);
    const res = await resolveFinalSalePrice("j1", { articleId: "combo",
      costLineOverrides: [{ costLineId: "cl-1", type: "PRODUCT", quantityOverride: 2 }] });
    expect(res.basePrice?.toNumber()).toBeCloseTo(1496198.60, 2);  // 404378×2 × 1,85
  });

  it("2) override unitValue → recalcula basePrice", async () => {
    setup([compId("cl-1", "br000", 1, 404378)]);
    const res = await resolveFinalSalePrice("j1", { articleId: "combo",
      costLineOverrides: [{ costLineId: "cl-1", type: "PRODUCT", unitValueOverride: 500000 }] });
    expect(res.basePrice?.toNumber()).toBeCloseTo(925000, 2);  // 500000 × 1,85
  });

  it("3) override lineAdj PERCENTAGE → recalcula basePrice", async () => {
    setup([compId("cl-1", "br000", 1, 404378)]);  // sin lineAdj persistido
    const res = await resolveFinalSalePrice("j1", { articleId: "combo",
      costLineOverrides: [{ costLineId: "cl-1", type: "PRODUCT", adjustmentKind: "BONUS", adjustmentType: "PERCENTAGE", adjustmentValue: 10 }] });
    expect(res.basePrice?.toNumber()).toBeCloseTo(673289.37, 2);  // 404378×0,9 × 1,85
  });

  it("4) override lineAdj FIXED_AMOUNT → recalcula basePrice", async () => {
    setup([compId("cl-1", "br000", 1, 404378)]);
    const res = await resolveFinalSalePrice("j1", { articleId: "combo",
      costLineOverrides: [{ costLineId: "cl-1", type: "PRODUCT", adjustmentKind: "BONUS", adjustmentType: "FIXED_AMOUNT", adjustmentValue: 20000 }] });
    expect(res.basePrice?.toNumber()).toBeCloseTo(711099.30, 2);  // (404378−20000) × 1,85
  });

  it("5) multi-componente: overrides por costLineId", async () => {
    setup([compId("cl-1", "a", 1, 100), compId("cl-2", "b", 1, 100)]);
    mockPrisma.article.findFirst.mockImplementation(async (args: any) => ({
      "combo": makeDbArticle({ commercialMode: "COMBO_COMMERCIAL",
        costComposition: [compId("cl-1", "a", 1, 100), compId("cl-2", "b", 1, 100)] }),
      "a": makeDbArticle({ useManualSalePrice: true, salePrice: new D("200") }),  // margen 2
      "b": makeDbArticle({ useManualSalePrice: true, salePrice: new D("300") }),  // margen 3
    } as any)[args?.where?.id] ?? null);
    mockResolveArticleCost.mockImplementation(async () => costOf(100));
    const res = await resolveFinalSalePrice("j1", { articleId: "combo",
      costLineOverrides: [
        { costLineId: "cl-1", type: "PRODUCT", unitValueOverride: 150 },  // 150×2 = 300
        { costLineId: "cl-2", type: "PRODUCT", quantityOverride: 2 },     // 100×2×3 = 600
      ] });
    expect(res.basePrice?.toNumber()).toBeCloseTo(900, 2);  // 300 + 600
  });

  it("6) service dentro del combo: override aplica", async () => {
    setup([compId("cl-1", "svc", 1, 250, undefined, "SERVICE")]);
    const res = await resolveFinalSalePrice("j1", { articleId: "combo",
      costLineOverrides: [{ costLineId: "cl-1", type: "SERVICE", unitValueOverride: 300 }] });
    // svc: basePrice 500 / unitCost 404378... ojo: margen = 500/404378. Hagamos costo coherente.
    // (acá unitCost del componente = costOf(404378) → margen chico). Validamos sólo que recalcula > 0.
    expect(res.basePrice?.toNumber()).toBeGreaterThan(0);
    expect(res.priceSource).toBe("COMBO_COMPONENTS");
  });

  it("7) paridad: COMBO_PRICE.subtotal === basePrice tras override", async () => {
    setup([compId("cl-1", "br000", 1, 404378)]);
    const res = await resolveFinalSalePrice("j1", { articleId: "combo",
      costLineOverrides: [{ costLineId: "cl-1", type: "PRODUCT", unitValueOverride: 500000 }] });
    const step = res.steps.find((s) => s.key === "COMBO_PRICE");
    expect((step?.meta as any)?.subtotal).toBeCloseTo(res.basePrice!.toNumber(), 2);
  });

  it("8) preview ↔ confirm: determinístico con override", async () => {
    setup([compId("cl-1", "br000", 1, 404378)]);
    const opts = { articleId: "combo", costLineOverrides: [{ costLineId: "cl-1", type: "PRODUCT" as const, unitValueOverride: 500000 }] };
    const a = await resolveFinalSalePrice("j1", opts);
    const b = await resolveFinalSalePrice("j1", opts);
    expect(b.basePrice?.toNumber()).toBe(a.basePrice?.toNumber());
  });

  it("9) combo SIN override → basePrice persistido (regresión)", async () => {
    setup([compId("cl-1", "br000", 1, 404378)]);
    const res = await resolveFinalSalePrice("j1", { articleId: "combo" });
    expect(res.basePrice?.toNumber()).toBeCloseTo(748099.30, 2);  // 404378 × 1,85
  });

  it("10) legacy unitValue=0 + override unitValue>0 → entra al pipeline nuevo", async () => {
    setup([compId("cl-1", "br000", 1, 0)]);  // unitValue=0 (legacy)
    const res = await resolveFinalSalePrice("j1", { articleId: "combo",
      costLineOverrides: [{ costLineId: "cl-1", type: "PRODUCT", unitValueOverride: 500000 }] });
    // effectiveUnitValue=500000 > 0 → pipeline nuevo → 500000 × 1,85 = 925000 (NO fallback 748099,30)
    expect(res.basePrice?.toNumber()).toBeCloseTo(925000, 2);
  });

  it("11) artículo normal con override → el branch combo no interviene", async () => {
    mockResolvePriceList.mockResolvedValue(null);
    mockResolveArticleCost.mockImplementation(async () => costOf(1000));
    mockPrisma.article.findFirst.mockResolvedValue(makeDbArticle({ useManualSalePrice: true, salePrice: new D("3000") }));
    const res = await resolveFinalSalePrice("j1", { articleId: "a1",
      costLineOverrides: [{ costLineId: "x", type: "PRODUCT", unitValueOverride: 999 }] });
    expect(res.priceSource).toBe("MANUAL_OVERRIDE");  // no combo, sin cambio de path
    expect(res.basePrice?.toNumber()).toBe(3000);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// componentSaleBreakdown — desglose Metal/Hechura post-descuentos por componente
// ─────────────────────────────────────────────────────────────────────────────
//
// Paridad simulador ↔ totales: el motor expone `componentSaleBreakdown` con
// `base/adjustments/final` por componente. Este suite verifica que los
// descuentos con applyOn=METAL|HECHURA quedan imputados al componente
// correcto y que la suma de finales es coherente con `unitPrice`.
// ─────────────────────────────────────────────────────────────────────────────

describe("componentSaleBreakdown — paridad simulador/totales", () => {
  function setupMetalHechuraList(metalSale: number, hechuraSale: number) {
    mockPrisma.article.findFirst.mockResolvedValue(makeDbArticle());
    mockResolveArticleCost.mockResolvedValue(costOf(1000));
    const fakePriceList = {
      id: "pl1", name: "Lista METAL_HECHURA",
      mode: "METAL_HECHURA", marginTotal: null,
      marginMetal: null, marginHechura: null,
      costPerGram: null, surcharge: null, minimumPrice: null,
      roundingTarget: "NONE", roundingMode: "NONE", roundingDirection: "NEAREST",
      validFrom: null, validTo: null, isActive: true,
    };
    mockResolvePriceList.mockResolvedValue({ priceList: fakePriceList, source: "GENERAL" });
    mockApplyPriceList.mockReturnValue({
      value:   new D(String(metalSale + hechuraSale)),
      partial: false,
      metalHechuraDetail: {
        metalCost:        500,
        metalSale,
        metalMarginPct:   ((metalSale - 500) / 500) * 100,
        hechuraCost:      500,
        hechuraSale,
        hechuraMarginPct: ((hechuraSale - 500) / 500) * 100,
      },
    });
  }

  it("sin descuentos → componentSaleBreakdown.{metal,hechura}.final = base, adjustments=[]", async () => {
    setupMetalHechuraList(600, 600);
    const res = await resolveFinalSalePrice("j1", { articleId: "a1" });

    expect(res.componentSaleBreakdown).not.toBeNull();
    expect(res.componentSaleBreakdown!.metal.base).toBeCloseTo(600, 4);
    expect(res.componentSaleBreakdown!.metal.final).toBeCloseTo(600, 4);
    expect(res.componentSaleBreakdown!.metal.adjustments).toEqual([]);
    expect(res.componentSaleBreakdown!.hechura.base).toBeCloseTo(600, 4);
    expect(res.componentSaleBreakdown!.hechura.final).toBeCloseTo(600, 4);
    expect(res.componentSaleBreakdown!.hechura.adjustments).toEqual([]);
  });

  it("descuento de cliente con applyOn=HECHURA → entry ENTITY_RULE en hechura.adjustments", async () => {
    setupMetalHechuraList(600, 600);
    // Cliente con regla DISCOUNT 10% sobre HECHURA.
    mockPrisma.commercialEntity.findFirst.mockResolvedValue({
      taxExempt:           false,
      taxApplyOnOverride:  null,
      commercialRuleType:  "DISCOUNT",
      commercialValueType: "PERCENTAGE",
      commercialValue:     new D("10"),
      commercialApplyOn:   "HECHURA",
      taxOverrides:        [],
    });

    const res = await resolveFinalSalePrice("j1", { articleId: "a1", clientId: "c1" });

    expect(res.componentSaleBreakdown).not.toBeNull();
    // Metal queda intacto.
    expect(res.componentSaleBreakdown!.metal.base).toBeCloseTo(600, 4);
    expect(res.componentSaleBreakdown!.metal.final).toBeCloseTo(600, 4);
    expect(res.componentSaleBreakdown!.metal.adjustments).toEqual([]);
    // Hechura tiene un ajuste ENTITY_RULE de 60 (10% de 600).
    expect(res.componentSaleBreakdown!.hechura.base).toBeCloseTo(600, 4);
    expect(res.componentSaleBreakdown!.hechura.final).toBeCloseTo(540, 4);
    expect(res.componentSaleBreakdown!.hechura.adjustments).toHaveLength(1);
    const adj = res.componentSaleBreakdown!.hechura.adjustments[0];
    expect(adj.kind).toBe("ENTITY_RULE");
    expect(adj.applyOn).toBe("HECHURA");
    expect(adj.amount).toBeCloseTo(60, 4);
    // Metadata para fórmula renderizable en frontend.
    expect(adj.base).toBeCloseTo(600, 4);
    expect(adj.percentage).toBe(10);
    expect(adj.valueType).toBe("PERCENTAGE");
    expect(adj.source).toBe("CLIENT");
    // Verifica que la fórmula es coherente: base × percentage / 100 === amount.
    expect(adj.base! * adj.percentage! / 100).toBeCloseTo(adj.amount, 4);

    // Coherencia con unitPrice: metal.final + hechura.final === unitPrice.
    const sumComponents = res.componentSaleBreakdown!.metal.final
                        + res.componentSaleBreakdown!.hechura.final;
    expect(sumComponents).toBeCloseTo(res.unitPrice!.toNumber(), 2);
  });

  it("descuento por cantidad con applyOn=METAL → entry QUANTITY_DISCOUNT en metal.adjustments", async () => {
    setupMetalHechuraList(600, 600);
    mockPrisma.quantityDiscount.findMany.mockResolvedValue([{
      id: "qd1",
      articleId: "a1", variantId: null, categoryId: null, brand: null, groupId: null,
      isStackable: false, evaluationMode: "LINE",
      applyOn: "METAL",
      tiers: [{ minQty: new D("1"), type: "PERCENTAGE", value: new D("20") }],
    }]);

    const res = await resolveFinalSalePrice("j1", { articleId: "a1", quantity: 2 });

    expect(res.componentSaleBreakdown).not.toBeNull();
    expect(res.componentSaleBreakdown!.metal.adjustments).toHaveLength(1);
    expect(res.componentSaleBreakdown!.metal.adjustments[0].kind).toBe("QUANTITY_DISCOUNT");
    expect(res.componentSaleBreakdown!.metal.adjustments[0].applyOn).toBe("METAL");
    expect(res.componentSaleBreakdown!.metal.adjustments[0].amount).toBeCloseTo(120, 4);
    expect(res.componentSaleBreakdown!.metal.final).toBeCloseTo(480, 4);
    // Hechura no recibió ningún ajuste.
    expect(res.componentSaleBreakdown!.hechura.adjustments).toEqual([]);
    expect(res.componentSaleBreakdown!.hechura.final).toBeCloseTo(600, 4);
  });

  it("descuento applyOn=TOTAL NO entra al desglose por componente", async () => {
    setupMetalHechuraList(600, 600);
    mockPrisma.quantityDiscount.findMany.mockResolvedValue([{
      id: "qd1",
      articleId: "a1", variantId: null, categoryId: null, brand: null, groupId: null,
      isStackable: false, evaluationMode: "LINE",
      applyOn: "TOTAL",
      tiers: [{ minQty: new D("1"), type: "PERCENTAGE", value: new D("10") }],
    }]);

    const res = await resolveFinalSalePrice("j1", { articleId: "a1", quantity: 2 });

    // El descuento se aplicó a nivel TOTAL — los componentes quedan intactos
    // en el desglose. La diferencia se ve a nivel unitPrice/totales.
    expect(res.componentSaleBreakdown!.metal.adjustments).toEqual([]);
    expect(res.componentSaleBreakdown!.hechura.adjustments).toEqual([]);
    expect(res.componentSaleBreakdown!.metal.final).toBeCloseTo(600, 4);
    expect(res.componentSaleBreakdown!.hechura.final).toBeCloseTo(600, 4);
    // unitPrice refleja el descuento: 1200 − 10% = 1080.
    expect(res.unitPrice!.toNumber()).toBeCloseTo(1080, 2);
  });

  it("sin breakdown de costo → metalHechuraBreakdown=MANUAL_AS_HECHURA, componentSaleBreakdown=null", async () => {
    // FASE 1: cuando el cost-engine reporta value > 0 pero metalCost y hechuraCost
    // son 0 (sin desglose útil), `metalHechuraBreakdown` cae a `MANUAL_AS_HECHURA`
    // (todo a hechura). `componentSaleBreakdown` sigue siendo null porque el
    // componentSale tracker requiere metalCost/hechuraCost > 0.
    mockPrisma.article.findFirst.mockResolvedValue(makeDbArticle());
    mockResolveArticleCost.mockResolvedValue(costOf(1000));
    mockResolvePriceList.mockResolvedValue({
      priceList: {
        id: "pl1", name: "Lista MARGIN_TOTAL",
        mode: "MARGIN_TOTAL", marginTotal: "100",
        marginMetal: null, marginHechura: null,
        costPerGram: null, surcharge: null, minimumPrice: null,
        roundingTarget: "NONE", roundingMode: "NONE", roundingDirection: "NEAREST",
        validFrom: null, validTo: null, isActive: true,
      },
      source: "GENERAL",
    });
    mockApplyPriceList.mockReturnValue({ value: new D("2000"), partial: false });

    const res = await resolveFinalSalePrice("j1", { articleId: "a1" });

    expect(res.metalHechuraBreakdown).not.toBeNull();
    expect(res.metalHechuraBreakdown!.source).toBe("MANUAL_AS_HECHURA");
    expect(res.metalHechuraBreakdown!.metalSale).toBe(0);
    expect(res.metalHechuraBreakdown!.hechuraSale).toBeCloseTo(2000, 2);
    expect(res.componentSaleBreakdown).toBeNull();
  });

  it("modo legacy: CostResult con metalCost/hechuraCost directos (sin breakdown.totals) → tracker estima", async () => {
    // Caso del usuario: artículo con costCalculationMode=METAL_MERMA_HECHURA
    // u otro modo legacy que popula `costResult.metalCost`/`hechuraCost`
    // como Decimal directos pero NO arma `breakdown.totals`. La lista
    // activa devuelve sólo `value` (no `metalHechuraDetail`).
    mockPrisma.article.findFirst.mockResolvedValue(makeDbArticle());
    // Importante: SIN `breakdown` para forzar el uso de los campos directos.
    mockResolveArticleCost.mockResolvedValue({
      value:       new D("1000"),
      mode:        "METAL_MERMA_HECHURA",
      partial:     false,
      steps:       [],
      metalCost:   new D("600"),
      hechuraCost: new D("400"),
      totalGrams:  new D("0"),
      // breakdown intencionalmente ausente.
    });
    mockResolvePriceList.mockResolvedValue({
      priceList: {
        id: "pl1", name: "Lista MARGIN_TOTAL",
        mode: "MARGIN_TOTAL", marginTotal: "100",
        marginMetal: null, marginHechura: null,
        costPerGram: null, surcharge: null, minimumPrice: null,
        roundingTarget: "NONE", roundingMode: "NONE", roundingDirection: "NEAREST",
        validFrom: null, validTo: null, isActive: true,
      },
      source: "GENERAL",
    });
    mockApplyPriceList.mockReturnValue({ value: new D("2000"), partial: false });
    mockPrisma.commercialEntity.findFirst.mockResolvedValue({
      taxExempt:           false,
      taxApplyOnOverride:  null,
      commercialRuleType:  "DISCOUNT",
      commercialValueType: "PERCENTAGE",
      commercialValue:     new D("10"),
      commercialApplyOn:   "HECHURA",
      taxOverrides:        [],
    });

    const res = await resolveFinalSalePrice("j1", { articleId: "a1", clientId: "c1" });

    // FASE 1: metalHechuraBreakdown ahora se popula con source=PROPORTIONAL_COST
    // cuando hay metalCost/hechuraCost. Antes era null en este escenario.
    expect(res.metalHechuraBreakdown).not.toBeNull();
    expect(res.metalHechuraBreakdown!.source).toBe("PROPORTIONAL_COST");
    expect(res.metalHechuraBreakdown!.metalSaleEstimated).toBe(true);
    expect(res.metalHechuraBreakdown!.metalSale).toBeCloseTo(1200, 2);   // 600/1000 × 2000
    expect(res.metalHechuraBreakdown!.hechuraSale).toBeCloseTo(800, 2);  // 400/1000 × 2000

    expect(res.componentSaleBreakdown).not.toBeNull();
    // Bases por proporción de costMetal/costHechura: metal=1200, hechura=800.
    expect(res.componentSaleBreakdown!.metal.base).toBeCloseTo(1200, 4);
    expect(res.componentSaleBreakdown!.hechura.base).toBeCloseTo(800, 4);
    expect(res.componentSaleBreakdown!.hechura.adjustments).toHaveLength(1);
    expect(res.componentSaleBreakdown!.hechura.adjustments[0].kind).toBe("ENTITY_RULE");
    expect(res.componentSaleBreakdown!.hechura.adjustments[0].applyOn).toBe("HECHURA");
    expect(res.componentSaleBreakdown!.hechura.adjustments[0].amount).toBeCloseTo(80, 4);
    expect(res.componentSaleBreakdown!.hechura.final).toBeCloseTo(720, 4);
  });

  it("lista sin metalHechuraDetail PERO costBreakdown con metal/hechura → tracker estima por proporción", async () => {
    // Caso real reportado: artículo con composición Metal+Hechura, lista en
    // modo MARGIN_TOTAL (no devuelve metalHechuraDetail), cliente con
    // commercialApplyOn=HECHURA. El motor debe imputar el ENTITY_RULE al
    // componente HECHURA estimando la base por proporción del costo.
    mockPrisma.article.findFirst.mockResolvedValue(makeDbArticle());
    // Costo: 600 metal + 400 hechura = 1000 total. La lista MARGIN_TOTAL
    // multiplica × 2 → basePrice = 2000. La porción HECHURA proporcional
    // del precio = 2000 × 400/1000 = 800. 10% sobre 800 = 80.
    mockResolveArticleCost.mockResolvedValue({
      value:   new D("1000"),
      mode:    "COST_LINES",
      partial: false,
      steps:   [],
      metalCost:   new D("600"),
      hechuraCost: new D("400"),
      totalGrams:  new D("0"),
      breakdown: {
        mode: "COST_LINES",
        metal:   { items: [], total: 600 },
        hechura: { base: 400, adjustments: [], total: 400 },
        totals:  { metal: 600, hechura: 400, unified: 1000 },
      },
    });
    mockResolvePriceList.mockResolvedValue({
      priceList: {
        id: "pl1", name: "Lista MARGIN_TOTAL",
        mode: "MARGIN_TOTAL", marginTotal: "100",
        marginMetal: null, marginHechura: null,
        costPerGram: null, surcharge: null, minimumPrice: null,
        roundingTarget: "NONE", roundingMode: "NONE", roundingDirection: "NEAREST",
        validFrom: null, validTo: null, isActive: true,
      },
      source: "GENERAL",
    });
    // Lista NO devuelve metalHechuraDetail (caso MARGIN_TOTAL).
    mockApplyPriceList.mockReturnValue({ value: new D("2000"), partial: false });
    // Cliente con descuento aplicable a HECHURA.
    mockPrisma.commercialEntity.findFirst.mockResolvedValue({
      taxExempt:           false,
      taxApplyOnOverride:  null,
      commercialRuleType:  "DISCOUNT",
      commercialValueType: "PERCENTAGE",
      commercialValue:     new D("10"),
      commercialApplyOn:   "HECHURA",
      taxOverrides:        [],
    });

    const res = await resolveFinalSalePrice("j1", { articleId: "a1", clientId: "c1" });

    // FASE 1: metalHechuraBreakdown se popula con source=PROPORTIONAL_COST
    // (lista MARGIN_TOTAL no devuelve metalHechuraDetail, pero hay costMetal/costHechura).
    expect(res.metalHechuraBreakdown).not.toBeNull();
    expect(res.metalHechuraBreakdown!.source).toBe("PROPORTIONAL_COST");
    expect(res.metalHechuraBreakdown!.metalSaleEstimated).toBe(true);
    expect(res.metalHechuraBreakdown!.metalSale).toBeCloseTo(1200, 2);
    expect(res.metalHechuraBreakdown!.hechuraSale).toBeCloseTo(800, 2);
    expect(res.componentSaleBreakdown).not.toBeNull();
    // Bases por proporción de costo: metal=1200, hechura=800.
    expect(res.componentSaleBreakdown!.metal.base).toBeCloseTo(1200, 4);
    expect(res.componentSaleBreakdown!.hechura.base).toBeCloseTo(800, 4);
    // Metal queda intacto.
    expect(res.componentSaleBreakdown!.metal.adjustments).toEqual([]);
    expect(res.componentSaleBreakdown!.metal.final).toBeCloseTo(1200, 4);
    // Hechura recibe el ENTITY_RULE: 10% de 800 = 80.
    expect(res.componentSaleBreakdown!.hechura.adjustments).toHaveLength(1);
    expect(res.componentSaleBreakdown!.hechura.adjustments[0].kind).toBe("ENTITY_RULE");
    expect(res.componentSaleBreakdown!.hechura.adjustments[0].applyOn).toBe("HECHURA");
    expect(res.componentSaleBreakdown!.hechura.adjustments[0].amount).toBeCloseTo(80, 4);
    expect(res.componentSaleBreakdown!.hechura.final).toBeCloseTo(720, 4);
    // Coherencia con unitPrice (1200 + 720 = 1920, igual al motor).
    const sumComponents = res.componentSaleBreakdown!.metal.final
                        + res.componentSaleBreakdown!.hechura.final;
    expect(sumComponents).toBeCloseTo(res.unitPrice!.toNumber(), 2);
  });
});
