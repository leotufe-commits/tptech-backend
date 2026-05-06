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
}));

const mockResolvePriceList = vi.hoisted(() => vi.fn());
const mockApplyPriceList   = vi.hoisted(() => vi.fn());
vi.mock("../pricing-engine.pricelist.js", () => ({
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
