// src/lib/pricing-engine/__tests__/integration.test.ts
// Tests de integración: motor completo (costo + venta) con Prisma mockeado.
// No se mockea resolveArticleCost ni resolvePriceList — el motor corre de verdad.

import { describe, it, expect, vi, beforeEach } from "vitest";
import { Prisma } from "@prisma/client";

// ── Mock Prisma (vi.hoisted garantiza disponibilidad en la factory) ───────────

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
}));

vi.mock("../../prisma.js", () => ({ prisma: mockPrisma }));

// Imports después de mocks
import { resolveFinalSalePrice } from "../pricing-engine.sale.js";

// ── Helpers ──────────────────────────────────────────────────────────────────

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

function noPromo()    { return []; }
function noDiscount() { return []; }

/** Config de política por defecto para todos los tests (sin bloqueos) */
function defaultJewelryConfig() {
  return {
    defaultMermaPercent:            null,
    pricingLowMarginWarningPercent:  null, // usará fallback 15%
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
  mockPrisma.promotion.findMany.mockResolvedValue(noPromo());
  mockPrisma.quantityDiscount.findMany.mockResolvedValue(noDiscount());
  mockPrisma.commercialEntity.findFirst.mockResolvedValue(null);
  mockPrisma.articleCategory.findFirst.mockResolvedValue(null);
  mockPrisma.priceList.findFirst.mockResolvedValue(null);
  mockPrisma.jewelry.findUnique.mockResolvedValue(defaultJewelryConfig());
  // Moneda base por defecto (necesaria para calculateCostFromLines)
  mockPrisma.currency.findFirst.mockResolvedValue({ id: "ARS" });
  mockPrisma.metalVariant.findMany.mockResolvedValue([]);
  mockPrisma.metalQuote.findMany.mockResolvedValue([]);
});

// ─────────────────────────────────────────────────────────────────────────────
// INTEGRACIÓN COMPLETA: costo → lista → qty → promo
// ─────────────────────────────────────────────────────────────────────────────

describe("Flujo completo: MANUAL + lista + descuentos", () => {
  it("costo=500 → lista +100% → 1000 → qty -10% → 900 → promo -50 → 850", async () => {
    mockPrisma.article.findFirst.mockResolvedValue(makeDbArticle({
      costComposition: [{ type: "MANUAL", quantity: new D("1"), unitValue: new D("500"), currencyId: null, mermaPercent: null, metalVariantId: null }],
    }));

    // Lista general que aplica 100% de margen sobre costo total
    mockPrisma.priceList.findFirst.mockResolvedValue({
      id:               "pl1",
      name:             "Lista General",
      mode:             "MARGIN_TOTAL",
      marginTotal:      new D("100"),
      marginMetal:      null,
      marginHechura:    null,
      costPerGram:      null,
      surcharge:        null,
      minimumPrice:     null,
      roundingTarget:   "NONE",
      roundingMode:     "NONE",
      roundingDirection: "NEAREST",
      validFrom:        null,
      validTo:          null,
      isActive:         true,
      scope:            "GENERAL",
      isFavorite:       true,
      deletedAt:        null,
      sortOrder:        0,
    });

    // Descuento por cantidad: -10% (isStackable=true para que se combine con la promo)
    mockPrisma.quantityDiscount.findMany.mockResolvedValue([{
      id: "qd1",
      articleId: "a1", variantId: null, categoryId: null, brand: null, groupId: null,
      isStackable: true, evaluationMode: "LINE",
      tiers: [{ minQty: new D("1"), type: "PERCENTAGE", value: new D("10") }],
    }]);

    // Promoción: -50 fijo (isStackable=true para que se combine con el qty discount)
    mockPrisma.promotion.findMany.mockResolvedValue([{
      id: "promo1", name: "Promo",
      type: "FIXED", value: new D("50"),
      scope: "ALL", applyOn: "TOTAL",
      validFrom: null, validTo: null,
      isActive: true, deletedAt: null, priority: 1,
      isStackable: true,
    }]);

    const res = await resolveFinalSalePrice("j1", { articleId: "a1", quantity: 2 });

    // Verificar valores clave
    expect(res.unitCost?.toNumber()).toBe(500);
    expect(res.basePrice?.toNumber()).toBeCloseTo(1000, 1);
    expect(res.quantityDiscountAmount?.toNumber()).toBeCloseTo(100, 1);
    expect(res.unitPrice?.toNumber()).toBeCloseTo(850, 1);
    expect(res.priceSource).toBe("PROMOTION");
    expect(res.baseSource).toBe("PRICE_LIST");

    // Verificar margen: (850 - 500) / 850 × 100 ≈ 41.17%
    expect(res.marginPercent?.toNumber()).toBeCloseTo(41.17, 0);

    // Verificar steps
    expect(res.steps.length).toBeGreaterThan(0);
    const keys = res.steps.map(s => s.key);
    expect(keys).toContain("PRICE_LIST");
    expect(keys).toContain("QUANTITY_DISCOUNT");
    expect(keys).toContain("PROMOTION");
    expect(keys).toContain("MARGIN");
    expect(keys).toContain("PRECIO_FINAL");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// INTEGRACIÓN: METAL_MERMA_HECHURA + lista
// ─────────────────────────────────────────────────────────────────────────────

describe("Flujo completo: COST_LINES metal + lista MARGIN_TOTAL", () => {
  it("10g × 50/g + merma 10% + hechura 200 = 750 → lista +50% → 1125", async () => {
    mockPrisma.currency.findFirst.mockResolvedValue({ id: "ARS" });
    mockPrisma.metalQuote.findMany.mockResolvedValue([{ variantId: "v1", price: new D("50") }]);
    mockPrisma.metalVariant.findMany.mockResolvedValue([{ id: "v1", saleFactor: new D("1") }]);

    mockPrisma.article.findFirst.mockResolvedValue(makeDbArticle({
      costComposition: [
        { type: "METAL",   quantity: new D("10"), unitValue: new D("0"),   currencyId: null, mermaPercent: new D("10"), metalVariantId: "v1" },
        { type: "HECHURA", quantity: new D("1"),  unitValue: new D("200"), currencyId: null, mermaPercent: null,        metalVariantId: null },
      ],
    }));

    mockPrisma.priceList.findFirst.mockResolvedValue({
      id:               "pl2",
      name:             "Lista Metal",
      mode:             "MARGIN_TOTAL",
      marginTotal:      new D("50"),
      marginMetal:      null, marginHechura: null,
      costPerGram:      null, surcharge: null, minimumPrice: null,
      roundingTarget:   "NONE", roundingMode: "NONE", roundingDirection: "NEAREST",
      validFrom: null, validTo: null, isActive: true,
      scope: "GENERAL", isFavorite: true, deletedAt: null, sortOrder: 0,
    });

    const res = await resolveFinalSalePrice("j1", { articleId: "a1" });

    // costo = 10×1.1×50 + 200 = 550 + 200 = 750
    expect(res.unitCost?.toNumber()).toBeCloseTo(750, 2);
    // precio = 750 × 1.5 = 1125
    expect(res.unitPrice?.toNumber()).toBeCloseTo(1125, 1);
    expect(res.priceSource).toBe("PRICE_LIST");
    expect(res.partial).toBe(false);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// INTEGRACIÓN: COST_LINES + descuento
// ─────────────────────────────────────────────────────────────────────────────

describe("Flujo completo: COST_LINES + cantidad", () => {
  it("COST_LINES=700 → manual salePrice=1400 → qty 20% → 1120", async () => {
    mockPrisma.currency.findFirst.mockResolvedValue({ id: "ARS" });
    mockPrisma.metalVariant.findMany.mockResolvedValue([{ id: "v1", saleFactor: new D("1") }]);
    mockPrisma.metalQuote.findMany.mockResolvedValue([{ variantId: "v1", price: new D("50") }]);

    mockPrisma.article.findFirst.mockResolvedValue(makeDbArticle({
      salePrice: new D("1400"),
      costComposition: [
        { type: "METAL",   quantity: new D("10"), unitValue: new D("0"),   currencyId: null, mermaPercent: new D("0"), metalVariantId: "v1" },
        { type: "HECHURA", quantity: new D("1"),  unitValue: new D("200"), currencyId: null, mermaPercent: null,       metalVariantId: null },
      ],
    }));

    mockPrisma.quantityDiscount.findMany.mockResolvedValue([{
      id: "qd1",
      articleId: "a1", variantId: null, categoryId: null, brand: null,
      tiers: [{ minQty: new D("1"), type: "PERCENTAGE", value: new D("20") }],
    }]);

    const res = await resolveFinalSalePrice("j1", { articleId: "a1", quantity: 10 });

    expect(res.unitCost?.toNumber()).toBeCloseTo(700, 2);   // 10×50 + 200
    expect(res.basePrice?.toNumber()).toBeCloseTo(1400, 1);
    expect(res.unitPrice?.toNumber()).toBeCloseTo(1120, 1); // 1400 × 0.8
    expect(res.costMode).toBe("COST_LINES");
    expect(res.costPartial).toBe(false);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// ALERTAS DE NEGOCIO
// ─────────────────────────────────────────────────────────────────────────────

describe("Alertas de negocio", () => {
  it("LOSS_SALE — precio final menor al costo", async () => {
    mockPrisma.article.findFirst.mockResolvedValue(makeDbArticle({
      costComposition: [{ type: "MANUAL", quantity: new D("1"), unitValue: new D("500"), currencyId: null, mermaPercent: null, metalVariantId: null }],
      salePrice: new D("300"), // precio < costo
    }));

    const res = await resolveFinalSalePrice("j1", { articleId: "a1" });

    const codes = res.alerts.map(a => a.code);
    expect(codes).toContain("LOSS_SALE");
    expect(res.alerts.find(a => a.code === "LOSS_SALE")?.level).toBe("error");
  });

  it("LOW_MARGIN — margen entre 0 y 15%", async () => {
    // costo=100, precio=110 → margen ≈ 9.09%
    mockPrisma.article.findFirst.mockResolvedValue(makeDbArticle({
      costComposition: [{ type: "MANUAL", quantity: new D("1"), unitValue: new D("100"), currencyId: null, mermaPercent: null, metalVariantId: null }],
      salePrice: new D("110"),
    }));

    const res = await resolveFinalSalePrice("j1", { articleId: "a1" });

    const codes = res.alerts.map(a => a.code);
    expect(codes).toContain("LOW_MARGIN");
    expect(res.alerts.find(a => a.code === "LOW_MARGIN")?.level).toBe("warning");
    // No debe haber LOSS_SALE (precio > costo)
    expect(codes).not.toContain("LOSS_SALE");
  });

  it("PARTIAL_DATA — costo parcial", async () => {
    // COST_LINES con línea METAL sin cotización → costPartial=true
    mockPrisma.currency.findFirst.mockResolvedValue({ id: "ARS" });
    mockPrisma.metalVariant.findMany.mockResolvedValue([{ id: "v1", saleFactor: new D("1") }]);
    mockPrisma.metalQuote.findMany.mockResolvedValue([]); // sin cotización → partial

    mockPrisma.article.findFirst.mockResolvedValue(makeDbArticle({
      costComposition: [{ type: "METAL", quantity: new D("10"), unitValue: new D("0"), currencyId: null, mermaPercent: new D("0"), metalVariantId: "v1" }],
      salePrice: new D("1000"),
    }));

    const res = await resolveFinalSalePrice("j1", { articleId: "a1" });

    const codes = res.alerts.map(a => a.code);
    expect(codes).toContain("PARTIAL_DATA");
    expect(res.alerts.find(a => a.code === "PARTIAL_DATA")?.level).toBe("warning");
  });

  it("ZERO_OR_NEGATIVE_PRICE — precio = 0 por promo excesiva", async () => {
    mockPrisma.article.findFirst.mockResolvedValue(makeDbArticle({ salePrice: new D("100") }));
    mockPrisma.promotion.findMany.mockResolvedValue([{
      id: "p1", name: "Mega promo",
      type: "FIXED", value: new D("99999"),
      scope: "ALL",
      validFrom: null, validTo: null,
      isActive: true, deletedAt: null, priority: 1,
    }]);

    const res = await resolveFinalSalePrice("j1", { articleId: "a1" });

    const codes = res.alerts.map(a => a.code);
    expect(codes).toContain("ZERO_OR_NEGATIVE_PRICE");
    expect(res.alerts.find(a => a.code === "ZERO_OR_NEGATIVE_PRICE")?.level).toBe("error");
  });

  it("COST_UNRESOLVED — sin precio de costo disponible", async () => {
    // Artículo con salePrice pero sin costComposition → costo no resuelto
    mockPrisma.article.findFirst.mockResolvedValue(makeDbArticle({
      costComposition: [],
      salePrice: new D("500"),
    }));

    const res = await resolveFinalSalePrice("j1", { articleId: "a1" });

    const codes = res.alerts.map(a => a.code);
    expect(codes).toContain("COST_UNRESOLVED");
    expect(res.alerts.find(a => a.code === "COST_UNRESOLVED")?.level).toBe("warning");
  });

  it("alertas ordenadas: errores antes que warnings", async () => {
    // precio < costo → LOSS_SALE (error) + potencial LOW_MARGIN (warning)
    mockPrisma.article.findFirst.mockResolvedValue(makeDbArticle({
      costComposition: [{ type: "MANUAL", quantity: "1", unitValue: new D("500"), currencyId: null, mermaPercent: null, metalVariantId: null }],
      salePrice: new D("400"),
    }));

    const res = await resolveFinalSalePrice("j1", { articleId: "a1" });

    const levels = res.alerts.map(a => a.level);
    const firstError = levels.indexOf("error");
    const firstWarning = levels.indexOf("warning");
    if (firstError !== -1 && firstWarning !== -1) {
      expect(firstError).toBeLessThan(firstWarning);
    }
  });

  it("sin alertas cuando precio y costo son válidos y margen es bueno", async () => {
    // costo=100, precio=200 → margen=50% → sin alertas
    mockPrisma.article.findFirst.mockResolvedValue(makeDbArticle({
      costComposition: [{ type: "MANUAL", quantity: "1", unitValue: new D("100"), currencyId: null, mermaPercent: null, metalVariantId: null }],
      salePrice: new D("200"),
    }));

    const res = await resolveFinalSalePrice("j1", { articleId: "a1" });

    expect(res.alerts).toHaveLength(0);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// EDGE CASES
// ─────────────────────────────────────────────────────────────────────────────

describe("Edge cases", () => {
  it("precio nunca es negativo — promo mayor al precio", async () => {
    mockPrisma.article.findFirst.mockResolvedValue(
      makeDbArticle({ salePrice: new D("100") })
    );
    mockPrisma.promotion.findMany.mockResolvedValue([{
      id: "p1", name: "Mega promo",
      type: "FIXED", value: new D("99999"),
      scope: "ALL",
      validFrom: null, validTo: null,
      isActive: true, deletedAt: null, priority: 1,
    }]);

    const res = await resolveFinalSalePrice("j1", { articleId: "a1" });
    expect(res.unitPrice?.toNumber()).toBeGreaterThanOrEqual(0);
  });

  it("partial=true cuando lista no puede calcularse por falta de costo", async () => {
    mockPrisma.article.findFirst.mockResolvedValue(makeDbArticle());
    // Sin salePrice, sin lista → unitPrice null
    const res = await resolveFinalSalePrice("j1", { articleId: "a1" });
    expect(res.unitPrice).toBeNull();
    expect(res.partial).toBe(true);
  });

  it("steps tienen status válido en cada paso", async () => {
    mockPrisma.article.findFirst.mockResolvedValue(makeDbArticle({
      costComposition: [{ type: "MANUAL", quantity: "1", unitValue: new D("300"), currencyId: null, mermaPercent: null, metalVariantId: null }],
      salePrice: new D("500"),
    }));
    const validStatuses = new Set(["ok", "partial", "missing", "skipped"]);
    const res = await resolveFinalSalePrice("j1", { articleId: "a1" });
    for (const step of res.steps) {
      expect(validStatuses.has(step.status)).toBe(true);
    }
  });

  it("quantity=0 → no causa error, descuento con qty=0 no aplica tier", async () => {
    mockPrisma.article.findFirst.mockResolvedValue(
      makeDbArticle({ salePrice: new D("1000") })
    );
    mockPrisma.quantityDiscount.findMany.mockResolvedValue([{
      id: "qd1",
      articleId: "a1", variantId: null, categoryId: null, brand: null,
      tiers: [{ minQty: new D("5"), type: "PERCENTAGE", value: new D("10") }],
    }]);

    // qty=0 → minQty=5 no aplica
    const res = await resolveFinalSalePrice("j1", { articleId: "a1", quantity: 0 });
    expect(res.unitPrice?.toNumber()).toBe(1000);
    expect(res.quantityDiscountAmount).toBeNull();
  });

  it("Todos los campos del resultado están presentes", async () => {
    mockPrisma.article.findFirst.mockResolvedValue(makeDbArticle({
      costComposition: [{ type: "MANUAL", quantity: "1", unitValue: new D("250"), currencyId: null, mermaPercent: null, metalVariantId: null }],
      salePrice: new D("500"),
    }));
    const res = await resolveFinalSalePrice("j1", { articleId: "a1" });

    expect(res).toHaveProperty("unitPrice");
    expect(res).toHaveProperty("basePrice");
    expect(res).toHaveProperty("quantityDiscountAmount");
    expect(res).toHaveProperty("promotionDiscountAmount");
    expect(res).toHaveProperty("discountAmount");
    expect(res).toHaveProperty("priceSource");
    expect(res).toHaveProperty("baseSource");
    expect(res).toHaveProperty("unitCost");
    expect(res).toHaveProperty("unitMargin");
    expect(res).toHaveProperty("marginPercent");
    expect(res).toHaveProperty("costPartial");
    expect(res).toHaveProperty("costMode");
    expect(res).toHaveProperty("partial");
    expect(res).toHaveProperty("appliedPriceListId");
    expect(res).toHaveProperty("appliedPromotionId");
    expect(res).toHaveProperty("appliedDiscountId");
    expect(Array.isArray(res.steps)).toBe(true);
    expect(Array.isArray(res.alerts)).toBe(true);
    expect(res).toHaveProperty("policy");
    expect(typeof res.policy.canConfirm).toBe("boolean");
    expect(Array.isArray(res.policy.blockingAlerts)).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// POLÍTICA DE CONFIRMACIÓN
// ─────────────────────────────────────────────────────────────────────────────

describe("Política de confirmación", () => {
  it("canConfirm=true cuando margen es bueno y no hay bloqueos activos", async () => {
    // costo=100, precio=200 → margen=50%
    mockPrisma.article.findFirst.mockResolvedValue(makeDbArticle({
      costComposition: [{ type: "MANUAL", quantity: "1", unitValue: new D("100"), currencyId: null, mermaPercent: null, metalVariantId: null }],
      salePrice: new D("200"),
    }));

    const res = await resolveFinalSalePrice("j1", { articleId: "a1" });
    expect(res.policy.canConfirm).toBe(true);
    expect(res.policy.blockingAlerts).toHaveLength(0);
  });

  it("canConfirm=false — ZERO_OR_NEGATIVE_PRICE bloquea por defecto", async () => {
    // Precio final = 0 (promo absurda)
    mockPrisma.article.findFirst.mockResolvedValue(makeDbArticle({ salePrice: new D("100") }));
    mockPrisma.promotion.findMany.mockResolvedValue([{
      id: "p1", name: "Mega promo",
      type: "FIXED", value: new D("99999"),
      scope: "ALL", validFrom: null, validTo: null,
      isActive: true, deletedAt: null, priority: 1,
    }]);

    const res = await resolveFinalSalePrice("j1", { articleId: "a1" });
    expect(res.policy.canConfirm).toBe(false);
    expect(res.policy.blockingAlerts).toContain("ZERO_OR_NEGATIVE_PRICE");
  });

  it("LOSS_SALE no bloquea cuando pricingBlockLossSale=false (default)", async () => {
    // costo=500, precio=300 → LOSS_SALE alert, pero no bloquea por default
    mockPrisma.article.findFirst.mockResolvedValue(makeDbArticle({
      costComposition: [{ type: "MANUAL", quantity: "1", unitValue: new D("500"), currencyId: null, mermaPercent: null, metalVariantId: null }],
      salePrice: new D("300"),
    }));
    // pricingBlockLossSale=false (default)

    const res = await resolveFinalSalePrice("j1", { articleId: "a1" });
    expect(res.alerts.map(a => a.code)).toContain("LOSS_SALE");
    expect(res.policy.canConfirm).toBe(true);           // no bloquea
    expect(res.policy.blockingAlerts).not.toContain("LOSS_SALE");
  });

  it("LOSS_SALE bloquea cuando pricingBlockLossSale=true", async () => {
    mockPrisma.jewelry.findUnique.mockResolvedValue({
      ...defaultJewelryConfig(),
      pricingBlockLossSale: true,
    });
    mockPrisma.article.findFirst.mockResolvedValue(makeDbArticle({
      costComposition: [{ type: "MANUAL", quantity: "1", unitValue: new D("500"), currencyId: null, mermaPercent: null, metalVariantId: null }],
      salePrice: new D("300"),
    }));

    const res = await resolveFinalSalePrice("j1", { articleId: "a1" });
    expect(res.policy.canConfirm).toBe(false);
    expect(res.policy.blockingAlerts).toContain("LOSS_SALE");
  });

  it("LOW_MARGIN — solo warning, no bloquea sin lowMarginBlockPercent", async () => {
    // costo=100, precio=110 → margen≈9.09% → LOW_MARGIN warning, no block
    mockPrisma.article.findFirst.mockResolvedValue(makeDbArticle({
      costComposition: [{ type: "MANUAL", quantity: "1", unitValue: new D("100"), currencyId: null, mermaPercent: null, metalVariantId: null }],
      salePrice: new D("110"),
    }));

    const res = await resolveFinalSalePrice("j1", { articleId: "a1" });
    expect(res.alerts.map(a => a.code)).toContain("LOW_MARGIN");
    expect(res.policy.canConfirm).toBe(true);            // solo warning
    expect(res.policy.blockingAlerts).not.toContain("LOW_MARGIN");
  });

  it("LOW_MARGIN bloquea cuando lowMarginBlockPercent está configurado y margen < umbral", async () => {
    mockPrisma.jewelry.findUnique.mockResolvedValue({
      ...defaultJewelryConfig(),
      pricingLowMarginBlockPercent: new D("20"), // bloquea si margen < 20%
    });
    // costo=100, precio=110 → margen≈9.09% < 20%
    mockPrisma.article.findFirst.mockResolvedValue(makeDbArticle({
      costComposition: [{ type: "MANUAL", quantity: "1", unitValue: new D("100"), currencyId: null, mermaPercent: null, metalVariantId: null }],
      salePrice: new D("110"),
    }));

    const res = await resolveFinalSalePrice("j1", { articleId: "a1" });
    expect(res.policy.canConfirm).toBe(false);
    expect(res.policy.blockingAlerts).toContain("LOW_MARGIN");
  });

  it("LOW_MARGIN NO bloquea cuando lowMarginBlockPercent está configurado pero margen > umbral", async () => {
    mockPrisma.jewelry.findUnique.mockResolvedValue({
      ...defaultJewelryConfig(),
      pricingLowMarginBlockPercent: new D("5"), // umbral bajo: 5%
    });
    // costo=100, precio=110 → margen≈9.09% > 5% → no bloquea
    mockPrisma.article.findFirst.mockResolvedValue(makeDbArticle({
      costComposition: [{ type: "MANUAL", quantity: "1", unitValue: new D("100"), currencyId: null, mermaPercent: null, metalVariantId: null }],
      salePrice: new D("110"),
    }));

    const res = await resolveFinalSalePrice("j1", { articleId: "a1" });
    expect(res.policy.canConfirm).toBe(true);
    expect(res.policy.blockingAlerts).not.toContain("LOW_MARGIN");
  });

  it("PARTIAL_DATA no bloquea cuando pricingBlockPartialData=false (default)", async () => {
    mockPrisma.metalQuote.findMany.mockResolvedValue([]); // sin cotización → partial
    mockPrisma.article.findFirst.mockResolvedValue(makeDbArticle({
      costComposition: [{ type: "METAL", quantity: new D("10"), unitValue: new D("0"), currencyId: null, mermaPercent: new D("0"), metalVariantId: "v1" }],
      salePrice: new D("1000"),
    }));

    const res = await resolveFinalSalePrice("j1", { articleId: "a1" });
    expect(res.alerts.map(a => a.code)).toContain("PARTIAL_DATA");
    expect(res.policy.canConfirm).toBe(true);             // no bloquea por default
  });
});
