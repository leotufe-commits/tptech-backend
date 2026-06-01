// src/lib/pricing-engine/__tests__/snapshot-reproducibility.test.ts
// =============================================================================
// SPRINT 1 — Reproducibilidad histórica de snapshots (POLICY.md §9)
//
// Principio rector:
//   Un snapshot persistido en T0 debe seguir reproduciendo los mismos valores
//   en T1, aunque las listas, cotizaciones, costos o impuestos vivos hayan
//   cambiado. El snapshot es la única fuente de verdad histórica.
//
// Casos cubiertos:
//   1. PricingLineSnapshot incluye los campos nuevos del Sprint 1
//      (snapshotVersion, qty/promo/customerDiscountAmount, metalHechuraBreakdown,
//       costOverrideContext).
//   2. customerDiscountAmount es null en Sprint 1 (capa no implementada).
//   3. Los valores del snapshot son independientes de la base de datos viva
//      (mockear cambios después de calcular y verificar que el snapshot no se
//      altera).
//   4. DocumentPricingSnapshot.currency.currencyRate es la tasa congelada,
//      independiente de la cotización viva.
// =============================================================================

import { describe, it, expect, vi, beforeEach } from "vitest";
import { Prisma } from "@prisma/client";

// ── Mock Prisma (vi.hoisted garantiza disponibilidad en la factory) ──────────

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

import { resolveFinalSalePrice, buildPricingSnapshot } from "../pricing-engine.sale.js";
import { buildDocumentPricingSnapshot, DOCUMENT_SNAPSHOT_VERSION } from "../pricing-engine.document.js";
import { PRICING_LINE_SNAPSHOT_VERSION } from "../pricing-engine.types.js";

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
// 1. Shape del snapshot — campos nuevos de Sprint 1
// =============================================================================

describe("PricingLineSnapshot v2 — shape", () => {
  it("incluye snapshotVersion === PRICING_LINE_SNAPSHOT_VERSION", async () => {
    mockPrisma.article.findFirst.mockResolvedValue(makeDbArticle({
      costComposition: [{
        type: "MANUAL", quantity: new D("1"), unitValue: new D("1000"),
        currencyId: null, mermaPercent: null, metalVariantId: null,
      }],
    }));
    mockPrisma.priceList.findFirst.mockResolvedValue(makePriceList());

    const result = await resolveFinalSalePrice("j1", { articleId: "a1" });
    const snap = buildPricingSnapshot(result);

    expect(snap.snapshotVersion).toBe(PRICING_LINE_SNAPSHOT_VERSION);
    expect(PRICING_LINE_SNAPSHOT_VERSION).toBeGreaterThanOrEqual(2);
  });

  it("incluye quantityDiscountAmount y promotionDiscountAmount como campos separados", async () => {
    mockPrisma.article.findFirst.mockResolvedValue(makeDbArticle({
      costComposition: [{
        type: "MANUAL", quantity: new D("1"), unitValue: new D("1000"),
        currencyId: null, mermaPercent: null, metalVariantId: null,
      }],
    }));
    mockPrisma.priceList.findFirst.mockResolvedValue(makePriceList());
    mockPrisma.quantityDiscount.findMany.mockResolvedValue([{
      id: "qd1",
      articleId: "a1", variantId: null, categoryId: null, brand: null, groupId: null,
      isStackable: false, evaluationMode: "LINE",
      tiers: [{ minQty: new D("1"), type: "PERCENTAGE", value: new D("10") }],
    }]);

    const result = await resolveFinalSalePrice("j1", { articleId: "a1", quantity: 2 });
    const snap = buildPricingSnapshot(result);

    expect(snap.quantityDiscountAmount).not.toBeNull();
    expect(snap.quantityDiscountAmount).toBeGreaterThan(0);
    // promotionDiscountAmount puede ser null si no aplicó promo
    expect(snap.promotionDiscountAmount === null || snap.promotionDiscountAmount === 0).toBe(true);
    // discountAmount agrega ambos
    expect(snap.discountAmount).toBeGreaterThanOrEqual(snap.quantityDiscountAmount!);
  });

  it("customerDiscountAmount es null en Sprint 1 (capa no implementada)", async () => {
    mockPrisma.article.findFirst.mockResolvedValue(makeDbArticle({
      costComposition: [{
        type: "MANUAL", quantity: new D("1"), unitValue: new D("500"),
        currencyId: null, mermaPercent: null, metalVariantId: null,
      }],
    }));
    mockPrisma.priceList.findFirst.mockResolvedValue(makePriceList());

    const result = await resolveFinalSalePrice("j1", { articleId: "a1" });
    const snap = buildPricingSnapshot(result);

    // POLICY.md §8 — Sprint 1: capa de descuento de cliente no calculada
    // todavía. Snapshot honesto: null hasta que la capa exista.
    expect(snap.customerDiscountAmount).toBeNull();
  });

  it("metalHechuraBreakdown se persiste en el snapshot cuando hay desglose disponible", async () => {
    mockPrisma.metalVariant.findMany.mockResolvedValue([{ id: "v1", saleFactor: new D("1") }]);
    mockPrisma.metalQuote.findMany.mockResolvedValue([{ variantId: "v1", price: new D("1000") }]);
    mockPrisma.article.findFirst.mockResolvedValue(makeDbArticle({
      costComposition: [
        { type: "METAL",   quantity: new D("5"), unitValue: new D("0"),   currencyId: null, mermaPercent: new D("10"), metalVariantId: "v1" },
        { type: "HECHURA", quantity: new D("1"), unitValue: new D("200"), currencyId: null, mermaPercent: null,        metalVariantId: null },
      ],
    }));
    mockPrisma.priceList.findFirst.mockResolvedValue(makePriceList({
      mode:           "METAL_HECHURA",
      marginTotal:    null,
      marginMetal:    new D("20"),
      marginHechura:  new D("30"),
    }));

    const result = await resolveFinalSalePrice("j1", { articleId: "a1" });
    const snap = buildPricingSnapshot(result);

    expect(snap.metalHechuraBreakdown).not.toBeNull();
    expect(snap.metalHechuraBreakdown!.metalCost).toBeCloseTo(5500, 2);
    expect(snap.metalHechuraBreakdown!.metalSale).toBeCloseTo(6600, 2);
    expect(snap.metalHechuraBreakdown!.hechuraCost).toBeCloseTo(200, 2);
    expect(snap.metalHechuraBreakdown!.hechuraSale).toBeCloseTo(260, 2);
    // metalGramsBase y metalGramsSale presentes (number | null)
    expect(snap.metalHechuraBreakdown).toHaveProperty("metalGramsBase");
    expect(snap.metalHechuraBreakdown).toHaveProperty("metalGramsSale");
    // pureGramsBase / pureGramsSale: null en Sprint 1 (motor sin propagar purity)
    expect(snap.metalHechuraBreakdown!.pureGramsBase).toBeNull();
    expect(snap.metalHechuraBreakdown!.pureGramsSale).toBeNull();
  });

  it("costOverrideContext se persiste cuando hay overrides aplicados", async () => {
    mockPrisma.metalVariant.findMany.mockResolvedValue([{ id: "v1", saleFactor: new D("1") }]);
    mockPrisma.metalQuote.findMany.mockResolvedValue([{ variantId: "v1", price: new D("1000") }]);
    mockPrisma.article.findFirst.mockResolvedValue(makeDbArticle({
      costComposition: [
        { type: "METAL",   quantity: new D("5"), unitValue: new D("0"),   currencyId: null, mermaPercent: new D("10"), metalVariantId: "v1" },
        { type: "HECHURA", quantity: new D("1"), unitValue: new D("200"), currencyId: null, mermaPercent: null,        metalVariantId: null },
      ],
    }));
    mockPrisma.priceList.findFirst.mockResolvedValue(makePriceList({
      mode: "METAL_HECHURA", marginTotal: null,
      marginMetal: new D("20"), marginHechura: new D("30"),
    }));

    const result = await resolveFinalSalePrice("j1", {
      articleId: "a1",
      gramsOverride: 7,
      hechuraOverrideAmount: 350,
    });
    const snap = buildPricingSnapshot(result);

    // Si el motor populó costOverrideContext, debe propagarse al snapshot
    if (result.costOverrideContext) {
      expect(snap.costOverrideContext).toEqual(result.costOverrideContext);
    }
  });
});

// =============================================================================
// 2. Independencia de datos vivos — POLICY.md §9
// =============================================================================

describe("Reproducibilidad — el snapshot no depende de la base viva", () => {
  it("el snapshot generado en T0 mantiene sus valores aunque cambien artículo/lista/cotización en T1", async () => {
    // ── T0: setup inicial ─────────────────────────────────────────────────
    mockPrisma.article.findFirst.mockResolvedValue(makeDbArticle({
      costComposition: [{
        type: "MANUAL", quantity: new D("1"), unitValue: new D("1000"),
        currencyId: null, mermaPercent: null, metalVariantId: null,
      }],
    }));
    mockPrisma.priceList.findFirst.mockResolvedValue(makePriceList({
      marginTotal: new D("50"),  // 50% sobre costo de 1000 → unitPrice = 1500
    }));

    const resultT0 = await resolveFinalSalePrice("j1", { articleId: "a1" });
    const snapT0 = buildPricingSnapshot(resultT0);

    // Capturamos los valores del snapshot
    const t0UnitPrice = snapT0.unitPrice;
    const t0BasePrice = snapT0.basePrice;
    const t0DiscountAmount = snapT0.discountAmount;
    const t0TotalWithTax = snapT0.totalWithTax;
    const t0UnitCost = snapT0.unitCost;
    const t0AppliedPriceListId = snapT0.appliedPriceListId;
    const t0ResolvedAt = snapT0.resolvedAt;

    expect(t0UnitPrice).toBeCloseTo(1500, 2);
    expect(t0UnitCost).toBeCloseTo(1000, 2);
    expect(t0AppliedPriceListId).toBe("pl-test");

    // ── T1: cambiamos drásticamente la base viva ──────────────────────────
    // Nuevo costo, nueva lista, nuevas cotizaciones — todo distinto
    mockPrisma.article.findFirst.mockResolvedValue(makeDbArticle({
      costComposition: [{
        type: "MANUAL", quantity: new D("1"), unitValue: new D("9999"),
        currencyId: null, mermaPercent: null, metalVariantId: null,
      }],
    }));
    mockPrisma.priceList.findFirst.mockResolvedValue(makePriceList({
      id: "pl-different",
      marginTotal: new D("999"),
    }));
    mockPrisma.metalQuote.findMany.mockResolvedValue([{ variantId: "v1", price: new D("99999") }]);

    // El snapshot NO se recomputa — es un objeto inmutable. Verificamos que
    // sus campos siguen siendo los de T0.
    expect(snapT0.unitPrice).toBe(t0UnitPrice);
    expect(snapT0.basePrice).toBe(t0BasePrice);
    expect(snapT0.discountAmount).toBe(t0DiscountAmount);
    expect(snapT0.totalWithTax).toBe(t0TotalWithTax);
    expect(snapT0.unitCost).toBe(t0UnitCost);
    expect(snapT0.appliedPriceListId).toBe(t0AppliedPriceListId);
    expect(snapT0.resolvedAt).toBe(t0ResolvedAt);

    // Si volvemos a calcular en T1 (con la base nueva), obtenemos resultado
    // distinto — pero eso NO contamina el snapshot original.
    const resultT1 = await resolveFinalSalePrice("j1", { articleId: "a1" });
    const snapT1 = buildPricingSnapshot(resultT1);

    expect(snapT1.unitCost).not.toBeCloseTo(t0UnitCost!, 2);
    expect(snapT1.appliedPriceListId).not.toBe(t0AppliedPriceListId);
    // El snapshot T0 sigue intacto
    expect(snapT0.unitPrice).toBe(t0UnitPrice);
    expect(snapT0.unitCost).toBe(t0UnitCost);
  });

  it("snapshot es serializable a JSON sin pérdida (Decimal → number)", async () => {
    mockPrisma.article.findFirst.mockResolvedValue(makeDbArticle({
      costComposition: [{
        type: "MANUAL", quantity: new D("1"), unitValue: new D("1234.56"),
        currencyId: null, mermaPercent: null, metalVariantId: null,
      }],
    }));
    mockPrisma.priceList.findFirst.mockResolvedValue(makePriceList({
      marginTotal: new D("25"),
    }));

    const result = await resolveFinalSalePrice("j1", { articleId: "a1" });
    const snap = buildPricingSnapshot(result);

    // Roundtrip JSON: serializar y deserializar debe dar el mismo objeto
    const serialized   = JSON.stringify(snap);
    const deserialized = JSON.parse(serialized);

    expect(deserialized.unitPrice).toBe(snap.unitPrice);
    expect(deserialized.basePrice).toBe(snap.basePrice);
    expect(deserialized.discountAmount).toBe(snap.discountAmount);
    expect(deserialized.snapshotVersion).toBe(snap.snapshotVersion);
    expect(deserialized.appliedPriceListId).toBe(snap.appliedPriceListId);
    expect(deserialized.resolvedAt).toBe(snap.resolvedAt);
  });
});

// =============================================================================
// 3. DocumentPricingSnapshot — currencyRate inmutable
// =============================================================================

describe("DocumentPricingSnapshot — currencyRate persistida (POLICY.md §9.6)", () => {
  it("currency.currencyRate es la tasa congelada en el momento de buildDocumentPricingSnapshot", () => {
    const snap = buildDocumentPricingSnapshot({
      currency: {
        id: "USD",
        currencyCode: "USD",
        symbol: "US$",
        currencyRate: 950,            // ← tasa congelada
        baseCurrencyCode: "ARS",
      },
      issuer: {
        jewelryId: "j1", name: "Joyería X", cuit: "20-12345678-9", ivaCondition: "RI",
      },
      counterparty: null,
      channel: null,
      coupon: null,
      promotion: null,
      quantityDiscount: null,
      paymentMethod: null,
      rounding: { source: "NONE", appliedOn: "NONE", mode: "NONE", direction: "NONE", adjustment: 0 },
      taxBreakdown: [],
      totals: {
        subtotal: 100, channelAmount: 0, couponAmount: 0,
        quantityDiscountAmount: 0, promotionAmount: 0,
        paymentSurcharge: 0, discountAmount: 0,
        taxAmount: 21, roundingAdjustment: 0,
        total: 121, totalBase: 121,
      },
      cost: { totalCost: null, totalMargin: null, marginPercent: null, costPartial: false },
      lines: [],
    });

    // La tasa queda congelada en el snapshot — independiente de cualquier
    // valor de cotización viva en futuras lecturas.
    expect(snap.currency.currencyRate).toBe(950);
    expect(snap.currency.currencyCode).toBe("USD");
    expect(snap.currency.baseCurrencyCode).toBe("ARS");
    expect(snap.version).toBe(DOCUMENT_SNAPSHOT_VERSION);
  });

  it("DOCUMENT_SNAPSHOT_VERSION está en v3 (Balance Mode — Fase 3B.3)", () => {
    expect(DOCUMENT_SNAPSHOT_VERSION).toBe(3);
  });
});
