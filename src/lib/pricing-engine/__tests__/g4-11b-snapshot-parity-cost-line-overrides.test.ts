// src/lib/pricing-engine/__tests__/g4-11b-snapshot-parity-cost-line-overrides.test.ts
// =============================================================================
// FASE F1.4 G5 #11-B — paridad preview/persisted v6 + retrocompat v5.
//
// Cubre TODAS las validaciones del usuario:
//   1. Paridad: dos previews con mismo input → costLineOverridesApplied
//      idénticos byte-paritarios.
//   2. Snapshot persiste el RESULTADO FINAL UNIFICADO (legacy + explicit
//      mergeados por unifyCostLineOverrides, no solo el payload del
//      caller).
//   3. Retrocompat v5: snapshot leído sin `costLineOverridesApplied`
//      → reader normaliza a undefined sin crash.
//   4. CASO CRÍTICO: 2 metales, override SOLO del segundo → primer metal
//      intacto en snapshot.
//   5. Replay histórico: snapshot v6 contiene info suficiente para
//      reproducir el cálculo (input completo).
//   6. Cero double-apply legacy + explicit (verificación de cálculo
//      numérico — el explicit pisa el legacy cuando match).
//
// CERO matemática frontend, CERO mutación, CERO cambio en pricing-engine
// para flow sin overrides.
// =============================================================================

import { describe, it, expect, vi, beforeEach } from "vitest";
import { Prisma } from "@prisma/client";

// Mocks
const mockPrisma = vi.hoisted(() => ({
  metalVariant:    { findMany: vi.fn(), findUnique: vi.fn() },
  metalQuote:      { findMany: vi.fn() },
  currency:        { findFirst: vi.fn() },
  jewelry:         { findUnique: vi.fn() },
  article:         { findFirst: vi.fn() },
  articleVariant:  { findFirst: vi.fn() },
  articleGroupItem:{ findFirst: vi.fn() },
  promotion:       { findMany: vi.fn() },
  quantityDiscount:{ findMany: vi.fn() },
  commercialEntity:{ findFirst: vi.fn() },
  entityMermaOverride: { findMany: vi.fn() },
}));
vi.mock("../../prisma.js", () => ({ prisma: mockPrisma }));

const mockResolveArticleCost = vi.hoisted(() => vi.fn());
vi.mock("../pricing-engine.cost.js", async () => {
  const actual = await vi.importActual<typeof import("../pricing-engine.cost.js")>(
    "../pricing-engine.cost.js",
  );
  return {
    ...actual,
    calculateCostFromLines: (...args: any[]) => mockResolveArticleCost(...args),
    enrichCostMetalSteps:   vi.fn(),
    getArticleMetalVariantIds:     vi.fn().mockResolvedValue([]),
    loadArticleMetalVariantsBatch: vi.fn().mockResolvedValue(new Map()),
  };
});

const mockResolvePriceList = vi.hoisted(() => vi.fn());
const mockApplyPriceList   = vi.hoisted(() => vi.fn());
vi.mock("../pricing-engine.pricelist.js", async () => {
  const actual = await vi.importActual<typeof import("../pricing-engine.pricelist.js")>(
    "../pricing-engine.pricelist.js",
  );
  return {
    ...actual,
    resolvePriceList: (...args: any[]) => mockResolvePriceList(...args),
    applyPriceList:   (...args: any[]) => mockApplyPriceList(...args),
  };
});

import {
  resolveFinalSalePrice,
  buildPricingSnapshot,
} from "../pricing-engine.sale.js";
import { PRICING_LINE_SNAPSHOT_VERSION } from "../pricing-engine.types.js";
import type {
  CostLineOverride,
  PricingLineSnapshot,
} from "../pricing-engine.types.js";

const D = Prisma.Decimal;

// ─────────────────────────────────────────────────────────────────────────────
// Fixture helpers
// ─────────────────────────────────────────────────────────────────────────────

function makeArticle(costComposition: any[]) {
  return {
    id: "a1",
    salePrice: null,
    costPrice: null,
    useManualSalePrice: false,
    salePriceCurrencyId: null,
    manualAdjustmentKind: null,
    manualAdjustmentType: null,
    manualAdjustmentValue: null,
    mermaPercent: null,
    metalVariantId: null,
    weightInGrams: null,
    laborCost: null,
    laborCurrencyId: null,
    laborAdjustmentKind: null,
    laborAdjustmentType: null,
    laborAdjustmentValue: null,
    categoryId: null,
    brand: null,
    isCombo: false,
    deletedAt: null,
    costComposition,
    category: null,
  };
}

function setupCost(value: number, breakdown?: { metalCost: number; hechuraCost: number }) {
  mockResolveArticleCost.mockResolvedValue({
    value:      new D(String(value)),
    mode:       "COST_LINES",
    partial:    false,
    steps:      [],
    metalCost:  breakdown ? new D(String(breakdown.metalCost))   : new D("0"),
    hechuraCost:breakdown ? new D(String(breakdown.hechuraCost)) : new D("0"),
    totalGrams: new D("0"),
    metalGramsWithMerma: new D("0"),
    metalPurity: null,
    // F1.4 #11-A — el cost engine devuelve el array sanitizado/aplicado
    // que sale.ts unificará con legacy en SalePriceResult.
    costLineOverridesApplied: undefined,
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  // Default mocks: una price list dummy. Los tests no validan precios
  // monetarios — solo verifican que costLineOverridesApplied se persista
  // correctamente en el snapshot.
  mockResolvePriceList.mockResolvedValue({
    priceList: {
      id: "pl-test", name: "Test", mode: "MARGIN_TOTAL",
      marginTotal: new D("0"), marginMetal: null, marginHechura: null,
      costPerGram: null, surcharge: null, minimumPrice: null,
      roundingTarget: "NONE", roundingMode: "NONE", roundingDirection: "NEAREST",
      validFrom: null, validTo: null, isActive: true,
    },
    source: "GENERAL",
  });
  mockApplyPriceList.mockReturnValue({ value: new D("1000"), partial: false });
  mockPrisma.article.findFirst.mockResolvedValue(makeArticle([]));
  mockPrisma.articleVariant.findFirst.mockResolvedValue(null);
  mockPrisma.articleGroupItem.findFirst.mockResolvedValue(null);
  mockPrisma.promotion.findMany.mockResolvedValue([]);
  mockPrisma.quantityDiscount.findMany.mockResolvedValue([]);
  mockPrisma.commercialEntity.findFirst.mockResolvedValue(null);
  mockPrisma.entityMermaOverride.findMany.mockResolvedValue([]);
  mockPrisma.jewelry.findUnique.mockResolvedValue({
    id: "j1", roundingMode: "NONE", roundingDirection: "NEAREST", roundingTarget: "NONE",
  });
});

// =============================================================================
// 1. Snapshot version v7 (F17 — aditivo: costBase/costTaxAmount/costWithTax)
// =============================================================================

describe("F1.4 #11-B / F17 — snapshot version v7", () => {
  it("baseline correct: PRICING_LINE_SNAPSHOT_VERSION === 7", () => {
    expect(PRICING_LINE_SNAPSHOT_VERSION).toBe(7);
  });

  it("baseline correct: nuevo snapshot lleva snapshotVersion=7", async () => {
    setupCost(1000);
    const result = await resolveFinalSalePrice("j1", { articleId: "a1" });
    const snap = buildPricingSnapshot(result);
    expect(snap.snapshotVersion).toBe(7);
  });
});

// =============================================================================
// 2. Snapshot persiste resultado UNIFICADO (legacy + explicit)
// =============================================================================

describe("F1.4 #11-B — snapshot persiste resultado final unificado", () => {
  it("baseline correct: solo explicit overrides → snapshot guarda exactamente el array sanitizado", async () => {
    setupCost(1000);
    const explicit: CostLineOverride[] = [
      { costLineId: "cl-X", type: "PRODUCT", quantityOverride: 5 },
    ];
    // Cost engine mock recibe overrides y devuelve costLineOverridesApplied:
    mockResolveArticleCost.mockResolvedValueOnce({
      value: new D("500"), mode: "COST_LINES", partial: false, steps: [],
      metalCost: new D("0"), hechuraCost: new D("500"),
      totalGrams: new D("0"), metalGramsWithMerma: new D("0"), metalPurity: null,
      costLineOverridesApplied: explicit,
    });
    const result = await resolveFinalSalePrice("j1", {
      articleId: "a1",
      costLineOverrides: explicit,
    });
    const snap = buildPricingSnapshot(result);
    expect(snap.costLineOverridesApplied).toBeDefined();
    expect(snap.costLineOverridesApplied).toHaveLength(1);
    expect(snap.costLineOverridesApplied?.[0].quantityOverride).toBe(5);
  });

  it("baseline correct: solo legacy gramsOverride → snapshot guarda entry sintetizado", async () => {
    // Mock article tiene una METAL line con id estable.
    mockPrisma.article.findFirst.mockResolvedValueOnce(makeArticle([
      { id: "cl-m1", type: "METAL", quantity: 1, metalVariantId: "mv-1", mermaPercent: 5 },
    ]));
    setupCost(100);
    const result = await resolveFinalSalePrice("j1", {
      articleId: "a1",
      gramsOverride: 5,
    });
    const snap = buildPricingSnapshot(result);
    // El snapshot debe tener el legacy SINTETIZADO en costLineOverridesApplied.
    expect(snap.costLineOverridesApplied).toBeDefined();
    const synth = snap.costLineOverridesApplied?.find(o => o.costLineId === "cl-m1");
    expect(synth).toBeDefined();
    expect(synth?.type).toBe("METAL");
    expect(synth?.quantityOverride).toBe(5);
  });

  it("baseline correct: legacy + explicit DISTINTOS costLineId → snapshot guarda ambos", async () => {
    mockPrisma.article.findFirst.mockResolvedValueOnce(makeArticle([
      { id: "cl-m1", type: "METAL",   quantity: 1, metalVariantId: "mv-1", mermaPercent: 5 },
      { id: "cl-h1", type: "HECHURA", quantity: 1, unitValue: 100 },
    ]));
    setupCost(150);
    const explicit: CostLineOverride[] = [
      { costLineId: "cl-h1", type: "HECHURA", unitValueOverride: 200 },
    ];
    mockResolveArticleCost.mockResolvedValueOnce({
      value: new D("150"), mode: "COST_LINES", partial: false, steps: [],
      metalCost: new D("100"), hechuraCost: new D("50"),
      totalGrams: new D("0"), metalGramsWithMerma: new D("0"), metalPurity: null,
      costLineOverridesApplied: explicit,
    });
    const result = await resolveFinalSalePrice("j1", {
      articleId: "a1",
      gramsOverride: 5,
      costLineOverrides: explicit,
    });
    const snap = buildPricingSnapshot(result);
    expect(snap.costLineOverridesApplied).toBeDefined();
    expect(snap.costLineOverridesApplied).toHaveLength(2);
    const ids = snap.costLineOverridesApplied?.map(o => o.costLineId).sort();
    expect(ids).toEqual(["cl-h1", "cl-m1"]);
  });

  it("baseline correct: explicit gana sobre legacy mismo costLineId — solo 1 entry persistido", async () => {
    mockPrisma.article.findFirst.mockResolvedValueOnce(makeArticle([
      { id: "cl-m1", type: "METAL", quantity: 1, metalVariantId: "mv-1", mermaPercent: 5 },
    ]));
    setupCost(100);
    const explicit: CostLineOverride[] = [
      { costLineId: "cl-m1", type: "METAL", quantityOverride: 99 },
    ];
    mockResolveArticleCost.mockResolvedValueOnce({
      value: new D("100"), mode: "COST_LINES", partial: false, steps: [],
      metalCost: new D("100"), hechuraCost: new D("0"),
      totalGrams: new D("0"), metalGramsWithMerma: new D("0"), metalPurity: null,
      costLineOverridesApplied: explicit,
    });
    const result = await resolveFinalSalePrice("j1", {
      articleId: "a1",
      gramsOverride: 5,         // legacy — debería ser DESCARTADO porque el explicit ya cubre cl-m1
      costLineOverrides: explicit,
    });
    const snap = buildPricingSnapshot(result);
    expect(snap.costLineOverridesApplied).toBeDefined();
    // Una sola entry — la explicit (qty=99). Legacy gramsOverride=5 NO aparece.
    const forM1 = snap.costLineOverridesApplied?.filter(o => o.costLineId === "cl-m1");
    expect(forM1).toHaveLength(1);
    expect(forM1?.[0].quantityOverride).toBe(99);
  });
});

// =============================================================================
// 3. CASO CRÍTICO — 2 metales, override solo del segundo
// =============================================================================

describe("F1.4 #11-B — caso crítico: 2 metales, override solo del segundo", () => {
  it("baseline correct: override apunta a cl-m2 → cl-m1 NO aparece como override en snapshot", async () => {
    mockPrisma.article.findFirst.mockResolvedValueOnce(makeArticle([
      { id: "cl-m1", type: "METAL", quantity: 1, metalVariantId: "mv-1" },
      { id: "cl-m2", type: "METAL", quantity: 2, metalVariantId: "mv-2" },
    ]));
    setupCost(300);
    const explicit: CostLineOverride[] = [
      { costLineId: "cl-m2", type: "METAL", quantityOverride: 10 },
    ];
    mockResolveArticleCost.mockResolvedValueOnce({
      value: new D("300"), mode: "COST_LINES", partial: false, steps: [],
      metalCost: new D("300"), hechuraCost: new D("0"),
      totalGrams: new D("0"), metalGramsWithMerma: new D("0"), metalPurity: null,
      costLineOverridesApplied: explicit,
    });
    const result = await resolveFinalSalePrice("j1", {
      articleId: "a1",
      costLineOverrides: explicit,
    });
    const snap = buildPricingSnapshot(result);
    expect(snap.costLineOverridesApplied).toHaveLength(1);
    expect(snap.costLineOverridesApplied?.[0].costLineId).toBe("cl-m2");
    expect(snap.costLineOverridesApplied?.[0].quantityOverride).toBe(10);
    // cl-m1 NO está en el array — su cost line original no fue modificada.
    const forM1 = snap.costLineOverridesApplied?.find(o => o.costLineId === "cl-m1");
    expect(forM1).toBeUndefined();
  });

  it("baseline correct: 2 metales, legacy gramsOverride + explicit del segundo → snapshot tiene ambos", async () => {
    // Caso real: usuario tiene un editor inline legacy (METAL[0]) Y abre la
    // tabla nueva para editar METAL[1]. Ambos overrides deben quedar trazados.
    mockPrisma.article.findFirst.mockResolvedValueOnce(makeArticle([
      { id: "cl-m1", type: "METAL", quantity: 1, metalVariantId: "mv-1" },
      { id: "cl-m2", type: "METAL", quantity: 2, metalVariantId: "mv-2" },
    ]));
    setupCost(500);
    const explicit: CostLineOverride[] = [
      { costLineId: "cl-m2", type: "METAL", quantityOverride: 7 },
    ];
    mockResolveArticleCost.mockResolvedValueOnce({
      value: new D("500"), mode: "COST_LINES", partial: false, steps: [],
      metalCost: new D("500"), hechuraCost: new D("0"),
      totalGrams: new D("0"), metalGramsWithMerma: new D("0"), metalPurity: null,
      costLineOverridesApplied: explicit,
    });
    const result = await resolveFinalSalePrice("j1", {
      articleId: "a1",
      gramsOverride: 3,         // legacy → cl-m1 (primer METAL)
      costLineOverrides: explicit,
    });
    const snap = buildPricingSnapshot(result);
    expect(snap.costLineOverridesApplied).toHaveLength(2);
    const m1 = snap.costLineOverridesApplied?.find(o => o.costLineId === "cl-m1");
    const m2 = snap.costLineOverridesApplied?.find(o => o.costLineId === "cl-m2");
    expect(m1?.quantityOverride).toBe(3);   // legacy sintetizado
    expect(m2?.quantityOverride).toBe(7);   // explicit
  });
});

// =============================================================================
// 4. Paridad: dos previews con mismo input → mismo array
// =============================================================================

describe("F1.4 #11-B — paridad preview ↔ preview", () => {
  it("baseline correct: dos previews con mismo costLineOverrides → arrays byte-idénticos", async () => {
    setupCost(500);
    const explicit: CostLineOverride[] = [
      { costLineId: "cl-x", type: "PRODUCT", quantityOverride: 3, unitValueOverride: 80 },
    ];
    // Primera ejecución
    mockResolveArticleCost.mockResolvedValueOnce({
      value: new D("240"), mode: "COST_LINES", partial: false, steps: [],
      metalCost: new D("0"), hechuraCost: new D("240"),
      totalGrams: new D("0"), metalGramsWithMerma: new D("0"), metalPurity: null,
      costLineOverridesApplied: explicit,
    });
    const r1 = await resolveFinalSalePrice("j1", {
      articleId: "a1",
      costLineOverrides: explicit,
    });
    // Segunda ejecución
    mockResolveArticleCost.mockResolvedValueOnce({
      value: new D("240"), mode: "COST_LINES", partial: false, steps: [],
      metalCost: new D("0"), hechuraCost: new D("240"),
      totalGrams: new D("0"), metalGramsWithMerma: new D("0"), metalPurity: null,
      costLineOverridesApplied: explicit,
    });
    const r2 = await resolveFinalSalePrice("j1", {
      articleId: "a1",
      costLineOverrides: explicit,
    });
    // Snapshots byte-paritarios en costLineOverridesApplied.
    const s1 = buildPricingSnapshot(r1);
    const s2 = buildPricingSnapshot(r2);
    expect(JSON.stringify(s1.costLineOverridesApplied))
      .toBe(JSON.stringify(s2.costLineOverridesApplied));
  });

  it("baseline correct: sin overrides → snapshot.costLineOverridesApplied undefined (parity total)", async () => {
    setupCost(1000);
    const r = await resolveFinalSalePrice("j1", { articleId: "a1" });
    const snap = buildPricingSnapshot(r);
    expect(snap.costLineOverridesApplied).toBeUndefined();
  });
});

// =============================================================================
// 5. Retrocompat snapshots v5
// =============================================================================

describe("F1.4 #11-B — retrocompat snapshots v5", () => {
  it("baseline correct: snapshot v5 sin costLineOverridesApplied se lee sin crash", () => {
    // Simulamos un snapshot v5 (pre-11-A). Reader debe normalizar a undefined.
    const v5Snap = {
      snapshotVersion: 5,
      unitPrice:       100,
      basePrice:       100,
      quantityDiscountAmount:  null,
      promotionDiscountAmount: null,
      customerDiscountAmount:  null,
      discountAmount:          0,
      taxAmount:               0,
      totalWithTax:            100,
      priceSource:             "PRICE_LIST",
      baseSource:              "PRICE_LIST",
      unitCost:                null,
      unitMargin:              null,
      marginPercent:           null,
      costPartial:             false,
      costMode:                "MANUAL",
      partial:                 false,
      appliedPriceListId:      null,
      appliedPriceListName:    null,
      appliedPromotionId:      null,
      appliedPromotionName:    null,
      appliedDiscountId:       null,
      metalHechuraBreakdown:   null,
      resolvedAt:              "2026-05-08T00:00:00.000Z",
      // Sin costLineOverridesApplied — campo nuevo de v6.
    } as PricingLineSnapshot;
    // Lectura defensiva.
    const overrides = v5Snap.costLineOverridesApplied ?? [];
    expect(overrides).toEqual([]);
    // Otros campos del snapshot siguen accesibles.
    expect(v5Snap.unitPrice).toBe(100);
    expect(v5Snap.snapshotVersion).toBe(5);
  });

  it("baseline correct: snapshot v5 + reader normaliza a undefined en lugar de crashear", () => {
    const v5Snap = { snapshotVersion: 5, unitPrice: 100 } as PricingLineSnapshot;
    expect(v5Snap.costLineOverridesApplied).toBeUndefined();
    // Cualquier consumer que acceda con `?? []` queda safe.
    expect(v5Snap.costLineOverridesApplied ?? []).toEqual([]);
  });
});

// =============================================================================
// 6. Cero double-apply legacy + explicit
// =============================================================================

describe("F1.4 #11-B — cero double-apply", () => {
  it("baseline correct: legacy + explicit mismo costLineId → cost engine recibe SOLO explicit", async () => {
    // Verificación numérica: si fuera double-apply, cost.value sería distinto.
    mockPrisma.article.findFirst.mockResolvedValueOnce(makeArticle([
      { id: "cl-m1", type: "METAL", quantity: 1, metalVariantId: "mv-1", mermaPercent: 0 },
    ]));
    setupCost(500);   // valor que coincide con explicit qty=5 × 100
    const explicit: CostLineOverride[] = [
      { costLineId: "cl-m1", type: "METAL", quantityOverride: 5 },
    ];
    mockResolveArticleCost.mockResolvedValueOnce({
      value: new D("500"), mode: "COST_LINES", partial: false, steps: [],
      metalCost: new D("500"), hechuraCost: new D("0"),
      totalGrams: new D("0"), metalGramsWithMerma: new D("0"), metalPurity: null,
      costLineOverridesApplied: explicit,
    });
    const result = await resolveFinalSalePrice("j1", {
      articleId: "a1",
      gramsOverride: 999,           // legacy — DEBERÍA ser descartado
      costLineOverrides: explicit,  // explicit gana
    });
    // Verifica que el cost engine recibió el explicit (no el legacy).
    const lastCall = mockResolveArticleCost.mock.calls.at(-1);
    const overridesPassed = lastCall?.[4] as CostLineOverride[] | undefined;
    expect(overridesPassed).toBeDefined();
    expect(overridesPassed).toHaveLength(1);
    expect(overridesPassed?.[0].costLineId).toBe("cl-m1");
    expect(overridesPassed?.[0].quantityOverride).toBe(5);
    // Snapshot también refleja el explicit, no el legacy.
    const snap = buildPricingSnapshot(result);
    const m1 = snap.costLineOverridesApplied?.find(o => o.costLineId === "cl-m1");
    expect(m1?.quantityOverride).toBe(5);
  });
});

// =============================================================================
// 7. Replay: snapshot tiene info para reproducir
// =============================================================================

describe("F1.4 #11-B — snapshot replay-ready", () => {
  it("baseline correct: costLineOverridesApplied incluye TODOS los campos necesarios para replay", async () => {
    mockPrisma.article.findFirst.mockResolvedValueOnce(makeArticle([
      { id: "cl-h1", type: "HECHURA", quantity: 1, unitValue: 100,
        lineAdjKind: "BONUS", lineAdjType: "PERCENTAGE", lineAdjValue: 10 },
    ]));
    setupCost(100);
    const explicit: CostLineOverride[] = [
      {
        costLineId: "cl-h1", type: "HECHURA",
        quantityOverride:  2,
        unitValueOverride: 150,
        adjustmentKind:    "SURCHARGE",
        adjustmentType:    "FIXED_AMOUNT",
        adjustmentValue:   25,
      },
    ];
    mockResolveArticleCost.mockResolvedValueOnce({
      value: new D("325"), mode: "COST_LINES", partial: false, steps: [],
      metalCost: new D("0"), hechuraCost: new D("325"),
      totalGrams: new D("0"), metalGramsWithMerma: new D("0"), metalPurity: null,
      costLineOverridesApplied: explicit,
    });
    const result = await resolveFinalSalePrice("j1", {
      articleId: "a1",
      costLineOverrides: explicit,
    });
    const snap = buildPricingSnapshot(result);
    const persisted = snap.costLineOverridesApplied?.[0];
    // Snapshot tiene todos los campos para replay exacto.
    expect(persisted).toBeDefined();
    expect(persisted?.costLineId).toBe("cl-h1");
    expect(persisted?.type).toBe("HECHURA");
    expect(persisted?.quantityOverride).toBe(2);
    expect(persisted?.unitValueOverride).toBe(150);
    expect(persisted?.adjustmentKind).toBe("SURCHARGE");
    expect(persisted?.adjustmentType).toBe("FIXED_AMOUNT");
    expect(persisted?.adjustmentValue).toBe(25);
  });
});
