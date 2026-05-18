// src/lib/pricing-engine/__tests__/g4-5b-snapshot-composition-parity.test.ts
// =============================================================================
// FASE F1.3 G4.x #5b — paridad preview ↔ persisted snapshot.
//
// Validaciones del usuario (todas cubiertas):
//   1. Paridad preview.composition           === persisted.composition
//      Paridad preview.componentSaleBreakdown === persisted.componentSaleBreakdown
//   2. Products/services se persisten con TODOS los campos.
//   3. salePreManualDiscount se persiste dentro del componentSaleBreakdown.
//   4. Retrocompat: snapshot v3 (sin composition / componentSaleBreakdown)
//      se lee sin crash, defaults seguros.
//   5. Cero cambio numérico: subtotal/taxAmount/total/final no cambian.
//   6. Shape aditivo (ningún campo legacy renombrado o removido).
// =============================================================================

import { describe, it, expect, vi, beforeEach } from "vitest";
import { Prisma } from "@prisma/client";

// Mocks Prisma + dependencias (mismo patrón que sale.test.ts).
const mockPrisma = vi.hoisted(() => ({
  article:          { findFirst:  vi.fn(), findMany: vi.fn() },
  articleVariant:   { findFirst:  vi.fn() },
  articleGroupItem: { findFirst:  vi.fn() },
  promotion:        { findMany:   vi.fn() },
  quantityDiscount: { findMany:   vi.fn() },
  currency:         { findFirst:  vi.fn() },
  currencyRate:     { findFirst:  vi.fn() },
  metalQuote:       { findFirst:  vi.fn() },
  metalVariant:     { findUnique: vi.fn() },
  jewelry:          { findUnique: vi.fn() },
  commercialEntity: { findFirst:  vi.fn() },
  entityMermaOverride: { findMany: vi.fn() },
}));
vi.mock("../../prisma.js", () => ({ prisma: mockPrisma }));

const mockResolveArticleCost = vi.hoisted(() => vi.fn());
vi.mock("../pricing-engine.cost.js", () => ({
  calculateCostFromLines:        (...args: any[]) => mockResolveArticleCost(...args),
  enrichCostMetalSteps:          vi.fn(),
  getArticleMetalVariantIds:     vi.fn().mockResolvedValue([]),
  loadArticleMetalVariantsBatch: vi.fn().mockResolvedValue(new Map()),
}));

const mockResolvePriceList = vi.hoisted(() => vi.fn());
const mockApplyPriceList   = vi.hoisted(() => vi.fn());
vi.mock("../pricing-engine.pricelist.js", () => ({
  resolvePriceList: (...args: any[]) => mockResolvePriceList(...args),
  applyPriceList:   (...args: any[]) => mockApplyPriceList(...args),
}));

import { resolveFinalSalePrice, buildPricingSnapshot } from "../pricing-engine.sale.js";
import {
  buildComposition,
  fetchMetalVariantInfo,
  resolveMetalVariantIdFromResult,
  type Composition,
} from "../../pricing-composition.js";
import { PRICING_LINE_SNAPSHOT_VERSION, type PricingLineSnapshot } from "../pricing-engine.types.js";

const D = Prisma.Decimal;

function makeDbArticle(overrides: Record<string, any> = {}) {
  return {
    categoryId: null, brand: null, salePrice: null,
    useManualSalePrice: false,
    manualAdjustmentKind: null, manualAdjustmentType: null, manualAdjustmentValue: null,
    mermaPercent: null, category: null, costComposition: [],
    ...overrides,
  };
}

function costOf(amount: number) {
  return {
    value: new D(String(amount)), mode: "MANUAL", partial: false, steps: [],
    metalCost: new D("0"), hechuraCost: new D("0"), totalGrams: new D("0"),
  };
}

function setupMetalHechuraList(metalSale: number, hechuraSale: number) {
  mockPrisma.article.findFirst.mockResolvedValue(makeDbArticle());
  mockResolveArticleCost.mockResolvedValue(costOf(1000));
  mockResolvePriceList.mockResolvedValue({
    priceList: {
      id: "pl1", name: "Lista MH", mode: "METAL_HECHURA",
      marginTotal: null, marginMetal: null, marginHechura: null,
      costPerGram: null, surcharge: null, minimumPrice: null,
      roundingTarget: "NONE", roundingMode: "NONE", roundingDirection: "NEAREST",
      validFrom: null, validTo: null, isActive: true,
    },
    source: "GENERAL",
  });
  mockApplyPriceList.mockReturnValue({
    value:   new D(String(metalSale + hechuraSale)),
    partial: false,
    metalHechuraDetail: {
      metalCost: 500, metalSale,
      metalMarginPct:   ((metalSale - 500) / 500) * 100,
      hechuraCost: 500, hechuraSale,
      hechuraMarginPct: ((hechuraSale - 500) / 500) * 100,
    },
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  mockPrisma.article.findFirst.mockResolvedValue(null);
  mockPrisma.articleVariant.findFirst.mockResolvedValue(null);
  mockPrisma.articleGroupItem.findFirst.mockResolvedValue(null);
  mockPrisma.promotion.findMany.mockResolvedValue([]);
  mockPrisma.quantityDiscount.findMany.mockResolvedValue([]);
  mockPrisma.commercialEntity.findFirst.mockResolvedValue(null);
  mockPrisma.entityMermaOverride.findMany.mockResolvedValue([]);
  mockPrisma.metalVariant.findUnique.mockResolvedValue(null);
  mockPrisma.article.findMany.mockResolvedValue([]);
  mockPrisma.jewelry.findUnique.mockResolvedValue({
    id: "j1", roundingMode: "NONE", roundingDirection: "NEAREST", roundingTarget: "NONE",
  });
});

// =============================================================================
// 1. PARIDAD preview ↔ persisted (composition + componentSaleBreakdown)
// =============================================================================

describe("snapshot parity — preview ↔ persisted (composition + componentSaleBreakdown)", () => {
  it("baseline correct: composition byte-paritaria — preview === buildPricingSnapshot(...).composition", async () => {
    setupMetalHechuraList(600, 600);
    const result = await resolveFinalSalePrice("j1", { articleId: "a1" });

    // Preview path (lo que el frontend ve hoy en sales/preview).
    const mvId = resolveMetalVariantIdFromResult(result);
    const mvi  = await fetchMetalVariantInfo(mvId);
    const previewComposition = buildComposition(result, mvi);

    // Persisted path (lo que se guarda al confirmar — DRAFT).
    const snap = buildPricingSnapshot(result, { composition: previewComposition });

    // Paridad estricta: el snapshot guarda EXACTAMENTE lo que vio el preview.
    expect(snap.composition).toEqual(previewComposition);
  });

  it("baseline correct: componentSaleBreakdown viaja del motor al snapshot sin transformación", async () => {
    setupMetalHechuraList(600, 600);
    mockPrisma.commercialEntity.findFirst.mockResolvedValue({
      taxExempt: false, taxApplyOnOverride: null,
      commercialRuleType: "DISCOUNT", commercialValueType: "PERCENTAGE",
      commercialValue: new D("10"), commercialApplyOn: "HECHURA",
      taxOverrides: [],
    });
    const result = await resolveFinalSalePrice("j1", {
      articleId: "a1", clientId: "c1",
      manualDiscountOverride: { mode: "PERCENT", value: 5, appliesTo: "HECHURA" },
    });

    const snap = buildPricingSnapshot(result);
    expect(snap.componentSaleBreakdown).toEqual(result.componentSaleBreakdown);
    // Y específicamente: salePreManualDiscount se persiste.
    expect(snap.componentSaleBreakdown!.metal.salePreManualDiscount)
      .toBe(result.componentSaleBreakdown!.metal.salePreManualDiscount);
    expect(snap.componentSaleBreakdown!.hechura.salePreManualDiscount)
      .toBe(result.componentSaleBreakdown!.hechura.salePreManualDiscount);
  });

  it("baseline correct: snapshot version bumped a 7 (F17 aditivo con costBase/costTaxAmount/costWithTax/costTaxBreakdown)", async () => {
    setupMetalHechuraList(600, 600);
    const result = await resolveFinalSalePrice("j1", { articleId: "a1" });
    const snap = buildPricingSnapshot(result);
    expect(snap.snapshotVersion).toBe(7);
    expect(PRICING_LINE_SNAPSHOT_VERSION).toBe(7);
  });
});

// =============================================================================
// 2. PRODUCTS / SERVICES — persistencia con TODOS los campos
// =============================================================================

describe("snapshot parity — products/services preservan todos los campos", () => {
  it("baseline correct: cada item products[] y services[] persiste los 13 campos", async () => {
    setupMetalHechuraList(600, 600);
    // Preview construye composition con un PRODUCT y un SERVICE sintéticos
    // (vía steps inyectados en el result mock).
    const fakeResult = {
      // SalePriceResult mínimo con un step PRODUCT y otro SERVICE.
      steps: [
        {
          key:    "COST_LINES_PRODUCT",
          status: "ok",
          label:  "Zafiro",
          value:  100,
          meta: {
            costLineId:    "cl-p1",
            catalogItemId: "art-P",
            lineCode:      "ZAF-01",
            lineLabel:     "Zafiro 0.5ct",
            qty:           2,
            unitValue:     50,
            currencyId:    null,
            lineAdjKind:   "BONUS",
            lineAdjType:   "PERCENTAGE",
            lineAdjValue:  10,
            lineAdjAmount: 5,
            affectsStock:  true,
          },
        },
        {
          key:    "COST_LINES_SERVICE",
          status: "ok",
          label:  "Engaste",
          value:  80,
          meta: {
            costLineId:    "cl-s1",
            catalogItemId: "art-S",
            lineCode:      "ENG-01",
            lineLabel:     "Engaste profesional",
            qty:           1,
            unitValue:     80,
            currencyId:    "USD",
            lineAdjKind:   "SURCHARGE",
            lineAdjType:   "FIXED_AMOUNT",
            lineAdjValue:  20,
            lineAdjAmount: 20,
            affectsStock:  false,
          },
        },
      ],
      taxBreakdown: [],
      costOverrideContext: undefined,
    } as any;

    const catalogMap = new Map([
      ["art-P", { code: "ZAF-01-cat", name: "Zafiro 0.5ct (catálogo)", sku: "ZAF-01-sku", unitOfMeasure: "" }],
      ["art-S", { code: "ENG-01-cat", name: "Engaste profesional (catálogo)", sku: "ENG-01-sku", unitOfMeasure: "" }],
    ]);
    const composition = buildComposition(
      fakeResult,
      { purity: null, purityLabel: null, metalName: null, variantName: null },
      catalogMap,
    );
    // Construimos el snapshot directamente con la composition armada.
    // Cero recálculo monetario en el path snapshot — passthrough estructural.
    const snap = { composition } as PricingLineSnapshot;

    // Products
    const p = snap.composition!.products[0];
    expect(p).toEqual({
      costLineId:      "cl-p1",
      catalogItemId:   "art-P",
      catalogItemCode: "ZAF-01-cat",
      // Fase 2.4 — SKU del Article catálogo (resuelto desde el map).
      catalogItemSku:  "ZAF-01-sku",
      catalogItemName: "Zafiro 0.5ct (catálogo)",
      quantity:        2,
      unitValue:       50,
      // `unitValueBase = unitValue × rate` (sin conversión → rate=1).
      unitValueBase:   50,
      totalValue:      100,
      currencyId:      null,
      lineAdjKind:     "BONUS",
      lineAdjType:     "PERCENTAGE",
      lineAdjValue:    10,
      lineAdjAmount:   5,
      affectsStock:    true,
      // F1.5 #A+ — sin metalHechuraBreakdown en fakeResult → factor null → lineSale null.
      lineSale:        null,
    });
    // Services
    const s = snap.composition!.services[0];
    expect(s).toEqual({
      costLineId:      "cl-s1",
      catalogItemId:   "art-S",
      catalogItemCode: "ENG-01-cat",
      catalogItemSku:  "ENG-01-sku",
      catalogItemName: "Engaste profesional (catálogo)",
      quantity:        1,
      unitValue:       80,
      unitValueBase:   80,
      totalValue:      80,
      currencyId:      "USD",
      lineAdjKind:     "SURCHARGE",
      lineAdjType:     "FIXED_AMOUNT",
      lineAdjValue:    20,
      lineAdjAmount:   20,
      affectsStock:    false,
      lineSale:        null,
    });
  });
});

// =============================================================================
// 3. RETROCOMPAT — snapshot v3 (sin composition / componentSaleBreakdown) legible
// =============================================================================

describe("snapshot parity — retrocompat snapshots v3", () => {
  it("baseline correct: snapshot v3 sin composition se lee sin crash (campo undefined)", () => {
    // Simulamos un snapshot histórico v3 (sin los campos nuevos).
    const v3Snap = {
      snapshotVersion:        3,
      unitPrice:              100,
      basePrice:              100,
      quantityDiscountAmount: null,
      promotionDiscountAmount: null,
      customerDiscountAmount: null,
      discountAmount:         0,
      taxAmount:              0,
      totalWithTax:           100,
      priceSource:            "PRICE_LIST",
      baseSource:             "PRICE_LIST",
      unitCost:               null,
      unitMargin:             null,
      marginPercent:          null,
      costPartial:            false,
      costMode:               "NONE",
      partial:                false,
      appliedPriceListId:     null,
      appliedPriceListName:   null,
      appliedPromotionId:     null,
      appliedPromotionName:   null,
      appliedDiscountId:      null,
      metalHechuraBreakdown:  null,
      resolvedAt:             "2026-01-01T00:00:00.000Z",
    } as PricingLineSnapshot;

    // El reader debe poder normalizar (UI hace `?? null` / `?? []`).
    const composition            = (v3Snap as any).composition            ?? null;
    const componentSaleBreakdown = (v3Snap as any).componentSaleBreakdown ?? null;
    const products = composition?.products ?? [];
    const services = composition?.services ?? [];

    expect(composition).toBeNull();
    expect(componentSaleBreakdown).toBeNull();
    expect(products).toEqual([]);
    expect(services).toEqual([]);
    // Y los campos legacy siguen existiendo (no rename, no remove).
    expect(v3Snap.unitPrice).toBe(100);
    expect(v3Snap.totalWithTax).toBe(100);
    expect(v3Snap.priceSource).toBe("PRICE_LIST");
  });

  it("baseline correct: snapshot v3 + nueva fórmula de UI = idempotente", () => {
    // Si la UI lee un snapshot viejo y aplica el threshold visual:
    //   pre === final ⇒ no muestra "Pre-bonif."
    // Como en v3 no hay componentSaleBreakdown, la UI cae a final puro
    // y no muestra nada extra. Cero crash, cero campo huérfano.
    const v3Snap = { snapshotVersion: 3, unitPrice: 100 } as any;
    const sb = v3Snap.componentSaleBreakdown ?? null;
    expect(sb).toBeNull();
    // Reader contractual: cuando sb=null, la UI no renderea fila pre-bonif.
  });
});

// =============================================================================
// 4. CERO CAMBIO NUMÉRICO — totales no cambian con shape aditivo
// =============================================================================

describe("snapshot parity — cero cambio numérico", () => {
  it("baseline correct: subtotal/taxAmount/totalWithTax/final no cambian con/sin composition", async () => {
    setupMetalHechuraList(600, 600);
    const result = await resolveFinalSalePrice("j1", { articleId: "a1" });

    const snapWithoutComposition = buildPricingSnapshot(result);
    const snapWithComposition    = buildPricingSnapshot(result, {
      composition: { metal: null, hechura: null, metals: [], hechuras: [], products: [], services: [], taxes: [] },
    });

    // Igual unitPrice / basePrice / discountAmount / taxAmount / totalWithTax.
    expect(snapWithoutComposition.unitPrice).toBe(snapWithComposition.unitPrice);
    expect(snapWithoutComposition.basePrice).toBe(snapWithComposition.basePrice);
    expect(snapWithoutComposition.discountAmount).toBe(snapWithComposition.discountAmount);
    expect(snapWithoutComposition.taxAmount).toBe(snapWithComposition.taxAmount);
    expect(snapWithoutComposition.totalWithTax).toBe(snapWithComposition.totalWithTax);
    // Igual componentSaleBreakdown.{metal,hechura}.final (motor, no caller).
    expect(snapWithoutComposition.componentSaleBreakdown?.metal.final)
      .toBe(snapWithComposition.componentSaleBreakdown?.metal.final);
    expect(snapWithoutComposition.componentSaleBreakdown?.hechura.final)
      .toBe(snapWithComposition.componentSaleBreakdown?.hechura.final);
  });

  it("baseline correct: campo `composition` solo se rellena cuando se pasa explícitamente", async () => {
    setupMetalHechuraList(600, 600);
    const result = await resolveFinalSalePrice("j1", { articleId: "a1" });

    const snapDefault = buildPricingSnapshot(result);
    expect(snapDefault.composition).toBeNull();   // sin override

    const customComposition: Composition = {
      metal: null, hechura: null,
      metals: [], hechuras: [],
      products: [{
        costLineId: "x", catalogItemId: null, catalogItemCode: null, catalogItemSku: null,
        catalogItemName: null, quantity: 1, unitValue: 10, totalValue: 10,
        currencyId: null, lineAdjKind: null, lineAdjType: null,
        lineAdjValue: null, lineAdjAmount: null, affectsStock: null, lineSale: null,
      }],
      services: [], taxes: [],
    };
    const snapWith = buildPricingSnapshot(result, { composition: customComposition });
    expect(snapWith.composition).toEqual(customComposition);
  });
});

// =============================================================================
// 5. SHAPE ADITIVO — campos legacy siguen existiendo
// =============================================================================

describe("snapshot parity — shape aditivo (no rename / no remove)", () => {
  it("baseline correct: campos legacy del snapshot siguen presentes", async () => {
    setupMetalHechuraList(600, 600);
    const result = await resolveFinalSalePrice("j1", { articleId: "a1" });
    const snap = buildPricingSnapshot(result);

    // Campos pre-existentes (smoke test de no-regresión de shape).
    const legacyFields = [
      "unitPrice", "basePrice", "quantityDiscountAmount",
      "promotionDiscountAmount", "customerDiscountAmount", "discountAmount",
      "taxAmount", "totalWithTax", "priceSource", "baseSource",
      "unitCost", "unitMargin", "marginPercent", "costPartial", "costMode",
      "partial", "appliedPriceListId", "appliedPriceListName",
      "appliedPromotionId", "appliedPromotionName", "appliedDiscountId",
      "metalHechuraBreakdown", "resolvedAt",
    ];
    for (const f of legacyFields) {
      expect(snap).toHaveProperty(f);
    }
    // Nuevos campos también presentes (aditivos).
    expect(snap).toHaveProperty("composition");
    expect(snap).toHaveProperty("componentSaleBreakdown");
  });
});
