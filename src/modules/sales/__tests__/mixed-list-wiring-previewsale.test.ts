// src/modules/sales/__tests__/mixed-list-wiring-previewsale.test.ts
// =============================================================================
// INTEGRACIÓN (Capa B) — Wiring MIXTO dirigido por `previewSale` REAL.
//
// A diferencia de la Capa A (contrato motor), este test ejercita la rama
// MIXED_LIST_FALLBACK del SERVICIO real, con `computeSaleDocumentTotals` REAL
// (no mockeado). Mockea solo las fronteras (Prisma, pricing per-línea, tax).
//
// Documento mixto: Línea 0 Unificada + Línea 1 Desglosada (listas distintas).
//   · `mockResolveFinalSalePrice` modela `applyPriceList`: devuelve la hechura
//     redondeada PRE-TAX salvo que el caller pase `suppressLineHechuraRounding`
//     (entonces hechura cruda). Esto permite que el test distinga el camino
//     contaminado (actual) del limpio (α / FASE 2).
//   · `mockComputeLineTaxes` modela IVA 30% sobre el `unitPrice`.
//
// EXPECTATIVA:
//   · CON el código ACTUAL → `Sale.total = 3380` (línea 1 contaminada, sin
//     consolidar) → este test FALLA (RED).
//   · CON FASE 2-4 (α)     → `Sale.total = 3300` → este test PASA (GREEN).
//
// =============================================================================

import { describe, it, expect, vi, beforeEach } from "vitest";
import { Prisma } from "@prisma/client";

const D = Prisma.Decimal;

// ── Mocks de frontera ────────────────────────────────────────────────────────
const mockPrisma = vi.hoisted(() => ({
  article:            { findMany: vi.fn(), findFirst: vi.fn() },
  articleVariant:     { findMany: vi.fn(), findFirst: vi.fn() },
  articleGroupItem:   { findMany: vi.fn() },
  metal:              { findMany: vi.fn() },
  sale:               { findFirst: vi.fn(), findMany: vi.fn(), create: vi.fn(), update: vi.fn(), count: vi.fn() },
  saleLine:           { update: vi.fn() },
  salesChannel:       { findFirst: vi.fn() },
  coupon:             { findFirst: vi.fn() },
  priceList:          { findMany: vi.fn(), findFirst: vi.fn() },
  promotion:          { findMany: vi.fn() },
  currency:           { findUnique: vi.fn() },
  jewelry:            { findUnique: vi.fn() },
  commercialEntity:   { findFirst: vi.fn() },
  $transaction:       vi.fn(),
}));
vi.mock("../../../lib/prisma.js", () => ({ prisma: mockPrisma }));

const mockResolveFinalSalePrice  = vi.hoisted(() => vi.fn());
const mockBuildPricingSnapshot   = vi.hoisted(() => vi.fn());
const mockCalculateCostFromLines = vi.hoisted(() => vi.fn());
const mockBuildBatchCostContext  = vi.hoisted(() => vi.fn());
const mockComputeLineTaxes       = vi.hoisted(() => vi.fn());
const mockEvaluatePricingPolicy  = vi.hoisted(() => vi.fn());

// Mantenemos REAL: computeSaleDocumentTotals + la familia de redondeo comercial
// (consolidación). Solo mockeamos las fronteras caras/no-deterministas.
vi.mock("../../../lib/pricing-engine/pricing-engine.js", async (importOriginal) => {
  const actual = await importOriginal<Record<string, any>>();
  return {
    ...actual,
    resolveFinalSalePrice:  (...a: any[]) => mockResolveFinalSalePrice(...a),
    buildPricingSnapshot:   (...a: any[]) => mockBuildPricingSnapshot(...a),
    calculateCostFromLines: (...a: any[]) => mockCalculateCostFromLines(...a),
    buildBatchCostContext:  (...a: any[]) => mockBuildBatchCostContext(...a),
    computeLineTaxes:       (...a: any[]) => mockComputeLineTaxes(...a),
    evaluatePricingPolicy:  (...a: any[]) => mockEvaluatePricingPolicy(...a),
    computePurchaseTaxes:   vi.fn().mockResolvedValue({ costBase: null, costTaxAmount: null, costWithTax: null, costTaxBreakdown: [] }),
    deriveMetalHechuraBreakdown: () => null,
    sumFixedTaxComponent:   () => 0,
  };
});

vi.mock("../../../lib/pricing-composition.js", () => ({
  buildComposition:                () => ({ metal: null, hechura: null, metals: [], hechuras: [], products: [], services: [], taxes: [] }),
  fetchMetalVariantInfo:           vi.fn().mockResolvedValue({ purity: null, purityLabel: null, metalName: null }),
  fetchMetalVariantInfoMap:        vi.fn().mockResolvedValue(new Map()),
  resolveMetalVariantIdFromResult: () => null,
  getAppliedMermaPercent:          () => null,
  buildCatalogItemsMapForCostLines: vi.fn().mockResolvedValue(new Map()),
  buildCatalogItemsMapForSteps:     vi.fn().mockResolvedValue(new Map()),
}));
vi.mock("../../../lib/pricing-engine/pricing-engine.currency.js", () => ({ getBaseCurrencyId: vi.fn().mockResolvedValue(null) }));
vi.mock("../../../lib/seller-commission.js", () => ({ calculateLineCommission: vi.fn().mockReturnValue({ base: null, amount: 0 }) }));

import { previewSale } from "../sales.service.js";

// ── Datos del escenario ──────────────────────────────────────────────────────
const TAX_RATE = 0.30;

beforeEach(() => {
  vi.clearAllMocks();

  mockPrisma.article.findMany.mockResolvedValue([
    { id: "art-unif", name: "Unif", categoryId: null, brand: null, manualTaxIds: ["tax-30"], costComposition: [], manualAdjustmentKind: null, manualAdjustmentType: null, manualAdjustmentValue: null },
    { id: "art-desg", name: "Desg", categoryId: null, brand: null, manualTaxIds: ["tax-30"], costComposition: [], manualAdjustmentKind: null, manualAdjustmentType: null, manualAdjustmentValue: null },
  ]);
  mockPrisma.articleVariant.findMany.mockResolvedValue([]);
  mockPrisma.articleGroupItem.findMany.mockResolvedValue([]);
  mockPrisma.metal.findMany.mockResolvedValue([]);
  mockPrisma.salesChannel.findFirst.mockResolvedValue(null);
  mockPrisma.coupon.findFirst.mockResolvedValue(null);
  mockPrisma.commercialEntity.findFirst.mockResolvedValue(null);
  mockPrisma.promotion.findMany.mockResolvedValue([]);
  mockPrisma.currency.findUnique.mockResolvedValue(null);
  mockPrisma.jewelry.findUnique.mockResolvedValue({ id: "j1", name: "J", numberFormat: null });
  mockPrisma.sale.findFirst.mockResolvedValue(null);

  // resolvePerLineCommercialConfigs lee estas listas: pl-desg = BREAKDOWN, pl-unif = unificada.
  mockPrisma.priceList.findMany.mockResolvedValue([
    { id: "pl-desg", name: "Desglosada", mode: "METAL_HECHURA", roundingTarget: "METAL", roundingMode: "NONE", roundingDirection: "NEAREST", roundingModeHechura: "HUNDRED", roundingDirectionHechura: "NEAREST", commercialRoundingMetalDomain: "MONETARY", commercialRoundingScope: "PER_LINE_LEGACY" },
    { id: "pl-unif", name: "Unificada", mode: "MARGIN_TOTAL", roundingTarget: "FINAL_PRICE", roundingMode: "NONE", roundingDirection: "NEAREST", roundingModeHechura: "NONE", roundingDirectionHechura: "NEAREST", commercialRoundingMetalDomain: "MONETARY", commercialRoundingScope: "PER_LINE_LEGACY" },
  ]);
  mockPrisma.priceList.findFirst.mockResolvedValue(null);

  mockEvaluatePricingPolicy.mockResolvedValue([]);
  mockBuildBatchCostContext.mockResolvedValue({ baseCurrencyId: "cur-1", defaultMermaPercent: null, metalVariantData: new Map(), rateMap: new Map() });
  mockCalculateCostFromLines.mockResolvedValue({ value: new D("400"), mode: "COST_LINES", partial: false, breakdown: null, steps: [] });

  // Tax = 30% del unitPrice (per-unit).
  mockComputeLineTaxes.mockImplementation((_jw: any, _ids: any, unitPriceDec: any) => {
    const up = Number(unitPriceDec?.toString?.() ?? unitPriceDec ?? 0);
    return Promise.resolve({ taxBreakdown: [], taxAmount: new D(String(Math.round(up * TAX_RATE * 100) / 100)) });
  });

  mockBuildPricingSnapshot.mockImplementation((res: any) => ({
    unitPrice: res.unitPrice?.toNumber?.() ?? null,
    basePrice: res.basePrice?.toNumber?.() ?? null,
    priceSource: res.priceSource, resolvedAt: "2026-06-03T00:00:00.000Z",
    appliedPriceListId: res.appliedPriceListId, appliedPriceListName: res.appliedPriceListName,
  }));

  // Modela applyPriceList: hechura redondeada PRE-TAX salvo supresión.
  mockResolveFinalSalePrice.mockImplementation((_jw: any, opts: any) => {
    const suppress = opts?.applyPriceListOptions?.suppressLineHechuraRounding === true;
    if (opts.articleId === "art-unif") {
      return Promise.resolve(fakePrice({ unitPrice: 1000, basePrice: 1000, appliedPriceListId: "pl-unif", metalHechuraBreakdown: null }));
    }
    // art-desg: hechura cruda 1560 → redondeo HUNDRED pre-tax = 1600 salvo supresión.
    const hechura = suppress ? 1560 : 1600;
    return Promise.resolve(fakePrice({
      unitPrice: hechura, basePrice: hechura, appliedPriceListId: "pl-desg",
      metalHechuraBreakdown: {
        metalCost: 0, metalSale: 0, metalMarginPct: 0,
        hechuraCost: 1560, hechuraSale: hechura, hechuraMarginPct: 0,
        hechuraSalePreRounding: suppress ? null : 1560,
        hechuraSaleRoundingDelta: suppress ? null : 40,
      },
    }));
  });
});

function fakePrice(over: Record<string, any> = {}) {
  return {
    quantityDiscountAmount: new D("0"), promotionDiscountAmount: new D("0"), discountAmount: new D("0"),
    priceSource: "PRICE_LIST", baseSource: "PRICE_LIST",
    unitCost: new D("0"), unitMargin: new D("0"), marginPercent: new D("0"),
    costPartial: false, costMode: "COST_LINES", partial: false,
    appliedPriceListId: "pl-1", appliedPriceListName: "L", appliedPriceListMode: "METAL_HECHURA",
    appliedPromotionId: null, appliedPromotionName: null, appliedDiscountId: null,
    steps: [], alerts: [], policy: { canConfirm: true, blockingAlerts: [] },
    metalHechuraBreakdown: null, componentSaleBreakdown: null,
    taxAmount: new D("0"), taxBreakdown: [], totalWithTax: new D("0"), appliedRounding: null,
    ...over,
    unitPrice: over.unitPrice != null ? new D(String(over.unitPrice)) : new D("1000"),
    basePrice: over.basePrice != null ? new D(String(over.basePrice)) : new D("1000"),
  };
}

function buildInput() {
  return {
    clientId: null,
    lines: [
      { articleId: "art-unif", quantity: 1, priceListIdOverride: "pl-unif" },
      { articleId: "art-desg", quantity: 1, priceListIdOverride: "pl-desg" },
    ],
  } as any;
}

describe("Wiring MIXTO — Capa B: previewSale REAL (fail-now / green-later)", () => {
  it("la línea Desglosada en MIXTO produce Sale.total = 3300 (RED con el código actual)", async () => {
    const res: any = await previewSale("j1", buildInput());
    // Σ totalPost esperado: Unificada 1300 + Desglosada 2000 = 3300.
    expect(res.total).toBe(3300);
  });

  it("la línea Desglosada NO debe arrastrar el doble redondeo (≠ 3380)", async () => {
    const res: any = await previewSale("j1", buildInput());
    expect(res.total).not.toBe(3380);
  });
});
