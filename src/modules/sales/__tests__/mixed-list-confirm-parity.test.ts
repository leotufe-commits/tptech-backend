// src/modules/sales/__tests__/mixed-list-confirm-parity.test.ts
// =============================================================================
// INTEGRACIÓN (Capa B') — PARIDAD preview ↔ confirm en listas MIXTAS (Opción α).
//
// Ejercita las DOS rutas del SERVICIO real (`previewSale` y `confirmSale`) con
// `computeSaleDocumentTotals` REAL + la familia de redondeo comercial REAL. Solo
// se mockean las fronteras (Prisma, pricing per-línea, tax, hooks, stock).
//
// El espejo en `confirmSale` (FASE 2 / Opción α) re-pricea LIMPIO las líneas
// DESGLOSADAS (suprimiendo el redondeo PER_LINE pre-tax que el DRAFT congeló),
// consolida `commercialDocumentRoundingPrecomputed` y alimenta el motor con
// montos limpios → `Sale.total (confirm) === Sale.total (preview)`.
//
// Modelo a escala (mismos números que `mixed-list-wiring-previewsale.test.ts`):
//   · Línea Unificada → unitPrice 1000, tax 30% (300) → 1300.
//   · Línea Desglosada (hechura HUNDRED):
//        LIMPIO (α): hechura 1560, tax 468 → 2028 → saldo post-tax HUNDRED = 2000.
//        DRAFT congeló CONTAMINADO: hechura 1600, tax 480 → 2080.
//
// Escenarios validados (3):
//   1. Unificada + Desglosada → 1300 + 2000 = 3300.
//   2. Desglosada + Desglosada → 2000 + 2000 = 4000.
//   3. Unificada + Unificada   → 1300 + 1300 = 2600 (sin redondeo comercial).
//
// La aserción central: `previewTotal === confirmEngineTotal === ESPERADO`.
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
  entityBalanceEntry: { createMany: vi.fn() },
  couponRedemption:   { create: vi.fn() },
  $transaction:       vi.fn(),
}));
vi.mock("../../../lib/prisma.js", () => ({ prisma: mockPrisma }));

const mockResolveFinalSalePrice  = vi.hoisted(() => vi.fn());
const mockBuildPricingSnapshot   = vi.hoisted(() => vi.fn());
const mockCalculateCostFromLines = vi.hoisted(() => vi.fn());
const mockBuildBatchCostContext  = vi.hoisted(() => vi.fn());
const mockComputeLineTaxes       = vi.hoisted(() => vi.fn());
const mockEvaluatePricingPolicy  = vi.hoisted(() => vi.fn());

// REAL: computeSaleDocumentTotals + familia de redondeo comercial. Solo
// mockeamos las fronteras caras / no-deterministas.
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
    // confirmSale arma el breakdown Metal/Hechura per línea vía este helper.
    // Pure-hechura: metalSale=0, hechuraSale = basePrice (frozen contaminado).
    deriveMetalHechuraBreakdown: (input: any) => ({
      metalCost:   0,
      hechuraCost: 1560,
      metalSale:   0,
      hechuraSale: Number(input?.basePrice ?? 0),
      metalSaleEstimated:   false,
      hechuraSaleEstimated: false,
    }),
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
vi.mock("../../../lib/stock-engine.js", () => ({ applyMovementImpact: vi.fn(), reverseMovementImpact: vi.fn() }));
vi.mock("../../../lib/document-hooks/sale.hook.js", () => ({
  onSaleConfirmed: vi.fn().mockResolvedValue({ receipts: [], accountMovements: [] }),
  onSaleCancelled: vi.fn().mockResolvedValue({}),
}));
vi.mock("../../payments/payments.service.js", () => ({ getCheckoutPreview: vi.fn().mockResolvedValue(null) }));
vi.mock("../../coupons/coupons.service.js", () => ({ validateCoupon: vi.fn().mockResolvedValue({ valid: false }) }));

import { previewSale, confirmSale } from "../sales.service.js";

const TAX_RATE = 0.30;

// ── Listas de precios del catálogo (config de redondeo comercial) ────────────
const PL_UNIF = (id: string) => ({
  id, name: "Unif", mode: "MARGIN_TOTAL", roundingTarget: "FINAL_PRICE",
  roundingMode: "NONE", roundingDirection: "NEAREST",
  roundingModeHechura: "NONE", roundingDirectionHechura: "NEAREST",
  commercialRoundingMetalDomain: "MONETARY", commercialRoundingScope: "PER_LINE_LEGACY",
});
const PL_DESG = (id: string) => ({
  id, name: "Desg", mode: "METAL_HECHURA", roundingTarget: "METAL",
  roundingMode: "NONE", roundingDirection: "NEAREST",
  roundingModeHechura: "HUNDRED", roundingDirectionHechura: "NEAREST",
  commercialRoundingMetalDomain: "MONETARY", commercialRoundingScope: "PER_LINE_LEGACY",
});

/** Resultado de `resolveFinalSalePrice` modelando `applyPriceList`. */
function fakePrice(over: Record<string, any> = {}) {
  return {
    quantityDiscountAmount: new D("0"), promotionDiscountAmount: new D("0"), discountAmount: new D("0"),
    priceSource: "PRICE_LIST", baseSource: "PRICE_LIST",
    unitCost: new D("0"), unitMargin: new D("0"), marginPercent: new D("0"),
    costPartial: false, costMode: "COST_LINES", partial: false,
    appliedPriceListName: "L", appliedPriceListMode: "METAL_HECHURA",
    appliedPromotionId: null, appliedPromotionName: null, appliedDiscountId: null,
    steps: [], alerts: [], policy: { canConfirm: true, blockingAlerts: [] },
    componentSaleBreakdown: null,
    taxAmount: new D("0"), taxBreakdown: [], totalWithTax: new D("0"), appliedRounding: null,
    ...over,
    unitPrice: new D(String(over.unitPrice ?? 1000)),
    basePrice: new D(String(over.basePrice ?? over.unitPrice ?? 1000)),
  };
}

/**
 * Configura todos los mocks para un escenario de 2 líneas.
 * @param kinds  ["UNIF"|"DESG", "UNIF"|"DESG"]  tipo de cada línea.
 */
function setupScenario(kinds: Array<"UNIF" | "DESG">) {
  // Cada línea con su PROPIA lista (ids distintos → MIXED_LIST_FALLBACK).
  const listIdByIdx = kinds.map((k, i) => `pl-${k.toLowerCase()}-${i}`);
  const artIdByIdx  = kinds.map((_, i) => `art-${i}`);

  mockPrisma.article.findMany.mockResolvedValue(
    artIdByIdx.map((id) => ({
      id, name: id, stockMode: "STOCK", commercialMode: null,
      categoryId: null, brand: null, mermaPercent: null, manualTaxIds: ["tax-30"],
      manualAdjustmentKind: null, manualAdjustmentType: null, manualAdjustmentValue: null,
      category: null, costComposition: [],
    })),
  );
  mockPrisma.articleVariant.findMany.mockResolvedValue([]);
  mockPrisma.articleGroupItem.findMany.mockResolvedValue([]);
  mockPrisma.metal.findMany.mockResolvedValue([]);
  mockPrisma.salesChannel.findFirst.mockResolvedValue(null);
  mockPrisma.coupon.findFirst.mockResolvedValue(null);
  mockPrisma.commercialEntity.findFirst.mockResolvedValue(null);
  mockPrisma.promotion.findMany.mockResolvedValue([]);
  mockPrisma.currency.findUnique.mockResolvedValue(null);
  mockPrisma.jewelry.findUnique.mockResolvedValue({ id: "j1", name: "J", numberFormat: null });

  // priceList.findMany alimenta resolvePerLineCommercialConfigs + el contexto MIXTO.
  const lists = kinds.map((k, i) => (k === "DESG" ? PL_DESG(listIdByIdx[i]) : PL_UNIF(listIdByIdx[i])));
  mockPrisma.priceList.findMany.mockResolvedValue(lists);
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
    priceSource: res.priceSource, resolvedAt: "2026-06-04T00:00:00.000Z",
    appliedPriceListId: res.appliedPriceListId, appliedPriceListName: res.appliedPriceListName,
  }));

  // Modela applyPriceList: DESG con hechura redondeada PRE-TAX (1600) salvo
  // supresión (1560). UNIF unitPrice plano 1000 (sin redondeo de hechura).
  mockResolveFinalSalePrice.mockImplementation((_jw: any, opts: any) => {
    const idx  = artIdByIdx.indexOf(opts.articleId);
    const kind = kinds[idx];
    const listId = listIdByIdx[idx];
    if (kind === "UNIF") {
      return Promise.resolve(fakePrice({ unitPrice: 1000, basePrice: 1000, appliedPriceListId: listId, metalHechuraBreakdown: null }));
    }
    const suppress = opts?.applyPriceListOptions?.suppressLineHechuraRounding === true;
    const hechura = suppress ? 1560 : 1600;
    return Promise.resolve(fakePrice({
      unitPrice: hechura, basePrice: hechura, appliedPriceListId: listId,
      metalHechuraBreakdown: {
        metalCost: 0, metalSale: 0, metalMarginPct: 0,
        hechuraCost: 1560, hechuraSale: hechura, hechuraMarginPct: 0,
        hechuraSalePreRounding: suppress ? null : 1560,
        hechuraSaleRoundingDelta: suppress ? null : 40,
      },
    }));
  });

  return { listIdByIdx, artIdByIdx };
}

/** Input de previewSale (líneas con priceListIdOverride por línea). */
function previewInput(artIdByIdx: string[], listIdByIdx: string[]) {
  return {
    clientId: null,
    lines: artIdByIdx.map((articleId, i) => ({ articleId, quantity: 1, priceListIdOverride: listIdByIdx[i] })),
  } as any;
}

/**
 * DRAFT persistido que `confirmSale` leerá: cada línea con su `pricingSnapshot`
 * CONGELADO (CONTAMINADO — el draft no suprimió el redondeo PER_LINE).
 */
function confirmDraftSale(kinds: Array<"UNIF" | "DESG">, artIdByIdx: string[], listIdByIdx: string[]) {
  const lines = kinds.map((k, i) => {
    const frozen = k === "DESG" ? 1600 : 1000;        // unitPrice congelado contaminado
    return {
      id: `L${i}`, articleId: artIdByIdx[i], variantId: null,
      quantity: new D("1"), unitPrice: new D(String(frozen)), discountPct: new D("0"),
      lineTotal: new D(String(frozen)),
      priceSource: "PRICE_LIST",
      appliedPriceListId: listIdByIdx[i], appliedPromotionId: null, appliedDiscountId: null,
      pricingSnapshot: {
        unitPrice: frozen, basePrice: frozen, discountAmount: 0,
        priceSource: "PRICE_LIST", baseSource: "PRICE_LIST",
        appliedPriceListId: listIdByIdx[i], appliedPriceListName: "L",
        resolvedAt: "2026-06-04T00:00:00.000Z",
      },
      manualPriceOverride: null, manualDiscountOverride: null, taxOverride: null,
      manualDiscountAppliesToOverride: null, manualTaxAppliesToOverride: null,
    };
  });
  return {
    id: "s1", code: "VTA-0001", status: "DRAFT",
    clientId: null, warehouseId: null,
    subtotal: new D("0"), discountAmount: new D("0"), taxAmount: new D("0"), total: new D("0"),
    couponId: null, balanceModeOverride: null,
    shippingAmount: null, globalDiscountType: null, globalDiscountValue: null,
    paymentMethodId: null, paymentInstallments: null, manualAdjustmentInput: null,
    client: null, seller: null, channel: null,
    lines,
  };
}

/** Corre confirmSale REAL y devuelve el `engineTotal` persistido (= total del motor). */
async function runConfirmEngineTotal(): Promise<number> {
  const captured: { engineTotal?: number; total?: number } = {};
  const txMock: any = {
    saleLine:           { update: vi.fn() },
    sale:               { update: vi.fn().mockImplementation((args: any) => { captured.engineTotal = Number(args?.data?.engineTotal); captured.total = Number(args?.data?.total); return Promise.resolve({}); }) },
    articleMovement:    { count: vi.fn().mockResolvedValue(0), create: vi.fn().mockResolvedValue({ id: "mov1" }) },
    entityBalanceEntry: { createMany: vi.fn() },
    couponRedemption:   { create: vi.fn() },
  };
  mockPrisma.$transaction.mockImplementation(async (cb: any) => cb(txMock));
  await confirmSale("s1", "j1", "u1");
  return captured.engineTotal ?? NaN;
}

describe("Paridad preview ↔ confirm — listas MIXTAS (Opción α)", () => {
  beforeEach(() => vi.clearAllMocks());

  const SCENARIOS: Array<{ name: string; kinds: Array<"UNIF" | "DESG">; expected: number }> = [
    { name: "Unificada + Desglosada", kinds: ["UNIF", "DESG"], expected: 3300 },
    { name: "Desglosada + Desglosada", kinds: ["DESG", "DESG"], expected: 4000 },
    { name: "Unificada + Unificada",   kinds: ["UNIF", "UNIF"], expected: 2600 },
  ];

  for (const sc of SCENARIOS) {
    it(`${sc.name}: previewTotal === confirmEngineTotal === ${sc.expected}`, async () => {
      // ── preview ──────────────────────────────────────────────────────────
      const { artIdByIdx, listIdByIdx } = setupScenario(sc.kinds);
      mockPrisma.sale.findFirst.mockResolvedValue(null);
      const previewRes: any = await previewSale("j1", previewInput(artIdByIdx, listIdByIdx));

      // ── confirm ──────────────────────────────────────────────────────────
      vi.clearAllMocks();
      setupScenario(sc.kinds);
      mockPrisma.sale.findFirst.mockResolvedValue(confirmDraftSale(sc.kinds, artIdByIdx, listIdByIdx));
      const confirmEngineTotal = await runConfirmEngineTotal();

      expect(previewRes.total).toBe(sc.expected);
      expect(confirmEngineTotal).toBe(sc.expected);
      expect(confirmEngineTotal).toBe(previewRes.total);
    });
  }
});
