// src/modules/sales/__tests__/cost-line-overrides-persistence.test.ts
// =============================================================================
// FASE 1.5 — paridad de overrides preview ↔ draft ↔ confirm ↔ recompute.
//
// Cubre:
//   1. resolveDraftSaleLinesPricing forwardea overrides (legacy + explicit)
//      al motor cuando vienen en `DraftSaleLineInput`.
//   2. El snapshot persistido en DRAFT trae `costLineOverridesApplied` cuando
//      el motor los aplicó (vía buildPricingSnapshot).
//   3. confirmSale lee `costLineOverridesApplied` del snapshot frozen y los
//      reaplica a `calculateCostFromLines` para que el costo recomputado
//      respete los mismos overrides → margen consistente.
//   4. confirmSale preserva `costLineOverridesApplied` en el snapshot
//      persistido (paridad histórica draft → confirmed).
//   5. Coexistencia legacy + explicit: ambos se reenvían al motor sin
//      transformación (el motor decide la precedencia).
//   6. Recompute estable: dos pasadas con los mismos inputs producen
//      `unitCost` byte-paritario (sin pérdida de precisión).
//
// Estilo: hereda de `draft-pricing.test.ts` y `confirm-sale-pricing-snapshot.test.ts`.
// =============================================================================

import { describe, it, expect, vi, beforeEach } from "vitest";
import { Prisma } from "@prisma/client";

// ── Mocks ────────────────────────────────────────────────────────────────────

const mockPrisma = vi.hoisted(() => ({
  article:            { findMany: vi.fn(), findFirst: vi.fn() },
  articleVariant:     { findMany: vi.fn(), findFirst: vi.fn() },
  articleGroupItem:   { findMany: vi.fn() },
  articleMovement:    { count: vi.fn(), create: vi.fn() },
  sale:               { findFirst: vi.fn(), findMany: vi.fn(), create: vi.fn(), update: vi.fn(), count: vi.fn() },
  saleLine:           { update: vi.fn() },
  salesChannel:       { findFirst: vi.fn() },
  coupon:             { findFirst: vi.fn() },
  couponRedemption:   { create: vi.fn() },
  priceList:          { findMany: vi.fn() },
  promotion:          { findMany: vi.fn() },
  currency:           { findUnique: vi.fn() },
  jewelry:            { findUnique: vi.fn() },
  commercialEntity:   { findFirst: vi.fn() },
  entityBalanceEntry: { createMany: vi.fn() },
  $transaction:       vi.fn(),
}));
vi.mock("../../../lib/prisma.js", () => ({ prisma: mockPrisma }));

const mockResolveFinalSalePrice  = vi.hoisted(() => vi.fn());
const mockBuildPricingSnapshot   = vi.hoisted(() => vi.fn());
const mockCalculateCostFromLines = vi.hoisted(() => vi.fn());
const mockBuildBatchCostContext  = vi.hoisted(() => vi.fn());
const mockComputeLineTaxes       = vi.hoisted(() => vi.fn());
const mockEvaluatePricingPolicy  = vi.hoisted(() => vi.fn());
const mockApplyChannel           = vi.hoisted(() => vi.fn());
const mockApplyCoupon            = vi.hoisted(() => vi.fn());
const mockBuildBalanceBreakdown  = vi.hoisted(() => vi.fn());
const mockComputeSaleDocTotals   = vi.hoisted(() => vi.fn());

vi.mock("../../../lib/pricing-engine/pricing-engine.js", () => ({
  resolveFinalSalePrice:          (...a: any[]) => mockResolveFinalSalePrice(...a),
  buildPricingSnapshot:           (...a: any[]) => mockBuildPricingSnapshot(...a),
  calculateCostFromLines:         (...a: any[]) => mockCalculateCostFromLines(...a),
  buildBatchCostContext:          (...a: any[]) => mockBuildBatchCostContext(...a),
  computeLineTaxes:               (...a: any[]) => mockComputeLineTaxes(...a),
  evaluatePricingPolicy:          (...a: any[]) => mockEvaluatePricingPolicy(...a),
  applySalesChannelAdjustment:    (...a: any[]) => mockApplyChannel(...a),
  applyCouponAdjustment:          (...a: any[]) => mockApplyCoupon(...a),
  buildBalanceBreakdownFromPrice: (...a: any[]) => mockBuildBalanceBreakdown(...a),
  computeSaleDocumentTotals:      (...a: any[]) => mockComputeSaleDocTotals(...a),
  computePurchaseTaxes:           vi.fn().mockResolvedValue({
    costBase: null, costTaxAmount: null, costWithTax: null, costTaxBreakdown: [],
  }),
  deriveMetalHechuraBreakdown:    () => null,
  resolveShippingAmount:          () => 0,
}));
vi.mock("../../../lib/pricing-composition.js", () => ({
  buildComposition: () => ({ metal: null, hechura: null, metals: [], hechuras: [], products: [], services: [], taxes: [] }),
  fetchMetalVariantInfo:            vi.fn().mockResolvedValue({ purity: null, purityLabel: null, metalName: null }),
  fetchMetalVariantInfoMap:         vi.fn().mockResolvedValue(new Map()),
  resolveMetalVariantIdFromResult:  () => null,
  getAppliedMermaPercent:           () => null,
  buildCatalogItemsMapForCostLines: vi.fn().mockResolvedValue(new Map()),
  buildCatalogItemsMapForSteps:     vi.fn().mockResolvedValue(new Map()),
}));
vi.mock("../../../lib/pricing-engine/pricing-engine.currency.js", () => ({
  getBaseCurrencyId: vi.fn().mockResolvedValue(null),
}));
vi.mock("../../../lib/seller-commission.js", () => ({
  calculateLineCommission: vi.fn().mockReturnValue({ base: null, amount: 0 }),
}));
vi.mock("../../../lib/stock-engine.js", () => ({
  applyMovementImpact:   vi.fn(),
  reverseMovementImpact: vi.fn(),
}));
vi.mock("../../../lib/document-hooks/sale.hook.js", () => ({
  onSaleConfirmed: vi.fn().mockResolvedValue({ receipts: [], accountMovements: [] }),
}));
vi.mock("../../payments/payments.service.js", () => ({
  getCheckoutPreview: vi.fn().mockResolvedValue(null),
}));
vi.mock("../../coupons/coupons.service.js", () => ({
  validateCoupon: vi.fn().mockResolvedValue({ valid: false }),
}));

import {
  resolveDraftSaleLinesPricing,
  confirmSale,
} from "../sales.service.js";
import type { CostLineOverride } from "../../../lib/pricing-engine/pricing-engine.js";

const D = Prisma.Decimal;

// ── Helpers ─────────────────────────────────────────────────────────────────

function fakeSalePriceResult(overrides: Record<string, any> = {}) {
  return {
    unitPrice:                new D("1000"),
    basePrice:                new D("1200"),
    quantityDiscountAmount:   new D("0"),
    promotionDiscountAmount:  new D("200"),
    discountAmount:           new D("200"),
    priceSource:              "PRICE_LIST",
    baseSource:               "PRICE_LIST",
    unitCost:                 new D("400"),
    unitMargin:               new D("600"),
    marginPercent:            new D("60"),
    costPartial:              false,
    costMode:                 "COST_LINES",
    partial:                  false,
    appliedPriceListId:       "pl-1",
    appliedPriceListName:     "Lista",
    appliedPromotionId:       null,
    appliedPromotionName:     null,
    appliedDiscountId:        null,
    steps:                    [],
    alerts:                   [],
    policy:                   { canConfirm: true, blockingAlerts: [] },
    stackingMode:             "NONE",
    metalHechuraBreakdown:    null,
    taxAmount:                new D("0"),
    taxBreakdown:             [],
    totalWithTax:             new D("1000"),
    taxExemptByEntity:        false,
    costLineOverridesApplied: [],
    debugWarnings:            [],
    ...overrides,
  };
}

function makeSnapshot(overrides: Record<string, any> = {}) {
  return {
    unitPrice:            1000,
    basePrice:            1200,
    discountAmount:       200,
    taxAmount:            0,
    totalWithTax:         1000,
    priceSource:          "PRICE_LIST",
    baseSource:           "PRICE_LIST",
    unitCost:             400,
    unitMargin:           600,
    marginPercent:        60,
    costPartial:          false,
    costMode:             "COST_LINES",
    partial:              false,
    appliedPriceListId:   "pl-1",
    appliedPriceListName: "Lista",
    appliedPromotionId:   null,
    appliedPromotionName: null,
    appliedDiscountId:    null,
    resolvedAt:           "2026-05-08T00:00:00.000Z",
    ...overrides,
  };
}

function fakeSnapshotFromResult(res: any, options?: any) {
  // Mirror lite del backend `buildPricingSnapshot`: incluye
  // `costLineOverridesApplied` cuando el motor lo emite.
  return {
    ...makeSnapshot({
      unitPrice:            res.unitPrice?.toNumber?.() ?? null,
      basePrice:            res.basePrice?.toNumber?.() ?? null,
      discountAmount:       res.discountAmount?.toNumber?.() ?? 0,
      taxAmount:            res.taxAmount?.toNumber?.() ?? 0,
      totalWithTax:         res.totalWithTax?.toNumber?.() ?? null,
      priceSource:          res.priceSource,
      baseSource:           res.baseSource,
      unitCost:             res.unitCost?.toNumber?.() ?? null,
      unitMargin:           res.unitMargin?.toNumber?.() ?? null,
      marginPercent:        res.marginPercent?.toNumber?.() ?? null,
      costPartial:          res.costPartial,
      costMode:             res.costMode,
      partial:              res.partial,
      appliedPriceListId:   res.appliedPriceListId,
      appliedPriceListName: res.appliedPriceListName,
      appliedPromotionId:   res.appliedPromotionId,
      appliedPromotionName: res.appliedPromotionName,
      appliedDiscountId:    res.appliedDiscountId,
      composition:          options?.composition ?? null,
    }),
    ...(Array.isArray(res.costLineOverridesApplied) && res.costLineOverridesApplied.length > 0
      ? { costLineOverridesApplied: res.costLineOverridesApplied }
      : {}),
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  mockPrisma.article.findMany.mockResolvedValue([]);
  mockPrisma.articleVariant.findMany.mockResolvedValue([]);
  mockPrisma.articleGroupItem.findMany.mockResolvedValue([]);
  mockBuildPricingSnapshot.mockImplementation(fakeSnapshotFromResult);
});

// ────────────────────────────────────────────────────────────────────────────
// 1. resolveDraftSaleLinesPricing forwardea overrides al motor
// ────────────────────────────────────────────────────────────────────────────

describe("Fase 1.5 — DRAFT: overrides viajan al motor y al snapshot", () => {
  it("forwardea costLineOverrides + legacy a resolveFinalSalePrice", async () => {
    mockResolveFinalSalePrice.mockResolvedValue(fakeSalePriceResult());

    const overrides: CostLineOverride[] = [
      { costLineId: "cl-metal-1", type: "METAL", quantityOverride: 5, mermaPercentOverride: 1.2 },
    ];

    await resolveDraftSaleLinesPricing("j1", [{
      articleId: "a1",
      variantId: null,
      quantity:  1,
      gramsOverride:         9,    // legacy
      hechuraOverrideAmount: 333,  // legacy
      costLineOverrides:     overrides,
    }]);

    expect(mockResolveFinalSalePrice).toHaveBeenCalledTimes(1);
    const opts = mockResolveFinalSalePrice.mock.calls[0][1];
    expect(opts.gramsOverride).toBe(9);
    expect(opts.hechuraOverrideAmount).toBe(333);
    // identidad referencial — sin clones ni transformaciones.
    expect(opts.costLineOverrides).toBe(overrides);
  });

  it("manda undefined cuando la línea no trae overrides", async () => {
    mockResolveFinalSalePrice.mockResolvedValue(fakeSalePriceResult());

    await resolveDraftSaleLinesPricing("j1", [{
      articleId: "a1",
      variantId: null,
      quantity:  1,
    }]);

    const opts = mockResolveFinalSalePrice.mock.calls[0][1];
    expect(opts.costLineOverrides).toBeUndefined();
    expect(opts.gramsOverride).toBeNull();
    expect(opts.hechuraOverrideAmount).toBeNull();
  });

  it("snapshot persistido contiene costLineOverridesApplied que devolvió el motor", async () => {
    const motorApplied: CostLineOverride[] = [
      { costLineId: "cl-metal-1", type: "METAL", quantityOverride: 5, mermaPercentOverride: 1.2 },
    ];
    // Motor: simulamos que el override redujo el cost y subió el margen.
    mockResolveFinalSalePrice.mockResolvedValue(fakeSalePriceResult({
      unitCost:                 new D("350"),
      unitMargin:               new D("650"),
      marginPercent:            new D("65"),
      costLineOverridesApplied: motorApplied,
    }));

    const out = await resolveDraftSaleLinesPricing("j1", [{
      articleId: "a1",
      variantId: null,
      quantity:  1,
      costLineOverrides: motorApplied,
    }]);

    expect(out[0].pricingSnapshot.unitPrice).toBe(1000);
    // El snapshot persistido carga el array tal cual lo emitió el motor.
    expect((out[0].pricingSnapshot as any).costLineOverridesApplied).toEqual(motorApplied);
  });

  it("snapshot NO contiene el campo cuando el motor no aplicó nada (retrocompat v5)", async () => {
    mockResolveFinalSalePrice.mockResolvedValue(fakeSalePriceResult({
      costLineOverridesApplied: [],
    }));

    const out = await resolveDraftSaleLinesPricing("j1", [{
      articleId: "a1", variantId: null, quantity: 1,
    }]);

    // Aditivo: cuando no hay overrides, el array NO se incluye en el snapshot
    // — esto preserva paridad con snapshots v5 viejos byte-a-byte.
    expect((out[0].pricingSnapshot as any).costLineOverridesApplied).toBeUndefined();
  });

  it("dos pasadas con los mismos overrides producen snapshots idénticos (estabilidad)", async () => {
    const motorApplied: CostLineOverride[] = [
      { costLineId: "cl-1", type: "METAL", quantityOverride: 7.123456 },
    ];
    mockResolveFinalSalePrice.mockResolvedValue(fakeSalePriceResult({
      costLineOverridesApplied: motorApplied,
    }));

    const out1 = await resolveDraftSaleLinesPricing("j1", [{
      articleId: "a1", variantId: null, quantity: 1, costLineOverrides: motorApplied,
    }]);
    const out2 = await resolveDraftSaleLinesPricing("j1", [{
      articleId: "a1", variantId: null, quantity: 1, costLineOverrides: motorApplied,
    }]);

    // Sin pérdida de precisión entre pasadas.
    expect(out1[0].unitPrice).toBe(out2[0].unitPrice);
    expect(out1[0].lineTotal).toBe(out2[0].lineTotal);
    expect((out1[0].pricingSnapshot as any).costLineOverridesApplied)
      .toEqual((out2[0].pricingSnapshot as any).costLineOverridesApplied);
  });
});

// ────────────────────────────────────────────────────────────────────────────
// 2. confirmSale: paridad cost recompute y snapshot persistido
// ────────────────────────────────────────────────────────────────────────────

describe("Fase 1.5 — CONFIRM: overrides se preservan y se reaplican", () => {
  function setupConfirmCommonMocks() {
    mockEvaluatePricingPolicy.mockResolvedValue([]);
    mockBuildBatchCostContext.mockResolvedValue({
      baseCurrencyId: "cur-1", defaultMermaPercent: null,
      metalVariantData: new Map(), rateMap: new Map(),
    });
    mockComputeLineTaxes.mockResolvedValue({ taxBreakdown: [], taxAmount: new D("0") });
    mockApplyChannel.mockReturnValue({
      baseAmount: 1000, finalAmount: 1000, channelAmount: 0,
      channelId: "", channelName: "",
    });
    mockApplyCoupon.mockReturnValue({
      baseAmount: 1000, discountAmount: 0, finalAmount: 1000,
      couponId: "", couponCode: "", couponName: "",
      discountType: "PERCENTAGE", discountValue: 0, applied: false,
    });
    mockComputeSaleDocTotals.mockImplementation((input: any) => {
      const subtotal = input.lines.reduce((s: number, l: any) => s + l.lineTotal, 0);
      const tax      = input.lines.reduce((s: number, l: any) => s + l.lineTaxAmount, 0);
      return {
        subtotalBeforeDiscounts: subtotal, lineDiscountAmount: 0,
        subtotalAfterLineDiscounts: subtotal,
        channelAdjustmentAmount: 0, couponDiscountAmount: 0,
        paymentAdjustmentAmount: 0, shippingAmount: 0, globalDiscountAmount: 0,
        taxableBase: subtotal, taxAmount: tax, roundingAdjustment: 0,
        totalBeforeTax: subtotal, totalWithTax: subtotal + tax,
        total: subtotal + tax, legacyCouponOnlyDiscount: 0,
        channelResult: { baseAmount: subtotal, channelAmount: 0, finalAmount: subtotal, channelName: "", channelId: "" },
        couponResult:  { baseAmount: subtotal, discountAmount: 0, finalAmount: subtotal, couponId: "", couponCode: "", couponName: "", discountType: "PERCENTAGE", discountValue: 0, applied: false },
        sourceTrace: [],
      };
    });

    mockPrisma.priceList.findMany.mockResolvedValue([]);
    mockPrisma.promotion.findMany.mockResolvedValue([]);
    mockPrisma.coupon.findFirst.mockResolvedValue(null);
    mockPrisma.currency.findUnique.mockResolvedValue(null);
    mockPrisma.commercialEntity.findFirst.mockResolvedValue(null);
    mockPrisma.jewelry.findUnique.mockResolvedValue({
      id: "j1", name: "J", legalName: "", cuit: "", ivaCondition: "", email: "",
      street: "", number: "", floor: "", apartment: "", city: "", province: "",
      country: "", postalCode: "", logoUrl: "",
    });
    mockPrisma.sale.update.mockResolvedValue({ id: "s1" });
    mockPrisma.sale.findFirst.mockResolvedValue({ id: "s1", lines: [] });

    const txMock: any = {
      saleLine:           { update: vi.fn() },
      sale:               { update: vi.fn().mockResolvedValue({}) },
      articleMovement:    { count: vi.fn().mockResolvedValue(0), create: vi.fn().mockResolvedValue({ id: "mov1" }) },
      entityBalanceEntry: { createMany: vi.fn() },
      couponRedemption:   { create: vi.fn() },
    };
    mockPrisma.$transaction.mockImplementation(async (cb: any) => cb(txMock));
    return { txMock };
  }

  function makeSale(overrides: Record<string, any> = {}) {
    return {
      id: "s1", code: "VTA-1.5", status: "DRAFT", clientId: null, warehouseId: null,
      subtotal: new D("1000"), discountAmount: new D("0"), taxAmount: new D("0"),
      total: new D("1000"), couponId: null,
      client: null, seller: null, channel: null,
      lines: [],
      ...overrides,
    };
  }

  function makeArticle(overrides: Record<string, any> = {}) {
    return {
      id: "a1", stockMode: "STOCK",
      mermaPercent: null, manualTaxIds: [],
      manualAdjustmentKind: null, manualAdjustmentType: null, manualAdjustmentValue: null,
      costComposition: [],
      ...overrides,
    };
  }

  it("calculateCostFromLines recibe los costLineOverrides del snapshot frozen", async () => {
    const { txMock } = setupConfirmCommonMocks();
    const frozenOverrides: CostLineOverride[] = [
      { costLineId: "cl-metal-1", type: "METAL", quantityOverride: 5 },
      { costLineId: "cl-hechura-1", type: "HECHURA", unitValueOverride: 1500 },
    ];
    mockCalculateCostFromLines.mockResolvedValue({
      value: new D("350"), mode: "COST_LINES", partial: false,
      breakdown: null, steps: [],
      costLineOverridesApplied: frozenOverrides,
    });

    const snap = makeSnapshot({
      unitPrice: 1000, basePrice: 1000,
      costLineOverridesApplied: frozenOverrides,
    });
    mockPrisma.sale.findFirst.mockResolvedValueOnce(makeSale({
      lines: [{
        id: "L1", articleId: "a1", variantId: null,
        quantity: new D("1"), unitPrice: new D("1000"), discountPct: new D("0"),
        lineTotal: new D("1000"),
        priceSource: "PRICE_LIST",
        appliedPriceListId: "pl-1",
        appliedPromotionId: null, appliedDiscountId: null,
        pricingSnapshot: snap,
      }],
    }));
    mockPrisma.article.findMany.mockResolvedValue([makeArticle()]);

    await confirmSale("s1", "j1", "u1");

    expect(mockCalculateCostFromLines).toHaveBeenCalledTimes(1);
    // Args: (jewelryId, lines, adjustment, ctx, costLineOverrides)
    const callArgs = mockCalculateCostFromLines.mock.calls[0];
    expect(callArgs[4]).toEqual(frozenOverrides);

    // Y el snapshot persistido CONFIRMED preserva los overrides.
    expect(txMock.saleLine.update).toHaveBeenCalledTimes(1);
    const persisted = txMock.saleLine.update.mock.calls[0][0].data.pricingSnapshot;
    expect(persisted.costLineOverridesApplied).toEqual(frozenOverrides);
  });

  it("margen frozen consistente: unitPrice (frozen) − unitCost (override-aware)", async () => {
    const { txMock } = setupConfirmCommonMocks();
    const ovs: CostLineOverride[] = [
      { costLineId: "cl-1", type: "METAL", quantityOverride: 5 },
    ];
    // Sin override el costo "ingenuo" sería 400 → margen 600.
    // Con override el motor responde 350 → margen 650.
    mockCalculateCostFromLines.mockResolvedValue({
      value: new D("350"), mode: "COST_LINES", partial: false,
      breakdown: null, steps: [],
      costLineOverridesApplied: ovs,
    });

    const snap = makeSnapshot({
      unitPrice: 1000, basePrice: 1000,
      costLineOverridesApplied: ovs,
    });
    mockPrisma.sale.findFirst.mockResolvedValueOnce(makeSale({
      lines: [{
        id: "L1", articleId: "a1", variantId: null,
        quantity: new D("1"), unitPrice: new D("1000"), discountPct: new D("0"),
        lineTotal: new D("1000"),
        priceSource: "PRICE_LIST",
        appliedPriceListId: "pl-1",
        appliedPromotionId: null, appliedDiscountId: null,
        pricingSnapshot: snap,
      }],
    }));
    mockPrisma.article.findMany.mockResolvedValue([makeArticle()]);

    await confirmSale("s1", "j1", "u1");

    const persisted = txMock.saleLine.update.mock.calls[0][0].data.pricingSnapshot;
    expect(persisted.unitPrice).toBe(1000);  // frozen del DRAFT
    expect(persisted.unitCost).toBe(350);    // recomputado con overrides
    expect(persisted.unitMargin).toBe(650);  // 1000 − 350 — coherente
  });

  it("sin overrides en el snapshot, calculateCostFromLines se llama sin el 5to arg poblado", async () => {
    const { txMock } = setupConfirmCommonMocks();
    mockCalculateCostFromLines.mockResolvedValue({
      value: new D("400"), mode: "COST_LINES", partial: false, breakdown: null, steps: [],
    });

    const snap = makeSnapshot();   // sin costLineOverridesApplied
    mockPrisma.sale.findFirst.mockResolvedValueOnce(makeSale({
      lines: [{
        id: "L1", articleId: "a1", variantId: null,
        quantity: new D("1"), unitPrice: new D("1000"), discountPct: new D("0"),
        lineTotal: new D("1000"),
        priceSource: "PRICE_LIST",
        appliedPriceListId: "pl-1",
        appliedPromotionId: null, appliedDiscountId: null,
        pricingSnapshot: snap,
      }],
    }));
    mockPrisma.article.findMany.mockResolvedValue([makeArticle()]);

    await confirmSale("s1", "j1", "u1");

    const callArgs = mockCalculateCostFromLines.mock.calls[0];
    // Cuando el snapshot no trae el array, viaja undefined al motor.
    expect(callArgs[4]).toBeUndefined();

    // Y el snapshot persistido NO crea el campo (retrocompat byte-a-byte).
    const persisted = txMock.saleLine.update.mock.calls[0][0].data.pricingSnapshot;
    expect(persisted.costLineOverridesApplied).toBeUndefined();
  });

  it("recompute estable: dos confirmSale sucesivos producen snapshots idénticos", async () => {
    const ovs: CostLineOverride[] = [
      { costLineId: "cl-1", type: "METAL", quantityOverride: 7.5, mermaPercentOverride: 0.8 },
      { costLineId: "cl-2", type: "PRODUCT", unitValueOverride: 33.33,
        adjustmentKind: "BONUS", adjustmentType: "PERCENTAGE", adjustmentValue: 5 },
    ];
    mockCalculateCostFromLines.mockResolvedValue({
      value: new D("325.50"), mode: "COST_LINES", partial: false,
      breakdown: null, steps: [],
      costLineOverridesApplied: ovs,
    });

    const snap = makeSnapshot({
      unitPrice: 1000, basePrice: 1000,
      costLineOverridesApplied: ovs,
    });
    function setupCall() {
      const { txMock } = setupConfirmCommonMocks();
      mockCalculateCostFromLines.mockResolvedValue({
        value: new D("325.50"), mode: "COST_LINES", partial: false,
        breakdown: null, steps: [],
        costLineOverridesApplied: ovs,
      });
      mockPrisma.sale.findFirst.mockResolvedValueOnce(makeSale({
        lines: [{
          id: "L1", articleId: "a1", variantId: null,
          quantity: new D("1"), unitPrice: new D("1000"), discountPct: new D("0"),
          lineTotal: new D("1000"),
          priceSource: "PRICE_LIST",
          appliedPriceListId: "pl-1",
          appliedPromotionId: null, appliedDiscountId: null,
          pricingSnapshot: snap,
        }],
      }));
      mockPrisma.article.findMany.mockResolvedValue([makeArticle()]);
      return txMock;
    }

    const tx1 = setupCall();
    await confirmSale("s1", "j1", "u1");
    const persisted1 = tx1.saleLine.update.mock.calls[0][0].data.pricingSnapshot;

    const tx2 = setupCall();
    await confirmSale("s1", "j1", "u1");
    const persisted2 = tx2.saleLine.update.mock.calls[0][0].data.pricingSnapshot;

    // Comparación bytewise (excepto resolvedAt que es Date.now()).
    const norm = (s: any) => ({ ...s, resolvedAt: "FIXED" });
    expect(norm(persisted1)).toEqual(norm(persisted2));
    expect(persisted1.unitPrice).toBe(persisted2.unitPrice);
    expect(persisted1.unitCost).toBe(persisted2.unitCost);
    expect(persisted1.unitMargin).toBe(persisted2.unitMargin);
    expect(persisted1.costLineOverridesApplied).toEqual(persisted2.costLineOverridesApplied);
  });
});
