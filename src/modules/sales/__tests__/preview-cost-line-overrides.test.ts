// src/modules/sales/__tests__/preview-cost-line-overrides.test.ts
// =============================================================================
// FASE 1 (refactor "Composición editable") — plumbing HTTP de costLineOverrides
// en `previewSale`.
//
// Cubre:
//   1. previewSale acepta `costLineOverrides` en la línea y los reenvía al
//      motor (`resolveFinalSalePrice`) sin tocarlos.
//   2. Cuando el array está vacío / undefined, el motor recibe `undefined`.
//   3. Override que cambia el resultado del motor cambia el total del preview
//      → end-to-end "preview con override modifica total".
//   4. Paridad con el motor: la firma exacta que recibe el engine coincide
//      byte-a-byte con la que pasaría una llamada directa con los mismos
//      inputs (zero transformation en el plumbing del controller).
//
// Estilo y mocks: heredados de `preview-confirm-parity.test.ts` para
// consistencia. NO testea cálculos del motor (eso es g4-11a/b) — solo el
// plumbing del endpoint.
// =============================================================================

import { describe, it, expect, vi, beforeEach } from "vitest";
import { Prisma } from "@prisma/client";

// ── Mocks ────────────────────────────────────────────────────────────────────

const mockPrisma = vi.hoisted(() => ({
  article:            { findMany: vi.fn(), findFirst: vi.fn() },
  articleVariant:     { findMany: vi.fn(), findFirst: vi.fn() },
  articleGroupItem:   { findMany: vi.fn() },
  salesChannel:       { findFirst: vi.fn() },
  coupon:             { findFirst: vi.fn() },
  priceList:          { findMany: vi.fn() },
  promotion:          { findMany: vi.fn() },
  currency:           { findUnique: vi.fn() },
  jewelry:            { findUnique: vi.fn() },
  commercialEntity:   { findFirst: vi.fn() },
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
  computePurchaseTaxes: vi.fn().mockResolvedValue({
    costBase:         null,
    costTaxAmount:    null,
    costWithTax:      null,
    costTaxBreakdown: [],
  }),
  deriveMetalHechuraBreakdown: () => null,
  resolveShippingAmount:       () => 0,
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
vi.mock("../../payments/payments.service.js", () => ({
  getCheckoutPreview: vi.fn().mockResolvedValue(null),
}));
vi.mock("../../coupons/coupons.service.js", () => ({
  validateCoupon: vi.fn().mockResolvedValue({ valid: false }),
}));

import { previewSale, type SalePreviewLineInput } from "../sales.service.js";
import type { CostLineOverride } from "../../../lib/pricing-engine/pricing-engine.js";

const D = Prisma.Decimal;

// ── Helpers ─────────────────────────────────────────────────────────────────

function fakeSalePriceResult(overrides: Record<string, any> = {}) {
  return {
    unitPrice:                new D("800"),
    basePrice:                new D("1000"),
    quantityDiscountAmount:   new D("0"),
    promotionDiscountAmount:  new D("0"),
    discountAmount:           new D("0"),
    priceSource:              "PRICE_LIST",
    baseSource:               "PRICE_LIST",
    unitCost:                 new D("400"),
    unitMargin:               new D("400"),
    marginPercent:            new D("50"),
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
    totalWithTax:             new D("800"),
    taxExemptByEntity:        false,
    // F1.4 G5 #11-A — el motor devuelve los overrides aplicados.
    costLineOverridesApplied: [],
    debugWarnings:            [],
    ...overrides,
  };
}

function fakeSnapshot(overrides: Record<string, any> = {}) {
  return {
    unitPrice:            800,
    basePrice:            1000,
    discountAmount:       0,
    taxAmount:            0,
    totalWithTax:         800,
    priceSource:          "PRICE_LIST",
    baseSource:           "PRICE_LIST",
    unitCost:             400,
    unitMargin:           400,
    marginPercent:        50,
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

beforeEach(() => {
  vi.clearAllMocks();

  mockPrisma.article.findMany.mockResolvedValue([{
    id: "a1", categoryId: null, brand: null,
    mermaPercent: null, manualTaxIds: [],
    manualAdjustmentKind: null, manualAdjustmentType: null, manualAdjustmentValue: null,
    category: null, costComposition: [],
  }]);
  mockPrisma.articleVariant.findMany.mockResolvedValue([]);
  mockPrisma.articleGroupItem.findMany.mockResolvedValue([]);
  mockPrisma.salesChannel.findFirst.mockResolvedValue(null);
  mockPrisma.coupon.findFirst.mockResolvedValue(null);
  mockPrisma.commercialEntity.findFirst.mockResolvedValue(null);
  mockPrisma.priceList.findMany.mockResolvedValue([]);
  mockPrisma.promotion.findMany.mockResolvedValue([]);
  mockPrisma.currency.findUnique.mockResolvedValue(null);
  mockPrisma.jewelry.findUnique.mockResolvedValue({
    id: "j1", name: "J", legalName: "", cuit: "", ivaCondition: "", email: "",
    street: "", number: "", floor: "", apartment: "", city: "", province: "",
    country: "", postalCode: "", logoUrl: "",
  });

  mockEvaluatePricingPolicy.mockResolvedValue([]);
  mockBuildBatchCostContext.mockResolvedValue({
    baseCurrencyId: "cur-1", defaultMermaPercent: null,
    metalVariantData: new Map(), rateMap: new Map(),
  });
  mockCalculateCostFromLines.mockResolvedValue({
    value: new D("400"), mode: "COST_LINES", partial: false, breakdown: null, steps: [],
  });
  mockComputeLineTaxes.mockResolvedValue({ taxBreakdown: [], taxAmount: new D("0") });
  mockApplyChannel.mockReturnValue({
    baseAmount: 800, channelAmount: 0, finalAmount: 800,
    channelName: "", channelId: "",
  });
  mockApplyCoupon.mockReturnValue({
    baseAmount: 800, discountAmount: 0, finalAmount: 800,
    couponId: "", couponCode: "", couponName: "",
    discountType: "PERCENTAGE", discountValue: 0, applied: false,
  });
  mockBuildPricingSnapshot.mockImplementation((res: any) => fakeSnapshot({
    unitPrice: res.unitPrice?.toNumber?.() ?? null,
    basePrice: res.basePrice?.toNumber?.() ?? null,
  }));
  mockComputeSaleDocTotals.mockImplementation((input: any) => {
    const subtotal = input.lines.reduce((s: number, l: any) => s + l.lineTotal, 0);
    const taxAmount = input.lines.reduce((s: number, l: any) => s + l.lineTaxAmount, 0);
    return {
      subtotalBeforeDiscounts:    input.lines.reduce((s: number, l: any) => s + (l.basePrice * l.quantity), 0),
      lineDiscountAmount:         0,
      subtotalAfterLineDiscounts: subtotal,
      channelAdjustmentAmount:    0,
      couponDiscountAmount:       0,
      paymentAdjustmentAmount:    0,
      shippingAmount:             0,
      globalDiscountAmount:       0,
      taxableBase:                subtotal,
      taxAmount,
      roundingAdjustment:         0,
      totalBeforeTax:             subtotal,
      totalWithTax:               subtotal + taxAmount,
      channelResult: { baseAmount: subtotal, channelAmount: 0, finalAmount: subtotal, channelName: "", channelId: "" },
      couponResult:  { baseAmount: subtotal, discountAmount: 0, finalAmount: subtotal, couponId: "", couponCode: "", couponName: "", discountType: "PERCENTAGE", discountValue: 0, applied: false },
      total:                      subtotal + taxAmount,
      legacyCouponOnlyDiscount:   0,
      sourceTrace:                [],
    };
  });
});

// ────────────────────────────────────────────────────────────────────────────
// 1. previewSale forwardea costLineOverrides al motor
// ────────────────────────────────────────────────────────────────────────────

describe("previewSale — Fase 1: plumbing de costLineOverrides", () => {
  it("forwardea el array sin transformaciones cuando viene en la línea", async () => {
    mockResolveFinalSalePrice.mockResolvedValue(fakeSalePriceResult());

    const overrides: CostLineOverride[] = [
      {
        costLineId:        "cl-metal-1",
        type:              "METAL",
        quantityOverride:  3.2,
        mermaPercentOverride: 1.5,
      },
      {
        costLineId:    "cl-hechura-1",
        type:          "HECHURA",
        unitValueOverride: 1500,
        adjustmentKind:    "BONUS",
        adjustmentType:    "PERCENTAGE",
        adjustmentValue:   10,
      },
    ];

    const line: SalePreviewLineInput = {
      articleId:         "a1",
      variantId:         null,
      quantity:          1,
      costLineOverrides: overrides,
    };

    await previewSale("j1", { lines: [line], clientId: null });

    expect(mockResolveFinalSalePrice).toHaveBeenCalledTimes(1);
    const opts = mockResolveFinalSalePrice.mock.calls[0][1];
    // El array llega EXACTAMENTE igual al motor — sin clones, sin reordenes.
    expect(opts.costLineOverrides).toBe(overrides);
  });

  it("manda undefined cuando la línea no trae overrides", async () => {
    mockResolveFinalSalePrice.mockResolvedValue(fakeSalePriceResult());

    await previewSale("j1", {
      lines: [{ articleId: "a1", variantId: null, quantity: 1 }],
      clientId: null,
    });

    const opts = mockResolveFinalSalePrice.mock.calls[0][1];
    expect(opts.costLineOverrides).toBeUndefined();
  });

  it("convive con los overrides legacy (gramsOverride / hechuraOverrideAmount)", async () => {
    mockResolveFinalSalePrice.mockResolvedValue(fakeSalePriceResult());

    const overrides: CostLineOverride[] = [
      { costLineId: "cl-metal-1", type: "METAL", quantityOverride: 5 },
    ];

    await previewSale("j1", {
      lines: [{
        articleId:             "a1",
        variantId:             null,
        quantity:              1,
        gramsOverride:         10,        // legacy
        hechuraOverrideAmount: 999,       // legacy
        costLineOverrides:     overrides, // explicit
      }],
      clientId: null,
    });

    const opts = mockResolveFinalSalePrice.mock.calls[0][1];
    // Los 3 viajan al motor — el motor decide la precedencia (explicit gana
    // por costLineId via `unifyCostLineOverrides`).
    expect(opts.gramsOverride).toBe(10);
    expect(opts.hechuraOverrideAmount).toBe(999);
    expect(opts.costLineOverrides).toBe(overrides);
  });
});

// ────────────────────────────────────────────────────────────────────────────
// 2. Override modifica el total del preview (end-to-end via mock del motor)
// ────────────────────────────────────────────────────────────────────────────

describe("previewSale — Fase 1: override modifica total del preview", () => {
  it("dos previews con costLineOverrides distintos producen distintos totales", async () => {
    // El mock del motor responde con unitPrice distinto según los overrides
    // que recibe — simulando el efecto real del motor (que sí hace la math).
    mockResolveFinalSalePrice.mockImplementation((_jid: string, opts: any) => {
      const ovs: CostLineOverride[] = opts?.costLineOverrides ?? [];
      const metalQty = ovs.find((o) => o.type === "METAL")?.quantityOverride ?? 1;
      // Precio unitario sintético: cuanto más metal, más caro.
      const unit = 800 + (Number(metalQty) - 1) * 100;
      return Promise.resolve(fakeSalePriceResult({
        unitPrice:    new D(String(unit)),
        basePrice:    new D(String(unit)),
        totalWithTax: new D(String(unit)),
      }));
    });

    const baseLine: SalePreviewLineInput = {
      articleId: "a1", variantId: null, quantity: 1,
    };

    const out1 = await previewSale("j1", { lines: [{ ...baseLine }], clientId: null });
    const out2 = await previewSale("j1", {
      lines: [{
        ...baseLine,
        costLineOverrides: [
          { costLineId: "cl-metal-1", type: "METAL", quantityOverride: 3 },
        ],
      }],
      clientId: null,
    });

    expect(out1.total).toBe(800);
    expect(out2.total).toBe(1000);  // 800 + (3 - 1) * 100
    expect(out2.total).not.toBe(out1.total);
  });
});

// ────────────────────────────────────────────────────────────────────────────
// 3. Paridad de plumbing: lo que el endpoint pasa al motor coincide con lo
//    que recibiría una llamada directa al motor con los mismos inputs.
// ────────────────────────────────────────────────────────────────────────────

describe("previewSale — Fase 1: paridad de plumbing motor vs endpoint", () => {
  it("la firma de costLineOverrides en opts es idéntica a la del input", async () => {
    mockResolveFinalSalePrice.mockResolvedValue(fakeSalePriceResult());

    const overrides: CostLineOverride[] = [
      { costLineId: "cl-1", type: "METAL", quantityOverride: 2.5, mermaPercentOverride: 0.8 },
      { costLineId: "cl-2", type: "PRODUCT", unitValueOverride: 50, adjustmentKind: "SURCHARGE", adjustmentType: "FIXED_AMOUNT", adjustmentValue: 5 },
    ];

    await previewSale("j1", {
      lines: [{ articleId: "a1", variantId: null, quantity: 1, costLineOverrides: overrides }],
      clientId: null,
    });

    const opts = mockResolveFinalSalePrice.mock.calls[0][1];
    // Identidad referencial — ningún copy/transform por el camino.
    expect(opts.costLineOverrides).toBe(overrides);
    expect(opts.costLineOverrides).toEqual([
      { costLineId: "cl-1", type: "METAL",   quantityOverride: 2.5, mermaPercentOverride: 0.8 },
      { costLineId: "cl-2", type: "PRODUCT", unitValueOverride: 50,
        adjustmentKind: "SURCHARGE", adjustmentType: "FIXED_AMOUNT", adjustmentValue: 5 },
    ]);
  });
});
