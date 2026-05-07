// src/modules/sales/__tests__/preview-shipping-input.test.ts
// =============================================================================
// SPRINT 3 — sales/preview acepta `shipping: { mode, value, weight }` crudo.
//
// POLICY.md §5 — el frontend envía solo los inputs del usuario; el backend
// resuelve el monto vía el helper único `resolveShippingAmount`.
// `shippingAmount` legacy queda como fallback hasta que todos los clients
// migren.
// =============================================================================

import { describe, it, expect, vi, beforeEach } from "vitest";
import { Prisma } from "@prisma/client";

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

vi.mock("../../../lib/pricing-engine/pricing-engine.js", async () => {
  // Importamos el real para que `resolveShippingAmount` use la
  // implementación real (es lo que estamos validando).
  const real = await vi.importActual<any>("../../../lib/pricing-engine/pricing-engine.js");
  return {
    ...real,
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
      costBase: null, costTaxAmount: null, costWithTax: null, costTaxBreakdown: [],
    }),
    deriveMetalHechuraBreakdown: () => null,
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

import { previewSale } from "../sales.service.js";

const D = Prisma.Decimal;

function fakeSalePriceResult(overrides: Record<string, any> = {}) {
  return {
    unitPrice:                new D("1000"),
    basePrice:                new D("1000"),
    quantityDiscountAmount:   new D("0"),
    promotionDiscountAmount:  new D("0"),
    customerDiscountAmount:   null,
    discountAmount:           new D("0"),
    priceSource:              "PRICE_LIST",
    baseSource:               "PRICE_LIST",
    unitCost:                 new D("500"),
    unitMargin:               new D("500"),
    marginPercent:            new D("100"),
    costPartial:              false,
    costMode:                 "COST_LINES",
    partial:                  false,
    appliedPriceListId:       "pl-1",
    appliedPriceListName:     "Lista",
    appliedPriceListMode:     "MARGIN_TOTAL",
    appliedPromotionId:       null,
    appliedPromotionName:     null,
    appliedDiscountId:        null,
    steps:                    [],
    alerts:                   [],
    policy:                   { canConfirm: true, blockingAlerts: [] },
    stackingMode:             "NONE",
    metalHechuraBreakdown:    null,
    componentSaleBreakdown:   null,
    taxAmount:                new D("0"),
    taxBreakdown:             [],
    totalWithTax:             new D("1000"),
    taxExemptByEntity:        false,
    appliedRounding:          null,
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

  mockResolveFinalSalePrice.mockResolvedValue(fakeSalePriceResult());
  mockBuildPricingSnapshot.mockReturnValue({
    snapshotVersion: 3,
    unitPrice: 1000, basePrice: 1000, discountAmount: 0,
    taxAmount: 0, totalWithTax: 1000,
    priceSource: "PRICE_LIST", baseSource: "PRICE_LIST",
    unitCost: 500, unitMargin: 500, marginPercent: 100,
    costPartial: false, costMode: "COST_LINES",
    partial: false, appliedPriceListId: "pl-1",
    appliedPriceListName: "Lista", appliedPriceListMode: "MARGIN_TOTAL",
    appliedPromotionId: null, appliedPromotionName: null, appliedDiscountId: null,
    quantityDiscountAmount: 0, promotionDiscountAmount: 0, customerDiscountAmount: null,
    metalHechuraBreakdown: null, costOverrideContext: undefined,
    resolvedAt: "2026-05-01T00:00:00.000Z",
  });
  mockCalculateCostFromLines.mockResolvedValue({
    value: new D("500"), mode: "COST_LINES", partial: false, breakdown: null, steps: [],
  });
  mockBuildBatchCostContext.mockResolvedValue({
    baseCurrencyId: "cur-1", defaultMermaPercent: null,
    metalVariantData: new Map(), rateMap: new Map(),
  });
  mockComputeLineTaxes.mockResolvedValue({ taxBreakdown: [], taxAmount: new D("0") });
  mockEvaluatePricingPolicy.mockResolvedValue([]);
  mockApplyChannel.mockReturnValue({ baseAmount: 1000, channelAmount: 0, finalAmount: 1000, channelName: "", channelId: "" });
  mockApplyCoupon.mockReturnValue({ baseAmount: 1000, discountAmount: 0, finalAmount: 1000, couponId: "", couponCode: "", couponName: "", discountType: "PERCENTAGE", discountValue: 0, applied: false });
  mockBuildBalanceBreakdown.mockReturnValue(null);
  mockComputeSaleDocTotals.mockImplementation((input: any) => ({
    subtotalBeforeDiscounts:    1000,
    lineDiscountAmount:         0,
    subtotalAfterLineDiscounts: 1000,
    channelAdjustmentAmount:    0,
    couponDiscountAmount:       0,
    paymentAdjustmentAmount:    0,
    shippingAmount:             input.shippingAmount ?? 0,
    globalDiscountAmount:       0,
    taxableBase:                1000,
    taxAmount:                  0,
    roundingAdjustment:         0,
    totalBeforeTax:             1000,
    totalWithTax:               1000 + (input.shippingAmount ?? 0),
    channelResult: { baseAmount: 1000, channelAmount: 0, finalAmount: 1000, channelName: "", channelId: "" },
    couponResult:  { baseAmount: 1000, discountAmount: 0, finalAmount: 1000, couponId: "", couponCode: "", couponName: "", discountType: "PERCENTAGE", discountValue: 0, applied: false },
    total:                      1000 + (input.shippingAmount ?? 0),
    legacyCouponOnlyDiscount:   0,
    sourceTrace:                [],
  }));
});

// ─────────────────────────────────────────────────────────────────────────────

describe("previewSale — input.shipping crudo (Sprint 3)", () => {
  it("shipping mode=FIXED resuelve shippingAmount en backend", async () => {
    await previewSale("j1", {
      lines: [{ articleId: "a1", variantId: null, quantity: 1 }],
      clientId: null,
      shipping: { mode: "FIXED", value: 250, weight: null },
    });

    expect(mockComputeSaleDocTotals).toHaveBeenCalledTimes(1);
    const call = mockComputeSaleDocTotals.mock.calls[0][0];
    expect(call.shippingAmount).toBe(250);
  });

  it("shipping mode=BY_WEIGHT con value y weight resuelve precio × peso", async () => {
    await previewSale("j1", {
      lines: [{ articleId: "a1", variantId: null, quantity: 1 }],
      clientId: null,
      shipping: { mode: "BY_WEIGHT", value: 100, weight: 3 },
    });

    const call = mockComputeSaleDocTotals.mock.calls[0][0];
    expect(call.shippingAmount).toBe(300);
  });

  it("shipping mode=FREE → shippingAmount = 0", async () => {
    await previewSale("j1", {
      lines: [{ articleId: "a1", variantId: null, quantity: 1 }],
      clientId: null,
      shipping: { mode: "FREE", value: null, weight: null },
    });

    const call = mockComputeSaleDocTotals.mock.calls[0][0];
    expect(call.shippingAmount).toBe(0);
  });

  it("input.shipping prevalece sobre input.shippingAmount cuando vienen ambos", async () => {
    await previewSale("j1", {
      lines: [{ articleId: "a1", variantId: null, quantity: 1 }],
      clientId: null,
      shippingAmount: 999,                          // legacy ignorado
      shipping: { mode: "FIXED", value: 100, weight: null },
    });

    const call = mockComputeSaleDocTotals.mock.calls[0][0];
    expect(call.shippingAmount).toBe(100);
  });

  it("sin shipping crudo, shippingAmount legacy sigue funcionando", async () => {
    await previewSale("j1", {
      lines: [{ articleId: "a1", variantId: null, quantity: 1 }],
      clientId: null,
      shippingAmount: 175,
    });

    const call = mockComputeSaleDocTotals.mock.calls[0][0];
    expect(call.shippingAmount).toBe(175);
  });

  it("sin shipping ni shippingAmount → 0", async () => {
    await previewSale("j1", {
      lines: [{ articleId: "a1", variantId: null, quantity: 1 }],
      clientId: null,
    });

    const call = mockComputeSaleDocTotals.mock.calls[0][0];
    expect(call.shippingAmount).toBe(0);
  });
});
