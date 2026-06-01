// src/modules/sales/__tests__/confirm-with-shipping-and-global-discount.test.ts
//
// Etapa 1.1 — Verifica que `confirmSale` reaplica los 3 ajustes a nivel
// documento que el DRAFT persistió:
//   · shippingAmount        (monto ya resuelto)
//   · globalDiscountAmount  (recomputado contra el subtotal de líneas)
//   · paymentAdjustmentAmount (vía getCheckoutPreview)
//
// Antes confirmSale los pasaba en 0 al motor y el total emitido divergía
// del previsualizado. Estos tests bloquean la regresión.

import { describe, it, expect, vi, beforeEach } from "vitest";
import { Prisma } from "@prisma/client";

// ── Mocks Prisma ────────────────────────────────────────────────────────────
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
  paymentMethod:      { findFirst: vi.fn() },
  $transaction:       vi.fn(),
}));
vi.mock("../../../lib/prisma.js", () => ({ prisma: mockPrisma }));

// ── Mocks pricing-engine ────────────────────────────────────────────────────
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
    costBase: null, costTaxAmount: null, costWithTax: null, costTaxBreakdown: [],
  }),
  deriveMetalHechuraBreakdown: () => null,
  // POLICY §Tax.3 — porción FIXED del impuesto (no escala con descuentos doc).
  sumFixedTaxComponent: () => 0,
  resolveShippingAmount: (input: any) => {
    if (!input || !input.mode) return null;
    if (input.mode === "FREE")  return { mode: "FREE",  amount: 0 };
    if (input.mode === "FIXED") return { mode: "FIXED", amount: Math.round(Number(input.value) * 100) / 100 };
    if (input.mode === "BY_WEIGHT") {
      return { mode: "BY_WEIGHT", amount: Math.round(Number(input.value) * Number(input.weight) * 100) / 100 };
    }
    return null;
  },
}));

vi.mock("../../../lib/pricing-composition.js", () => ({
  buildComposition:               () => ({ metal: null, hechura: null, metals: [], hechuras: [], products: [], services: [], taxes: [] }),
  fetchMetalVariantInfo:          vi.fn().mockResolvedValue({ purity: null, purityLabel: null, metalName: null }),
  fetchMetalVariantInfoMap:       vi.fn().mockResolvedValue(new Map()),
  resolveMetalVariantIdFromResult: () => null,
  getAppliedMermaPercent:         () => null,
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
  getCheckoutPreview: vi.fn(),
}));
vi.mock("../../coupons/coupons.service.js", () => ({
  validateCoupon: vi.fn().mockResolvedValue({ valid: false }),
}));

import { confirmSale } from "../sales.service.js";

const D = Prisma.Decimal;

function fakeSnapshot(overrides: Record<string, any> = {}) {
  return {
    unitPrice:            1000,
    basePrice:            1000,
    discountAmount:       0,
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
    appliedPriceListId:   null,
    appliedPriceListName: null,
    appliedPromotionId:   null,
    appliedPromotionName: null,
    appliedDiscountId:    null,
    resolvedAt:           "2026-05-26T00:00:00.000Z",
    ...overrides,
  };
}

function setupDefaults() {
  vi.clearAllMocks();
  mockPrisma.article.findMany.mockResolvedValue([]);
  mockPrisma.articleVariant.findMany.mockResolvedValue([]);
  mockPrisma.articleGroupItem.findMany.mockResolvedValue([]);
  // `confirmSale` invoca `getSale` al final → segunda llamada al findFirst.
  // Default seguro para que no falle con "Venta no encontrada".
  mockPrisma.sale.findFirst.mockResolvedValue({ id: "s1", lines: [] });
  mockPrisma.sale.update.mockResolvedValue({ id: "s1" });
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
  mockComputeLineTaxes.mockResolvedValue({
    taxBreakdown: [], taxAmount: new D("0"),
  });
  mockApplyChannel.mockReturnValue({
    baseAmount: 1000, channelAmount: 0, finalAmount: 1000,
    channelName: "", channelId: "",
  });
  mockApplyCoupon.mockReturnValue({
    baseAmount: 1000, discountAmount: 0, finalAmount: 1000,
    couponId: "", couponCode: "", couponName: "",
    discountType: "PERCENTAGE", discountValue: 0, applied: false,
  });
  mockBuildPricingSnapshot.mockImplementation((res: any) => fakeSnapshot({
    unitPrice: res.unitPrice?.toNumber() ?? null,
    basePrice: res.basePrice?.toNumber() ?? null,
  }));
}

function makeSaleWithAdjustments(over: Record<string, any> = {}) {
  return {
    id: "s1", code: "VTA-0001", status: "DRAFT" as const,
    clientId: null, warehouseId: null,
    subtotal: new D("1000"), discountAmount: new D("0"),
    taxAmount: new D("0"), total: new D("1000"), couponId: null,
    balanceModeOverride: null,
    // ── Etapa 1.1 — ajustes persistidos en el DRAFT ─────────────────────
    shippingAmount:      new D("200"),
    globalDiscountType:  "PERCENT" as const,
    globalDiscountValue: new D("10"),
    paymentMethodId:     "pm-1",
    paymentInstallments: 3,
    client: null, seller: null, channel: null,
    lines: [{
      id: "L1", articleId: "a1", variantId: null,
      quantity: new D("1"), unitPrice: new D("1000"), discountPct: new D("0"),
      lineTotal: new D("1000"),
      priceSource: "PRICE_LIST",
      appliedPriceListId: null, appliedPromotionId: null, appliedDiscountId: null,
      pricingSnapshot: fakeSnapshot({ unitPrice: 1000, basePrice: 1000 }),
    }],
    ...over,
  };
}

beforeEach(setupDefaults);

describe("confirmSale — ajustes a nivel documento (Etapa 1.1)", () => {
  it("pasa al motor el shippingAmount persistido en el DRAFT", async () => {
    mockPrisma.article.findMany.mockResolvedValue([{
      id: "a1", categoryId: null, brand: null,
      stockMode: "STOCK", mermaPercent: null, manualTaxIds: [],
      manualAdjustmentKind: null, manualAdjustmentType: null, manualAdjustmentValue: null,
      category: null, costComposition: [],
    }]);
    const { getCheckoutPreview } = await import("../../payments/payments.service.js");
    (getCheckoutPreview as any).mockResolvedValue(null);

    mockComputeSaleDocTotals.mockImplementation((input: any) => ({
      subtotalBeforeDiscounts: 1000, lineDiscountAmount: 0,
      subtotalAfterLineDiscounts: 1000, channelAdjustmentAmount: 0,
      couponDiscountAmount: 0, paymentAdjustmentAmount: input.paymentAdjustmentAmount ?? 0,
      shippingAmount: input.shippingAmount ?? 0,
      globalDiscountAmount: input.globalDiscountAmount ?? 0,
      taxableBase: 1000, taxAmount: 0, roundingAdjustment: 0,
      totalBeforeTax: 1000, totalWithTax: 1000,
      channelResult: { baseAmount: 1000, channelAmount: 0, finalAmount: 1000, channelName: "", channelId: "" },
      couponResult:  { baseAmount: 1000, discountAmount: 0, finalAmount: 1000, couponId: "", couponCode: "", couponName: "", discountType: "PERCENTAGE", discountValue: 0, applied: false },
      total: 1000 + (input.shippingAmount ?? 0) - (input.globalDiscountAmount ?? 0) + (input.paymentAdjustmentAmount ?? 0),
      legacyCouponOnlyDiscount: 0, sourceTrace: [],
    }));

    mockPrisma.sale.findFirst.mockResolvedValueOnce(makeSaleWithAdjustments({
      // Sin globalDiscount ni paymentMethod — solo shipping.
      globalDiscountType: null, globalDiscountValue: null,
      paymentMethodId: null, paymentInstallments: null,
    }));
    const txMock: any = {
      saleLine:           { update: vi.fn() },
      sale:               { update: vi.fn().mockResolvedValue({}) },
      articleMovement:    { count: vi.fn().mockResolvedValue(0), create: vi.fn().mockResolvedValue({ id: "mov1" }) },
      entityBalanceEntry: { createMany: vi.fn() },
      couponRedemption:   { create: vi.fn() },
    };
    mockPrisma.$transaction.mockImplementation(async (cb: any) => cb(txMock));

    await confirmSale("s1", "j1", "u1");

    expect(mockComputeSaleDocTotals).toHaveBeenCalledTimes(1);
    const input = mockComputeSaleDocTotals.mock.calls[0][0];
    expect(input.shippingAmount).toBe(200);
    expect(input.globalDiscountAmount).toBe(0);
    expect(input.paymentAdjustmentAmount).toBe(0);
  });

  it("recomputa globalDiscountAmount contra el subtotal de líneas (PERCENT)", async () => {
    mockPrisma.article.findMany.mockResolvedValue([{
      id: "a1", categoryId: null, brand: null,
      stockMode: "STOCK", mermaPercent: null, manualTaxIds: [],
      manualAdjustmentKind: null, manualAdjustmentType: null, manualAdjustmentValue: null,
      category: null, costComposition: [],
    }]);
    const { getCheckoutPreview } = await import("../../payments/payments.service.js");
    (getCheckoutPreview as any).mockResolvedValue(null);

    mockComputeSaleDocTotals.mockImplementation((input: any) => ({
      subtotalBeforeDiscounts: 1000, lineDiscountAmount: 0,
      subtotalAfterLineDiscounts: 1000, channelAdjustmentAmount: 0,
      couponDiscountAmount: 0, paymentAdjustmentAmount: 0,
      shippingAmount: input.shippingAmount ?? 0,
      globalDiscountAmount: input.globalDiscountAmount ?? 0,
      taxableBase: 1000, taxAmount: 0, roundingAdjustment: 0,
      totalBeforeTax: 1000, totalWithTax: 1000,
      channelResult: { baseAmount: 1000, channelAmount: 0, finalAmount: 1000, channelName: "", channelId: "" },
      couponResult:  { baseAmount: 1000, discountAmount: 0, finalAmount: 1000, couponId: "", couponCode: "", couponName: "", discountType: "PERCENTAGE", discountValue: 0, applied: false },
      total: 1000 - (input.globalDiscountAmount ?? 0),
      legacyCouponOnlyDiscount: 0, sourceTrace: [],
    }));

    mockPrisma.sale.findFirst.mockResolvedValueOnce(makeSaleWithAdjustments({
      shippingAmount: null,
      // PERCENT 10 sobre subtotal 1000 → 100
      paymentMethodId: null, paymentInstallments: null,
    }));
    const txMock: any = {
      saleLine:           { update: vi.fn() },
      sale:               { update: vi.fn().mockResolvedValue({}) },
      articleMovement:    { count: vi.fn().mockResolvedValue(0), create: vi.fn().mockResolvedValue({ id: "mov1" }) },
      entityBalanceEntry: { createMany: vi.fn() },
      couponRedemption:   { create: vi.fn() },
    };
    mockPrisma.$transaction.mockImplementation(async (cb: any) => cb(txMock));

    await confirmSale("s1", "j1", "u1");
    const input = mockComputeSaleDocTotals.mock.calls[0][0];
    expect(input.globalDiscountAmount).toBe(100);
  });

  it("invoca getCheckoutPreview con la base post-canal/cupón y propaga el paymentAdjustmentAmount", async () => {
    mockPrisma.article.findMany.mockResolvedValue([{
      id: "a1", categoryId: null, brand: null,
      stockMode: "STOCK", mermaPercent: null, manualTaxIds: [],
      manualAdjustmentKind: null, manualAdjustmentType: null, manualAdjustmentValue: null,
      category: null, costComposition: [],
    }]);
    const { getCheckoutPreview } = await import("../../payments/payments.service.js");
    (getCheckoutPreview as any).mockResolvedValue({
      baseAmount: 1000, finalAmount: 1075, installments: 3, paymentMethodId: "pm-1",
    });

    mockComputeSaleDocTotals.mockImplementation((input: any) => ({
      subtotalBeforeDiscounts: 1000, lineDiscountAmount: 0,
      subtotalAfterLineDiscounts: 1000, channelAdjustmentAmount: 0,
      couponDiscountAmount: 0,
      paymentAdjustmentAmount: input.paymentAdjustmentAmount ?? 0,
      shippingAmount: 0, globalDiscountAmount: 0,
      taxableBase: 1000, taxAmount: 0, roundingAdjustment: 0,
      totalBeforeTax: 1000, totalWithTax: 1000 + (input.paymentAdjustmentAmount ?? 0),
      channelResult: { baseAmount: 1000, channelAmount: 0, finalAmount: 1000, channelName: "", channelId: "" },
      couponResult:  { baseAmount: 1000, discountAmount: 0, finalAmount: 1000, couponId: "", couponCode: "", couponName: "", discountType: "PERCENTAGE", discountValue: 0, applied: false },
      total: 1000 + (input.paymentAdjustmentAmount ?? 0),
      legacyCouponOnlyDiscount: 0, sourceTrace: [],
    }));

    mockPrisma.sale.findFirst.mockResolvedValueOnce(makeSaleWithAdjustments({
      shippingAmount: null,
      globalDiscountType: null, globalDiscountValue: null,
      // paymentMethodId "pm-1" + 3 cuotas
    }));
    const txMock: any = {
      saleLine:           { update: vi.fn() },
      sale:               { update: vi.fn().mockResolvedValue({}) },
      articleMovement:    { count: vi.fn().mockResolvedValue(0), create: vi.fn().mockResolvedValue({ id: "mov1" }) },
      entityBalanceEntry: { createMany: vi.fn() },
      couponRedemption:   { create: vi.fn() },
    };
    mockPrisma.$transaction.mockImplementation(async (cb: any) => cb(txMock));

    await confirmSale("s1", "j1", "u1");

    // getCheckoutPreview se invocó con paymentMethodId + cuotas del DRAFT.
    expect(getCheckoutPreview).toHaveBeenCalledWith("j1", expect.any(Number), "pm-1", 3);

    const input = mockComputeSaleDocTotals.mock.calls[0][0];
    expect(input.paymentAdjustmentAmount).toBe(75);  // 1075 - 1000
  });

  it("el total que se persiste en Sale incluye shipping + globalDiscount + paymentAdjustment", async () => {
    mockPrisma.article.findMany.mockResolvedValue([{
      id: "a1", categoryId: null, brand: null,
      stockMode: "STOCK", mermaPercent: null, manualTaxIds: [],
      manualAdjustmentKind: null, manualAdjustmentType: null, manualAdjustmentValue: null,
      category: null, costComposition: [],
    }]);
    const { getCheckoutPreview } = await import("../../payments/payments.service.js");
    // Recargo del 5% sobre la base real (no estático): así el cómputo de
    // `paymentAdjustmentAmount` en confirmSale converge sin importar la base.
    (getCheckoutPreview as any).mockImplementation(async (_j: string, base: number) => ({
      baseAmount:      base,
      finalAmount:     Math.round(base * 1.05 * 100) / 100,
      installments:    3,
      paymentMethodId: "pm-1",
    }));

    // Motor que respeta los 3 ajustes para producir un total realista.
    //   subtotal 1000 + shipping 200 − globalDiscount 100 + paymentAdj 50 = 1150
    mockComputeSaleDocTotals.mockImplementation((input: any) => {
      const total =
          1000
        + (input.shippingAmount ?? 0)
        - (input.globalDiscountAmount ?? 0)
        + (input.paymentAdjustmentAmount ?? 0);
      return {
        subtotalBeforeDiscounts:    1000,
        lineDiscountAmount:         0,
        subtotalAfterLineDiscounts: 1000,
        channelAdjustmentAmount:    0,
        couponDiscountAmount:       0,
        paymentAdjustmentAmount:    input.paymentAdjustmentAmount ?? 0,
        shippingAmount:             input.shippingAmount ?? 0,
        globalDiscountAmount:       input.globalDiscountAmount ?? 0,
        taxableBase:                1000,
        taxAmount:                  0,
        roundingAdjustment:         0,
        totalBeforeTax:             total,
        totalWithTax:               total,
        channelResult: { baseAmount: 1000, channelAmount: 0, finalAmount: 1000, channelName: "", channelId: "" },
        couponResult:  { baseAmount: 1000, discountAmount: 0, finalAmount: 1000, couponId: "", couponCode: "", couponName: "", discountType: "PERCENTAGE", discountValue: 0, applied: false },
        total,
        legacyCouponOnlyDiscount:   0,
        sourceTrace:                [],
      };
    });

    mockPrisma.sale.findFirst.mockResolvedValueOnce(makeSaleWithAdjustments());  // los 3 ajustes
    const txMock: any = {
      saleLine:           { update: vi.fn() },
      sale:               { update: vi.fn().mockResolvedValue({}) },
      articleMovement:    { count: vi.fn().mockResolvedValue(0), create: vi.fn().mockResolvedValue({ id: "mov1" }) },
      entityBalanceEntry: { createMany: vi.fn() },
      couponRedemption:   { create: vi.fn() },
    };
    mockPrisma.$transaction.mockImplementation(async (cb: any) => cb(txMock));

    await confirmSale("s1", "j1", "u1");

    // El motor recibió los 3 ajustes correctos.
    const motorInput = mockComputeSaleDocTotals.mock.calls[0][0];
    expect(motorInput.shippingAmount).toBe(200);
    expect(motorInput.globalDiscountAmount).toBe(100);
    expect(motorInput.paymentAdjustmentAmount).toBe(50);

    // El sale.update dentro de la TX persiste el total del motor (1150), no
    // el subtotal del DRAFT (1000).
    expect(txMock.sale.update).toHaveBeenCalledTimes(1);
    const updateArgs = txMock.sale.update.mock.calls[0][0];
    expect(updateArgs.data.total).toBe(1150);
    expect(updateArgs.data.status).toBe("CONFIRMED");
  });

  it("DRAFT sin ajustes → motor recibe 0 (back-compat con sales históricas)", async () => {
    mockPrisma.article.findMany.mockResolvedValue([{
      id: "a1", categoryId: null, brand: null,
      stockMode: "STOCK", mermaPercent: null, manualTaxIds: [],
      manualAdjustmentKind: null, manualAdjustmentType: null, manualAdjustmentValue: null,
      category: null, costComposition: [],
    }]);
    const { getCheckoutPreview } = await import("../../payments/payments.service.js");
    (getCheckoutPreview as any).mockResolvedValue(null);

    mockComputeSaleDocTotals.mockImplementation((input: any) => ({
      subtotalBeforeDiscounts: 1000, lineDiscountAmount: 0,
      subtotalAfterLineDiscounts: 1000, channelAdjustmentAmount: 0,
      couponDiscountAmount: 0,
      paymentAdjustmentAmount: input.paymentAdjustmentAmount ?? 0,
      shippingAmount: input.shippingAmount ?? 0,
      globalDiscountAmount: input.globalDiscountAmount ?? 0,
      taxableBase: 1000, taxAmount: 0, roundingAdjustment: 0,
      totalBeforeTax: 1000, totalWithTax: 1000,
      channelResult: { baseAmount: 1000, channelAmount: 0, finalAmount: 1000, channelName: "", channelId: "" },
      couponResult:  { baseAmount: 1000, discountAmount: 0, finalAmount: 1000, couponId: "", couponCode: "", couponName: "", discountType: "PERCENTAGE", discountValue: 0, applied: false },
      total: 1000, legacyCouponOnlyDiscount: 0, sourceTrace: [],
    }));

    mockPrisma.sale.findFirst.mockResolvedValueOnce(makeSaleWithAdjustments({
      shippingAmount:      null,
      globalDiscountType:  null,
      globalDiscountValue: null,
      paymentMethodId:     null,
      paymentInstallments: null,
    }));
    const txMock: any = {
      saleLine:           { update: vi.fn() },
      sale:               { update: vi.fn().mockResolvedValue({}) },
      articleMovement:    { count: vi.fn().mockResolvedValue(0), create: vi.fn().mockResolvedValue({ id: "mov1" }) },
      entityBalanceEntry: { createMany: vi.fn() },
      couponRedemption:   { create: vi.fn() },
    };
    mockPrisma.$transaction.mockImplementation(async (cb: any) => cb(txMock));

    await confirmSale("s1", "j1", "u1");

    const motorInput = mockComputeSaleDocTotals.mock.calls[0][0];
    expect(motorInput.shippingAmount).toBe(0);
    expect(motorInput.globalDiscountAmount).toBe(0);
    expect(motorInput.paymentAdjustmentAmount).toBe(0);
    expect(getCheckoutPreview).not.toHaveBeenCalled();
  });
});
