// src/modules/sales/__tests__/preview-discount-override-per-line.test.ts
// =============================================================================
// Auditoría Bonificación por línea (análoga a la del taxOverride).
//
// A diferencia del bug de impuestos, `previewSale` SÍ pasa
// `manualDiscountOverride` a `resolveFinalSalePrice` (no hay un segundo
// recompute que lo descarte). Este test fija ese contrato de punta a punta:
//   · el override de bonificación viaja POR LÍNEA al motor;
//   · 2 líneas del MISMO artículo con bonif distinta NO comparten resultado;
//   · limpiar (value 0) vuelve al precio de lista (no revive el anterior);
//   · PERCENT y AMOUNT (FIXED) se reenvían correctamente.
//
// `resolveFinalSalePrice` se stubea para APLICAR el descuento de forma
// determinística (echo): unitPrice = basePrice − descuento. La matemática
// real del override ya está cubierta por `g4-3-sale-pre-manual-discount`.
// =============================================================================

import { describe, it, expect, vi, beforeEach } from "vitest";
import { Prisma } from "@prisma/client";

const mockPrisma = vi.hoisted(() => ({
  article:          { findMany: vi.fn(), findFirst: vi.fn() },
  articleVariant:   { findMany: vi.fn() },
  articleGroupItem: { findMany: vi.fn() },
  salesChannel:     { findFirst: vi.fn() },
  coupon:           { findFirst: vi.fn() },
  commercialEntity: { findFirst: vi.fn() },
  priceList:        { findMany: vi.fn() },
  promotion:        { findMany: vi.fn() },
  currency:         { findUnique: vi.fn() },
  jewelry:          { findUnique: vi.fn() },
  tax:              { findMany: vi.fn() },
}));
vi.mock("../../../lib/prisma.js", () => ({ prisma: mockPrisma }));

const mockResolveFinalSalePrice  = vi.hoisted(() => vi.fn());
const mockBuildPricingSnapshot   = vi.hoisted(() => vi.fn());
const mockCalculateCostFromLines = vi.hoisted(() => vi.fn());
const mockBuildBatchCostContext  = vi.hoisted(() => vi.fn());
const mockEvaluatePricingPolicy  = vi.hoisted(() => vi.fn());
const mockComputeLineTaxes       = vi.hoisted(() => vi.fn());
const mockComputeSaleDocTotals   = vi.hoisted(() => vi.fn());

vi.mock("../../../lib/pricing-engine/pricing-engine.js", async (importActual) => {
  const actual = await importActual<any>();
  return {
    ...actual,
    resolveFinalSalePrice:     (...a: any[]) => mockResolveFinalSalePrice(...a),
    buildPricingSnapshot:      (...a: any[]) => mockBuildPricingSnapshot(...a),
    calculateCostFromLines:    (...a: any[]) => mockCalculateCostFromLines(...a),
    buildBatchCostContext:     (...a: any[]) => mockBuildBatchCostContext(...a),
    evaluatePricingPolicy:     (...a: any[]) => mockEvaluatePricingPolicy(...a),
    computeLineTaxes:          (...a: any[]) => mockComputeLineTaxes(...a),
    computeSaleDocumentTotals: (...a: any[]) => mockComputeSaleDocTotals(...a),
    computePurchaseTaxes: vi.fn().mockResolvedValue({
      costBase: null, costTaxAmount: null, costWithTax: null, costTaxBreakdown: [],
    }),
    deriveMetalHechuraBreakdown: () => null,
  };
});
vi.mock("../../../lib/pricing-composition.js", () => ({
  buildComposition: () => ({ metal: null, hechura: null, metals: [], hechuras: [], products: [], services: [], taxes: [] }),
  fetchMetalVariantInfo: vi.fn().mockResolvedValue({ purity: null, purityLabel: null, metalName: null }),
  fetchMetalVariantInfoMap: vi.fn().mockResolvedValue(new Map()),
  resolveMetalVariantIdFromResult: () => null,
  getAppliedMermaPercent: () => null,
  buildCatalogItemsMapForCostLines: vi.fn().mockResolvedValue(new Map()),
  buildCatalogItemsMapForSteps: vi.fn().mockResolvedValue(new Map()),
}));
vi.mock("../../../lib/pricing-engine/pricing-engine.currency.js", () => ({
  getBaseCurrencyId: vi.fn().mockResolvedValue(null),
}));
vi.mock("../../payments/payments.service.js", () => ({
  getCheckoutPreview: vi.fn().mockResolvedValue(null),
}));
vi.mock("../../coupons/coupons.service.js", () => ({
  validateCoupon: vi.fn().mockResolvedValue({ valid: false }),
}));

import { previewSale } from "../sales.service.js";

const D = Prisma.Decimal;
const BASE = 100_000;

beforeEach(() => {
  vi.clearAllMocks();

  mockPrisma.article.findMany.mockResolvedValue([{
    id: "ART-1", categoryId: null, brand: null, mermaPercent: null,
    manualTaxIds: [],
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
  mockPrisma.tax.findMany.mockResolvedValue([]);

  mockEvaluatePricingPolicy.mockResolvedValue([]);
  mockBuildBatchCostContext.mockResolvedValue({
    baseCurrencyId: "cur-1", defaultMermaPercent: null,
    metalVariantData: new Map(), rateMap: new Map(),
  });
  mockCalculateCostFromLines.mockResolvedValue({
    value: new D("0"), mode: "NONE", partial: true, breakdown: null, steps: [],
  });
  mockComputeLineTaxes.mockResolvedValue({ taxBreakdown: [], taxAmount: new D("0") });
  mockBuildPricingSnapshot.mockImplementation((res: any) => ({
    unitPrice: res.unitPrice?.toNumber?.() ?? BASE,
    basePrice: res.basePrice?.toNumber?.() ?? BASE,
    discountAmount: res.discountAmount?.toNumber?.() ?? 0,
    taxAmount: 0, totalWithTax: res.unitPrice?.toNumber?.() ?? BASE,
    priceSource: "PRICE_LIST", baseSource: "PRICE_LIST",
    unitCost: null, unitMargin: null, marginPercent: null,
    costPartial: true, costMode: "NONE", partial: false,
    appliedPriceListId: null, appliedPriceListName: null,
    appliedPromotionId: null, appliedPromotionName: null, appliedDiscountId: null,
    resolvedAt: "2026-05-17T00:00:00.000Z",
  }));

  // ECHO determinístico: aplica la bonificación sobre BASE.
  mockResolveFinalSalePrice.mockImplementation((_j: string, opts: any) => {
    const od = opts.manualDiscountOverride ?? null;
    let unit = BASE;
    let disc = 0;
    if (od && Number.isFinite(od.value) && od.value >= 0) {
      disc = od.mode === "PERCENT" ? (BASE * od.value) / 100 : od.value;
      unit = Math.max(0, BASE - disc);
    }
    return Promise.resolve({
      unitPrice: new D(String(unit)), basePrice: new D(String(BASE)),
      quantityDiscountAmount: new D("0"), promotionDiscountAmount: new D("0"),
      discountAmount: new D(String(disc)),
      priceSource: od ? "MANUAL_OVERRIDE" : "PRICE_LIST", baseSource: "PRICE_LIST",
      unitCost: null, unitMargin: null, marginPercent: null, costPartial: true,
      costMode: "NONE", partial: false, appliedPriceListId: null,
      appliedPriceListName: null, appliedPromotionId: null, appliedPromotionName: null,
      appliedDiscountId: null, steps: [], alerts: [],
      policy: { canConfirm: true, blockingAlerts: [] }, stackingMode: "NONE",
      metalHechuraBreakdown: null, taxAmount: new D("0"), taxBreakdown: [],
      totalWithTax: new D(String(unit)), taxExemptByEntity: false,
    });
  });

  mockComputeSaleDocTotals.mockImplementation((input: any) => {
    const subtotal = input.lines.reduce((s: number, l: any) => s + l.lineTotal, 0);
    const tax      = input.lines.reduce((s: number, l: any) => s + l.lineTaxAmount, 0);
    return {
      subtotalBeforeDiscounts: input.lines.reduce((s: number, l: any) => s + l.basePrice * l.quantity, 0),
      lineDiscountAmount: 0, subtotalAfterLineDiscounts: subtotal,
      channelAdjustmentAmount: 0, couponDiscountAmount: 0, paymentAdjustmentAmount: 0,
      shippingAmount: 0, globalDiscountAmount: 0, taxableBase: subtotal,
      taxAmount: tax, roundingAdjustment: 0, totalBeforeTax: subtotal,
      totalWithTax: subtotal + tax, total: subtotal + tax,
      channelResult: null, couponResult: null, legacyCouponOnlyDiscount: 0, sourceTrace: [],
    };
  });
});

describe("previewSale — Bonificación por línea (mismo artículo)", () => {
  it("forwardea manualDiscountOverride POR LÍNEA al pricing-engine", async () => {
    await previewSale("j1", {
      lines: [
        { articleId: "ART-1", variantId: null, quantity: 1 },
        { articleId: "ART-1", variantId: null, quantity: 1,
          manualDiscountOverride: { mode: "PERCENT", value: 10, appliesTo: "TOTAL" } },
        { articleId: "ART-1", variantId: null, quantity: 1,
          manualDiscountOverride: { mode: "PERCENT", value: 30, appliesTo: "TOTAL" } },
      ],
      clientId: null,
    });

    const calls = mockResolveFinalSalePrice.mock.calls;
    expect(calls).toHaveLength(3);
    expect(calls[0][1].manualDiscountOverride).toBeNull();
    expect(calls[1][1].manualDiscountOverride).toEqual({ mode: "PERCENT", value: 10, appliesTo: "TOTAL" });
    expect(calls[2][1].manualDiscountOverride).toEqual({ mode: "PERCENT", value: 30, appliesTo: "TOTAL" });
  });

  it("3 líneas mismo artículo: sin bonif / 10% / 30% → resultados distintos", async () => {
    const out = await previewSale("j1", {
      lines: [
        { articleId: "ART-1", variantId: null, quantity: 1 },
        { articleId: "ART-1", variantId: null, quantity: 1,
          manualDiscountOverride: { mode: "PERCENT", value: 10, appliesTo: "TOTAL" } },
        { articleId: "ART-1", variantId: null, quantity: 1,
          manualDiscountOverride: { mode: "PERCENT", value: 30, appliesTo: "TOTAL" } },
      ],
      clientId: null,
    });

    expect(out.lines[0].unitPrice).toBe(BASE);            // sin bonif
    expect(out.lines[1].unitPrice).toBe(BASE * 0.9);      // 10%
    expect(out.lines[2].unitPrice).toBe(BASE * 0.7);      // 30%
    expect(out.lines[0].lineTotalWithTax).toBe(BASE);
    expect(out.lines[1].lineTotalWithTax).toBe(BASE * 0.9);
    expect(out.lines[2].lineTotalWithTax).toBe(BASE * 0.7);
    // No comparten snapshot
    expect(out.lines[1].lineTotalWithTax).not.toBe(out.lines[2].lineTotalWithTax);
    // documentTotals reacciona
    expect(out.documentTotals.subtotalAfterLineDiscounts).toBe(BASE + BASE * 0.9 + BASE * 0.7);
  });

  it("limpiar bonificación (value 0) vuelve al precio de lista (no revive el anterior)", async () => {
    const out = await previewSale("j1", {
      lines: [
        { articleId: "ART-1", variantId: null, quantity: 1,
          manualDiscountOverride: { mode: "PERCENT", value: 0, appliesTo: "TOTAL" } },
      ],
      clientId: null,
    });
    expect(out.lines[0].unitPrice).toBe(BASE);
    expect(out.lines[0].lineDiscount).toBe(0);
    expect(out.lines[0].lineTotalWithTax).toBe(BASE);
  });

  it("AMOUNT (FIXED) se reenvía y aplica como monto fijo", async () => {
    const out = await previewSale("j1", {
      lines: [
        { articleId: "ART-1", variantId: null, quantity: 2,
          manualDiscountOverride: { mode: "AMOUNT", value: 15_000, appliesTo: "TOTAL" } },
      ],
      clientId: null,
    });
    expect(mockResolveFinalSalePrice.mock.calls[0][1].manualDiscountOverride)
      .toEqual({ mode: "AMOUNT", value: 15_000, appliesTo: "TOTAL" });
    expect(out.lines[0].unitPrice).toBe(BASE - 15_000);
    expect(out.lines[0].lineTotal).toBe((BASE - 15_000) * 2);
  });
});
