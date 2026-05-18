// src/modules/sales/__tests__/preview-applies-to-override-per-line.test.ts
// =============================================================================
// Contrato "Aplica a" independiente del valor, end-to-end en previewSale:
//   · `manualDiscountAppliesToOverride` viaja a resolveFinalSalePrice como
//     `discountAppliesToOverride` (POR LÍNEA).
//   · `manualTaxAppliesToOverride` recalcula el impuesto HEREDADO sobre esa
//     base (computeLineTaxes REAL) SIN override de valor → el preview cambia
//     al toque aunque la tasa siga configurada.
//   · Dos líneas del mismo artículo: una hereda, otra rebasea → distinto.
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
const mockComputeSaleDocTotals   = vi.hoisted(() => vi.fn());

vi.mock("../../../lib/pricing-engine/pricing-engine.js", async (importActual) => {
  const actual = await importActual<any>();
  return {
    ...actual,
    computeLineTaxes:          actual.computeLineTaxes, // REAL
    resolveFinalSalePrice:     (...a: any[]) => mockResolveFinalSalePrice(...a),
    buildPricingSnapshot:      (...a: any[]) => mockBuildPricingSnapshot(...a),
    calculateCostFromLines:    (...a: any[]) => mockCalculateCostFromLines(...a),
    buildBatchCostContext:     (...a: any[]) => mockBuildBatchCostContext(...a),
    evaluatePricingPolicy:     (...a: any[]) => mockEvaluatePricingPolicy(...a),
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
const UNIT = 1000;
const HECHURA_SALE = 600; // base HECHURA del metalHechuraBreakdown

beforeEach(() => {
  vi.clearAllMocks();
  mockPrisma.article.findMany.mockResolvedValue([{
    id: "ART-1", categoryId: null, brand: null, mermaPercent: null,
    manualTaxIds: ["iva-21"],
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
  mockPrisma.tax.findMany.mockResolvedValue([{
    id: "iva-21", name: "IVA", code: "IVA", taxType: "VAT",
    calculationType: "PERCENTAGE", applyOn: "TOTAL",
    rate: new D("21"), fixedAmount: null, validFrom: null, validTo: null,
  }]);

  mockEvaluatePricingPolicy.mockResolvedValue([]);
  mockBuildBatchCostContext.mockResolvedValue({
    baseCurrencyId: "cur-1", defaultMermaPercent: null,
    metalVariantData: new Map(), rateMap: new Map(),
  });
  mockCalculateCostFromLines.mockResolvedValue({
    value: new D("0"), mode: "NONE", partial: true, breakdown: null, steps: [],
  });
  mockBuildPricingSnapshot.mockImplementation((res: any) => ({
    unitPrice: res.unitPrice?.toNumber?.() ?? UNIT, basePrice: UNIT,
    discountAmount: 0, taxAmount: 0, totalWithTax: UNIT,
    priceSource: "PRICE_LIST", baseSource: "PRICE_LIST",
    unitCost: null, unitMargin: null, marginPercent: null,
    costPartial: true, costMode: "NONE", partial: false,
    appliedPriceListId: null, appliedPriceListName: null,
    appliedPromotionId: null, appliedPromotionName: null, appliedDiscountId: null,
    resolvedAt: "2026-05-17T00:00:00.000Z",
  }));
  mockResolveFinalSalePrice.mockResolvedValue({
    unitPrice: new D(String(UNIT)), basePrice: new D(String(UNIT)),
    quantityDiscountAmount: new D("0"), promotionDiscountAmount: new D("0"),
    discountAmount: new D("0"), priceSource: "PRICE_LIST", baseSource: "PRICE_LIST",
    unitCost: null, unitMargin: null, marginPercent: null, costPartial: true,
    costMode: "NONE", partial: false, appliedPriceListId: null,
    appliedPriceListName: null, appliedPromotionId: null, appliedPromotionName: null,
    appliedDiscountId: null, steps: [], alerts: [],
    policy: { canConfirm: true, blockingAlerts: [] }, stackingMode: "NONE",
    // Para que la base HECHURA del recompute de impuestos exista.
    metalHechuraBreakdown: { metalCost: 0, metalSale: 400, metalMarginPct: 0,
      hechuraCost: 0, hechuraSale: HECHURA_SALE, hechuraMarginPct: 0 },
    taxAmount: new D("0"), taxBreakdown: [],
    totalWithTax: new D(String(UNIT)), taxExemptByEntity: false,
  });
  mockComputeSaleDocTotals.mockImplementation((input: any) => {
    const subtotal = input.lines.reduce((s: number, l: any) => s + l.lineTotal, 0);
    const tax      = input.lines.reduce((s: number, l: any) => s + l.lineTaxAmount, 0);
    return {
      subtotalBeforeDiscounts: subtotal, lineDiscountAmount: 0,
      subtotalAfterLineDiscounts: subtotal, channelAdjustmentAmount: 0,
      couponDiscountAmount: 0, paymentAdjustmentAmount: 0, shippingAmount: 0,
      globalDiscountAmount: 0, taxableBase: subtotal, taxAmount: tax,
      roundingAdjustment: 0, totalBeforeTax: subtotal,
      totalWithTax: subtotal + tax, total: subtotal + tax,
      channelResult: null, couponResult: null, legacyCouponOnlyDiscount: 0, sourceTrace: [],
    };
  });
});

describe("previewSale — override de base 'Aplica a' independiente del valor", () => {
  it("forwardea manualDiscountAppliesToOverride por línea a resolveFinalSalePrice", async () => {
    await previewSale("j1", {
      lines: [
        { articleId: "ART-1", variantId: null, quantity: 1 },
        { articleId: "ART-1", variantId: null, quantity: 1,
          manualDiscountAppliesToOverride: "HECHURA" },
      ],
      clientId: null,
    });
    const calls = mockResolveFinalSalePrice.mock.calls;
    expect(calls[0][1].discountAppliesToOverride).toBeNull();
    expect(calls[1][1].discountAppliesToOverride).toBe("HECHURA");
  });

  it("manualTaxAppliesToOverride recalcula el IVA heredado sobre esa base (sin override de valor)", async () => {
    const out = await previewSale("j1", {
      lines: [
        // Línea A: hereda → IVA 21% sobre TOTAL (1000) = 210.
        { articleId: "ART-1", variantId: null, quantity: 1 },
        // Línea B: misma, base → HECHURA → IVA 21% sobre 600 = 126.
        { articleId: "ART-1", variantId: null, quantity: 1,
          manualTaxAppliesToOverride: "HECHURA" },
      ],
      clientId: null,
    });
    expect(out.lines[0].lineTaxAmount).toBeCloseTo(UNIT * 0.21, 0);
    expect(out.lines[1].lineTaxAmount).toBeCloseTo(HECHURA_SALE * 0.21, 0);
    expect(out.lines[0].lineTaxAmount).not.toBe(out.lines[1].lineTaxAmount);
    // La tasa NO se tocó (sigue 21) — solo cambió la base.
    expect((out.lines[1].taxBreakdown as any[])[0].rate).toBe(21);
  });
});
