// src/modules/sales/__tests__/preview-tax-override-per-line.test.ts
// =============================================================================
// Bug confirmado por logs: previewSale recibía `taxOverride` por línea pero
// el recompute interno de impuestos OMITÍA el 9º argumento de
// `computeLineTaxes`, así que el motor caía al IVA heredado (manualTaxIds) y
// el override del operador se perdía.
//
// Este test usa el `computeLineTaxes` REAL (no mockeado) y solo stubea
// `resolveFinalSalePrice` para fijar un unitPrice determinístico. Verifica
// el MISMO artículo en 3 líneas:
//   · Línea 1: sin override            → IVA heredado 21%.
//   · Línea 2: override PERCENT 30     → 30% sobre la base.
//   · Línea 3: override PERCENT 0      → 0 (sin impuesto), total = neto.
// =============================================================================

import { describe, it, expect, vi, beforeEach } from "vitest";
import { Prisma } from "@prisma/client";

const mockPrisma = vi.hoisted(() => ({
  article:            { findMany: vi.fn(), findFirst: vi.fn() },
  articleVariant:     { findMany: vi.fn() },
  articleGroupItem:   { findMany: vi.fn() },
  salesChannel:       { findFirst: vi.fn() },
  coupon:             { findFirst: vi.fn() },
  commercialEntity:   { findFirst: vi.fn() },
  priceList:          { findMany: vi.fn() },
  promotion:          { findMany: vi.fn() },
  currency:           { findUnique: vi.fn() },
  jewelry:            { findUnique: vi.fn() },
  tax:                { findMany: vi.fn() },
}));
vi.mock("../../../lib/prisma.js", () => ({ prisma: mockPrisma }));

// Mock SELECTIVO de pricing-engine: conservamos el `computeLineTaxes` REAL
// (es lo que estamos validando) y solo stubeamos lo pesado.
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
    // REAL: computeLineTaxes (lo que el bug omitía alimentar correctamente).
    computeLineTaxes:               actual.computeLineTaxes,
    resolveFinalSalePrice:          (...a: any[]) => mockResolveFinalSalePrice(...a),
    buildPricingSnapshot:           (...a: any[]) => mockBuildPricingSnapshot(...a),
    calculateCostFromLines:         (...a: any[]) => mockCalculateCostFromLines(...a),
    buildBatchCostContext:          (...a: any[]) => mockBuildBatchCostContext(...a),
    evaluatePricingPolicy:          (...a: any[]) => mockEvaluatePricingPolicy(...a),
    computeSaleDocumentTotals:      (...a: any[]) => mockComputeSaleDocTotals(...a),
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
const UNIT = 2_246_830.59;

beforeEach(() => {
  vi.clearAllMocks();

  mockPrisma.article.findMany.mockResolvedValue([{
    id: "ART-1", categoryId: null, brand: null, mermaPercent: null,
    manualTaxIds: ["iva-21"],            // IVA 21% heredado del artículo
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
  // IVA 21% — lo que computeLineTaxes (REAL) usa para la línea SIN override.
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
    unitPrice: res.unitPrice?.toNumber?.() ?? UNIT,
    basePrice: res.basePrice?.toNumber?.() ?? UNIT,
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
    metalHechuraBreakdown: null, taxAmount: new D("0"), taxBreakdown: [],
    totalWithTax: new D(String(UNIT)), taxExemptByEntity: false,
  });
  // documentTotals: pasa-través — suma de lineTaxAmount de cada línea.
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
      channelResult: null, couponResult: null,
      legacyCouponOnlyDiscount: 0, sourceTrace: [],
    };
  });
});

describe("previewSale — taxOverride por línea (mismo artículo)", () => {
  it("línea sin override → IVA 21%; override 30 → 30%; override 0 → 0", async () => {
    const out = await previewSale("j1", {
      lines: [
        { articleId: "ART-1", variantId: null, quantity: 1 },
        { articleId: "ART-1", variantId: null, quantity: 1,
          taxOverride: { mode: "PERCENT", value: 30, appliesTo: "TOTAL" } },
        { articleId: "ART-1", variantId: null, quantity: 1,
          taxOverride: { mode: "PERCENT", value: 0, appliesTo: "TOTAL" } },
      ],
      clientId: null,
    });

    expect(out.lines).toHaveLength(3);

    // Línea 1 — IVA heredado 21%
    expect(out.lines[0].lineTaxAmount).toBeCloseTo(UNIT * 0.21, 1);
    expect(out.lines[0].lineTotalWithTax).toBeCloseTo(UNIT * 1.21, 1);

    // Línea 2 — override 30%
    expect(out.lines[1].lineTaxAmount).toBeCloseTo(UNIT * 0.30, 1);
    expect(out.lines[1].lineTotalWithTax).toBeCloseTo(UNIT * 1.30, 1);

    // Línea 3 — override 0 → sin impuesto, total = neto
    expect(out.lines[2].lineTaxAmount).toBe(0);
    expect(out.lines[2].lineTotalWithTax).toBeCloseTo(UNIT, 2);

    // Las 3 líneas (mismo artículo) NO comparten resultado
    expect(out.lines[0].lineTotalWithTax).not.toBe(out.lines[1].lineTotalWithTax);
    expect(out.lines[1].lineTotalWithTax).not.toBe(out.lines[2].lineTotalWithTax);

    // Footer impuestos = solo líneas gravadas (21% + 30% + 0)
    expect(out.documentTotals.taxAmount).toBeCloseTo(UNIT * 0.21 + UNIT * 0.30, 0);
  });

  it("taxBreakdown refleja la tasa del OVERRIDE, no la heredada", async () => {
    const out = await previewSale("j1", {
      lines: [
        { articleId: "ART-1", variantId: null, quantity: 1,
          taxOverride: { mode: "PERCENT", value: 30, appliesTo: "TOTAL" } },
      ],
      clientId: null,
    });
    const tb = out.lines[0].taxBreakdown as any[];
    expect(tb).toHaveLength(1);
    expect(tb[0].code).toBe("MANUAL_OVERRIDE");
    expect(tb[0].rate).toBe(30);
    expect(tb[0].taxAmount).toBeCloseTo(UNIT * 0.30, 1);
  });

  it("manualOverridesApplied.tax coincide con el cálculo real (override 0)", async () => {
    const out = await previewSale("j1", {
      lines: [
        { articleId: "ART-1", variantId: null, quantity: 1,
          taxOverride: { mode: "PERCENT", value: 0, appliesTo: "TOTAL" } },
      ],
      clientId: null,
    });
    expect((out.lines[0] as any).manualOverridesApplied.tax).toBe(true);
    expect(out.lines[0].lineTaxAmount).toBe(0);
  });
});

// ============================================================================
// Cliente exento + override manual de impuesto — bug reportado: el guard
// externo `!clientTaxExempt` (sales.service.ts:2873) saltaba TODO el bloque
// de cálculo de tax cuando cliente es exento, incluyendo el override del
// operador. Resultado: TPNumber mostraba 30%, badge "Impuesto manual", pero
// el footer mostraba "Impuestos: ARS 0,00" y el total no sumaba.
//
// Fix: el guard ahora permite entrar también cuando hay override manual:
//   (!clientTaxExempt || lineHasManualTaxOverride)
// Y dentro, taxIds se vacía para cliente exento (la exención cubre los
// heredados; solo el override cuenta).
// ============================================================================
describe("previewSale — cliente exento + override manual (BUG REPORTADO)", () => {
  beforeEach(() => {
    // Override del beforeEach del describe anterior: cliente exento.
    mockPrisma.commercialEntity.findFirst.mockResolvedValue({
      id: "client-exempt", taxExempt: true,
      paymentTermDays: null, balanceType: null, taxApplyOnOverride: null,
      discountRuleId: null, discountRule: null,
      clientDiscountValue: null, clientDiscountValueType: null, clientDiscountApplyOn: null,
    } as any);
  });

  it("exento + sin override → tax=0 (modo automático preservado)", async () => {
    const out = await previewSale("j1", {
      lines: [
        { articleId: "ART-1", variantId: null, quantity: 1 },
      ],
      clientId: "client-exempt",
    });
    // Sin override + exento → tax=0 (la exención cubre el IVA 21% heredado).
    expect(out.lines[0].lineTaxAmount).toBe(0);
    expect(out.lines[0].lineTotalWithTax).toBeCloseTo(UNIT, 2);
    // Footer también en 0.
    expect(out.documentTotals.taxAmount).toBe(0);
  });

  it("FIX: exento + override 30% → tax > 0 (el override gana sobre la exención)", async () => {
    const out = await previewSale("j1", {
      lines: [
        { articleId: "ART-1", variantId: null, quantity: 1,
          taxOverride: { mode: "PERCENT", value: 30, appliesTo: "TOTAL" } },
      ],
      clientId: "client-exempt",
    });
    // El operador eligió explícitamente 30% manual sobre un cliente exento:
    // el motor debe calcular el tax y el footer debe sumarlo. Sin el fix
    // del guard, el bloque se saltaba completo y devolvía 0.
    expect(out.lines[0].lineTaxAmount).toBeCloseTo(UNIT * 0.30, 1);
    expect(out.lines[0].lineTotalWithTax).toBeCloseTo(UNIT * 1.30, 1);
    // Footer documento suma correctamente el override manual.
    expect(out.documentTotals.taxAmount).toBeCloseTo(UNIT * 0.30, 1);
    // El breakdown debe ser del OVERRIDE, NO del IVA 21% heredado del
    // artículo (que también está configurado en mockPrisma.tax). Eso lo
    // garantiza el vaciado de taxIds=[] para cliente exento dentro del
    // bloque.
    const tb = out.lines[0].taxBreakdown as any[];
    expect(tb).toHaveLength(1);
    expect(tb[0].code).toBe("MANUAL_OVERRIDE");
    expect(tb[0].rate).toBe(30);
  });

  it("FIX: exento + override AMOUNT $500 → tax = $500 efectivo", async () => {
    const out = await previewSale("j1", {
      lines: [
        { articleId: "ART-1", variantId: null, quantity: 1,
          taxOverride: { mode: "AMOUNT", value: 500, appliesTo: "TOTAL" } },
      ],
      clientId: "client-exempt",
    });
    expect(out.lines[0].lineTaxAmount).toBeCloseTo(500, 1);
    expect(out.documentTotals.taxAmount).toBeCloseTo(500, 1);
  });

  it("FIX: exento + override 0 (X = manual 0) → tax=0 (correcto por override, NO por exención)", async () => {
    // Con la semántica X=manual 0, escribir 0 (o tocar X) deja
    // taxOverride={value:0}. El motor aplica 0 manual. Visualmente igual
    // al modo automático exento, pero la causa es distinta (override).
    const out = await previewSale("j1", {
      lines: [
        { articleId: "ART-1", variantId: null, quantity: 1,
          taxOverride: { mode: "PERCENT", value: 0, appliesTo: "TOTAL" } },
      ],
      clientId: "client-exempt",
    });
    expect(out.lines[0].lineTaxAmount).toBe(0);
    expect((out.lines[0] as any).manualOverridesApplied.tax).toBe(true);
  });

  it("FIX: 2 líneas (1 sin override + 1 con override) → solo la segunda suma tax al footer", async () => {
    const out = await previewSale("j1", {
      lines: [
        // Línea 1: exenta, sin override → tax 0.
        { articleId: "ART-1", variantId: null, quantity: 1 },
        // Línea 2: exenta + override 30% → tax aplicado.
        { articleId: "ART-1", variantId: null, quantity: 1,
          taxOverride: { mode: "PERCENT", value: 30, appliesTo: "TOTAL" } },
      ],
      clientId: "client-exempt",
    });
    expect(out.lines[0].lineTaxAmount).toBe(0);
    expect(out.lines[1].lineTaxAmount).toBeCloseTo(UNIT * 0.30, 1);
    expect(out.documentTotals.taxAmount).toBeCloseTo(UNIT * 0.30, 1);
  });
});
