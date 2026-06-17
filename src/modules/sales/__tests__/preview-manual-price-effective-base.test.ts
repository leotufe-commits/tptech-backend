// src/modules/sales/__tests__/preview-manual-price-effective-base.test.ts
// =============================================================================
// Base EFECTIVA del documento con precio MANUAL por línea.
//
// Contrato (CLAUDE.md raíz — "Backend calcula, frontend renderiza"):
//   La fila "Precio" del footer del comprobante = `documentTotals
//   .subtotalBeforeDiscounts` = Σ (basePrice_efectivo × qty). El motor de venta
//   mantiene `basePrice` SIEMPRE en el precio de LISTA (la UI lo lee para el
//   default del input y la traza del descuento). PERO cuando el operador fija un
//   precio MANUAL (`priceSource === "MANUAL_OVERRIDE"`), la base EFECTIVA del
//   documento debe ser el manual (= `unitPrice`), NO la lista. Así:
//     · "Precio" = manual × qty
//     · `lineDiscountAmount` = 0 (no hay "descuento" inventado lista→manual)
//   Para líneas SIN manual, comportamiento intacto (lista).
//
// Estrategia: `resolveFinalSalePrice` se stubea (echo) para emular el motor:
// con `manualPriceOverride` devuelve unitPrice=manual, basePrice=LISTA (distinto)
// y priceSource="MANUAL_OVERRIDE". `computeSaleDocumentTotals` es el REAL
// (importActual) — así el test verifica la fila "Precio" / descuento de verdad,
// y captura las líneas que `previewSale` arma para él (la base efectiva que
// `confirmSale` debe espejar para mantener la paridad).
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
const mockDocTotalsSpy           = vi.hoisted(() => vi.fn());

vi.mock("../../../lib/pricing-engine/pricing-engine.js", async (importActual) => {
  const actual = await importActual<any>();
  return {
    ...actual,
    resolveFinalSalePrice:  (...a: any[]) => mockResolveFinalSalePrice(...a),
    buildPricingSnapshot:   (...a: any[]) => mockBuildPricingSnapshot(...a),
    calculateCostFromLines: (...a: any[]) => mockCalculateCostFromLines(...a),
    buildBatchCostContext:  (...a: any[]) => mockBuildBatchCostContext(...a),
    evaluatePricingPolicy:  (...a: any[]) => mockEvaluatePricingPolicy(...a),
    computeLineTaxes:       (...a: any[]) => mockComputeLineTaxes(...a),
    // REAL computeSaleDocumentTotals — solo lo espiamos para capturar las
    // líneas que `previewSale` le arma (base efectiva), luego delegamos.
    computeSaleDocumentTotals: (...a: any[]) => {
      mockDocTotalsSpy(...a);
      return actual.computeSaleDocumentTotals(...a);
    },
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
const LIST   = 100_000; // precio de LISTA (basePrice del motor — SIEMPRE)
const MANUAL = 60_000;  // precio MANUAL que fija el operador

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
    unitPrice: res.unitPrice?.toNumber?.() ?? LIST,
    basePrice: res.basePrice?.toNumber?.() ?? LIST,
    discountAmount: res.discountAmount?.toNumber?.() ?? 0,
    taxAmount: 0, totalWithTax: res.unitPrice?.toNumber?.() ?? LIST,
    priceSource: res.priceSource ?? "PRICE_LIST", baseSource: "PRICE_LIST",
    unitCost: null, unitMargin: null, marginPercent: null,
    costPartial: true, costMode: "NONE", partial: false,
    appliedPriceListId: null, appliedPriceListName: null,
    appliedPromotionId: null, appliedPromotionName: null, appliedDiscountId: null,
    resolvedAt: "2026-05-17T00:00:00.000Z",
  }));

  // ECHO del motor real:
  //   · con manualPriceOverride → priceSource MANUAL_OVERRIDE, unitPrice=manual,
  //     basePrice=LISTA (distinto a propósito — la UI lee la lista).
  //   · sin override → PRICE_LIST, unitPrice=basePrice=LISTA.
  mockResolveFinalSalePrice.mockImplementation((_j: string, opts: any) => {
    const hasManual =
      opts.manualPriceOverride != null && Number.isFinite(opts.manualPriceOverride);
    const unit = hasManual ? Number(opts.manualPriceOverride) : LIST;
    return Promise.resolve({
      unitPrice: new D(String(unit)), basePrice: new D(String(LIST)),
      quantityDiscountAmount: new D("0"), promotionDiscountAmount: new D("0"),
      discountAmount: new D("0"),
      priceSource: hasManual ? "MANUAL_OVERRIDE" : "PRICE_LIST", baseSource: "PRICE_LIST",
      unitCost: null, unitMargin: null, marginPercent: null, costPartial: true,
      costMode: "NONE", partial: false, appliedPriceListId: null,
      appliedPriceListName: null, appliedPromotionId: null, appliedPromotionName: null,
      appliedDiscountId: null, steps: [], alerts: [],
      policy: { canConfirm: true, blockingAlerts: [] }, stackingMode: "NONE",
      metalHechuraBreakdown: null, taxAmount: new D("0"), taxBreakdown: [],
      totalWithTax: new D(String(unit)), taxExemptByEntity: false,
    });
  });
});

describe("previewSale — precio MANUAL usa base EFECTIVA en el documento", () => {
  it("línea con precio manual → 'Precio' (subtotalBeforeDiscounts) = manual × qty, descuento 0", async () => {
    const qty = 2;
    const out = await previewSale("j1", {
      lines: [
        { articleId: "ART-1", variantId: null, quantity: qty,
          manualPriceOverride: MANUAL },
      ],
      clientId: null,
    });

    // La base efectiva que `previewSale` pasó al motor de totales = MANUAL.
    const passedLines = mockDocTotalsSpy.mock.calls[0][0].lines;
    expect(passedLines).toHaveLength(1);
    expect(passedLines[0].basePrice).toBe(MANUAL);   // NO la lista
    expect(passedLines[0].unitPrice).toBe(MANUAL);

    // Fila "Precio" del footer = manual × qty (no lista × qty).
    expect(out.documentTotals.subtotalBeforeDiscounts).toBe(MANUAL * qty);
    // Descuento de línea = 0 (no se inventa el delta lista→manual).
    expect(out.documentTotals.lineDiscountAmount).toBe(0);
    // Cadena reconcilia: subtotal post = subtotal pre (sin descuento).
    expect(out.documentTotals.subtotalAfterLineDiscounts).toBe(MANUAL * qty);
  });

  it("línea SIN precio manual → comportamiento intacto (base = lista)", async () => {
    const qty = 3;
    const out = await previewSale("j1", {
      lines: [
        { articleId: "ART-1", variantId: null, quantity: qty },
      ],
      clientId: null,
    });

    const passedLines = mockDocTotalsSpy.mock.calls[0][0].lines;
    expect(passedLines[0].basePrice).toBe(LIST);     // lista intacta
    expect(out.documentTotals.subtotalBeforeDiscounts).toBe(LIST * qty);
    expect(out.documentTotals.lineDiscountAmount).toBe(0);
  });

  it("mixto: 1 línea manual + 1 línea lista → cada una con su base efectiva", async () => {
    const out = await previewSale("j1", {
      lines: [
        { articleId: "ART-1", variantId: null, quantity: 1,
          manualPriceOverride: MANUAL },            // efectiva = MANUAL
        { articleId: "ART-1", variantId: null, quantity: 1 }, // efectiva = LIST
      ],
      clientId: null,
    });

    const passedLines = mockDocTotalsSpy.mock.calls[0][0].lines;
    expect(passedLines[0].basePrice).toBe(MANUAL);
    expect(passedLines[1].basePrice).toBe(LIST);
    expect(out.documentTotals.subtotalBeforeDiscounts).toBe(MANUAL + LIST);
    expect(out.documentTotals.lineDiscountAmount).toBe(0);
  });
});
