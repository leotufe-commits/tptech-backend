// src/modules/sales/__tests__/preview-confirm-parity.test.ts
//
// Tests Fase 4 — paridad de cálculo entre `previewSale()` y `confirmSale()`.
//
// Objetivo: verificar que ambos pasan por `computeSaleDocumentTotals` y por
// la misma resolución de impuestos. Si alguien edita uno solo, los tests
// rompen.
//
// Estrategia: mockeamos `computeSaleDocumentTotals` para asegurarnos de que
// las dos rutas lo invocan con el MISMO input cuando los datos comerciales
// son los mismos (mismas líneas, mismo canal, mismo cupón). El stub devuelve
// un total determinístico para que el test verifique que ambas rutas usan
// ese resultado en lugar de calcularlo a mano.

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
  // Fase 2A.7 — `previewSale` arma costo de compra por línea para paridad
  // con `articles/pricing-preview`. Stubbeado a vacío para no impactar
  // los tests existentes.
  computePurchaseTaxes: vi.fn().mockResolvedValue({
    costBase:         null,
    costTaxAmount:    null,
    costWithTax:      null,
    costTaxBreakdown: [],
  }),
  // FASE 2 — confirmSale invoca el helper para armar el breakdown
  // Metal/Hechura por línea. Mock que devuelve null mantiene los tests
  // existentes intactos (los agregados doc-level quedan en 0).
  deriveMetalHechuraBreakdown:    () => null,
}));
// Helper compartido `pricing-composition` también lo usa previewSale. Lo
// mockeamos vacío para que los tests no necesiten metalVariant en DB.
vi.mock("../../../lib/pricing-composition.js", () => ({
  buildComposition:               () => ({ metal: null, hechura: null, products: [], services: [], taxes: [] }),
  fetchMetalVariantInfo:          vi.fn().mockResolvedValue({ purity: null, purityLabel: null, metalName: null }),
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
  getCheckoutPreview: vi.fn().mockResolvedValue(null),
}));
vi.mock("../../coupons/coupons.service.js", () => ({
  validateCoupon: vi.fn().mockResolvedValue({ valid: false }),
}));

import { previewSale, confirmSale } from "../sales.service.js";

const D = Prisma.Decimal;

// ── Helpers ─────────────────────────────────────────────────────────────────

function fakeSalePriceResult(overrides: Record<string, any> = {}) {
  return {
    unitPrice:                new D("800"),
    basePrice:                new D("1000"),
    quantityDiscountAmount:   new D("0"),
    promotionDiscountAmount:  new D("200"),
    discountAmount:           new D("200"),
    priceSource:              "PROMOTION",
    baseSource:               "PRICE_LIST",
    unitCost:                 new D("400"),
    unitMargin:               new D("400"),
    marginPercent:            new D("50"),
    costPartial:              false,
    costMode:                 "COST_LINES",
    partial:                  false,
    appliedPriceListId:       "pl-1",
    appliedPriceListName:     "Lista",
    appliedPromotionId:       "promo-1",
    appliedPromotionName:     "Promo",
    appliedDiscountId:        null,
    steps:                    [],
    alerts:                   [],
    policy:                   { canConfirm: true, blockingAlerts: [] },
    stackingMode:             "BEST_OF_PROMO",
    metalHechuraBreakdown:    null,
    taxAmount:                new D("0"),
    taxBreakdown:             [],
    totalWithTax:             new D("800"),
    taxExemptByEntity:        false,
    ...overrides,
  };
}

function fakeSnapshot(overrides: Record<string, any> = {}) {
  return {
    unitPrice:            800,
    basePrice:            1000,
    discountAmount:       200,
    taxAmount:            0,
    totalWithTax:         800,
    priceSource:          "PROMOTION",
    baseSource:           "PRICE_LIST",
    unitCost:             400,
    unitMargin:           400,
    marginPercent:        50,
    costPartial:          false,
    costMode:             "COST_LINES",
    partial:              false,
    appliedPriceListId:   "pl-1",
    appliedPriceListName: "Lista",
    appliedPromotionId:   "promo-1",
    appliedPromotionName: "Promo",
    appliedDiscountId:    null,
    resolvedAt:           "2026-04-28T00:00:00.000Z",
    ...overrides,
  };
}

beforeEach(() => {
  vi.clearAllMocks();

  mockPrisma.article.findMany.mockResolvedValue([]);
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
  mockPrisma.sale.findFirst.mockResolvedValue({ id: "s1", lines: [] });
  mockPrisma.sale.update.mockResolvedValue({ id: "s1" });

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
    baseAmount: 800, channelAmount: 0, finalAmount: 800,
    channelName: "", channelId: "",
  });
  mockApplyCoupon.mockReturnValue({
    baseAmount: 800, discountAmount: 0, finalAmount: 800,
    couponId: "", couponCode: "", couponName: "",
    discountType: "PERCENTAGE", discountValue: 0, applied: false,
  });
  mockBuildPricingSnapshot.mockImplementation((res: any) => fakeSnapshot({
    unitPrice: res.unitPrice?.toNumber() ?? null,
    basePrice: res.basePrice?.toNumber() ?? null,
    priceSource: res.priceSource,
  }));

  // Stub determinístico — total = subtotal + tax. Si las dos rutas llaman a
  // este mock con el mismo input, ambas usan el mismo total.
  mockComputeSaleDocTotals.mockImplementation((input: any) => {
    const subtotalAfterLineDiscounts = input.lines.reduce((s: number, l: any) => s + l.lineTotal, 0);
    const taxAmount                  = input.lines.reduce((s: number, l: any) => s + l.lineTaxAmount, 0);
    return {
      subtotalBeforeDiscounts:    input.lines.reduce((s: number, l: any) => s + (l.basePrice * l.quantity), 0),
      lineDiscountAmount:         input.lines.reduce((s: number, l: any) => s + Math.max(0, l.basePrice * l.quantity - l.lineTotal), 0),
      subtotalAfterLineDiscounts,
      channelAdjustmentAmount:    0,
      couponDiscountAmount:       0,
      paymentAdjustmentAmount:    input.paymentAdjustmentAmount ?? 0,
      shippingAmount:             0,
      globalDiscountAmount:       0,
      taxableBase:                subtotalAfterLineDiscounts,
      taxAmount,
      roundingAdjustment:         0,
      totalBeforeTax:             subtotalAfterLineDiscounts,
      totalWithTax:               subtotalAfterLineDiscounts + taxAmount,
      channelResult: { baseAmount: subtotalAfterLineDiscounts, channelAmount: 0, finalAmount: subtotalAfterLineDiscounts, channelName: "", channelId: "" },
      couponResult:  { baseAmount: subtotalAfterLineDiscounts, discountAmount: 0, finalAmount: subtotalAfterLineDiscounts, couponId: "", couponCode: "", couponName: "", discountType: "PERCENTAGE", discountValue: 0, applied: false },
      total:                      subtotalAfterLineDiscounts + taxAmount,
      legacyCouponOnlyDiscount:   0,
      sourceTrace:                [],
    };
  });
});

// ────────────────────────────────────────────────────────────────────────────
// 1. previewSale usa computeSaleDocumentTotals (no formula manual local)
// ────────────────────────────────────────────────────────────────────────────

describe("previewSale — Fase 4: usa computeSaleDocumentTotals", () => {
  it("invoca computeSaleDocumentTotals al menos una vez", async () => {
    mockResolveFinalSalePrice.mockResolvedValue(fakeSalePriceResult());
    mockPrisma.article.findMany.mockResolvedValue([{
      id: "a1", categoryId: null, brand: null,
      mermaPercent: null, manualTaxIds: [],
      manualAdjustmentKind: null, manualAdjustmentType: null, manualAdjustmentValue: null,
      category: null, costComposition: [],
    }]);

    const out = await previewSale("j1", {
      lines: [{ articleId: "a1", variantId: null, quantity: 1 }],
      clientId: null,
    });

    expect(mockComputeSaleDocTotals).toHaveBeenCalledTimes(1);
    expect(out.documentTotals).toBeDefined();
    expect(out.total).toBe(out.documentTotals.total);
    expect(out.subtotal).toBe(out.documentTotals.subtotalAfterLineDiscounts);
  });

  it("Fase 5 — expone unitMargin, marginPercent, qty/promo discount, metalHechuraBreakdown y pricingSnapshot por línea", async () => {
    mockResolveFinalSalePrice.mockResolvedValue(fakeSalePriceResult({
      unitPrice:                new D("800"),
      basePrice:                new D("1000"),
      quantityDiscountAmount:   new D("100"),
      promotionDiscountAmount:  new D("100"),
      unitCost:                 new D("400"),
      unitMargin:               new D("400"),
      marginPercent:            new D("50"),
      metalHechuraBreakdown: {
        metalCost: 200, metalSale: 240, metalMarginPct: 20,
        hechuraCost: 200, hechuraSale: 560, hechuraMarginPct: 180,
        metalGramsBase: 5, metalGramsSale: 6, metalPricePerGram: 40,
      },
    }));
    mockComputeLineTaxes.mockResolvedValue({ taxBreakdown: [], taxAmount: new D("0") });
    mockPrisma.article.findMany.mockResolvedValue([{
      id: "a1", categoryId: null, brand: null,
      mermaPercent: null, manualTaxIds: [],
      manualAdjustmentKind: null, manualAdjustmentType: null, manualAdjustmentValue: null,
      category: null, costComposition: [],
    }]);

    const out = await previewSale("j1", {
      lines: [{ articleId: "a1", variantId: null, quantity: 1 }],
      clientId: null,
    });

    const ln = out.lines[0];
    expect(ln.quantityDiscountAmount).toBe(100);
    expect(ln.promotionDiscountAmount).toBe(100);
    expect(ln.unitMargin).toBe(400);
    expect(ln.marginPercent).toBe(50);
    expect(ln.metalHechuraBreakdown).not.toBeNull();
    expect(ln.metalHechuraBreakdown?.metalSale).toBe(240);
    expect(ln.metalHechuraBreakdown?.hechuraSale).toBe(560);
    expect(ln.pricingSnapshot).toBeDefined();
    expect(ln.pricingSnapshot.unitPrice).toBe(800);
    expect(ln.pricingSnapshot.basePrice).toBe(1000);
  });

  it("Fase 5 — resuelve globalDiscount { type: PERCENT, value: 10 } contra el subtotal del backend", async () => {
    mockResolveFinalSalePrice.mockResolvedValue(fakeSalePriceResult({
      unitPrice: new D("1000"), basePrice: new D("1000"),
    }));
    mockComputeLineTaxes.mockResolvedValue({ taxBreakdown: [], taxAmount: new D("0") });
    mockPrisma.article.findMany.mockResolvedValue([{
      id: "a1", categoryId: null, brand: null,
      mermaPercent: null, manualTaxIds: [],
      manualAdjustmentKind: null, manualAdjustmentType: null, manualAdjustmentValue: null,
      category: null, costComposition: [],
    }]);

    await previewSale("j1", {
      lines: [{ articleId: "a1", variantId: null, quantity: 2 }],   // subtotal=2000
      clientId: null,
      globalDiscount: { type: "PERCENT", value: 10 },
    });

    expect(mockComputeSaleDocTotals).toHaveBeenCalledTimes(1);
    const input = mockComputeSaleDocTotals.mock.calls[0][0];
    // 10% de 2000 = 200 — el frontend NO mandó el monto, el backend lo resolvió.
    expect(input.globalDiscountAmount).toBe(200);
  });

  it("Fase 5 — globalDiscount { type: AMOUNT } se pasa como monto directo", async () => {
    mockResolveFinalSalePrice.mockResolvedValue(fakeSalePriceResult({
      unitPrice: new D("500"), basePrice: new D("500"),
    }));
    mockComputeLineTaxes.mockResolvedValue({ taxBreakdown: [], taxAmount: new D("0") });
    mockPrisma.article.findMany.mockResolvedValue([{
      id: "a1", categoryId: null, brand: null,
      mermaPercent: null, manualTaxIds: [],
      manualAdjustmentKind: null, manualAdjustmentType: null, manualAdjustmentValue: null,
      category: null, costComposition: [],
    }]);

    await previewSale("j1", {
      lines: [{ articleId: "a1", variantId: null, quantity: 1 }],
      clientId: null,
      globalDiscount: { type: "AMOUNT", value: 75 },
    });

    const input = mockComputeSaleDocTotals.mock.calls[0][0];
    expect(input.globalDiscountAmount).toBe(75);
  });

  it("expone basePrice, lineTotal, lineTaxAmount, lineDiscount por línea", async () => {
    mockResolveFinalSalePrice.mockResolvedValue(fakeSalePriceResult({
      unitPrice: new D("800"),
      basePrice: new D("1000"),
    }));
    mockComputeLineTaxes.mockResolvedValue({
      taxBreakdown: [{ taxId: "t1", name: "IVA", taxAmount: 168 } as any],
      taxAmount:    new D("168"),
    });
    mockPrisma.article.findMany.mockResolvedValue([{
      id: "a1", categoryId: null, brand: null,
      mermaPercent: null, manualTaxIds: ["t1"],
      manualAdjustmentKind: null, manualAdjustmentType: null, manualAdjustmentValue: null,
      category: null, costComposition: [],
    }]);

    const out = await previewSale("j1", {
      lines: [{ articleId: "a1", variantId: null, quantity: 2 }],
      clientId: null,
    });

    expect(out.lines).toHaveLength(1);
    const ln = out.lines[0];
    expect(ln.unitPrice).toBe(800);
    expect(ln.basePrice).toBe(1000);
    expect(ln.lineTotal).toBe(1600);
    expect(ln.lineTaxAmount).toBe(336);          // 168 × 2
    expect(ln.lineDiscount).toBe(400);           // (1000 - 800) × 2
    expect(ln.lineTotalWithTax).toBe(1936);
    expect(ln.taxBreakdown).toHaveLength(1);
  });
});

// ────────────────────────────────────────────────────────────────────────────
// 2. previewSale y confirmSale invocan computeSaleDocumentTotals con el
//    mismo input cuando comparten líneas y contexto comercial
// ────────────────────────────────────────────────────────────────────────────

describe("paridad previewSale ↔ confirmSale", () => {
  it("ambos pasan por computeSaleDocumentTotals con el mismo lineTotal y lineTaxAmount", async () => {
    // Setup compartido: mismo precio, mismo impuesto, mismas cantidades
    mockResolveFinalSalePrice.mockResolvedValue(fakeSalePriceResult({
      unitPrice: new D("1000"),
      basePrice: new D("1000"),
    }));
    mockComputeLineTaxes.mockResolvedValue({
      taxBreakdown: [], taxAmount: new D("210"),
    });

    const articleData = [{
      id: "a1", categoryId: null, brand: null,
      stockMode: "STOCK", mermaPercent: null, manualTaxIds: ["t1"],
      manualAdjustmentKind: null, manualAdjustmentType: null, manualAdjustmentValue: null,
      category: null, costComposition: [],
    }];
    mockPrisma.article.findMany.mockResolvedValue(articleData);

    // ── 1) previewSale ────────────────────────────────────────────────────
    await previewSale("j1", {
      lines: [{ articleId: "a1", variantId: null, quantity: 1 }],
      clientId: null,
    });
    expect(mockComputeSaleDocTotals).toHaveBeenCalledTimes(1);
    const previewInput = mockComputeSaleDocTotals.mock.calls[0][0];

    // ── 2) confirmSale ────────────────────────────────────────────────────
    mockComputeSaleDocTotals.mockClear();
    const snap = fakeSnapshot({ unitPrice: 1000, basePrice: 1000 });
    mockPrisma.sale.findFirst.mockResolvedValueOnce({
      id: "s1", code: "VTA-0001", status: "DRAFT",
      clientId: null, warehouseId: null,
      subtotal: new D("1000"), discountAmount: new D("0"),
      taxAmount: new D("0"), total: new D("1000"), couponId: null,
      client: null, seller: null, channel: null,
      lines: [{
        id: "L1", articleId: "a1", variantId: null,
        quantity: new D("1"), unitPrice: new D("1000"), discountPct: new D("0"),
        lineTotal: new D("1000"),
        priceSource: "PROMOTION",
        appliedPriceListId: "pl-1", appliedPromotionId: "promo-1", appliedDiscountId: null,
        pricingSnapshot: snap,
      }],
    });
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
    const confirmInput = mockComputeSaleDocTotals.mock.calls[0][0];

    // ── Paridad: ambos llamados producen mismo lineTotal y lineTaxAmount ──
    expect(previewInput.lines[0].quantity).toBe(confirmInput.lines[0].quantity);
    expect(previewInput.lines[0].basePrice).toBe(confirmInput.lines[0].basePrice);
    expect(previewInput.lines[0].unitPrice).toBe(confirmInput.lines[0].unitPrice);
    expect(previewInput.lines[0].lineTotal).toBe(confirmInput.lines[0].lineTotal);
    expect(previewInput.lines[0].lineTaxAmount).toBe(confirmInput.lines[0].lineTaxAmount);
  });

  it("misma respuesta de motor → mismo total entre preview y confirm", async () => {
    // Setup determinístico
    mockResolveFinalSalePrice.mockResolvedValue(fakeSalePriceResult({
      unitPrice: new D("500"),
      basePrice: new D("500"),
    }));
    mockComputeLineTaxes.mockResolvedValue({
      taxBreakdown: [], taxAmount: new D("105"),
    });
    mockPrisma.article.findMany.mockResolvedValue([{
      id: "a1", categoryId: null, brand: null,
      stockMode: "STOCK", mermaPercent: null, manualTaxIds: ["t1"],
      manualAdjustmentKind: null, manualAdjustmentType: null, manualAdjustmentValue: null,
      category: null, costComposition: [],
    }]);

    const previewRes = await previewSale("j1", {
      lines: [{ articleId: "a1", variantId: null, quantity: 3 }],
      clientId: null,
    });

    // Ahora confirm con MISMA línea (quantity 3, mismo articleId)
    mockComputeSaleDocTotals.mockClear();
    const snap = fakeSnapshot({ unitPrice: 500, basePrice: 500 });
    mockPrisma.sale.findFirst.mockResolvedValueOnce({
      id: "s1", code: "VTA-0001", status: "DRAFT",
      clientId: null, warehouseId: null,
      subtotal: new D("1500"), discountAmount: new D("0"),
      taxAmount: new D("0"), total: new D("1500"), couponId: null,
      client: null, seller: null, channel: null,
      lines: [{
        id: "L1", articleId: "a1", variantId: null,
        quantity: new D("3"), unitPrice: new D("500"), discountPct: new D("0"),
        lineTotal: new D("1500"),
        priceSource: "PRICE_LIST",
        appliedPriceListId: null, appliedPromotionId: null, appliedDiscountId: null,
        pricingSnapshot: snap,
      }],
    });
    const txMock: any = {
      saleLine:           { update: vi.fn() },
      sale:               { update: vi.fn().mockResolvedValue({}) },
      articleMovement:    { count: vi.fn().mockResolvedValue(0), create: vi.fn().mockResolvedValue({ id: "mov1" }) },
      entityBalanceEntry: { createMany: vi.fn() },
      couponRedemption:   { create: vi.fn() },
    };
    mockPrisma.$transaction.mockImplementation(async (cb: any) => cb(txMock));
    await confirmSale("s1", "j1", "u1");

    // El stub devuelve total = subtotal + tax para ambos. Si los inputs son
    // los mismos, los totals son los mismos.
    const confirmTotals = mockComputeSaleDocTotals.mock.results[0].value;
    expect(previewRes.total).toBe(confirmTotals.total);
    expect(previewRes.documentTotals.taxAmount).toBe(confirmTotals.taxAmount);
  });
});
