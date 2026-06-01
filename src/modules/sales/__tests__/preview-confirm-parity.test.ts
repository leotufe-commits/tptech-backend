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
  // POLICY §Tax.3 — `previewSale` / `confirmSale` calculan la porción FIXED
  // de los impuestos vía este helper puro. Sin el mock vitest tira
  // "No 'sumFixedTaxComponent' export is defined on the mock" en cuanto el
  // flujo llega a ese map. Devolvemos 0 (los tests no validan tax FIXED).
  sumFixedTaxComponent: () => 0,
  // Etapa 1.1 — `previewSale` resuelve el shipping crudo a monto vía este
  // helper puro. En tests usamos la implementación real (es determinística).
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
// Helper compartido `pricing-composition` también lo usa previewSale. Lo
// mockeamos vacío para que los tests no necesiten metalVariant en DB.
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
  getCheckoutPreview: vi.fn().mockResolvedValue(null),
}));
vi.mock("../../coupons/coupons.service.js", () => ({
  validateCoupon: vi.fn().mockResolvedValue({ valid: false }),
}));

import { previewSale, confirmSale, syncDraftDocumentTotals } from "../sales.service.js";

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
      // POLICY §Tax.4-6 — `taxScaling` siempre poblado por el motor real.
      // En el stub usamos un payload "sin scaling" (effectiveSaleRatio=1) que
      // representa el caso por defecto: sin descuentos de cabecera, todo el
      // tax viene de las líneas. confirmSale lee `taxScaling.scalingApplied`
      // para decidir si persistir documentFiscalSnapshot — con false persiste
      // null (auditable directo desde SaleLine snapshots).
      taxScaling: {
        effectiveSaleRatio:         1,
        effectiveDiscountRatio:     0,
        subtotalAfterLineDiscounts,
        taxableBase:                subtotalAfterLineDiscounts,
        originalTaxAmount:          taxAmount,
        scalableTaxAmount:          taxAmount,
        fixedTaxAmount:             0,
        scaledScalableTax:          taxAmount,
        scaledTaxAmount:            taxAmount,
        scalingApplied:             false,
      },
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

  // T43.4 — Paridad preview ↔ confirm con manualPrice + bonificación
  // manual + impuesto manual. Verifica:
  //   1. previewSale invoca `resolveFinalSalePrice` con los 3 overrides.
  //   2. confirmSale reproduce el motor con los mismos overrides (leídos
  //      del Sale persistido).
  //   3. Ambos endpoints producen el mismo `lineTotal` y `lineTaxAmount`
  //      en su llamada a `computeSaleDocumentTotals`.
  it("T43.4 — preview y confirm con manualPrice + manualDiscount + taxOverride: mismo motor, mismos totales", async () => {
    // Motor stub: unitPrice = manualPrice (1500), después del descuento manual
    // 10% queda 1350, tax manual 21% sobre 1350 = 283.5.
    mockResolveFinalSalePrice.mockResolvedValue(fakeSalePriceResult({
      unitPrice:          new D("1350"),  // manualPrice 1500 − 10%
      basePrice:          new D("1500"),  // manualPrice como base
      discountAmount:     new D("150"),
      priceSource:        "MANUAL_OVERRIDE",
      taxAmount:          new D("283.5"),
      totalWithTax:       new D("1633.5"),
      taxExemptByEntity:  false,
    }));
    mockComputeLineTaxes.mockResolvedValue({
      taxBreakdown: [{ taxId: "OVERRIDE_MANUAL", name: "Impuesto manual", taxAmount: 283.5 } as any],
      taxAmount:    new D("283.5"),
    });
    const articleData = [{
      id: "a1", categoryId: null, brand: null,
      stockMode: "STOCK", mermaPercent: null, manualTaxIds: [],
      manualAdjustmentKind: null, manualAdjustmentType: null, manualAdjustmentValue: null,
      category: null, costComposition: [],
    }];
    mockPrisma.article.findMany.mockResolvedValue(articleData);

    // ── 1) previewSale con overrides en el payload ──────────────────────────
    await previewSale("j1", {
      lines: [{
        articleId:               "a1",
        variantId:               null,
        quantity:                1,
        manualPriceOverride:     1500,
        manualDiscountOverride:  { mode: "PERCENT", value: 10, appliesTo: "TOTAL", kind: "BONUS" },
        taxOverride:             { mode: "PERCENT", value: 21, appliesTo: "TOTAL" },
      }],
      clientId: null,
    });
    // El motor recibió los 3 overrides.
    expect(mockResolveFinalSalePrice).toHaveBeenCalledTimes(1);
    const previewCallArgs = mockResolveFinalSalePrice.mock.calls[0][1];
    expect(previewCallArgs.manualPriceOverride).toBe(1500);
    expect(previewCallArgs.manualDiscountOverride).toEqual({
      mode: "PERCENT", value: 10, appliesTo: "TOTAL", kind: "BONUS",
    });
    expect(previewCallArgs.taxOverride).toEqual({
      mode: "PERCENT", value: 21, appliesTo: "TOTAL",
    });
    // El total documento del preview refleja el resultado del motor.
    expect(mockComputeSaleDocTotals).toHaveBeenCalledTimes(1);
    const previewInput = mockComputeSaleDocTotals.mock.calls[0][0];
    expect(previewInput.lines[0].unitPrice).toBe(1350);
    expect(previewInput.lines[0].lineTotal).toBe(1350);
    expect(previewInput.lines[0].lineTaxAmount).toBe(283.5);

    // ── 2) confirmSale con la misma línea persistida ────────────────────────
    mockResolveFinalSalePrice.mockClear();
    mockComputeSaleDocTotals.mockClear();
    const snap = fakeSnapshot({
      unitPrice: 1350, basePrice: 1500,
      discountAmount: 150, taxAmount: 283.5, totalWithTax: 1633.5,
      priceSource: "MANUAL_OVERRIDE",
    });
    mockPrisma.sale.findFirst.mockResolvedValueOnce({
      id: "s1", code: "VTA-0001", status: "DRAFT",
      clientId: null, warehouseId: null,
      subtotal: new D("1350"), discountAmount: new D("150"),
      taxAmount: new D("283.5"), total: new D("1633.5"), couponId: null,
      client: null, seller: null, channel: null,
      lines: [{
        id: "L1", articleId: "a1", variantId: null,
        quantity: new D("1"), unitPrice: new D("1350"), discountPct: new D("10"),
        lineTotal: new D("1350"),
        priceSource: "MANUAL_OVERRIDE",
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

    // ── Paridad: confirm produce mismo unitPrice/lineTotal/lineTaxAmount ───
    expect(mockComputeSaleDocTotals).toHaveBeenCalledTimes(1);
    const confirmInput = mockComputeSaleDocTotals.mock.calls[0][0];
    expect(confirmInput.lines[0].unitPrice).toBe(previewInput.lines[0].unitPrice);
    expect(confirmInput.lines[0].lineTotal).toBe(previewInput.lines[0].lineTotal);
    expect(confirmInput.lines[0].lineTaxAmount).toBe(previewInput.lines[0].lineTaxAmount);
  });

  // Etapa 1.1 — Paridad para los 3 ajustes a nivel documento (shipping,
  // globalDiscount, paymentAdjustment). Antes confirmSale los pasaba en 0
  // al motor, ahora los lee del DRAFT persistido y los pasa con el mismo
  // valor que preview computa.
  it("Etapa 1.1 — preview y confirm pasan al motor el mismo shippingAmount, globalDiscountAmount y paymentAdjustmentAmount", async () => {
    // ── Setup motor ──────────────────────────────────────────────────────
    mockResolveFinalSalePrice.mockResolvedValue(fakeSalePriceResult({
      unitPrice: new D("1000"),
      basePrice: new D("1000"),
    }));
    mockComputeLineTaxes.mockResolvedValue({
      taxBreakdown: [], taxAmount: new D("0"),
    });
    mockPrisma.article.findMany.mockResolvedValue([{
      id: "a1", categoryId: null, brand: null,
      stockMode: "STOCK", mermaPercent: null, manualTaxIds: [],
      manualAdjustmentKind: null, manualAdjustmentType: null, manualAdjustmentValue: null,
      category: null, costComposition: [],
    }]);

    // PaymentMethod válido para la sanitización del input de preview.
    const { getCheckoutPreview } = await import("../../payments/payments.service.js");
    (getCheckoutPreview as any).mockResolvedValue({
      baseAmount:  1000,
      finalAmount: 1050,  // +5% interés
      installments: 3,
      paymentMethodId: "pm-1",
    });

    // ── 1) previewSale con shipping + globalDiscount + paymentMethod ─────
    await previewSale("j1", {
      lines: [{ articleId: "a1", variantId: null, quantity: 1 }],
      clientId:        null,
      shipping:        { mode: "FIXED", value: 200 },
      globalDiscount:  { type: "PERCENT", value: 10 },  // 10% × 1000 = 100
      paymentMethodId: "pm-1",
      installmentsQty: 3,
    });
    expect(mockComputeSaleDocTotals).toHaveBeenCalledTimes(1);
    const previewInput = mockComputeSaleDocTotals.mock.calls[0][0];

    // Sanity: preview pasó los 3 ajustes resueltos al motor.
    expect(previewInput.shippingAmount).toBe(200);
    expect(previewInput.globalDiscountAmount).toBe(100);
    expect(previewInput.paymentAdjustmentAmount).toBe(50);  // 1050 - 1000

    // ── 2) confirmSale con DRAFT que persistió los mismos ajustes ────────
    mockComputeSaleDocTotals.mockClear();
    const snap = fakeSnapshot({ unitPrice: 1000, basePrice: 1000 });
    mockPrisma.sale.findFirst.mockResolvedValueOnce({
      id: "s1", code: "VTA-0001", status: "DRAFT",
      clientId: null, warehouseId: null,
      subtotal: new D("1000"), discountAmount: new D("0"),
      taxAmount: new D("0"), total: new D("1000"), couponId: null,
      // Etapa 1.1 — campos persistidos en el DRAFT.
      shippingAmount:      new D("200"),
      globalDiscountType:  "PERCENT",
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

    // ── Paridad byte-equivalente de los 3 ajustes ────────────────────────
    expect(confirmInput.shippingAmount).toBe(previewInput.shippingAmount);
    expect(confirmInput.globalDiscountAmount).toBe(previewInput.globalDiscountAmount);
    expect(confirmInput.paymentAdjustmentAmount).toBe(previewInput.paymentAdjustmentAmount);

    // POLICY §R-Rounding-6 — `Sale.engineTotal` se persiste con el
    // `documentTotals.total` del motor INMEDIATAMENTE después del rounding
    // (capa 15 del pipeline) y ANTES de cualquier ajuste manual humano
    // futuro. Hoy `Sale.total === Sale.engineTotal` porque manualAdjustment
    // no existe todavía; cuando se implemente, `Sale.total = engineTotal +
    // manualAdjustment.totals.monetaryAdjustment`.
    //
    // Validamos sobre el spy del `tx.sale.update` que ambos campos viajan
    // al UPDATE y son idénticos. El stub de `computeSaleDocumentTotals`
    // (`mockComputeSaleDocTotals`) devuelve un `total` determinístico
    // — el `engineTotal` persistido debe coincidir byte a byte.
    expect(txMock.sale.update).toHaveBeenCalled();
    const lastUpdate = txMock.sale.update.mock.calls.at(-1)[0];
    const engineTotalPersisted = lastUpdate?.data?.engineTotal;
    const totalPersisted       = lastUpdate?.data?.total;
    expect(engineTotalPersisted).toBeDefined();
    expect(engineTotalPersisted).toBe(totalPersisted);
    // Y refleja exactamente lo que el motor emitió (passthrough sin drift).
    const motorOutput = mockComputeSaleDocTotals.mock.results.at(-1)?.value;
    expect(engineTotalPersisted).toBe(motorOutput?.total);
  });
});

// =============================================================================
// Etapa 2.4 + 2.5 — Paridad PREVIEW / DRAFT / CONFIRM + Gate de scope
// =============================================================================
// Estos tests validan el contrato canónico de la Etapa 1+2:
//   · El response de previewSale expone TOP-LEVEL:
//       - engineTotal, finalTotal
//       - manualAdjustmentSnapshot (canónico) + manualAdjustment (alias deprecated)
//       - documentRoundingSnapshot
//   · Los 4 campos son determinísticos (mismo input → mismo output).
//   · El alias deprecated comparte referencia con el canónico (cero divergencia).
//   · El gate scope BREAKDOWN + balanceMode UNIFIED tira 400 en preview.
// =============================================================================

describe("Etapa 2 — paridad preview / draft / confirm (contrato canónico)", () => {
  function baseArticleRow() {
    return [{
      id: "a1", categoryId: null, brand: null,
      stockMode: "STOCK", mermaPercent: null, manualTaxIds: [],
      manualAdjustmentKind: null, manualAdjustmentType: null, manualAdjustmentValue: null,
      category: null, costComposition: [],
    }];
  }

  function setupBaseMocks() {
    mockResolveFinalSalePrice.mockResolvedValue(fakeSalePriceResult({
      unitPrice: new D("1000"),
      basePrice: new D("1000"),
      discountAmount: new D("0"),
      promotionDiscountAmount: new D("0"),
      taxAmount: new D("0"),
      totalWithTax: new D("1000"),
    }));
    mockComputeLineTaxes.mockResolvedValue({ taxBreakdown: [], taxAmount: new D("0") });
    mockPrisma.article.findMany.mockResolvedValue(baseArticleRow());
  }

  // ── Caso 1 — UNIFIED sin ajuste: response expone los 4 campos top-level ───
  it("Caso 1 — UNIFIED sin ajuste: engineTotal/finalTotal/manualAdjustmentSnapshot/documentRoundingSnapshot expuestos top-level", async () => {
    setupBaseMocks();

    const out: any = await previewSale("j1", {
      lines: [{ articleId: "a1", variantId: null, quantity: 1 }],
      clientId: null,
    });

    // Los 4 campos canónicos viven top-level (no enterrados, no any-cast).
    expect(out.engineTotal).toBeTypeOf("number");
    expect(out.finalTotal).toBeTypeOf("number");
    expect(out).toHaveProperty("manualAdjustmentSnapshot");
    expect(out).toHaveProperty("documentRoundingSnapshot");

    // Sin ajuste manual → snapshot null y engineTotal === finalTotal.
    expect(out.manualAdjustmentSnapshot).toBeNull();
    expect(out.engineTotal).toBe(out.finalTotal);

    // Alias deprecated comparte la MISMA referencia que el canónico (cero
    // divergencia, cero doble conversión moneda).
    expect(out.manualAdjustment).toBe(out.manualAdjustmentSnapshot);
  });

  // ── Caso 2 — UNIFIED con ajuste: snapshot determinístico + finalTotal correcto ──
  it("Caso 2 — UNIFIED con ajuste: snapshot canónico + finalTotal = engineTotal + ajuste", async () => {
    setupBaseMocks();

    const out: any = await previewSale("j1", {
      lines: [{ articleId: "a1", variantId: null, quantity: 1 }],
      clientId: null,
      manualAdjustment: { scope: "UNIFIED", amount: -100, reason: "test" },
    });

    expect(out.manualAdjustmentSnapshot).not.toBeNull();
    expect(out.manualAdjustmentSnapshot.scope).toBe("UNIFIED");
    expect(out.manualAdjustmentSnapshot.unified?.amount).toBe(-100);
    // finalTotal = engineTotal + monetaryAdjustment (clamp ≥ 0 si negativo).
    expect(out.finalTotal).toBe(Math.max(0, out.engineTotal - 100));
    // Alias deprecated apunta al MISMO objeto snapshot.
    expect(out.manualAdjustment).toBe(out.manualAdjustmentSnapshot);
  });

  // ── Caso 3 — BREAKDOWN sin ajuste: balanceMode resuelto + snapshot null ───
  it("Caso 3 — BREAKDOWN sin ajuste: balanceMode BREAKDOWN + manualAdjustmentSnapshot null", async () => {
    setupBaseMocks();

    const out: any = await previewSale("j1", {
      lines: [{ articleId: "a1", variantId: null, quantity: 1 }],
      clientId: null,
      balanceModeOverride: "BREAKDOWN",
    });

    expect(out.balanceMode).toBe("BREAKDOWN");
    expect(out.manualAdjustmentSnapshot).toBeNull();
    expect(out.engineTotal).toBe(out.finalTotal);
  });

  // ── Caso 4 — BREAKDOWN con ajuste monetario: snapshot.breakdown.monetary ──
  it("Caso 4 — BREAKDOWN con ajuste monetario: snapshot expone monetary.amount", async () => {
    setupBaseMocks();

    const out: any = await previewSale("j1", {
      lines: [{ articleId: "a1", variantId: null, quantity: 1 }],
      clientId: null,
      balanceModeOverride: "BREAKDOWN",
      manualAdjustment: { scope: "BREAKDOWN", metals: [], monetaryAmount: 50 },
    });

    expect(out.manualAdjustmentSnapshot).not.toBeNull();
    expect(out.manualAdjustmentSnapshot.scope).toBe("BREAKDOWN");
    expect(out.manualAdjustmentSnapshot.breakdown?.monetary?.amount).toBe(50);
    // El bucket monetario afecta finalTotal vía totals.monetaryAdjustment.
    expect(out.manualAdjustmentSnapshot.totals?.monetaryAdjustment).toBe(50);
    expect(out.finalTotal).toBe(out.engineTotal + 50);
  });

  // ── Caso 5 — Determinismo: mismo input dos veces, mismo output ───────────
  it("Caso 5 — Determinismo: dos previewSale consecutivos con mismo input dan resultado idéntico", async () => {
    setupBaseMocks();
    const input = {
      lines: [{ articleId: "a1", variantId: null, quantity: 2 }],
      clientId: null,
      balanceModeOverride: "BREAKDOWN" as const,
      manualAdjustment: { scope: "BREAKDOWN" as const, metals: [], monetaryAmount: 75 },
    };

    // Re-aplicar el setup en cada iteración (los mocks de motor agotan llamadas).
    const out1: any = await previewSale("j1", input);
    setupBaseMocks();
    const out2: any = await previewSale("j1", input);

    // Los datos canónicos son byte-a-byte idénticos. Excluimos `audit.appliedAt`
    // del snapshot manual porque es un timestamp generado en cada invocación
    // (`new Date().toISOString()`) — por diseño, NO forma parte del determinismo
    // del cálculo. El resto del snapshot (scope, totals, breakdown, unified) sí.
    const stripAudit = (s: any) => s ? { ...s, audit: undefined } : s;
    expect(out1.engineTotal).toBe(out2.engineTotal);
    expect(out1.finalTotal).toBe(out2.finalTotal);
    expect(stripAudit(out1.manualAdjustmentSnapshot)).toEqual(stripAudit(out2.manualAdjustmentSnapshot));
    expect(out1.documentRoundingSnapshot).toEqual(out2.documentRoundingSnapshot);
  });

  // ── Caso 6 — Gate funcional: scope BREAKDOWN + balanceMode UNIFIED → 400 ─
  it("Caso 6 (Etapa 2.5) — scope BREAKDOWN con balanceMode UNIFIED tira 400 en preview", async () => {
    setupBaseMocks();

    let caught: any = null;
    try {
      await previewSale("j1", {
        lines: [{ articleId: "a1", variantId: null, quantity: 1 }],
        clientId: null,
        // NO se envía balanceModeOverride → resuelve a UNIFIED por tenant default.
        manualAdjustment: { scope: "BREAKDOWN", metals: [], monetaryAmount: 10 },
      });
    } catch (e) {
      caught = e;
    }

    expect(caught).not.toBeNull();
    expect(caught.status).toBe(400);
    expect(String(caught.message)).toContain("BREAKDOWN");
  });

  // ── Caso 7 (E2E) — preview → save draft → reload → preview otra vez ──────
  // Valida el contrato canónico de la Etapa 1+2 backend end-to-end:
  //   1. previewSale devuelve los 4 campos top-level (estado A).
  //   2. syncDraftDocumentTotals persiste EXACTAMENTE los mismos campos.
  //   3. Re-leer el draft + re-prevear devuelve byte-a-byte lo mismo.
  // Sin esto, la "sensación de guardado" del frontend sería incoherente: el
  // operador vería un total al guardar y otro al reabrir el documento.
  it("Caso 7 (E2E) — syncDraftDocumentTotals persiste lo mismo que preview, y reload+preview coincide", async () => {
    setupBaseMocks();

    const input = {
      lines: [{ articleId: "a1", variantId: null, quantity: 2 }],
      clientId: null,
      balanceModeOverride: "BREAKDOWN" as const,
      manualAdjustment: {
        scope:          "BREAKDOWN" as const,
        metals:         [],
        monetaryAmount: 50,
        reason:         "ajuste e2e",
      },
    };

    // ── Paso 1: preview ANTES del save (estado A) ─────────────────────────
    const previewBefore: any = await previewSale("j1", input);
    expect(previewBefore.engineTotal).toBeTypeOf("number");
    expect(previewBefore.finalTotal).toBeTypeOf("number");
    expect(previewBefore.balanceMode).toBe("BREAKDOWN");
    expect(previewBefore.manualAdjustmentSnapshot).not.toBeNull();

    // ── Paso 2: simulamos save → reload → sync ────────────────────────────
    // El sync hace getSale → previewSale(internamente) → prisma.sale.update.
    // El mock de findFirst devuelve el draft persistido con todos los campos
    // que reconstruyen el SalePreviewInput tal cual el operador lo envió.
    const persistedDraft: any = {
      id: "s1", code: "VTA-0001", status: "DRAFT",
      clientId: null, warehouseId: null, channelId: null, couponId: null,
      subtotal:       new D("2000"),
      discountAmount: new D("0"),
      taxAmount:      new D("0"),
      total:          new D("2000"),
      // Etapa A — intención del operador (lo que el frontend mandó al crear).
      manualAdjustmentInput: input.manualAdjustment,
      balanceModeOverride:   "BREAKDOWN",
      shippingAmount:        null,
      globalDiscountType:    null,
      globalDiscountValue:   null,
      paymentMethodId:       null,
      paymentInstallments:   0,
      client: null, seller: null, channel: null, coupon: null,
      lines: [{
        id: "L1", articleId: "a1", variantId: null,
        quantity: new D("2"), unitPrice: new D("1000"), discountPct: new D("0"),
        lineTotal: new D("2000"),
        priceSource: "PRICE_LIST",
        appliedPriceListId: null, appliedPromotionId: null, appliedDiscountId: null,
        pricingSnapshot: fakeSnapshot({ unitPrice: 1000, basePrice: 1000 }),
        manualPriceOverride: null, manualDiscountOverride: null, taxOverride: null,
        manualDiscountAppliesToOverride: null, manualTaxAppliesToOverride: null,
        priceListIdOverride: null,
      }],
    };
    mockPrisma.sale.findFirst.mockResolvedValueOnce(persistedDraft);
    mockPrisma.sale.update.mockResolvedValueOnce({ id: "s1" });

    await syncDraftDocumentTotals("s1", "j1");

    // ── Paso 3: el sync persistió los 4 campos canónicos ──────────────────
    expect(mockPrisma.sale.update).toHaveBeenCalled();
    const persistedData = mockPrisma.sale.update.mock.calls.at(-1)![0].data;

    // engineTotal: exacto al del preview (POLICY §R-Rounding-6).
    expect(persistedData.engineTotal).toBe(previewBefore.engineTotal);
    // total: igual al finalTotal del preview (POLICY §R-Rounding-1).
    expect(persistedData.total).toBe(previewBefore.finalTotal);
    // balanceMode resuelto coincide.
    expect(persistedData.balanceMode).toBe(previewBefore.balanceMode);
    // Snapshots persistidos: no null cuando había ajuste/redondeo.
    expect(persistedData.manualAdjustmentSnapshot).toBeDefined();
    expect(persistedData.manualAdjustmentSnapshot).not.toBe(null);

    // ── Paso 4: reload + preview → mismo resultado byte-a-byte ────────────
    // En producción: el frontend reabre el draft (getSale lo trae con los
    // snapshots persistidos) y re-prevea para mostrar la card de totales.
    // Verificamos que ese segundo preview devuelve los MISMOS números.
    setupBaseMocks();
    const previewAfter: any = await previewSale("j1", input);

    expect(previewAfter.engineTotal).toBe(previewBefore.engineTotal);
    expect(previewAfter.finalTotal).toBe(previewBefore.finalTotal);
    expect(previewAfter.balanceMode).toBe(previewBefore.balanceMode);
    // Snapshot determinístico (excluyendo audit.appliedAt — timestamp por diseño).
    const stripAudit = (s: any) => s ? { ...s, audit: undefined } : s;
    expect(stripAudit(previewAfter.manualAdjustmentSnapshot))
      .toEqual(stripAudit(previewBefore.manualAdjustmentSnapshot));
    expect(previewAfter.documentRoundingSnapshot)
      .toEqual(previewBefore.documentRoundingSnapshot);
  });
});
