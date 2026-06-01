// src/modules/sales/__tests__/confirm-sale-pricing-snapshot.test.ts
//
// Tests Fase 2 — confirmSale debe usar pricingSnapshot como fuente de verdad
// y NO reconstruir basePrice mediante `unitPrice / (1 - discountPct/100)`.

import { describe, it, expect, vi, beforeEach } from "vitest";
import { Prisma } from "@prisma/client";

// ── Mocks (vi.hoisted garantiza disponibilidad en las factories) ────────────

const mockPrisma = vi.hoisted(() => ({
  article:            { findMany: vi.fn(), findFirst: vi.fn() },
  articleVariant:     { findMany: vi.fn(), findFirst: vi.fn() },
  articleGroupItem:   { findMany: vi.fn() },
  articleMovement:    { count:    vi.fn(), create: vi.fn() },
  sale:               { findFirst: vi.fn(), findMany: vi.fn(), create: vi.fn(), update: vi.fn(), count: vi.fn() },
  saleLine:           { update:   vi.fn() },
  salesChannel:       { findFirst: vi.fn() },
  coupon:             { findFirst: vi.fn() },
  couponRedemption:   { create:   vi.fn() },
  priceList:          { findMany: vi.fn() },
  promotion:          { findMany: vi.fn() },
  currency:           { findUnique: vi.fn() },
  jewelry:            { findUnique: vi.fn() },
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
  // FASE 2 — confirmSale invoca el helper para armar el breakdown Metal/Hechura
  // por línea. El mock devuelve null (motor de doc-totals trata las líneas
  // sin metalHechuraBreakdown como agregados=0; no afecta los assertions
  // existentes de este archivo de tests).
  deriveMetalHechuraBreakdown:    () => null,
  // POLICY §Tax.3 — porción FIXED del impuesto (no escala con descuentos doc).
  // Mock retorna 0 → los tests no validan tax FIXED, equivale a "todo escalable".
  sumFixedTaxComponent:           () => 0,
  // F17 — sales.service ahora llama computePurchaseTaxes en
  // getLinePricingSnapshotForConfirm (legacy recompute path) para que el
  // snapshot v7 persistido incluya el bloque de impuestos de costo.
  computePurchaseTaxes: vi.fn().mockResolvedValue({
    costBase: null, costTaxAmount: null, costWithTax: null, costTaxBreakdown: [],
  }),
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
  validateCoupon: vi.fn(),
}));

// Import DESPUÉS de los mocks
import {
  getLinePricingSnapshotForConfirm,
  confirmSale,
} from "../sales.service.js";

const D = Prisma.Decimal;

// ── Helpers ─────────────────────────────────────────────────────────────────

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
    appliedPriceListName: "Lista Mayorista",
    appliedPromotionId:   null,
    appliedPromotionName: null,
    appliedDiscountId:    null,
    resolvedAt:           "2026-04-28T00:00:00.000Z",
    ...overrides,
  };
}

function fakeSalePriceResult(overrides: Record<string, any> = {}) {
  return {
    unitPrice:                new D("888"),
    basePrice:                new D("1000"),
    quantityDiscountAmount:   new D("0"),
    promotionDiscountAmount:  new D("112"),
    discountAmount:           new D("112"),
    priceSource:              "PROMOTION",
    baseSource:               "PRICE_LIST",
    unitCost:                 new D("300"),
    unitMargin:               new D("588"),
    marginPercent:            new D("66"),
    costPartial:              false,
    costMode:                 "COST_LINES",
    partial:                  false,
    appliedPriceListId:       "pl-fresh",
    appliedPriceListName:     "Fresh List",
    appliedPromotionId:       "promo-fresh",
    appliedPromotionName:     "Promo Fresh",
    appliedDiscountId:        null,
    steps:                    [],
    alerts:                   [],
    policy:                   { canConfirm: true, blockingAlerts: [] },
    stackingMode:             "BEST_OF_PROMO",
    metalHechuraBreakdown:    null,
    taxAmount:                new D("0"),
    taxBreakdown:             [],
    totalWithTax:             new D("888"),
    taxExemptByEntity:        false,
    ...overrides,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  mockBuildPricingSnapshot.mockImplementation((res: any) => ({
    unitPrice:            res.unitPrice?.toNumber() ?? null,
    basePrice:            res.basePrice?.toNumber() ?? null,
    discountAmount:       res.discountAmount?.toNumber() ?? 0,
    taxAmount:            res.taxAmount?.toNumber() ?? 0,
    totalWithTax:         res.totalWithTax?.toNumber() ?? null,
    priceSource:          res.priceSource,
    baseSource:           res.baseSource,
    unitCost:             res.unitCost?.toNumber() ?? null,
    unitMargin:           res.unitMargin?.toNumber() ?? null,
    marginPercent:        res.marginPercent?.toNumber() ?? null,
    costPartial:          res.costPartial,
    costMode:             res.costMode,
    partial:              res.partial,
    appliedPriceListId:   res.appliedPriceListId,
    appliedPriceListName: res.appliedPriceListName,
    appliedPromotionId:   res.appliedPromotionId,
    appliedPromotionName: res.appliedPromotionName,
    appliedDiscountId:    res.appliedDiscountId,
    resolvedAt:           "2026-04-28T00:00:00.000Z",
  }));
});

// ────────────────────────────────────────────────────────────────────────────
// Helper unitario — getLinePricingSnapshotForConfirm
// ────────────────────────────────────────────────────────────────────────────

describe("getLinePricingSnapshotForConfirm", () => {
  it("devuelve el snapshot tal cual cuando la línea trae uno válido", async () => {
    const snap = makeSnapshot({ unitPrice: 1500, priceSource: "PROMOTION" });
    const out = await getLinePricingSnapshotForConfirm("j1", {
      id: "L1",
      articleId: "a1",
      variantId: null,
      quantity: 1,
      unitPrice: 9999,    // valor stale en columna
      discountPct: 90,    // valor stale en columna
      pricingSnapshot: snap,
      priceSource: "PROMOTION",
      appliedPriceListId: "pl-1",
      appliedPromotionId: "promo-1",
      appliedDiscountId: null,
    }, { clientId: null });

    expect(out.recomputed).toBe(false);
    expect(out.snapshot.unitPrice).toBe(1500);
    expect(out.snapshot.priceSource).toBe("PROMOTION");
    expect(mockResolveFinalSalePrice).not.toHaveBeenCalled();
  });

  it("recalcula con motor cuando el snapshot está ausente (línea legada)", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    mockResolveFinalSalePrice.mockResolvedValue(fakeSalePriceResult());

    const out = await getLinePricingSnapshotForConfirm("j1", {
      id: "L-old",
      articleId: "a1",
      variantId: null,
      quantity: 2,
      unitPrice: 500,
      discountPct: 0,
      pricingSnapshot: null,
      priceSource: "",
      appliedPriceListId: null,
      appliedPromotionId: null,
      appliedDiscountId: null,
    }, { clientId: "c1" });

    expect(out.recomputed).toBe(true);
    expect(mockResolveFinalSalePrice).toHaveBeenCalledTimes(1);
    expect(out.snapshot.unitPrice).toBe(888);
    expect(out.snapshot.priceSource).toBe("PROMOTION");
    expect(warn).toHaveBeenCalled();
    warn.mockRestore();
  });

  it("recalcula también si pricingSnapshot.unitPrice no es number", async () => {
    mockResolveFinalSalePrice.mockResolvedValue(fakeSalePriceResult());
    vi.spyOn(console, "warn").mockImplementation(() => {});

    const out = await getLinePricingSnapshotForConfirm("j1", {
      id: "L-corrupt",
      articleId: "a1",
      variantId: null,
      quantity: 1,
      unitPrice: 100,
      discountPct: 0,
      pricingSnapshot: { unitPrice: "not a number", priceSource: "PRICE_LIST" } as any,
      priceSource: "",
      appliedPriceListId: null,
      appliedPromotionId: null,
      appliedDiscountId: null,
    }, { clientId: null });

    expect(out.recomputed).toBe(true);
    expect(mockResolveFinalSalePrice).toHaveBeenCalled();
  });

  it("último recurso: snapshot mínimo desde columnas si motor también falla", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    mockResolveFinalSalePrice.mockResolvedValue(fakeSalePriceResult({
      unitPrice: null,
      basePrice: null,
      priceSource: "NONE",
      baseSource:  "NONE",
    }));

    const out = await getLinePricingSnapshotForConfirm("j1", {
      id: "L-no-engine",
      articleId: "a1",
      variantId: null,
      quantity: 1,
      unitPrice: 700,
      discountPct: 30,         // → basePrice = 700 / 0.7 = 1000
      pricingSnapshot: null,
      priceSource: "PRICE_LIST",
      appliedPriceListId: "pl-X",
      appliedPromotionId: null,
      appliedDiscountId: null,
    }, { clientId: null });

    expect(out.recomputed).toBe(true);
    expect(out.snapshot.unitPrice).toBe(700);
    expect(out.snapshot.basePrice).toBeCloseTo(1000, 4);
    expect(out.snapshot.priceSource).toBe("PRICE_LIST");
    expect(out.snapshot.appliedPriceListId).toBe("pl-X");
    expect(out.snapshot.partial).toBe(true);
    expect(warn).toHaveBeenCalled();
    warn.mockRestore();
  });
});

// ────────────────────────────────────────────────────────────────────────────
// Integración — confirmSale debe usar el snapshot, no reconstrucción inversa
// ────────────────────────────────────────────────────────────────────────────

describe("confirmSale — usa pricingSnapshot como fuente de verdad", () => {
  function setupCommonMocks() {
    mockEvaluatePricingPolicy.mockResolvedValue([]);
    mockBuildBatchCostContext.mockResolvedValue({
      baseCurrencyId: "cur-1",
      defaultMermaPercent: null,
      metalVariantData: new Map(),
      rateMap: new Map(),
    });
    mockCalculateCostFromLines.mockResolvedValue({
      value: new D("400"),
      mode: "COST_LINES",
      partial: false,
      breakdown: null,
      steps: [],
    });
    mockComputeLineTaxes.mockResolvedValue({
      taxBreakdown: [],
      taxAmount:    new D("0"),
    });
    mockApplyChannel.mockReturnValue({
      baseAmount: 1000, finalAmount: 1000, adjustment: 0, channelId: "", channelName: "", adjustmentType: "PERCENTAGE", adjustmentValue: 0, applied: false, steps: [],
    });
    mockApplyCoupon.mockReturnValue({
      baseAmount: 1000, discountAmount: 0, finalAmount: 1000, couponId: "", couponCode: "", couponName: "", discountType: "PERCENTAGE", discountValue: 0, applied: false,
    });

    // Stub determinístico: total = Σ lineTotal + Σ lineTaxAmount.
    mockComputeSaleDocTotals.mockImplementation((input: any) => {
      const subtotal = input.lines.reduce((s: number, l: any) => s + l.lineTotal, 0);
      const tax      = input.lines.reduce((s: number, l: any) => s + l.lineTaxAmount, 0);
      return {
        subtotalBeforeDiscounts:    subtotal,
        lineDiscountAmount:         0,
        subtotalAfterLineDiscounts: subtotal,
        channelAdjustmentAmount:    0,
        couponDiscountAmount:       0,
        paymentAdjustmentAmount:    0,
        shippingAmount:             0,
        globalDiscountAmount:       0,
        taxableBase:                subtotal,
        taxAmount:                  tax,
        roundingAdjustment:         0,
        totalBeforeTax:             subtotal,
        totalWithTax:               subtotal + tax,
        total:                      subtotal + tax,
        legacyCouponOnlyDiscount:   0,
        // Fase 6: channelResult/couponResult son parte del payload.
        channelResult: {
          baseAmount: subtotal, channelAmount: 0, finalAmount: subtotal,
          channelName: "", channelId: "",
        },
        couponResult: {
          baseAmount: subtotal, discountAmount: 0, finalAmount: subtotal,
          couponId: "", couponCode: "", couponName: "",
          discountType: "PERCENTAGE", discountValue: 0, applied: false,
        },
        sourceTrace: [],
      };
    });

    mockPrisma.priceList.findMany.mockResolvedValue([]);
    mockPrisma.promotion.findMany.mockResolvedValue([]);
    mockPrisma.coupon.findFirst.mockResolvedValue(null);
    mockPrisma.currency.findUnique.mockResolvedValue(null);
    mockPrisma.jewelry.findUnique.mockResolvedValue({
      id: "j1", name: "J", legalName: "", cuit: "", ivaCondition: "", email: "",
      street: "", number: "", floor: "", apartment: "", city: "", province: "",
      country: "", postalCode: "", logoUrl: "",
    });
    mockPrisma.sale.update.mockResolvedValue({ id: "s1" });
    // default: incluye lines:[] para que el getSale() final de confirmSale
    // no rompa al iterar. Tests que necesiten datos especiales encadenan
    // `mockResolvedValueOnce(...)` antes para la primera llamada.
    mockPrisma.sale.findFirst.mockResolvedValue({ id: "s1", lines: [] });

    // $transaction: ejecuta la callback con un tx mock
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
      id: "s1",
      code: "VTA-0001",
      status: "DRAFT",
      clientId: null,
      warehouseId: null,
      subtotal: new D("1000"),
      discountAmount: new D("0"),
      taxAmount: new D("0"),
      total: new D("1000"),
      couponId: null,
      client: null,
      seller: null,
      channel: null,
      lines: [],
      ...overrides,
    };
  }

  function makeArticle(overrides: Record<string, any> = {}) {
    return {
      id: "a1",
      stockMode: "STOCK",
      mermaPercent: null,
      manualTaxIds: [],
      manualAdjustmentKind:  null,
      manualAdjustmentType:  null,
      manualAdjustmentValue: null,
      costComposition: [],
      ...overrides,
    };
  }

  it("computeLineTaxes recibe basePrice del snapshot, NO la reconstrucción inversa", async () => {
    const { txMock } = setupCommonMocks();
    // snapshot: unitPrice=800 (final), basePrice=1000 (lista). Reconstrucción
    // INVERSA basada en columnas legacy daría unitPrice / (1 - 0/100) = 800,
    // que es DIFERENTE al basePrice real (1000). El test valida que se use 1000.
    const snap = makeSnapshot({ unitPrice: 800, basePrice: 1000, discountAmount: 200, priceSource: "PROMOTION" });
    mockPrisma.sale.findFirst.mockResolvedValueOnce(makeSale({
      lines: [{
        id: "L1",
        articleId: "a1",
        variantId: null,
        quantity:    new D("1"),
        unitPrice:   new D("800"),  // matches snapshot
        discountPct: new D("0"),
        lineTotal:   new D("800"),
        priceSource: "PROMOTION",
        appliedPriceListId: "pl-1",
        appliedPromotionId: "promo-1",
        appliedDiscountId:  null,
        pricingSnapshot:    snap,
      }],
    }));
    mockPrisma.article.findMany.mockResolvedValue([makeArticle()]);

    await confirmSale("s1", "j1", "u1");

    expect(mockComputeLineTaxes).toHaveBeenCalledTimes(1);
    const callArgs = mockComputeLineTaxes.mock.calls[0];
    // Args: (jewelryId, taxIds, unitPriceDec, basePriceDec, ...)
    const unitArg = callArgs[2];
    const baseArg = callArgs[3];
    expect(parseFloat(unitArg.toString())).toBe(800);
    expect(parseFloat(baseArg.toString())).toBe(1000);   // ← clave Fase 2
  });

  it("preserva priceSource=PROMOTION y appliedPromotionId en el snapshot persistido", async () => {
    const { txMock } = setupCommonMocks();
    const snap = makeSnapshot({
      unitPrice: 800, basePrice: 1000,
      priceSource: "PROMOTION",
      appliedPriceListId: "pl-1",
      appliedPromotionId: "promo-7",
      appliedPromotionName: "BlackFriday",
    });
    mockPrisma.sale.findFirst.mockResolvedValueOnce(makeSale({
      lines: [{
        id: "L1", articleId: "a1", variantId: null,
        quantity: new D("1"), unitPrice: new D("800"), discountPct: new D("0"),
        lineTotal: new D("800"),
        priceSource: "PROMOTION",
        appliedPriceListId: "pl-1",
        appliedPromotionId: "promo-7",
        appliedDiscountId: null,
        pricingSnapshot: snap,
      }],
    }));
    mockPrisma.article.findMany.mockResolvedValue([makeArticle()]);

    await confirmSale("s1", "j1", "u1");

    expect(txMock.saleLine.update).toHaveBeenCalledTimes(1);
    const persistedData = txMock.saleLine.update.mock.calls[0][0].data;
    expect(persistedData.pricingSnapshot.priceSource).toBe("PROMOTION");
    expect(persistedData.pricingSnapshot.appliedPromotionId).toBe("promo-7");
    expect(persistedData.pricingSnapshot.appliedPromotionName).toBe("BlackFriday");
  });

  it("preserva priceSource=QUANTITY_DISCOUNT y appliedDiscountId", async () => {
    const { txMock } = setupCommonMocks();
    const snap = makeSnapshot({
      unitPrice: 900, basePrice: 1000,
      priceSource: "QUANTITY_DISCOUNT",
      appliedPromotionId: null,
      appliedPromotionName: null,
      appliedDiscountId: "qd-3",
    });
    mockPrisma.sale.findFirst.mockResolvedValueOnce(makeSale({
      lines: [{
        id: "L1", articleId: "a1", variantId: null,
        quantity: new D("10"), unitPrice: new D("900"), discountPct: new D("0"),
        lineTotal: new D("9000"),
        priceSource: "QUANTITY_DISCOUNT",
        appliedPriceListId: "pl-1",
        appliedPromotionId: null,
        appliedDiscountId: "qd-3",
        pricingSnapshot: snap,
      }],
    }));
    mockPrisma.article.findMany.mockResolvedValue([makeArticle()]);

    await confirmSale("s1", "j1", "u1");

    const persistedData = txMock.saleLine.update.mock.calls[0][0].data;
    expect(persistedData.pricingSnapshot.priceSource).toBe("QUANTITY_DISCOUNT");
    expect(persistedData.pricingSnapshot.appliedDiscountId).toBe("qd-3");
    expect(persistedData.pricingSnapshot.appliedPromotionId).toBeNull();
  });

  it("línea legada sin snapshot: recalcula con motor y persiste snapshot nuevo", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const { txMock } = setupCommonMocks();
    mockResolveFinalSalePrice.mockResolvedValue(fakeSalePriceResult({
      unitPrice: new D("777"),
      basePrice: new D("999"),
      priceSource: "PRICE_LIST",
    }));

    mockPrisma.sale.findFirst.mockResolvedValueOnce(makeSale({
      lines: [{
        id: "L-old", articleId: "a1", variantId: null,
        quantity: new D("1"), unitPrice: new D("500"), discountPct: new D("0"),
        lineTotal: new D("500"),
        priceSource: "",
        appliedPriceListId: null,
        appliedPromotionId: null,
        appliedDiscountId:  null,
        pricingSnapshot:   null,    // legada
      }],
    }));
    mockPrisma.article.findMany.mockResolvedValue([makeArticle()]);

    await confirmSale("s1", "j1", "u1");

    expect(mockResolveFinalSalePrice).toHaveBeenCalledTimes(1);
    const persistedData = txMock.saleLine.update.mock.calls[0][0].data;
    expect(persistedData.pricingSnapshot.unitPrice).toBe(777);
    expect(persistedData.pricingSnapshot.basePrice).toBe(999);
  });

  it("ignora unitPrice/discountPct stale de columnas si snapshot trae valores correctos", async () => {
    const { txMock } = setupCommonMocks();
    // Snapshot dice 1000, pero la columna unitPrice quedó stale en 9999 y
    // discountPct stale en 90 (escenario hipotético post-Fase 1 con corrupción).
    const snap = makeSnapshot({ unitPrice: 1000, basePrice: 1200, priceSource: "PRICE_LIST" });
    mockPrisma.sale.findFirst.mockResolvedValueOnce(makeSale({
      lines: [{
        id: "L1", articleId: "a1", variantId: null,
        quantity: new D("1"),
        unitPrice:   new D("9999"),  // stale
        discountPct: new D("90"),    // stale
        lineTotal:   new D("9999"),  // stale
        priceSource: "PRICE_LIST",
        appliedPriceListId: "pl-1",
        appliedPromotionId: null,
        appliedDiscountId: null,
        pricingSnapshot: snap,
      }],
    }));
    mockPrisma.article.findMany.mockResolvedValue([makeArticle()]);

    await confirmSale("s1", "j1", "u1");

    const callArgs = mockComputeLineTaxes.mock.calls[0];
    const unitArg = callArgs[2];
    const baseArg = callArgs[3];
    // El motor recibe valores del snapshot, no de las columnas stale.
    expect(parseFloat(unitArg.toString())).toBe(1000);
    expect(parseFloat(baseArg.toString())).toBe(1200);

    const persistedData = txMock.saleLine.update.mock.calls[0][0].data;
    expect(persistedData.pricingSnapshot.unitPrice).toBe(1000);
    expect(persistedData.pricingSnapshot.basePrice).toBe(1200);
  });

  it("precio frozen: NO se llama al motor de venta para líneas con snapshot, aunque cambie la lista", async () => {
    const { txMock } = setupCommonMocks();
    const snap = makeSnapshot({ unitPrice: 800, basePrice: 1000, priceSource: "PRICE_LIST" });
    mockPrisma.sale.findFirst.mockResolvedValueOnce(makeSale({
      lines: [{
        id: "L1", articleId: "a1", variantId: null,
        quantity: new D("1"), unitPrice: new D("800"), discountPct: new D("0"),
        lineTotal: new D("800"),
        priceSource: "PRICE_LIST",
        appliedPriceListId: "pl-1",
        appliedPromotionId: null,
        appliedDiscountId: null,
        pricingSnapshot: snap,
      }],
    }));
    mockPrisma.article.findMany.mockResolvedValue([makeArticle()]);
    // Si el motor se llamara, devolvería un precio nuevo (1500). Verificamos
    // que NO se llame y que el persistido siga siendo 800.
    mockResolveFinalSalePrice.mockResolvedValue(fakeSalePriceResult({
      unitPrice: new D("1500"),
    }));

    await confirmSale("s1", "j1", "u1");

    expect(mockResolveFinalSalePrice).not.toHaveBeenCalled();
    const persistedData = txMock.saleLine.update.mock.calls[0][0].data;
    expect(persistedData.pricingSnapshot.unitPrice).toBe(800);   // frozen
  });
});

// ────────────────────────────────────────────────────────────────────────────
// Fase 3 — confirmSale debe persistir Sale.total/taxAmount/discountAmount
// directo desde computeSaleDocumentTotals, no calcularlos a mano.
// ────────────────────────────────────────────────────────────────────────────

describe("confirmSale — Fase 3: usa computeSaleDocumentTotals para los totales", () => {
  function makeSale(overrides: Record<string, any> = {}) {
    return {
      id: "s1",
      code: "VTA-0001",
      status: "DRAFT",
      clientId: null,
      warehouseId: null,
      subtotal: new D("1000"),
      discountAmount: new D("0"),
      taxAmount: new D("0"),
      total: new D("1000"),
      couponId: null,
      client: null,
      seller: null,
      channel: null,
      lines: [],
      ...overrides,
    };
  }
  function makeArticle(overrides: Record<string, any> = {}) {
    return {
      id: "a1", stockMode: "STOCK", mermaPercent: null,
      manualTaxIds: [], manualAdjustmentKind: null, manualAdjustmentType: null,
      manualAdjustmentValue: null, costComposition: [],
      ...overrides,
    };
  }

  function setupBase() {
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

    mockPrisma.priceList.findMany.mockResolvedValue([]);
    mockPrisma.promotion.findMany.mockResolvedValue([]);
    mockPrisma.coupon.findFirst.mockResolvedValue(null);
    mockPrisma.currency.findUnique.mockResolvedValue(null);
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

  it("Sale.total = documentTotals.total y Sale.taxAmount = documentTotals.taxAmount", async () => {
    const { txMock } = setupBase();
    // Stub: total fijo en 1234.56 y tax en 234.56, sin importar las líneas.
    mockComputeSaleDocTotals.mockReturnValue({
      subtotalBeforeDiscounts:    1000,
      lineDiscountAmount:         0,
      subtotalAfterLineDiscounts: 1000,
      channelAdjustmentAmount:    0,
      couponDiscountAmount:       50,
      paymentAdjustmentAmount:    0,
      shippingAmount:             0,
      globalDiscountAmount:       0,
      taxableBase:                950,
      taxAmount:                  234.56,
      roundingAdjustment:         0,
      totalBeforeTax:             950,
      totalWithTax:               1184.56,
      total:                      1234.56,
      legacyCouponOnlyDiscount:   50,
      channelResult: { baseAmount: 1000, channelAmount: 0, finalAmount: 1000, channelName: "", channelId: "" },
      couponResult:  { baseAmount: 1000, discountAmount: 50, finalAmount: 950, couponId: "", couponCode: "", couponName: "", discountType: "PERCENTAGE", discountValue: 0, applied: false },
      sourceTrace:                [],
    });

    const snap = makeSnapshot({ unitPrice: 1000, basePrice: 1000 });
    mockPrisma.sale.findFirst.mockResolvedValueOnce(makeSale({
      lines: [{
        id: "L1", articleId: "a1", variantId: null,
        quantity: new D("1"), unitPrice: new D("1000"), discountPct: new D("0"),
        lineTotal: new D("1000"),
        priceSource: "PRICE_LIST",
        appliedPriceListId: "pl-1", appliedPromotionId: null, appliedDiscountId: null,
        pricingSnapshot: snap,
      }],
    }));
    mockPrisma.article.findMany.mockResolvedValue([makeArticle()]);

    await confirmSale("s1", "j1", "u1");

    expect(mockComputeSaleDocTotals).toHaveBeenCalledTimes(1);
    expect(txMock.sale.update).toHaveBeenCalled();
    const updateData = txMock.sale.update.mock.calls[0][0].data;
    expect(updateData.total).toBe(1234.56);
    expect(updateData.taxAmount).toBe(234.56);
    expect(updateData.discountAmount).toBe(50);  // legacyCouponOnlyDiscount
  });

  it("Sale.discountAmount mantiene compat legacy (solo cupón) aunque haya descuentos por línea", async () => {
    const { txMock } = setupBase();
    // Línea con descuento de 200 + cupón de 100 → legacy guarda solo 100.
    mockComputeSaleDocTotals.mockReturnValue({
      subtotalBeforeDiscounts:    1000,
      lineDiscountAmount:         200,         // descuento por línea (promoción)
      subtotalAfterLineDiscounts: 800,
      channelAdjustmentAmount:    0,
      couponDiscountAmount:       100,
      paymentAdjustmentAmount:    0,
      shippingAmount:             0,
      globalDiscountAmount:       0,
      taxableBase:                700,
      taxAmount:                  0,
      roundingAdjustment:         0,
      totalBeforeTax:             700,
      totalWithTax:               700,
      total:                      700,
      legacyCouponOnlyDiscount:   100,
      channelResult: { baseAmount: 800, channelAmount: 0, finalAmount: 800, channelName: "", channelId: "" },
      couponResult:  { baseAmount: 800, discountAmount: 100, finalAmount: 700, couponId: "", couponCode: "", couponName: "", discountType: "PERCENTAGE", discountValue: 0, applied: false },
      sourceTrace:                [],
    });

    const snap = makeSnapshot({ unitPrice: 800, basePrice: 1000 });
    mockPrisma.sale.findFirst.mockResolvedValueOnce(makeSale({
      lines: [{
        id: "L1", articleId: "a1", variantId: null,
        quantity: new D("1"), unitPrice: new D("800"), discountPct: new D("0"),
        lineTotal: new D("800"),
        priceSource: "PROMOTION", appliedPriceListId: "pl-1",
        appliedPromotionId: "promo-1", appliedDiscountId: null,
        pricingSnapshot: snap,
      }],
    }));
    mockPrisma.article.findMany.mockResolvedValue([makeArticle()]);

    await confirmSale("s1", "j1", "u1");

    const updateData = txMock.sale.update.mock.calls[0][0].data;
    expect(updateData.discountAmount).toBe(100);   // solo cupón (legacy)
    expect(updateData.total).toBe(700);
  });

  it("documentLine recibe basePrice del snapshot, no de columnas legacy", async () => {
    setupBase();
    const snap = makeSnapshot({ unitPrice: 800, basePrice: 1000 });
    mockPrisma.sale.findFirst.mockResolvedValueOnce(makeSale({
      lines: [{
        id: "L1", articleId: "a1", variantId: null,
        quantity: new D("2"),
        unitPrice:   new D("9999"),    // stale
        discountPct: new D("90"),      // stale
        lineTotal:   new D("1600"),    // qty × unitPrice del snapshot
        priceSource: "PROMOTION",
        appliedPriceListId: "pl-1", appliedPromotionId: "promo-1", appliedDiscountId: null,
        pricingSnapshot: snap,
      }],
    }));
    mockPrisma.article.findMany.mockResolvedValue([makeArticle()]);

    await confirmSale("s1", "j1", "u1");

    expect(mockComputeSaleDocTotals).toHaveBeenCalledTimes(1);
    const inputArg = mockComputeSaleDocTotals.mock.calls[0][0];
    expect(inputArg.lines).toHaveLength(1);
    expect(inputArg.lines[0].basePrice).toBe(1000);   // del snapshot, no 9999
    expect(inputArg.lines[0].unitPrice).toBe(800);
  });

  it("escenario combinado promoción + descuento por cantidad + cupón + impuestos: total no diverge entre líneas y header", async () => {
    const { txMock } = setupBase();
    // 2 líneas con priceSource distinto (promoción y qty discount), cupón
    // y canal. mockComputeSaleDocTotals devuelve total derivado para chequear
    // que confirmSale lo persiste tal cual sin recalcular nada.
    const expected = {
      subtotalBeforeDiscounts:    2500,
      lineDiscountAmount:         400,
      subtotalAfterLineDiscounts: 2100,
      channelAdjustmentAmount:    105,
      couponDiscountAmount:       200,
      paymentAdjustmentAmount:    0,
      shippingAmount:             0,
      globalDiscountAmount:       0,
      taxableBase:                2005,
      taxAmount:                  210,
      roundingAdjustment:         0,
      totalBeforeTax:             2005,
      totalWithTax:               2215,
      total:                      2215,
      legacyCouponOnlyDiscount:   200,
      channelResult: { baseAmount: 2100, channelAmount: 105, finalAmount: 2205, channelName: "", channelId: "" },
      couponResult:  { baseAmount: 2205, discountAmount: 200, finalAmount: 2005, couponId: "cp-9", couponCode: "", couponName: "", discountType: "FIXED_AMOUNT", discountValue: 200, applied: true },
      sourceTrace:                [],
    };
    mockComputeSaleDocTotals.mockReturnValue(expected);

    const snap1 = makeSnapshot({ unitPrice: 800, basePrice: 1000, priceSource: "PROMOTION", appliedPromotionId: "promo-1" });
    const snap2 = makeSnapshot({ unitPrice: 500, basePrice: 500,  priceSource: "QUANTITY_DISCOUNT", appliedPromotionId: null, appliedDiscountId: "qd-7" });

    mockPrisma.sale.findFirst.mockResolvedValueOnce(makeSale({
      couponId: "cp-9",
      lines: [
        {
          id: "L1", articleId: "a1", variantId: null,
          quantity: new D("2"), unitPrice: new D("800"), discountPct: new D("0"),
          lineTotal: new D("1600"),
          priceSource: "PROMOTION",
          appliedPriceListId: "pl-1", appliedPromotionId: "promo-1", appliedDiscountId: null,
          pricingSnapshot: snap1,
        },
        {
          id: "L2", articleId: "a1", variantId: null,
          quantity: new D("1"), unitPrice: new D("500"), discountPct: new D("0"),
          lineTotal: new D("500"),
          priceSource: "QUANTITY_DISCOUNT",
          appliedPriceListId: "pl-1", appliedPromotionId: null, appliedDiscountId: "qd-7",
          pricingSnapshot: snap2,
        },
      ],
    }));
    mockPrisma.article.findMany.mockResolvedValue([makeArticle()]);

    await confirmSale("s1", "j1", "u1");

    const updateData = txMock.sale.update.mock.calls[0][0].data;
    expect(updateData.total).toBe(expected.total);
    expect(updateData.taxAmount).toBe(expected.taxAmount);
    expect(updateData.discountAmount).toBe(expected.legacyCouponOnlyDiscount);
    // El motor recibió 2 líneas con sus basePrice/unitPrice correctos
    const inputArg = mockComputeSaleDocTotals.mock.calls[0][0];
    expect(inputArg.lines).toHaveLength(2);
    expect(inputArg.lines[0].basePrice).toBe(1000);
    expect(inputArg.lines[0].unitPrice).toBe(800);
    expect(inputArg.lines[1].basePrice).toBe(500);
    expect(inputArg.lines[1].unitPrice).toBe(500);
  });
});
