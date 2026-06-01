// src/modules/sales/__tests__/sale-line-overrides.test.ts
//
// Etapa 4 (cierre limitación Etapa 3) — verifica que los overrides
// comerciales per-line viajen al motor en `createSale` / `updateSale`
// y queden persistidos en `SaleLine` para que un reopen del DRAFT no
// pierda los ajustes manuales.
//
// Cubre:
//   1. createSale persiste manualPriceOverride / manualDiscountOverride /
//      taxOverride / appliesTo / priceListIdOverride.
//   2. updateSale reemplaza las líneas y persiste los overrides nuevos.
//   3. Reopen flow: la sale persistida con overrides los expone en el
//      detail (mismo shape que el frontend rehidrata).
//   4. Roundtrip: createSale → updateSale con MISMOS overrides → los
//      campos persistidos quedan idénticos.

import { describe, it, expect, vi, beforeEach } from "vitest";
import { Prisma } from "@prisma/client";

const mockPrisma = vi.hoisted(() => ({
  article:          { findMany: vi.fn(), findFirst: vi.fn() },
  articleVariant:   { findMany: vi.fn(), findFirst: vi.fn() },
  articleGroupItem: { findMany: vi.fn() },
  sale:             { findFirst: vi.fn(), findUnique: vi.fn(), create: vi.fn(), update: vi.fn(), count: vi.fn() },
  saleLine:         { findMany: vi.fn() },
  salesChannel:     { findFirst: vi.fn() },
  coupon:           { findFirst: vi.fn() },
  priceList:        { findMany: vi.fn() },
  promotion:        { findMany: vi.fn() },
  paymentMethod:    { findFirst: vi.fn() },
  $transaction:     vi.fn(),
}));
vi.mock("../../../lib/prisma.js", () => ({ prisma: mockPrisma }));

const mockResolveFinalSalePrice  = vi.hoisted(() => vi.fn());
const mockBuildPricingSnapshot   = vi.hoisted(() => vi.fn());
const mockCalculateCostFromLines = vi.hoisted(() => vi.fn());
const mockBuildBatchCostContext  = vi.hoisted(() => vi.fn());

vi.mock("../../../lib/pricing-engine/pricing-engine.js", () => ({
  resolveFinalSalePrice:          (...a: any[]) => mockResolveFinalSalePrice(...a),
  buildPricingSnapshot:           (...a: any[]) => mockBuildPricingSnapshot(...a),
  calculateCostFromLines:         (...a: any[]) => mockCalculateCostFromLines(...a),
  buildBatchCostContext:          (...a: any[]) => mockBuildBatchCostContext(...a),
  computeLineTaxes:               vi.fn(),
  evaluatePricingPolicy:          vi.fn().mockResolvedValue([]),
  applySalesChannelAdjustment:    vi.fn(),
  applyCouponAdjustment:          vi.fn(),
  buildBalanceBreakdownFromPrice: vi.fn(),
  computeSaleDocumentTotals:      vi.fn(),
  computePurchaseTaxes: vi.fn().mockResolvedValue({
    costBase: null, costTaxAmount: null, costWithTax: null, costTaxBreakdown: [],
  }),
  deriveMetalHechuraBreakdown: () => null,
  resolveShippingAmount: (input: any) => {
    if (!input || !input.mode) return null;
    if (input.mode === "FIXED") return { mode: "FIXED", amount: Number(input.value) };
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

import { createSale, updateSale } from "../sales.service.js";

const D = Prisma.Decimal;

function fakeSalePriceResult(overrides: Record<string, any> = {}) {
  return {
    unitPrice:                new D("1000"),
    basePrice:                new D("1000"),
    quantityDiscountAmount:   new D("0"),
    promotionDiscountAmount:  new D("0"),
    discountAmount:           new D("0"),
    priceSource:              "PRICE_LIST",
    baseSource:               "PRICE_LIST",
    unitCost:                 new D("400"),
    unitMargin:               new D("600"),
    marginPercent:            new D("60"),
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
    stackingMode:             "BEST_OF_PROMO",
    metalHechuraBreakdown:    null,
    taxAmount:                new D("0"),
    taxBreakdown:             [],
    totalWithTax:             new D("1000"),
    taxExemptByEntity:        false,
    ...overrides,
  };
}

function fakeSaleDetailWithLine(overrides: Record<string, any> = {}) {
  return {
    id: "sale-1", code: "VTA-0001", status: "DRAFT" as const,
    lines: [{ id: "L1", ...overrides }],
    ...overrides,
  };
}

beforeEach(() => {
  // resetAllMocks limpia tanto las llamadas como las implementaciones encoladas
  // (mockResolvedValueOnce). Sin esto, mocks "once" de un test contaminan al
  // siguiente.
  vi.resetAllMocks();
  mockPrisma.articleVariant.findMany.mockResolvedValue([]);
  mockPrisma.articleGroupItem.findMany.mockResolvedValue([]);
  mockPrisma.salesChannel.findFirst.mockResolvedValue(null);
  mockPrisma.coupon.findFirst.mockResolvedValue(null);
  mockPrisma.priceList.findMany.mockResolvedValue([]);
  mockPrisma.promotion.findMany.mockResolvedValue([]);
  mockPrisma.paymentMethod.findFirst.mockResolvedValue(null);
  mockPrisma.article.findMany.mockResolvedValue([{
    id: "a1", name: "Anillo", code: "AN-001", sku: "SKU-1", barcode: "",
    salePrice: new D("1000"),
    _count: { variants: 0 },
    categoryId: null, brand: null,
    costComposition: [],
  }]);
  mockPrisma.sale.findFirst.mockResolvedValue({ id: "sale-1", status: "DRAFT", clientId: null });
  // saleCode helper consulta `sale.findFirst` también — ya cubierto por
  // findFirst con el mock por defecto del seg argumento.
  mockResolveFinalSalePrice.mockResolvedValue(fakeSalePriceResult());
  mockBuildPricingSnapshot.mockReturnValue({ unitPrice: 1000, basePrice: 1000 });
  mockBuildBatchCostContext.mockResolvedValue({
    baseCurrencyId: "cur-1", defaultMermaPercent: null,
    metalVariantData: new Map(), rateMap: new Map(),
  });
  mockCalculateCostFromLines.mockResolvedValue({
    value: new D("400"), mode: "COST_LINES", partial: false, breakdown: null, steps: [],
  });
});

// ────────────────────────────────────────────────────────────────────────────
describe("createSale — overrides per-line persisten", () => {
  it("manualPriceOverride viaja al motor y se persiste en SaleLine", async () => {
    mockPrisma.sale.create.mockImplementation(async ({ data }) => ({
      id: "sale-1", code: "VTA-0001",
      ...data,
      lines: data.lines.create,
    }));

    await createSale("j1", "u1", {
      clientId: "client-1",
      lines: [{
        articleId: "a1", quantity: 1, unitPrice: 0,
        manualPriceOverride: 1500,
      }],
    });

    // El motor recibió el override.
    expect(mockResolveFinalSalePrice).toHaveBeenCalledTimes(1);
    const motorArgs = mockResolveFinalSalePrice.mock.calls[0][1];
    expect(motorArgs.manualPriceOverride).toBe(1500);

    // El SaleLine se creó con el override persistido.
    expect(mockPrisma.sale.create).toHaveBeenCalledTimes(1);
    const createArgs = mockPrisma.sale.create.mock.calls[0][0];
    const linePersisted = createArgs.data.lines.create[0];
    expect(linePersisted.manualPriceOverride).toBe(1500);
  });

  it("manualDiscountOverride (objeto) se persiste como JSON", async () => {
    mockPrisma.sale.create.mockImplementation(async ({ data }) => ({
      id: "sale-1", code: "VTA-0001",
      ...data,
      lines: data.lines.create,
    }));

    const discount = { mode: "PERCENT" as const, value: 15, appliesTo: "TOTAL" as const, kind: "BONUS" as const };
    await createSale("j1", "u1", {
      clientId: "client-1",
      lines: [{
        articleId: "a1", quantity: 1, unitPrice: 0,
        manualDiscountOverride: discount,
      }],
    });

    const motorArgs = mockResolveFinalSalePrice.mock.calls[0][1];
    expect(motorArgs.manualDiscountOverride).toEqual(discount);

    const linePersisted = mockPrisma.sale.create.mock.calls[0][0].data.lines.create[0];
    expect(linePersisted.manualDiscountOverride).toEqual(discount);
  });

  it("taxOverride (objeto) + appliesTo + priceListIdOverride se persisten", async () => {
    mockPrisma.sale.create.mockImplementation(async ({ data }) => ({
      id: "sale-1", code: "VTA-0001",
      ...data,
      lines: data.lines.create,
    }));

    await createSale("j1", "u1", {
      clientId: "client-1",
      lines: [{
        articleId: "a1", quantity: 1, unitPrice: 0,
        taxOverride: { mode: "PERCENT", value: 21, appliesTo: "TOTAL" },
        manualDiscountAppliesToOverride: "METAL",
        manualTaxAppliesToOverride: "HECHURA",
        priceListIdOverride: "pl-vip",
      }],
    });

    const motorArgs = mockResolveFinalSalePrice.mock.calls[0][1];
    expect(motorArgs.taxOverride).toEqual({ mode: "PERCENT", value: 21, appliesTo: "TOTAL" });
    // El motor recibe los appliesTo overrides con nombres propios.
    expect(motorArgs.discountAppliesToOverride).toBe("METAL");
    expect(motorArgs.taxAppliesToOverride).toBe("HECHURA");
    expect(motorArgs.priceListIdOverride).toBe("pl-vip");

    const linePersisted = mockPrisma.sale.create.mock.calls[0][0].data.lines.create[0];
    expect(linePersisted.taxOverride).toEqual({ mode: "PERCENT", value: 21, appliesTo: "TOTAL" });
    expect(linePersisted.manualDiscountAppliesToOverride).toBe("METAL");
    expect(linePersisted.manualTaxAppliesToOverride).toBe("HECHURA");
    expect(linePersisted.priceListIdOverride).toBe("pl-vip");
  });

  it("sin overrides → todos persisten como null (no campos huérfanos)", async () => {
    mockPrisma.sale.create.mockImplementation(async ({ data }) => ({
      id: "sale-1", code: "VTA-0001",
      ...data,
      lines: data.lines.create,
    }));

    await createSale("j1", "u1", {
      clientId: "client-1",
      lines: [{ articleId: "a1", quantity: 1, unitPrice: 0 }],
    });

    const linePersisted = mockPrisma.sale.create.mock.calls[0][0].data.lines.create[0];
    expect(linePersisted.manualPriceOverride).toBeNull();
    expect(linePersisted.manualDiscountOverride).toBeNull();
    expect(linePersisted.taxOverride).toBeNull();
    expect(linePersisted.manualDiscountAppliesToOverride).toBeNull();
    expect(linePersisted.manualTaxAppliesToOverride).toBeNull();
    expect(linePersisted.priceListIdOverride).toBeNull();
  });
});

// ────────────────────────────────────────────────────────────────────────────
describe("updateSale — reemplazo de líneas preserva overrides nuevos", () => {
  it("update con overrides → líneas nuevas con overrides persistidos", async () => {
    // Sale DRAFT existente sin overrides previos. Counter para distinguir
    // la 1ra llamada (validación) de la 2da+ (getSale al final).
    mockPrisma.sale.findFirst.mockReset();
    let findFirstCalls = 0;
    mockPrisma.sale.findFirst.mockImplementation(async () => {
      findFirstCalls += 1;
      if (findFirstCalls === 1) {
        return { id: "sale-1", status: "DRAFT", clientId: "client-1" };
      }
      return {
        id: "sale-1", code: "VTA-0001", status: "DRAFT",
        lines: [], payments: [], receipts: [],
      };
    });
    mockPrisma.sale.update.mockImplementation(async ({ data }) => ({
      id: "sale-1", code: "VTA-0001",
      ...data,
    }));

    await updateSale("sale-1", "j1", {
      lines: [{
        articleId: "a1", quantity: 2, unitPrice: 0,
        manualPriceOverride: 999,
        taxOverride: { mode: "AMOUNT", value: 50 },
      }],
    });

    expect(mockPrisma.sale.update).toHaveBeenCalledTimes(1);
    const updateArgs = mockPrisma.sale.update.mock.calls[0][0];
    const linePersisted = updateArgs.data.lines.create[0];
    expect(linePersisted.manualPriceOverride).toBe(999);
    expect(linePersisted.taxOverride).toEqual({ mode: "AMOUNT", value: 50 });
  });

  it("update sin overrides → líneas nuevas SIN overrides (limpieza)", async () => {
    mockPrisma.sale.findFirst.mockReset();
    let calls = 0;
    mockPrisma.sale.findFirst.mockImplementation(async () => {
      calls += 1;
      if (calls === 1) {
        return { id: "sale-1", status: "DRAFT", clientId: "client-1" };
      }
      return {
        id: "sale-1", code: "VTA-0001", status: "DRAFT",
        lines: [], payments: [], receipts: [],
      };
    });
    mockPrisma.sale.update.mockImplementation(async ({ data }) => ({
      id: "sale-1", code: "VTA-0001",
      ...data,
    }));

    await updateSale("sale-1", "j1", {
      lines: [{ articleId: "a1", quantity: 1, unitPrice: 0 }],
    });

    const linePersisted = mockPrisma.sale.update.mock.calls[0][0].data.lines.create[0];
    expect(linePersisted.manualPriceOverride).toBeNull();
    expect(linePersisted.manualDiscountOverride).toBeNull();
    expect(linePersisted.taxOverride).toBeNull();
  });
});

// ────────────────────────────────────────────────────────────────────────────
describe("Roundtrip create → update con mismos overrides", () => {
  it("los campos persistidos quedan idénticos en ambos pasos", async () => {
    const overrides = {
      manualPriceOverride: 2500,
      manualDiscountOverride: { mode: "PERCENT" as const, value: 10, appliesTo: "TOTAL" as const, kind: "BONUS" as const },
      taxOverride: { mode: "PERCENT" as const, value: 21 },
      manualDiscountAppliesToOverride: "HECHURA" as const,
      manualTaxAppliesToOverride: "METAL" as const,
      priceListIdOverride: "pl-special",
    };

    // CREATE
    mockPrisma.sale.create.mockImplementation(async ({ data }) => ({
      id: "sale-1", code: "VTA-0001",
      ...data,
      lines: data.lines.create,
    }));

    await createSale("j1", "u1", {
      clientId: "client-1",
      lines: [{ articleId: "a1", quantity: 1, unitPrice: 0, ...overrides }],
    });
    const linePersistedAfterCreate = mockPrisma.sale.create.mock.calls[0][0].data.lines.create[0];

    // UPDATE con los mismos overrides — usamos mockImplementation con un
    // contador para distinguir la 1ra llamada (validación: necesita
    // {id,status,clientId}) de la 2da+ (getSale final: necesita lines[]).
    mockPrisma.sale.findFirst.mockReset();
    let findFirstCalls = 0;
    mockPrisma.sale.findFirst.mockImplementation(async () => {
      findFirstCalls += 1;
      if (findFirstCalls === 1) {
        return { id: "sale-1", status: "DRAFT", clientId: "client-1" };
      }
      return {
        id: "sale-1", code: "VTA-0001", status: "DRAFT",
        lines: [], payments: [], receipts: [],
      };
    });
    mockPrisma.sale.update.mockImplementation(async ({ data }) => ({
      id: "sale-1", code: "VTA-0001",
      ...data,
    }));

    await updateSale("sale-1", "j1", {
      lines: [{ articleId: "a1", quantity: 1, unitPrice: 0, ...overrides }],
    });
    const linePersistedAfterUpdate = mockPrisma.sale.update.mock.calls[0][0].data.lines.create[0];

    // Roundtrip: mismos overrides → mismos campos persistidos.
    expect(linePersistedAfterCreate.manualPriceOverride).toBe(linePersistedAfterUpdate.manualPriceOverride);
    expect(linePersistedAfterCreate.manualDiscountOverride).toEqual(linePersistedAfterUpdate.manualDiscountOverride);
    expect(linePersistedAfterCreate.taxOverride).toEqual(linePersistedAfterUpdate.taxOverride);
    expect(linePersistedAfterCreate.manualDiscountAppliesToOverride).toBe(linePersistedAfterUpdate.manualDiscountAppliesToOverride);
    expect(linePersistedAfterCreate.manualTaxAppliesToOverride).toBe(linePersistedAfterUpdate.manualTaxAppliesToOverride);
    expect(linePersistedAfterCreate.priceListIdOverride).toBe(linePersistedAfterUpdate.priceListIdOverride);
  });
});
