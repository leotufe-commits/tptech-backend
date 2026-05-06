// src/modules/sales/__tests__/draft-pricing.test.ts
//
// Tests Fase 1 — el backend es la única fuente de verdad para el precio en
// createSale() y updateSale(). El cliente puede mandar unitPrice/discountPct
// por compatibilidad pero NO se usan como fuente principal.

import { describe, it, expect, vi, beforeEach } from "vitest";
import { Prisma } from "@prisma/client";

// ── Mocks (vi.hoisted garantiza disponibilidad en las factories) ────────────

const mockPrisma = vi.hoisted(() => ({
  article:          { findMany: vi.fn(), findFirst: vi.fn() },
  articleVariant:   { findMany: vi.fn(), findFirst: vi.fn() },
  articleGroupItem: { findMany: vi.fn() },
  sale:             { findFirst: vi.fn(), findMany: vi.fn(), create: vi.fn(), update: vi.fn(), count: vi.fn() },
  salesChannel:     { findFirst: vi.fn() },
  coupon:           { findFirst: vi.fn() },
  $transaction:     vi.fn(),
}));
vi.mock("../../../lib/prisma.js", () => ({ prisma: mockPrisma }));

const mockResolveFinalSalePrice = vi.hoisted(() => vi.fn());
const mockBuildPricingSnapshot  = vi.hoisted(() => vi.fn());
vi.mock("../../../lib/pricing-engine/pricing-engine.js", () => ({
  resolveFinalSalePrice:          (...args: any[]) => mockResolveFinalSalePrice(...args),
  buildPricingSnapshot:           (...args: any[]) => mockBuildPricingSnapshot(...args),
  // Stubs para los demás exports que sales.service.ts importa pero que estos
  // tests no ejercitan.
  calculateCostFromLines:         vi.fn(),
  buildBatchCostContext:          vi.fn(),
  buildBalanceBreakdownFromPrice: vi.fn(),
  evaluatePricingPolicy:          vi.fn().mockResolvedValue([]),
  computeLineTaxes:               vi.fn(),
  applySalesChannelAdjustment:    vi.fn(),
  applyCouponAdjustment:          vi.fn(),
}));

// Otros imports transitivos de sales.service.ts que pueden tener efectos
// colaterales — los neutralizamos para que el test sea hermético.
vi.mock("../../../lib/pricing-engine/pricing-engine.currency.js", () => ({
  getBaseCurrencyId: vi.fn(),
}));
vi.mock("../../../lib/seller-commission.js", () => ({
  calculateLineCommission: vi.fn(),
}));
vi.mock("../../../lib/stock-engine.js", () => ({
  applyMovementImpact:   vi.fn(),
  reverseMovementImpact: vi.fn(),
}));
vi.mock("../../../lib/document-hooks/sale.hook.js", () => ({
  onSaleConfirmed: vi.fn(),
}));
vi.mock("../../payments/payments.service.js", () => ({
  getCheckoutPreview: vi.fn(),
}));
vi.mock("../../coupons/coupons.service.js", () => ({
  validateCoupon: vi.fn(),
}));

// Import DESPUÉS de los mocks
import {
  resolveDraftSaleLinesPricing,
  createSale,
  updateSale,
} from "../sales.service.js";

// ── Helpers ─────────────────────────────────────────────────────────────────

const D = Prisma.Decimal;

function fakeSalePriceResult(overrides: Record<string, any> = {}) {
  return {
    unitPrice:                new D("1000"),
    basePrice:                new D("1200"),
    quantityDiscountAmount:   new D("0"),
    promotionDiscountAmount:  new D("200"),
    discountAmount:           new D("200"),
    priceSource:              "PROMOTION",
    baseSource:               "PRICE_LIST",
    unitCost:                 new D("400"),
    unitMargin:               new D("600"),
    marginPercent:            new D("60"),
    costPartial:              false,
    costMode:                 "COST_LINES",
    partial:                  false,
    appliedPriceListId:       "pl-1",
    appliedPriceListName:     "Lista Mayorista",
    appliedPromotionId:       "promo-1",
    appliedPromotionName:     "BlackFriday",
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

function fakeSnapshotFromResult(res: any) {
  return {
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
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  mockPrisma.article.findMany.mockResolvedValue([]);
  mockPrisma.articleVariant.findMany.mockResolvedValue([]);
  mockPrisma.articleGroupItem.findMany.mockResolvedValue([]);
  mockBuildPricingSnapshot.mockImplementation(fakeSnapshotFromResult);
});

// ────────────────────────────────────────────────────────────────────────────
// resolveDraftSaleLinesPricing — núcleo del refactor
// ────────────────────────────────────────────────────────────────────────────

describe("resolveDraftSaleLinesPricing", () => {
  it("usa el unitPrice del motor e ignora el legacy del cliente", async () => {
    mockResolveFinalSalePrice.mockResolvedValue(fakeSalePriceResult({
      unitPrice: new D("1000"),
    }));

    const out = await resolveDraftSaleLinesPricing("j1", [{
      articleId: "a1",
      variantId: null,
      quantity: 2,
      legacyClientUnitPrice:   9999,  // intento de spoof
      legacyClientDiscountPct: 50,
    }]);

    expect(out).toHaveLength(1);
    expect(out[0].unitPrice).toBe(1000);
    expect(out[0].discountPct).toBe(0);
    expect(out[0].lineTotal).toBe(2000);
    expect(out[0].priceSource).toBe("PROMOTION");
    expect(out[0].appliedPriceListId).toBe("pl-1");
    expect(out[0].appliedPromotionId).toBe("promo-1");
    expect(out[0].pricingSnapshot.unitPrice).toBe(1000);
    expect(out[0].pricingSnapshot.basePrice).toBe(1200);
  });

  it("loguea warn cuando el cliente manda unitPrice distinto del motor", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    mockResolveFinalSalePrice.mockResolvedValue(fakeSalePriceResult({
      unitPrice: new D("1000"),
    }));

    await resolveDraftSaleLinesPricing("j1", [{
      articleId: "a1",
      quantity: 1,
      legacyClientUnitPrice: 750,
    }]);

    expect(warn).toHaveBeenCalled();
    expect(warn.mock.calls[0][0]).toMatch(/unitPrice=750/);
    warn.mockRestore();
  });

  it("hace fallback al legacy con warn cuando el motor devuelve null", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    mockResolveFinalSalePrice.mockResolvedValue(fakeSalePriceResult({
      unitPrice: null,
      basePrice: null,
      priceSource: "NONE",
      baseSource:  "NONE",
    }));

    const out = await resolveDraftSaleLinesPricing("j1", [{
      articleId: "a1",
      quantity: 3,
      legacyClientUnitPrice: 500,
    }]);

    expect(out[0].unitPrice).toBe(500);
    expect(out[0].lineTotal).toBe(1500);
    expect(warn.mock.calls[0][0]).toMatch(/Motor no pudo calcular precio/);
    warn.mockRestore();
  });

  it("guarda priceSource y appliedDiscountId cuando viene de QUANTITY_DISCOUNT", async () => {
    mockResolveFinalSalePrice.mockResolvedValue(fakeSalePriceResult({
      priceSource:          "QUANTITY_DISCOUNT",
      appliedPromotionId:   null,
      appliedPromotionName: null,
      appliedDiscountId:    "qd-1",
    }));

    const out = await resolveDraftSaleLinesPricing("j1", [{
      articleId: "a1",
      quantity: 10,
      legacyClientUnitPrice: 1000,
    }]);

    expect(out[0].priceSource).toBe("QUANTITY_DISCOUNT");
    expect(out[0].appliedDiscountId).toBe("qd-1");
    expect(out[0].appliedPromotionId).toBeNull();
  });

  it("retorna [] sin tocar el motor si no hay líneas", async () => {
    const out = await resolveDraftSaleLinesPricing("j1", []);
    expect(out).toEqual([]);
    expect(mockResolveFinalSalePrice).not.toHaveBeenCalled();
  });

  it("propaga categoryTotal/brandTotal/groupTotal al motor (multi-línea)", async () => {
    mockPrisma.article.findMany.mockResolvedValue([
      { id: "a1", categoryId: "cat-1", brand: "BrandX" },
      { id: "a2", categoryId: "cat-1", brand: "BrandX" },
    ]);
    mockPrisma.articleGroupItem.findMany.mockResolvedValue([
      { variantId: "v1", groupId: "grp-1" },
      { variantId: "v2", groupId: "grp-1" },
    ]);
    mockResolveFinalSalePrice.mockResolvedValue(fakeSalePriceResult());

    await resolveDraftSaleLinesPricing("j1", [
      { articleId: "a1", variantId: "v1", quantity: 3 },
      { articleId: "a2", variantId: "v2", quantity: 2 },
    ]);

    expect(mockResolveFinalSalePrice).toHaveBeenCalledTimes(2);
    expect(mockResolveFinalSalePrice).toHaveBeenCalledWith("j1",
      expect.objectContaining({
        categoryTotal: 5,
        brandTotal:    5,
        groupTotal:    5,
      }),
    );
  });
});

// ────────────────────────────────────────────────────────────────────────────
// createSale — debe persistir lo que dice el motor, no lo que dice el cliente
// ────────────────────────────────────────────────────────────────────────────

describe("createSale — fuente de verdad: motor", () => {
  beforeEach(() => {
    // Artículo válido (sin variantes activas)
    mockPrisma.article.findMany.mockImplementation(async (args: any) => {
      const ids = args?.where?.id?.in ?? [];
      // findMany para validación (con _count) y findMany del helper (sin _count)
      const wantsCount = !!args?.select?._count;
      return ids.map((id: string) => ({
        id,
        name:     `Artículo ${id}`,
        code:     `ART-${id}`,
        sku:      `SKU-${id}`,
        barcode:  "",
        salePrice: new D("1000"),
        categoryId: null,
        brand:      null,
        ...(wantsCount ? { _count: { variants: 0 } } : {}),
      }));
    });
    // No hay venta previa con código → primer código
    mockPrisma.sale.findFirst.mockResolvedValue(null);
    // Devolver lo que se le pasa a create
    mockPrisma.sale.create.mockImplementation(async (args: any) => ({ id: "s1", ...args.data }));

    mockResolveFinalSalePrice.mockResolvedValue(fakeSalePriceResult({
      unitPrice: new D("1000"),
    }));
  });

  it("ignora el unitPrice falso del cliente y persiste el del motor", async () => {
    await createSale("j1", "u1", {
      lines: [{
        articleId: "a1",
        quantity: 2,
        unitPrice:   9999,   // falso
        discountPct: 50,
      }],
    });

    expect(mockPrisma.sale.create).toHaveBeenCalledTimes(1);
    const createArgs = mockPrisma.sale.create.mock.calls[0][0];
    const lineCreate = createArgs.data.lines.create[0];

    expect(lineCreate.unitPrice).toBe(1000);
    expect(lineCreate.discountPct).toBe(0);
    expect(lineCreate.lineTotal).toBe(2000);
    expect(lineCreate.priceSource).toBe("PROMOTION");
    expect(lineCreate.appliedPriceListId).toBe("pl-1");
    expect(lineCreate.appliedPromotionId).toBe("promo-1");
  });

  it("guarda pricingSnapshot en SaleLine al crear DRAFT", async () => {
    await createSale("j1", "u1", {
      lines: [{
        articleId: "a1",
        quantity: 1,
        unitPrice: 1000,
        discountPct: 0,
      }],
    });

    const createArgs = mockPrisma.sale.create.mock.calls[0][0];
    const lineCreate = createArgs.data.lines.create[0];

    expect(lineCreate.pricingSnapshot).toBeDefined();
    expect(lineCreate.pricingSnapshot.unitPrice).toBe(1000);
    expect(lineCreate.pricingSnapshot.basePrice).toBe(1200);
    expect(lineCreate.pricingSnapshot.priceSource).toBe("PROMOTION");
    expect(lineCreate.pricingSnapshot.appliedPromotionId).toBe("promo-1");
  });
});

// ────────────────────────────────────────────────────────────────────────────
// updateSale — mismo criterio que createSale al editar líneas
// ────────────────────────────────────────────────────────────────────────────

describe("updateSale — fuente de verdad: motor", () => {
  beforeEach(() => {
    // Venta DRAFT existente
    mockPrisma.sale.findFirst.mockResolvedValueOnce({
      id: "s1", status: "DRAFT", clientId: null,
    });
    // findFirst posterior usado por getSale al final → resuelve con cualquier cosa
    mockPrisma.sale.findFirst.mockResolvedValue({
      id: "s1", status: "DRAFT", lines: [],
    });
    mockPrisma.sale.update.mockResolvedValue({ id: "s1" });

    mockPrisma.article.findMany.mockImplementation(async (args: any) => {
      const ids = args?.where?.id?.in ?? [];
      const wantsCount = !!args?.select?._count;
      return ids.map((id: string) => ({
        id,
        name:    `Artículo ${id}`,
        sku:     `SKU-${id}`,
        barcode: "",
        categoryId: null,
        brand: null,
        ...(wantsCount ? { _count: { variants: 0 } } : {}),
      }));
    });

    mockResolveFinalSalePrice.mockResolvedValue(fakeSalePriceResult({
      unitPrice: new D("1500"),
    }));
  });

  it("ignora el unitPrice falso del cliente al editar líneas", async () => {
    await updateSale("s1", "j1", {
      lines: [{
        articleId: "a1",
        quantity: 4,
        unitPrice:   1,        // intento de spoof
        discountPct: 90,
      }],
    });

    expect(mockPrisma.sale.update).toHaveBeenCalledTimes(1);
    const updateArgs = mockPrisma.sale.update.mock.calls[0][0];
    const lineCreate = updateArgs.data.lines.create[0];

    expect(lineCreate.unitPrice).toBe(1500);   // del motor, no del cliente
    expect(lineCreate.discountPct).toBe(0);
    expect(lineCreate.lineTotal).toBe(6000);   // 4 × 1500
    expect(lineCreate.pricingSnapshot.unitPrice).toBe(1500);
  });
});
