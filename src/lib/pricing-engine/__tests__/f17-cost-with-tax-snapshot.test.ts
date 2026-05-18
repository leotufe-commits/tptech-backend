// src/lib/pricing-engine/__tests__/f17-cost-with-tax-snapshot.test.ts
// =============================================================================
// FASE F17 — Snapshot v7 persiste impuestos de costo
//
// Verifica que `buildPricingSnapshot(result, { purchaseTaxes })` persista en
// el snapshot v7 los campos `costBase / costTaxAmount / costWithTax /
// costTaxBreakdown` resueltos en el momento del preview/confirm. Cumple
// POLICY: snapshots inmutables, paridad preview ↔ confirm.
//
// Cubre:
//   1. Sin impuestos → fields null/[].
//   2. Impuesto NO recuperable → costWithTax = costBase + taxAmount.
//   3. Impuesto recuperable → costWithTax === costBase (no suma).
//   4. appliesOnPurchase=false → no suma.
//   5. Ajuste global BONUS % → costBase post-ajuste, taxes sobre ese costBase.
//   6. Ajuste global SURCHARGE FIXED → costBase post-ajuste.
//   7. Preview/confirm parity: el mismo `purchaseTaxes` produce el mismo
//      bloque persistido byte-a-byte.
//   8. Sin `purchaseTaxes` → snapshot v7 con campos undefined (retrocompat).
// =============================================================================

import { describe, it, expect, vi, beforeEach } from "vitest";
import { Prisma } from "@prisma/client";

// Mocks mínimos para resolveFinalSalePrice — copio el patrón de
// `g4-11b-snapshot-parity-cost-line-overrides.test.ts`.
const mockPrisma = vi.hoisted(() => ({
  metalVariant:    { findMany: vi.fn(), findUnique: vi.fn() },
  metalQuote:      { findMany: vi.fn() },
  currency:        { findFirst: vi.fn() },
  jewelry:         { findUnique: vi.fn() },
  article:         { findFirst: vi.fn() },
  articleVariant:  { findFirst: vi.fn() },
  articleGroupItem:{ findFirst: vi.fn() },
  promotion:       { findMany: vi.fn() },
  quantityDiscount:{ findMany: vi.fn() },
  commercialEntity:{ findFirst: vi.fn() },
  entityMermaOverride: { findMany: vi.fn() },
  tax:             { findMany: vi.fn() },
}));
vi.mock("../../prisma.js", () => ({ prisma: mockPrisma }));

const mockResolveArticleCost = vi.hoisted(() => vi.fn());
vi.mock("../pricing-engine.cost.js", async () => {
  const actual = await vi.importActual<typeof import("../pricing-engine.cost.js")>(
    "../pricing-engine.cost.js",
  );
  return {
    ...actual,
    calculateCostFromLines: (...args: any[]) => mockResolveArticleCost(...args),
    enrichCostMetalSteps:   vi.fn(),
    getArticleMetalVariantIds:     vi.fn().mockResolvedValue([]),
    loadArticleMetalVariantsBatch: vi.fn().mockResolvedValue(new Map()),
  };
});

const mockResolvePriceList = vi.hoisted(() => vi.fn());
const mockApplyPriceList   = vi.hoisted(() => vi.fn());
vi.mock("../pricing-engine.pricelist.js", async () => {
  const actual = await vi.importActual<typeof import("../pricing-engine.pricelist.js")>(
    "../pricing-engine.pricelist.js",
  );
  return {
    ...actual,
    resolvePriceList: (...args: any[]) => mockResolvePriceList(...args),
    applyPriceList:   (...args: any[]) => mockApplyPriceList(...args),
  };
});

import {
  resolveFinalSalePrice,
  buildPricingSnapshot,
  computePurchaseTaxes,
  type PurchaseTaxResult,
} from "../pricing-engine.sale.js";
import { PRICING_LINE_SNAPSHOT_VERSION } from "../pricing-engine.types.js";

const D = Prisma.Decimal;

function makeArticle(extras?: Partial<{
  manualAdjustmentKind:  string;
  manualAdjustmentType:  string;
  manualAdjustmentValue: number;
  manualTaxIds:          string[];
}>) {
  return {
    id: "a1",
    salePrice: null,
    costPrice: null,
    useManualSalePrice: false,
    salePriceCurrencyId: null,
    manualAdjustmentKind:  extras?.manualAdjustmentKind  ?? null,
    manualAdjustmentType:  extras?.manualAdjustmentType  ?? null,
    manualAdjustmentValue: extras?.manualAdjustmentValue != null ? new D(String(extras.manualAdjustmentValue)) : null,
    manualTaxIds:          extras?.manualTaxIds ?? [],
    mermaPercent: null,
    metalVariantId: null,
    weightInGrams: null,
    laborCost: null,
    laborCurrencyId: null,
    laborAdjustmentKind: null,
    laborAdjustmentType: null,
    laborAdjustmentValue: null,
    categoryId: null,
    brand: null,
    isCombo: false,
    deletedAt: null,
    costComposition: [],
    category: null,
  };
}

function setupCost(value: number) {
  mockResolveArticleCost.mockResolvedValue({
    value:      new D(String(value)),
    mode:       "COST_LINES",
    partial:    false,
    steps:      [],
    metalCost:  new D("0"),
    hechuraCost:new D("0"),
    totalGrams: new D("0"),
    metalGramsWithMerma: new D("0"),
    metalPurity: null,
    costLineOverridesApplied: undefined,
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  mockResolvePriceList.mockResolvedValue({
    priceList: {
      id: "pl-test", name: "Test", mode: "MARGIN_TOTAL",
      marginTotal: new D("0"), marginMetal: null, marginHechura: null,
      costPerGram: null, surcharge: null, minimumPrice: null,
      roundingTarget: "NONE", roundingMode: "NONE", roundingDirection: "NEAREST",
      validFrom: null, validTo: null, isActive: true,
    },
    source: "GENERAL",
  });
  mockApplyPriceList.mockReturnValue({ value: new D("1000"), partial: false });
  mockPrisma.article.findFirst.mockResolvedValue(makeArticle());
  mockPrisma.articleVariant.findFirst.mockResolvedValue(null);
  mockPrisma.articleGroupItem.findFirst.mockResolvedValue(null);
  mockPrisma.promotion.findMany.mockResolvedValue([]);
  mockPrisma.quantityDiscount.findMany.mockResolvedValue([]);
  mockPrisma.commercialEntity.findFirst.mockResolvedValue(null);
  mockPrisma.entityMermaOverride.findMany.mockResolvedValue([]);
  mockPrisma.tax.findMany.mockResolvedValue([]);
  mockPrisma.jewelry.findUnique.mockResolvedValue({
    id: "j1", roundingMode: "NONE", roundingDirection: "NEAREST", roundingTarget: "NONE",
  });
});

// =============================================================================
// 1. buildPricingSnapshot persiste el bloque
// =============================================================================
describe("F17 — buildPricingSnapshot(opts.purchaseTaxes) persiste en snapshot v7", () => {
  it("sin purchaseTaxes → snapshot v7 con campos costo/imp undefined (retrocompat aditiva)", async () => {
    setupCost(1000);
    const result = await resolveFinalSalePrice("j1", { articleId: "a1" });
    const snap = buildPricingSnapshot(result);
    expect(snap.snapshotVersion).toBe(7);
    expect(snap.costBase).toBeUndefined();
    expect(snap.costTaxAmount).toBeUndefined();
    expect(snap.costWithTax).toBeUndefined();
    expect(snap.costTaxBreakdown).toBeUndefined();
  });

  it("con purchaseTaxes vacío (sin impuestos) → costBase poblado, taxAmount=null, costWithTax=costBase", async () => {
    setupCost(1000);
    const result = await resolveFinalSalePrice("j1", { articleId: "a1" });
    const purchaseTaxes: PurchaseTaxResult = {
      costBase:         "1000.0000",
      costTaxAmount:    null,
      costWithTax:      "1000.0000",
      costTaxBreakdown: [],
    };
    const snap = buildPricingSnapshot(result, { purchaseTaxes });
    expect(snap.costBase).toBe("1000.0000");
    expect(snap.costTaxAmount).toBeNull();
    expect(snap.costWithTax).toBe("1000.0000");
    expect(snap.costTaxBreakdown).toEqual([]);
  });

  it("con purchaseTaxes (1 impuesto no recuperable 21%) → costWithTax = costBase + taxAmount", async () => {
    setupCost(1000);
    const result = await resolveFinalSalePrice("j1", { articleId: "a1" });
    const purchaseTaxes: PurchaseTaxResult = {
      costBase:         "1000.0000",
      costTaxAmount:    "210.0000",
      costWithTax:      "1210.0000",
      costTaxBreakdown: [{
        taxId: "t-iva", name: "IVA Compra", calculationType: "PERCENTAGE",
        rate: 21, fixedAmount: 0, taxAmount: 210,
      }],
    };
    const snap = buildPricingSnapshot(result, { purchaseTaxes });
    expect(snap.costBase).toBe("1000.0000");
    expect(snap.costTaxAmount).toBe("210.0000");
    expect(snap.costWithTax).toBe("1210.0000");
    expect(snap.costTaxBreakdown).toEqual([{
      taxId: "t-iva", name: "IVA Compra", calculationType: "PERCENTAGE",
      rate: 21, fixedAmount: 0, taxAmount: 210,
    }]);
  });

  it("paridad preview/confirm: mismo purchaseTaxes ⇒ snapshot byte-paritario", async () => {
    setupCost(800);
    const result = await resolveFinalSalePrice("j1", { articleId: "a1" });
    const purchaseTaxes: PurchaseTaxResult = {
      costBase:         "800.0000",
      costTaxAmount:    "80.0000",
      costWithTax:      "880.0000",
      costTaxBreakdown: [{
        taxId: "t-1", name: "ImpCompra10", calculationType: "PERCENTAGE",
        rate: 10, fixedAmount: 0, taxAmount: 80,
      }],
    };
    const preview = buildPricingSnapshot(result, { purchaseTaxes });
    const confirm = buildPricingSnapshot(result, { purchaseTaxes });
    expect(preview.costBase).toBe(confirm.costBase);
    expect(preview.costTaxAmount).toBe(confirm.costTaxAmount);
    expect(preview.costWithTax).toBe(confirm.costWithTax);
    expect(preview.costTaxBreakdown).toEqual(confirm.costTaxBreakdown);
  });
});

// =============================================================================
// 2. computePurchaseTaxes filtra correctamente
// =============================================================================
describe("F17 — computePurchaseTaxes respeta flags appliesOnPurchase / isRecoverable", () => {
  it("sin manualTaxIds → costWithTax = costBase, breakdown vacío", async () => {
    mockPrisma.article.findFirst.mockResolvedValue(makeArticle({ manualTaxIds: [] }));
    const res = await computePurchaseTaxes("j1", "a1", new D("1000"));
    expect(res.costBase).toBe("1000.0000");
    expect(res.costTaxAmount).toBeNull();
    expect(res.costWithTax).toBe("1000.0000");
    expect(res.costTaxBreakdown).toEqual([]);
  });

  it("impuesto recuperable (isRecoverable=true) → NO suma (filtrado por el query)", async () => {
    mockPrisma.article.findFirst.mockResolvedValue(makeArticle({ manualTaxIds: ["t-rec"] }));
    // El query interno ya filtra por isRecoverable=false → recoverable NO viene.
    mockPrisma.tax.findMany.mockResolvedValue([]);
    const res = await computePurchaseTaxes("j1", "a1", new D("1000"));
    expect(res.costTaxAmount).toBeNull();
    expect(res.costWithTax).toBe("1000.0000");
  });

  it("appliesOnPurchase=false → NO suma (filtrado por el query)", async () => {
    mockPrisma.article.findFirst.mockResolvedValue(makeArticle({ manualTaxIds: ["t-sale-only"] }));
    mockPrisma.tax.findMany.mockResolvedValue([]);  // simulado el filtro del backend
    const res = await computePurchaseTaxes("j1", "a1", new D("1000"));
    expect(res.costTaxAmount).toBeNull();
    expect(res.costWithTax).toBe("1000.0000");
  });

  it("impuesto NO recuperable + appliesOnPurchase=true → suma a costWithTax", async () => {
    mockPrisma.article.findFirst.mockResolvedValue(makeArticle({ manualTaxIds: ["t-iibb"] }));
    mockPrisma.tax.findMany.mockResolvedValue([{
      id: "t-iibb", name: "IIBB", rate: new D("3"), fixedAmount: new D("0"),
      calculationType: "PERCENTAGE",
    }]);
    const res = await computePurchaseTaxes("j1", "a1", new D("1000"));
    expect(res.costBase).toBe("1000.0000");
    expect(res.costTaxAmount).toBe("30.0000");
    expect(res.costWithTax).toBe("1030.0000");
    expect(res.costTaxBreakdown).toHaveLength(1);
    expect(res.costTaxBreakdown[0]).toMatchObject({
      taxId: "t-iibb", name: "IIBB", calculationType: "PERCENTAGE",
      rate: 3, taxAmount: 30,
    });
  });

  it("FIXED_AMOUNT no recuperable → costTaxAmount fijo, costWithTax = costBase + fixed", async () => {
    mockPrisma.article.findFirst.mockResolvedValue(makeArticle({ manualTaxIds: ["t-fix"] }));
    mockPrisma.tax.findMany.mockResolvedValue([{
      id: "t-fix", name: "ImpFijo", rate: new D("0"), fixedAmount: new D("50"),
      calculationType: "FIXED_AMOUNT",
    }]);
    const res = await computePurchaseTaxes("j1", "a1", new D("1000"));
    expect(res.costTaxAmount).toBe("50.0000");
    expect(res.costWithTax).toBe("1050.0000");
  });

  it("2 impuestos no recuperables → suma de ambos", async () => {
    mockPrisma.article.findFirst.mockResolvedValue(makeArticle({ manualTaxIds: ["t-a", "t-b"] }));
    mockPrisma.tax.findMany.mockResolvedValue([
      { id: "t-a", name: "ImpA", rate: new D("10"), fixedAmount: new D("0"), calculationType: "PERCENTAGE" },
      { id: "t-b", name: "ImpB", rate: new D("0"),  fixedAmount: new D("25"), calculationType: "FIXED_AMOUNT" },
    ]);
    const res = await computePurchaseTaxes("j1", "a1", new D("1000"));
    // 1000 × 10% = 100 + 25 fijo = 125
    expect(res.costTaxAmount).toBe("125.0000");
    expect(res.costWithTax).toBe("1125.0000");
    expect(res.costTaxBreakdown).toHaveLength(2);
  });

  it("costBase=null → costTaxBreakdown vacío, costWithTax=null", async () => {
    const res = await computePurchaseTaxes("j1", "a1", null);
    expect(res.costBase).toBeNull();
    expect(res.costTaxAmount).toBeNull();
    expect(res.costWithTax).toBeNull();
    expect(res.costTaxBreakdown).toEqual([]);
  });
});

// =============================================================================
// 3. Integración con ajuste global del artículo
// =============================================================================
describe("F17 — costBase es POST-ajuste global del artículo", () => {
  it("BONUS 10% global: pricing.unitCost ya viene reducido; computePurchaseTaxes lo usa tal cual", async () => {
    // El motor aplica el manualAdjustment internamente. Para este test, el
    // valor de costo que llega a computePurchaseTaxes es el POST-ajuste.
    mockPrisma.article.findFirst.mockResolvedValue(makeArticle({ manualTaxIds: ["t-iibb"] }));
    mockPrisma.tax.findMany.mockResolvedValue([{
      id: "t-iibb", name: "IIBB", rate: new D("3"), fixedAmount: new D("0"),
      calculationType: "PERCENTAGE",
    }]);
    // unitCost post-ajuste = 1000 × (1 − 0.10) = 900
    const res = await computePurchaseTaxes("j1", "a1", new D("900"));
    expect(res.costBase).toBe("900.0000");
    // 900 × 3% = 27
    expect(res.costTaxAmount).toBe("27.0000");
    expect(res.costWithTax).toBe("927.0000");
  });

  it("SURCHARGE $200 global: pricing.unitCost ya viene aumentado", async () => {
    mockPrisma.article.findFirst.mockResolvedValue(makeArticle({ manualTaxIds: ["t-iibb"] }));
    mockPrisma.tax.findMany.mockResolvedValue([{
      id: "t-iibb", name: "IIBB", rate: new D("3"), fixedAmount: new D("0"),
      calculationType: "PERCENTAGE",
    }]);
    // unitCost post-ajuste = 1000 + 200 = 1200
    const res = await computePurchaseTaxes("j1", "a1", new D("1200"));
    expect(res.costBase).toBe("1200.0000");
    // 1200 × 3% = 36
    expect(res.costTaxAmount).toBe("36.0000");
    expect(res.costWithTax).toBe("1236.0000");
  });
});

// =============================================================================
// 4. PRICING_LINE_SNAPSHOT_VERSION bump
// =============================================================================
describe("F17 — snapshot version v7", () => {
  it("PRICING_LINE_SNAPSHOT_VERSION === 7", () => {
    expect(PRICING_LINE_SNAPSHOT_VERSION).toBe(7);
  });
});
