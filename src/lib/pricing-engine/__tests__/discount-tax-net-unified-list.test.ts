// src/lib/pricing-engine/__tests__/discount-tax-net-unified-list.test.ts
// =============================================================================
// BUG REAL (Factura, lista "Valor Unificado"): con bonificación + impuesto
// por base parcial (Solo metal / Solo hechura), el impuesto se calculaba
// sobre el componente BRUTO. La lista NO emite `metalHechuraDetail`, así que
// el motor deriva el split por proporción de costo en
// `componentBaseMetal/Hechura`. La base imponible debe ser la NETA del
// componente luego del descuento que afectó esa misma base — SIMÉTRICO
// metal/hechura.
//
// `composition.taxes[]` (lo que pinta el label) es passthrough puro de
// `result.taxBreakdown` (pricing-composition.ts), por eso este test sobre
// `resolveFinalSalePrice` cubre exactamente el número visible.
//
// Caso real: metalSale 381.562,50 · hechuraSale 18.500 · total 400.062,50.
// =============================================================================

import { describe, it, expect, vi, beforeEach } from "vitest";
import { Prisma } from "@prisma/client";

const mockPrisma = vi.hoisted(() => ({
  article:          { findFirst:  vi.fn() },
  articleVariant:   { findFirst:  vi.fn() },
  articleGroupItem: { findFirst:  vi.fn() },
  promotion:        { findMany:   vi.fn() },
  quantityDiscount: { findMany:   vi.fn() },
  currency:         { findFirst:  vi.fn() },
  currencyRate:     { findFirst:  vi.fn() },
  metalQuote:       { findFirst:  vi.fn() },
  jewelry:          { findUnique: vi.fn() },
  commercialEntity: { findFirst:  vi.fn() },
  entityMermaOverride: { findMany: vi.fn() },
  tax:              { findMany:   vi.fn() },
}));
vi.mock("../../prisma.js", () => ({ prisma: mockPrisma }));

const mockResolveArticleCost = vi.hoisted(() => vi.fn());
vi.mock("../pricing-engine.cost.js", () => ({
  calculateCostFromLines:        (...a: any[]) => mockResolveArticleCost(...a),
  enrichCostMetalSteps:          vi.fn(),
  getArticleMetalVariantIds:     vi.fn().mockResolvedValue([]),
  loadArticleMetalVariantsBatch: vi.fn().mockResolvedValue(new Map()),
}));

const mockResolvePriceList = vi.hoisted(() => vi.fn());
const mockApplyPriceList   = vi.hoisted(() => vi.fn());
vi.mock("../pricing-engine.pricelist.js", () => ({
  resolvePriceList: (...a: any[]) => mockResolvePriceList(...a),
  applyPriceList:   (...a: any[]) => mockApplyPriceList(...a),
}));

import { resolveFinalSalePrice } from "../pricing-engine.sale.js";

const D = Prisma.Decimal;

const M_SALE = 381562.5;
const H_SALE = 18500;
const TOTAL  = M_SALE + H_SALE; // 400062.5

beforeEach(() => {
  vi.clearAllMocks();
  mockPrisma.article.findFirst.mockResolvedValue({
    categoryId: null, brand: null, salePrice: null, useManualSalePrice: false,
    manualAdjustmentKind: null, manualAdjustmentType: null, manualAdjustmentValue: null,
    mermaPercent: null, category: null, costComposition: [], manualTaxIds: [],
  });
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

  // Lista UNIFICADA: value sin `metalHechuraDetail` (clave del bug).
  mockResolvePriceList.mockResolvedValue({
    priceList: {
      id: "pl1", name: "Minorista — Valor Unificado", mode: "UNIFIED",
      marginTotal: null, marginMetal: null, marginHechura: null,
      costPerGram: null, surcharge: null, minimumPrice: null,
      roundingTarget: "NONE", roundingMode: "NONE", roundingDirection: "NEAREST",
      validFrom: null, validTo: null, isActive: true,
    },
    source: "GENERAL",
  });
  mockApplyPriceList.mockReturnValue({ value: new D(String(TOTAL)), partial: false });

  // Costo con composición metal/hechura → el motor sintetiza
  // effectiveCostBreakdown y deriva componentBaseMetal/Hechura por proporción
  // (= M_SALE / H_SALE sobre basePrice).
  mockResolveArticleCost.mockResolvedValue({
    value: new D(String(TOTAL)), mode: "MANUAL", partial: false, steps: [],
    metalCost: new D(String(M_SALE)), hechuraCost: new D(String(H_SALE)),
    totalGrams: new D("0"), breakdown: null,
  });
});

describe("Lista UNIFICADA — impuesto sobre base NETA por componente (simétrico)", () => {
  it("METAL: Bonif 10% Solo metal + Impuesto 10% Solo metal → 34.340,625 (no 38.156,25)", async () => {
    const r = await resolveFinalSalePrice("j1", {
      articleId: "a1",
      manualDiscountOverride: { mode: "PERCENT", value: 10, appliesTo: "METAL" },
      taxOverride:            { mode: "PERCENT", value: 10, appliesTo: "METAL" },
    });
    expect(r.quantityDiscountAmount?.toNumber()).toBeCloseTo(38156.25, 2);
    expect(r.taxBreakdown[0].base).toBeCloseTo(343406.25, 2);   // metal NETO
    expect(r.taxAmount.toNumber()).toBeCloseTo(34340.625, 3);   // 10% del neto
  });

  it("HECHURA: Bonif 10% Solo hechura + Impuesto 10% Solo hechura → 1.665 (no 1.850)", async () => {
    const r = await resolveFinalSalePrice("j1", {
      articleId: "a1",
      manualDiscountOverride: { mode: "PERCENT", value: 10, appliesTo: "HECHURA" },
      taxOverride:            { mode: "PERCENT", value: 10, appliesTo: "HECHURA" },
    });
    expect(r.quantityDiscountAmount?.toNumber()).toBeCloseTo(1850, 2);
    expect(r.taxBreakdown[0].base).toBeCloseTo(16650, 2);       // hechura NETA
    expect(r.taxAmount.toNumber()).toBeCloseTo(1665, 3);
  });

  it("simetría: la misma fórmula cubre METAL y HECHURA (sin sesgo de componente)", async () => {
    const metal = await resolveFinalSalePrice("j1", {
      articleId: "a1",
      manualDiscountOverride: { mode: "PERCENT", value: 10, appliesTo: "METAL" },
      taxOverride:            { mode: "PERCENT", value: 10, appliesTo: "METAL" },
    });
    const hechura = await resolveFinalSalePrice("j1", {
      articleId: "a1",
      manualDiscountOverride: { mode: "PERCENT", value: 10, appliesTo: "HECHURA" },
      taxOverride:            { mode: "PERCENT", value: 10, appliesTo: "HECHURA" },
    });
    // Cada uno = 10% del componente NETO de su propia base.
    expect(metal.taxAmount.toNumber()).toBeCloseTo(34340.625, 3);
    expect(hechura.taxAmount.toNumber()).toBeCloseTo(1665, 3);
  });
});
