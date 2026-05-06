// src/lib/pricing-engine/__tests__/cross-flow-consistency.test.ts
// =============================================================================
// FASE 3 — Tests de consistencia cruzada entre flujos del motor de pricing.
//
// Principio rector: si dos flujos usan la misma verdad de pricing para el mismo
// caso de negocio, deben producir el mismo resultado numérico.
//
// Diferencias JUSTIFICADAS documentadas aquí:
//   - Checkout: suma un ajuste de forma de pago sobre unitPrice de venta.
//   - Batch (listado): NO aplica descuentos por cantidad (scope: vista rápida).
//   - priceListIdOverride (simulador): mismo precio que resolución normal
//     cuando apunta a la misma lista.
//
// Flujos cubiertos:
//   A. METAL_HECHURA full integration (no cubierto en integration.test.ts)
//   B. priceListIdOverride == lista resuelta normalmente para la misma lista
//   C. Checkout pipeline: resolveCheckoutPrice parte de unitPrice de venta
//   D. Rounding deferred NET: redondeo se aplica DESPUÉS del descuento
//   E. Diferencia documentada: batch pricing no aplica quantity discounts
//   F. Barrel smoke: las funciones clave son accesibles desde el barrel
// =============================================================================

import { describe, it, expect, vi, beforeEach } from "vitest";
import { Prisma } from "@prisma/client";

// ── Mock Prisma (vi.hoisted garantiza disponibilidad en la factory) ───────────

const mockPrisma = vi.hoisted(() => ({
  currency:         { findFirst:  vi.fn() },
  currencyRate:     { findFirst:  vi.fn() },
  metalQuote:       { findFirst:  vi.fn(), findMany: vi.fn() },
  metalVariant:     { findMany:   vi.fn() },
  jewelry:          { findUnique: vi.fn() },
  article:          { findFirst:  vi.fn() },
  articleVariant:   { findFirst:  vi.fn() },
  articleGroupItem: { findFirst:  vi.fn() },
  promotion:        { findMany:   vi.fn() },
  quantityDiscount: { findMany:   vi.fn() },
  commercialEntity: { findFirst:  vi.fn() },
  articleCategory:  { findFirst:  vi.fn() },
  priceList:        { findFirst:  vi.fn() },
  tax:              { findMany:   vi.fn() },
}));

vi.mock("../../prisma.js", () => ({ prisma: mockPrisma }));

// Imports DESPUÉS de los mocks
import { resolveFinalSalePrice }  from "../pricing-engine.sale.js";
import { resolveCheckoutPrice }   from "../pricing-engine.payment.js";
import { applyPriceList }         from "../pricing-engine.pricelist.js";

// ── Helpers ──────────────────────────────────────────────────────────────────

const D = Prisma.Decimal;

function makeDbArticle(overrides: Record<string, any> = {}) {
  return {
    categoryId:            null,
    brand:                 null,
    groupId:               null,
    salePrice:             null,
    useManualSalePrice:    false,
    manualAdjustmentKind:  null,
    manualAdjustmentType:  null,
    manualAdjustmentValue: null,
    costComposition:       [],
    manualTaxIds:          [],
    ...overrides,
  };
}

/** Lista de precios mínima para mocks */
function makePriceList(overrides: Record<string, any> = {}) {
  return {
    id:               "pl-test",
    name:             "Lista Test",
    mode:             "MARGIN_TOTAL",
    marginTotal:      new D("100"),
    marginMetal:      null,
    marginHechura:    null,
    costPerGram:      null,
    surcharge:        null,
    minimumPrice:     null,
    roundingTarget:   "NONE",
    roundingMode:     "NONE",
    roundingDirection:"NEAREST",
    roundingApplyOn:  "PRICE",
    validFrom:        null,
    validTo:          null,
    isActive:         true,
    scope:            "GENERAL",
    isFavorite:       true,
    deletedAt:        null,
    sortOrder:        0,
    ...overrides,
  };
}

/** Política por defecto del tenant (sin bloqueos) */
function defaultPolicy() {
  return {
    defaultMermaPercent:            null,
    pricingLowMarginWarningPercent:  null,
    pricingLowMarginBlockPercent:    null,
    pricingBlockLossSale:            false,
    pricingBlockZeroOrNegativePrice: true,
    pricingBlockPartialData:         false,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  mockPrisma.article.findFirst.mockResolvedValue(null);
  mockPrisma.articleVariant.findFirst.mockResolvedValue(null);
  mockPrisma.promotion.findMany.mockResolvedValue([]);
  mockPrisma.quantityDiscount.findMany.mockResolvedValue([]);
  mockPrisma.commercialEntity.findFirst.mockResolvedValue(null);
  mockPrisma.articleCategory.findFirst.mockResolvedValue(null);
  mockPrisma.priceList.findFirst.mockResolvedValue(null);
  mockPrisma.jewelry.findUnique.mockResolvedValue(defaultPolicy());
  mockPrisma.currency.findFirst.mockResolvedValue({ id: "ARS" });
  mockPrisma.metalVariant.findMany.mockResolvedValue([]);
  mockPrisma.metalQuote.findMany.mockResolvedValue([]);
  mockPrisma.tax.findMany.mockResolvedValue([]);
});

// =============================================================================
// A. METAL_HECHURA full integration
// =============================================================================
// Valida que el desglose metalCost/hechuraCost de calculateCostFromLines
// fluye correctamente a través de applyPriceList(METAL_HECHURA) y llega
// al resultado final de resolveFinalSalePrice en metalHechuraBreakdown.
//
// Este camino no estaba cubierto en integration.test.ts (que solo usa MARGIN_TOTAL).
// =============================================================================

describe("A. METAL_HECHURA — integración completa costo → lista → resultado", () => {
  it("metalCost+hechuraCost del motor fluyen a metalHechuraBreakdown en el resultado de venta", async () => {
    // Setup metal:
    //   5g × precio=1000/g, merma=10%, saleFactor=1
    //   gramsConMerma = 5 × 1.10 = 5.5
    //   metalCost     = 5.5 × 1000 = 5500
    // Setup hechura: 1 × 200 = 200
    // totalCost = 5700
    mockPrisma.metalVariant.findMany.mockResolvedValue([
      { id: "v1", saleFactor: new D("1") },
    ]);
    mockPrisma.metalQuote.findMany.mockResolvedValue([
      { variantId: "v1", price: new D("1000") },
    ]);
    mockPrisma.article.findFirst.mockResolvedValue(makeDbArticle({
      costComposition: [
        { type: "METAL",   quantity: new D("5"), unitValue: new D("0"),   currencyId: null, mermaPercent: new D("10"), metalVariantId: "v1" },
        { type: "HECHURA", quantity: new D("1"), unitValue: new D("200"), currencyId: null, mermaPercent: null,        metalVariantId: null },
      ],
    }));

    // Lista METAL_HECHURA: margen 20% sobre metal, 30% sobre hechura
    //   metalSale   = 5500 × 1.20 = 6600
    //   hechuraSale = 200  × 1.30 = 260
    //   unitPrice   = 6860
    mockPrisma.priceList.findFirst.mockResolvedValue(makePriceList({
      mode:           "METAL_HECHURA",
      marginTotal:    null,
      marginMetal:    new D("20"),
      marginHechura:  new D("30"),
    }));

    const res = await resolveFinalSalePrice("j1", { articleId: "a1" });

    // Precio final correcto
    expect(res.unitPrice?.toNumber()).toBeCloseTo(6860, 2);
    expect(res.priceSource).toBe("PRICE_LIST");

    // El desglose debe estar presente y ser correcto
    expect(res.metalHechuraBreakdown).not.toBeNull();
    expect(res.metalHechuraBreakdown!.metalCost).toBeCloseTo(5500, 2);
    expect(res.metalHechuraBreakdown!.metalSale).toBeCloseTo(6600, 2);
    expect(res.metalHechuraBreakdown!.metalMarginPct).toBe(20);
    expect(res.metalHechuraBreakdown!.hechuraCost).toBeCloseTo(200, 2);
    expect(res.metalHechuraBreakdown!.hechuraSale).toBeCloseTo(260, 2);
    expect(res.metalHechuraBreakdown!.hechuraMarginPct).toBe(30);

    // Costo y margen están bien calculados
    expect(res.unitCost?.toNumber()).toBeCloseTo(5700, 2);
    expect(res.costMode).toBe("COST_LINES");
    expect(res.costPartial).toBe(false);
  });

  it("METAL_HECHURA + qty discount: desglose metal/hechura persiste, precio final descontado", async () => {
    mockPrisma.metalVariant.findMany.mockResolvedValue([{ id: "v1", saleFactor: new D("1") }]);
    mockPrisma.metalQuote.findMany.mockResolvedValue([{ variantId: "v1", price: new D("500") }]);

    // metal: 10g × 500/g, merma=0% = 5000; hechura = 1000; total = 6000
    mockPrisma.article.findFirst.mockResolvedValue(makeDbArticle({
      costComposition: [
        { type: "METAL",   quantity: new D("10"), unitValue: new D("0"),    currencyId: null, mermaPercent: new D("0"), metalVariantId: "v1" },
        { type: "HECHURA", quantity: new D("1"),  unitValue: new D("1000"), currencyId: null, mermaPercent: null,       metalVariantId: null },
      ],
    }));
    // marginMetal=10%, marginHechura=20%
    // metalSale=5500, hechuraSale=1200, base=6700
    mockPrisma.priceList.findFirst.mockResolvedValue(makePriceList({
      mode:          "METAL_HECHURA",
      marginTotal:   null,
      marginMetal:   new D("10"),
      marginHechura: new D("20"),
    }));
    // qty discount 10% → 6700 × 0.9 = 6030
    mockPrisma.quantityDiscount.findMany.mockResolvedValue([{
      id: "qd1",
      articleId: "a1", variantId: null, categoryId: null, brand: null, groupId: null,
      isStackable: false, evaluationMode: "LINE",
      tiers: [{ minQty: new D("1"), type: "PERCENTAGE", value: new D("10") }],
    }]);

    const res = await resolveFinalSalePrice("j1", { articleId: "a1", quantity: 3 });

    expect(res.basePrice?.toNumber()).toBeCloseTo(6700, 2);
    expect(res.unitPrice?.toNumber()).toBeCloseTo(6030, 2);
    // El desglose permanece (del precio base, antes del descuento)
    expect(res.metalHechuraBreakdown).not.toBeNull();
    expect(res.metalHechuraBreakdown!.metalSale).toBeCloseTo(5500, 2);
    expect(res.metalHechuraBreakdown!.hechuraSale).toBeCloseTo(1200, 2);
  });

  it("applyPriceList(METAL_HECHURA) es determinista: mismo input → mismo resultado en batch y en motor", () => {
    // Valida que la función compartida produce exactamente el mismo resultado
    // sin importar desde qué contexto se la llame (batch o motor de venta).
    const priceList = {
      id: "pl", name: "L", mode: "METAL_HECHURA",
      marginTotal: null, marginMetal: "25", marginHechura: "35",
      costPerGram: null, surcharge: null, minimumPrice: null,
      roundingTarget: "NONE", roundingMode: "NONE", roundingDirection: "NEAREST",
      roundingApplyOn: "PRICE", validFrom: null, validTo: null, isActive: true,
    };
    const cost = { value: new D("1800"), metalCost: new D("1500"), hechuraCost: new D("300") };

    const result1 = applyPriceList(priceList as any, cost);
    const result2 = applyPriceList(priceList as any, cost); // mismo input

    // metalSale = 1500 × 1.25 = 1875, hechuraSale = 300 × 1.35 = 405, total = 2280
    expect(result1.value?.toNumber()).toBeCloseTo(2280, 2);
    expect(result2.value?.toNumber()).toBeCloseTo(result1.value!.toNumber(), 8);
    // Garantía de determinismo: igual resultado en batch y en motor
  });
});

// =============================================================================
// B. priceListIdOverride — mismo resultado que resolución normal
// =============================================================================
// El simulador puede pasar priceListIdOverride para forzar una lista específica.
// Cuando la lista forzada es la misma que la que se resolvería naturalmente,
// el precio final debe ser idéntico.
// =============================================================================

describe("B. priceListIdOverride — consistencia simulador vs resolución natural", () => {
  it("override con la misma lista general → mismo precio que sin override", async () => {
    const sharedPL = makePriceList({
      id:          "pl-general",
      marginTotal: new D("80"),
    });

    mockPrisma.article.findFirst.mockResolvedValue(makeDbArticle({
      costComposition: [{
        type: "MANUAL", quantity: new D("1"), unitValue: new D("1000"),
        currencyId: null, mermaPercent: null, metalVariantId: null,
      }],
    }));

    // Para ambas llamadas, priceList.findFirst devuelve la misma lista
    mockPrisma.priceList.findFirst.mockResolvedValue(sharedPL);

    // Caso 1: sin override (resolución natural → lista general)
    const withoutOverride = await resolveFinalSalePrice("j1", {
      articleId: "a1",
    });

    // Caso 2: con override explícito al mismo ID
    const withOverride = await resolveFinalSalePrice("j1", {
      articleId:           "a1",
      priceListIdOverride: "pl-general",
    });

    // Mismo precio base (1000 × 1.80 = 1800)
    expect(withoutOverride.basePrice?.toNumber()).toBeCloseTo(1800, 2);
    expect(withOverride.basePrice?.toNumber()).toBeCloseTo(
      withoutOverride.basePrice!.toNumber(), 4
    );
    expect(withOverride.appliedPriceListId).toBe(withoutOverride.appliedPriceListId);
  });

  it("override a lista diferente → precio diferente (confirma que override actúa)", async () => {
    const generalPL = makePriceList({ id: "pl-general", marginTotal: new D("50") });
    const overridePL = makePriceList({ id: "pl-especial", marginTotal: new D("200") });

    mockPrisma.article.findFirst.mockResolvedValue(makeDbArticle({
      costComposition: [{
        type: "MANUAL", quantity: new D("1"), unitValue: new D("500"),
        currencyId: null, mermaPercent: null, metalVariantId: null,
      }],
    }));

    // Sin override: devuelve la lista general (50%)
    mockPrisma.priceList.findFirst.mockResolvedValueOnce(generalPL);
    const natural = await resolveFinalSalePrice("j1", { articleId: "a1" });

    // Con override a lista especial (200%)
    mockPrisma.priceList.findFirst.mockResolvedValueOnce(overridePL);
    const forced = await resolveFinalSalePrice("j1", {
      articleId: "a1", priceListIdOverride: "pl-especial",
    });

    // Naturales: 500 × 1.50 = 750; Override: 500 × 3 = 1500
    expect(natural.basePrice?.toNumber()).toBeCloseTo(750, 2);
    expect(forced.basePrice?.toNumber()).toBeCloseTo(1500, 2);
    expect(forced.appliedPriceListId).toBe("pl-especial");
    expect(natural.appliedPriceListId).toBe("pl-general");
  });
});

// =============================================================================
// C. Checkout pipeline — contrato venta → checkout
// =============================================================================
// resolveCheckoutPrice recibe el unitPrice de resolveFinalSalePrice como base.
// No recalcula el precio de venta — solo le suma el ajuste de la forma de pago.
//
// Diferencia justificada: checkout agrega recargo/descuento de pago. El motor
// de venta no sabe nada de la forma de pago.
// =============================================================================

describe("C. Checkout pipeline — resolveCheckoutPrice parte de unitPrice de venta", () => {
  it("checkout sin ajuste: finalAmount == unitPrice × quantity", async () => {
    mockPrisma.article.findFirst.mockResolvedValue(makeDbArticle({
      costComposition: [{ type: "MANUAL", quantity: new D("1"), unitValue: new D("500"), currencyId: null, mermaPercent: null, metalVariantId: null }],
      salePrice: new D("1000"),
    }));

    const sale = await resolveFinalSalePrice("j1", { articleId: "a1", quantity: 2 });
    expect(sale.unitPrice?.toNumber()).toBe(1000);

    // Checkout con unitPrice de venta, sin forma de pago
    const checkout = resolveCheckoutPrice({
      unitPrice: sale.unitPrice!.toNumber(),
      quantity:  2,
    });

    expect(checkout.baseAmount).toBe(2000);   // unitPrice × qty
    expect(checkout.paymentAdjustment).toBe(0);
    expect(checkout.finalAmount).toBe(2000);
    // No hay recalculación del precio de venta
  });

  it("checkout con recargo 10%: finalAmount == (unitPrice × qty) × 1.10", async () => {
    mockPrisma.article.findFirst.mockResolvedValue(makeDbArticle({
      salePrice: new D("800"),
    }));

    const sale = await resolveFinalSalePrice("j1", { articleId: "a1" });
    const unitPrice = sale.unitPrice!.toNumber(); // 800

    const checkout = resolveCheckoutPrice({
      unitPrice,
      quantity: 3,
      paymentMethod: { adjustmentType: "PERCENTAGE", adjustmentValue: 10 },
    });

    // base = 800 × 3 = 2400; recargo = 240; final = 2640
    expect(checkout.baseAmount).toBe(2400);
    expect(checkout.paymentAdjustment).toBeCloseTo(240, 2);
    expect(checkout.finalAmount).toBeCloseTo(2640, 2);
  });

  it("checkout con descuento fijo: finalAmount == base - descuento", () => {
    // Escenario puro (sin necesidad de resolveFinalSalePrice)
    const checkout = resolveCheckoutPrice({
      unitPrice: 1000,
      quantity:  1,
      paymentMethod: { adjustmentType: "FIXED", adjustmentValue: -50 }, // descuento
    });

    expect(checkout.baseAmount).toBe(1000);
    expect(checkout.paymentAdjustment).toBeCloseTo(-50, 2);
    expect(checkout.finalAmount).toBeCloseTo(950, 2);
  });

  it("contrato: pasos de checkout reflejan el precio de venta como base, no lo recalculan", () => {
    // El paso CHECKOUT_BASE debe ser unitPrice × qty
    // No debe haber pasos de PRICE_LIST, MARGIN, etc. (esos son del motor de venta)
    const checkout = resolveCheckoutPrice({
      unitPrice: 1500,
      quantity: 2,
      paymentMethod: { adjustmentType: "PERCENTAGE", adjustmentValue: 5 },
    });

    const stepCodes = checkout.steps.map(s => s.code);
    expect(stepCodes).toContain("CHECKOUT_BASE");
    expect(stepCodes).toContain("PAYMENT_ADJUSTMENT");
    expect(stepCodes).toContain("CHECKOUT_FINAL");

    // El motor de venta nunca genera estos pasos en el checkout
    expect(stepCodes).not.toContain("PRICE_LIST");
    expect(stepCodes).not.toContain("MARGIN");
    expect(stepCodes).not.toContain("PROMOTION");

    // Verificar que CHECKOUT_BASE usa el precio de venta como entrada
    const baseStep = checkout.steps.find(s => s.code === "CHECKOUT_BASE")!;
    expect(baseStep.amount).toBe(3000); // 1500 × 2
  });
});

// =============================================================================
// D. Rounding deferred NET — el redondeo se aplica DESPUÉS del descuento
// =============================================================================
// Cuando roundingApplyOn=NET, applyPriceList devuelve el precio SIN redondear
// y almacena la config en roundingDeferred. El motor de venta aplica el redondeo
// sobre el precio neto (después de descuentos), no sobre el precio de lista.
//
// Esto es crucial para mantener la intención de negocio: el precio final
// redondeado ya considera los descuentos.
// =============================================================================

describe("D. Rounding deferred NET — redondeo DESPUÉS del descuento", () => {
  // Setup: costo=500, lista MARGIN_TOTAL 71.5% → precio bruto=857.5
  //   roundingApplyOn=NET, INTEGER, UP
  //
  // Sin descuento: ceil(857.5) = 858
  // Con qty 10%: net=857.5×0.9=771.75 → ceil(771.75) = 772
  //
  // Si el redondeo se aplicara sobre el precio de lista (incorrecto):
  //   ceil(857.5) = 858 → 858 × 0.9 = 772.2 (diferente!)

  function setupArticleWithManualCost(costValue: number) {
    mockPrisma.article.findFirst.mockResolvedValue(makeDbArticle({
      costComposition: [{
        type: "MANUAL", quantity: new D("1"), unitValue: new D(String(costValue)),
        currencyId: null, mermaPercent: null, metalVariantId: null,
      }],
    }));
  }

  function makeDeferredNetList(marginTotal: string) {
    return makePriceList({
      marginTotal:      new D(marginTotal),
      roundingTarget:   "FINAL_PRICE", // FINAL_PRICE activa el redondeo del precio final
      roundingMode:     "INTEGER",     // redondear a entero
      roundingDirection:"UP",          // hacia arriba (ceil)
      roundingApplyOn:  "NET",         // diferir: aplicar después de descuentos
    });
  }

  it("sin descuento: ceil(857.5) = 858", async () => {
    setupArticleWithManualCost(500);
    mockPrisma.priceList.findFirst.mockResolvedValue(
      makeDeferredNetList("71.5") // 500 × 1.715 = 857.5
    );

    const res = await resolveFinalSalePrice("j1", { articleId: "a1" });

    expect(res.unitPrice?.toNumber()).toBe(858);
    // El step ROUNDING debe existir y mostrar que se aplicó sobre el neto
    const roundingStep = res.steps.find(s => s.key === "ROUNDING");
    expect(roundingStep).toBeDefined();
    expect(roundingStep!.meta?.applyOn).toBe("NET");
    expect(roundingStep!.meta?.preRounding).toBe("857.5");
  });

  it("con qty discount 10%: net=771.75 → ceil(771.75)=772 (no 772.2)", async () => {
    setupArticleWithManualCost(500);
    mockPrisma.priceList.findFirst.mockResolvedValue(
      makeDeferredNetList("71.5") // base=857.5
    );
    mockPrisma.quantityDiscount.findMany.mockResolvedValue([{
      id: "qd1",
      articleId: "a1", variantId: null, categoryId: null, brand: null, groupId: null,
      isStackable: false, evaluationMode: "LINE",
      tiers: [{ minQty: new D("1"), type: "PERCENTAGE", value: new D("10") }],
    }]);

    const res = await resolveFinalSalePrice("j1", { articleId: "a1", quantity: 5 });

    // Precio neto antes de redondeo = 857.5 × 0.9 = 771.75
    // Redondeo NET ceil: 772 (no 772.2 que sería si se redondeara primero)
    expect(res.unitPrice?.toNumber()).toBe(772);

    const roundingStep = res.steps.find(s => s.key === "ROUNDING");
    expect(roundingStep).toBeDefined();
    expect(roundingStep!.meta?.applyOn).toBe("NET");
    // El preRounding muestra el valor antes del redondeo final (post-descuento)
    const preRounding = parseFloat(roundingStep!.meta?.preRounding as string);
    expect(preRounding).toBeCloseTo(771.75, 2);
  });

  it("rounding PRICE (no deferred): redondeo ocurre antes del descuento → resultado diferente", async () => {
    setupArticleWithManualCost(500);
    // Misma lista pero con roundingApplyOn=PRICE (no deferred)
    mockPrisma.priceList.findFirst.mockResolvedValue(makePriceList({
      marginTotal:       new D("71.5"),
      roundingTarget:    "FINAL_PRICE",
      roundingMode:      "INTEGER",
      roundingDirection: "UP",
      roundingApplyOn:   "PRICE", // aplica sobre precio de lista (antes de descuento)
    }));
    mockPrisma.quantityDiscount.findMany.mockResolvedValue([{
      id: "qd1",
      articleId: "a1", variantId: null, categoryId: null, brand: null, groupId: null,
      isStackable: false, evaluationMode: "LINE",
      tiers: [{ minQty: new D("1"), type: "PERCENTAGE", value: new D("10") }],
    }]);

    const res = await resolveFinalSalePrice("j1", { articleId: "a1", quantity: 5 });

    // ceil(857.5) = 858 → 858 × 0.9 = 772.2
    expect(res.unitPrice?.toNumber()).toBeCloseTo(772.2, 1);
    // Este resultado es DIFERENTE al deferred (772) porque el redondeo
    // ocurrió antes del descuento. Ambos comportamientos son válidos
    // según la configuración — el test documenta la diferencia.
  });
});

// =============================================================================
// E. Diferencia documentada: batch pricing vs resolveFinalSalePrice
// =============================================================================
// batchResolveSalePricesNoClient (en articles.service.ts) es una vista
// simplificada para el listado general de artículos. Difiere de
// resolveFinalSalePrice en:
//
//   1. NO aplica quantity discounts (scope: listado general, sin cantidad)
//   2. NO resuelve lista de precios del cliente (por eso se llama "NoClient")
//   3. NO genera alertas ni política de confirmación
//   4. NO computa impuestos via computeLineTaxes (usa helper simplificado)
//
// Estas diferencias son JUSTIFICADAS: el listado es una vista rápida.
// El precio definitivo de una venta siempre pasa por resolveFinalSalePrice.
//
// Este test documenta y regresiona el punto 1 (qty discounts ausentes en batch).
// =============================================================================

describe("E. Diferencia justificada: batch pricing NO aplica quantity discounts", () => {
  it("resolveFinalSalePrice SÍ aplica qty discount, applyPriceList solo da precio base", async () => {
    const priceList = {
      id: "pl", name: "Lista", mode: "MARGIN_TOTAL",
      marginTotal: "100", marginMetal: null, marginHechura: null,
      costPerGram: null, surcharge: null, minimumPrice: null,
      roundingTarget: "NONE", roundingMode: "NONE", roundingDirection: "NEAREST",
      roundingApplyOn: "PRICE", validFrom: null, validTo: null, isActive: true,
    };
    const costBreakdown = { value: new D("500"), metalCost: null, hechuraCost: null };

    // Lo que hace el batch internamente: solo applyPriceList, sin qty discount
    const batchResult = applyPriceList(priceList as any, costBreakdown);
    // 500 × (1 + 100/100) = 1000
    expect(batchResult.value?.toNumber()).toBe(1000);

    // Lo que hace resolveFinalSalePrice con el mismo costo y lista + qty discount
    mockPrisma.article.findFirst.mockResolvedValue(makeDbArticle({
      costComposition: [{
        type: "MANUAL", quantity: new D("1"), unitValue: new D("500"),
        currencyId: null, mermaPercent: null, metalVariantId: null,
      }],
    }));
    mockPrisma.priceList.findFirst.mockResolvedValue({ ...priceList, sortOrder: 0, scope: "GENERAL", isFavorite: true, deletedAt: null, id: "pl" });
    mockPrisma.quantityDiscount.findMany.mockResolvedValue([{
      id: "qd1",
      articleId: "a1", variantId: null, categoryId: null, brand: null, groupId: null,
      isStackable: false, evaluationMode: "LINE",
      tiers: [{ minQty: new D("1"), type: "PERCENTAGE", value: new D("20") }],
    }]);

    const saleResult = await resolveFinalSalePrice("j1", { articleId: "a1", quantity: 10 });

    // Motor completo: 1000 base - 20% = 800
    expect(saleResult.basePrice?.toNumber()).toBeCloseTo(1000, 2);
    expect(saleResult.unitPrice?.toNumber()).toBeCloseTo(800, 2);
    expect(saleResult.quantityDiscountAmount?.toNumber()).toBeCloseTo(200, 2);

    // DIFERENCIA DOCUMENTADA: batch=1000, individual=800
    // El batch muestra el precio base de lista; el individual aplica el descuento real
    expect(batchResult.value!.toNumber()).not.toBe(saleResult.unitPrice?.toNumber());
    // Batch da el precio de lista (lo que el cliente ve en el catálogo)
    expect(batchResult.value!.toNumber()).toBe(saleResult.basePrice?.toNumber());
  });

  it("cuando NO hay qty discount, batch y resolveFinalSalePrice coinciden en precio base", async () => {
    const priceList = {
      id: "pl", name: "L", mode: "MARGIN_TOTAL",
      marginTotal: "50", marginMetal: null, marginHechura: null,
      costPerGram: null, surcharge: null, minimumPrice: null,
      roundingTarget: "NONE", roundingMode: "NONE", roundingDirection: "NEAREST",
      roundingApplyOn: "PRICE", validFrom: null, validTo: null, isActive: true,
    };
    const costBreakdown = { value: new D("1000"), metalCost: null, hechuraCost: null };

    const batchResult = applyPriceList(priceList as any, costBreakdown);
    // 1000 × 1.5 = 1500

    mockPrisma.article.findFirst.mockResolvedValue(makeDbArticle({
      costComposition: [{
        type: "MANUAL", quantity: new D("1"), unitValue: new D("1000"),
        currencyId: null, mermaPercent: null, metalVariantId: null,
      }],
    }));
    mockPrisma.priceList.findFirst.mockResolvedValue({ ...priceList, sortOrder: 0, scope: "GENERAL", isFavorite: true, deletedAt: null });

    const saleResult = await resolveFinalSalePrice("j1", { articleId: "a1", quantity: 1 });

    // Sin qty discount: batch price == sale base price == sale unit price
    expect(batchResult.value?.toNumber()).toBeCloseTo(1500, 2);
    expect(saleResult.basePrice?.toNumber()).toBeCloseTo(1500, 2);
    expect(saleResult.unitPrice?.toNumber()).toBeCloseTo(1500, 2);
    expect(saleResult.quantityDiscountAmount).toBeNull();
  });
});

// =============================================================================
// F. Barrel smoke — el barrel exporta correctamente todas las funciones clave
// =============================================================================
// Garantiza que ninguna refactorización futura rompa el contrato del barrel.
// Si alguna función deja de exportarse, este test falla antes de llegar a prod.
// =============================================================================

describe("F. Barrel smoke — funciones clave accesibles desde el barrel", () => {
  it("todas las funciones de pricing están exportadas y son callable", async () => {
    // Importar desde el barrel (no desde sub-archivos)
    const barrel = await import("../pricing-engine.js");

    // Motor de costo
    expect(typeof barrel.calculateCostFromLines).toBe("function");
    expect(typeof barrel.buildBatchCostContext).toBe("function");
    expect(typeof barrel.resolveVariantAwareWeight).toBe("function");

    // Motor de venta
    expect(typeof barrel.resolveFinalSalePrice).toBe("function");
    expect(typeof barrel.evaluatePricingPolicy).toBe("function");
    expect(typeof barrel.computeLineTaxes).toBe("function");

    // Checkout
    expect(typeof barrel.resolveCheckoutPrice).toBe("function");

    // Balance
    expect(typeof barrel.buildBalanceBreakdownFromPrice).toBe("function");

    // Listas de precios
    expect(typeof barrel.resolvePriceList).toBe("function");
    expect(typeof barrel.applyPriceList).toBe("function");
    expect(typeof barrel.isPriceListValidNow).toBe("function");
    expect(barrel.PL_COMPUTE_SELECT).toBeDefined();

    // Moneda
    expect(typeof barrel.getBaseCurrencyId).toBe("function");
    expect(typeof barrel.getExchangeRate).toBe("function");
    expect(typeof barrel.convertMoney).toBe("function");
  });
});
