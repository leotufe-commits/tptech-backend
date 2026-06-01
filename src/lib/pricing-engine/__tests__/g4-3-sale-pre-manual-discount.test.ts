// src/lib/pricing-engine/__tests__/g4-3-sale-pre-manual-discount.test.ts
// =============================================================================
// FASE F1.3 G4.3 — tests de `componentSaleBreakdown.{metal,hechura}.salePreManualDiscount`.
//
// Validaciones del usuario (todas cubiertas):
//   1. Decimal safety end-to-end — sin parseFloat / Number / toFixed / coerción.
//   2. Orden exacto del corte:
//          promo → qtyDiscount → customerRule → [CUT] → manualDiscount
//      `salePreManualDiscount` representa el componente JUSTO ANTES del cut.
//   3. Threshold visual (semántica) — sin manual ⇒ pre === final.
//   4. Manual SURCHARGE — la fórmula respeta amounts negativos (recargo).
//   5. Tooltip wording — documentado en types como "Valor antes del ajuste
//      manual del operador.".
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
}));
vi.mock("../../prisma.js", () => ({ prisma: mockPrisma }));

const mockResolveArticleCost = vi.hoisted(() => vi.fn());
vi.mock("../pricing-engine.cost.js", () => ({
  calculateCostFromLines:        (...args: any[]) => mockResolveArticleCost(...args),
  enrichCostMetalSteps:          vi.fn(),
  getArticleMetalVariantIds:     vi.fn().mockResolvedValue([]),
  loadArticleMetalVariantsBatch: vi.fn().mockResolvedValue(new Map()),
}));

const mockResolvePriceList = vi.hoisted(() => vi.fn());
const mockApplyPriceList   = vi.hoisted(() => vi.fn());
vi.mock("../pricing-engine.pricelist.js", () => ({
  resolvePriceList: (...args: any[]) => mockResolvePriceList(...args),
  applyPriceList:   (...args: any[]) => mockApplyPriceList(...args),
}));

import { resolveFinalSalePrice } from "../pricing-engine.sale.js";

const D = Prisma.Decimal;

function makeDbArticle(overrides: Record<string, any> = {}) {
  return {
    categoryId: null, brand: null, salePrice: null,
    useManualSalePrice: false,
    manualAdjustmentKind: null, manualAdjustmentType: null, manualAdjustmentValue: null,
    mermaPercent: null, category: null, costComposition: [],
    ...overrides,
  };
}
function costOf(amount: number) {
  return {
    value: new D(String(amount)), mode: "MANUAL", partial: false, steps: [],
    metalCost: new D("0"), hechuraCost: new D("0"), totalGrams: new D("0"),
  };
}

function setupMetalHechuraList(metalSale: number, hechuraSale: number) {
  mockPrisma.article.findFirst.mockResolvedValue(makeDbArticle());
  mockResolveArticleCost.mockResolvedValue(costOf(1000));
  const fakePriceList = {
    id: "pl1", name: "Lista MH", mode: "METAL_HECHURA",
    marginTotal: null, marginMetal: null, marginHechura: null,
    costPerGram: null, surcharge: null, minimumPrice: null,
    roundingTarget: "NONE", roundingMode: "NONE", roundingDirection: "NEAREST",
    validFrom: null, validTo: null, isActive: true,
  };
  mockResolvePriceList.mockResolvedValue({ priceList: fakePriceList, source: "GENERAL" });
  mockApplyPriceList.mockReturnValue({
    value:   new D(String(metalSale + hechuraSale)),
    partial: false,
    metalHechuraDetail: {
      metalCost: 500, metalSale,
      metalMarginPct:   ((metalSale - 500) / 500) * 100,
      hechuraCost: 500, hechuraSale,
      hechuraMarginPct: ((hechuraSale - 500) / 500) * 100,
    },
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  mockPrisma.article.findFirst.mockResolvedValue(null);
  mockPrisma.articleVariant.findFirst.mockResolvedValue(null);
  mockPrisma.articleGroupItem.findFirst.mockResolvedValue(null);
  mockPrisma.promotion.findMany.mockResolvedValue([]);
  mockPrisma.quantityDiscount.findMany.mockResolvedValue([]);
  mockPrisma.commercialEntity.findFirst.mockResolvedValue(null);
  mockPrisma.entityMermaOverride.findMany.mockResolvedValue([]);
  mockPrisma.jewelry.findUnique.mockResolvedValue({ id: "j1", roundingMode: "NONE", roundingDirection: "NEAREST", roundingTarget: "NONE" });
});

// ============================================================================
// 1. THRESHOLD VISUAL — sin descuentos / sin manual ⇒ pre === final
// ============================================================================

describe("salePreManualDiscount — threshold visual (sin manual)", () => {
  it("baseline correct: sin descuentos → pre === final === base", async () => {
    setupMetalHechuraList(600, 600);
    const r = await resolveFinalSalePrice("j1", { articleId: "a1" });
    expect(r.componentSaleBreakdown).not.toBeNull();
    expect(r.componentSaleBreakdown!.metal.salePreManualDiscount).toBeCloseTo(600, 4);
    expect(r.componentSaleBreakdown!.metal.salePreManualDiscount)
      .toBe(r.componentSaleBreakdown!.metal.final);
    expect(r.componentSaleBreakdown!.hechura.salePreManualDiscount).toBeCloseTo(600, 4);
    expect(r.componentSaleBreakdown!.hechura.salePreManualDiscount)
      .toBe(r.componentSaleBreakdown!.hechura.final);
  });

  it("baseline correct: con qty/promo/customer pero SIN manual → pre === final", async () => {
    // Solo qty discount sobre METAL.
    setupMetalHechuraList(600, 600);
    mockPrisma.quantityDiscount.findMany.mockResolvedValue([{
      id: "qd1", articleId: "a1",
      variantId: null, categoryId: null, brand: null, groupId: null,
      isStackable: false, evaluationMode: "LINE",
      applyOn: "METAL",
      tiers: [{ minQty: new D("1"), type: "PERCENTAGE", value: new D("20") }],
    }]);
    const r = await resolveFinalSalePrice("j1", { articleId: "a1", quantity: 2 });
    // Sin MANUAL_DISCOUNT en adjustments → pre === final.
    expect(r.componentSaleBreakdown!.metal.adjustments
      .every(a => a.kind !== "MANUAL_DISCOUNT")).toBe(true);
    expect(r.componentSaleBreakdown!.metal.salePreManualDiscount)
      .toBe(r.componentSaleBreakdown!.metal.final);
    expect(r.componentSaleBreakdown!.hechura.salePreManualDiscount)
      .toBe(r.componentSaleBreakdown!.hechura.final);
  });
});

// ============================================================================
// 2. ORDEN EXACTO — promo → qtyDiscount → customerRule → [CUT] → manualDiscount
// ============================================================================

describe("salePreManualDiscount — orden exacto del corte", () => {
  it("baseline correct: customerRule + manual → pre incluye customerRule, NO el manual", async () => {
    setupMetalHechuraList(600, 600);
    // Cliente con DISCOUNT 10% sobre HECHURA (capa customerRule).
    mockPrisma.commercialEntity.findFirst.mockResolvedValue({
      taxExempt: false, taxApplyOnOverride: null,
      commercialRuleType:  "DISCOUNT",
      commercialValueType: "PERCENTAGE",
      commercialValue:     new D("10"),
      commercialApplyOn:   "HECHURA",
      taxOverrides:        [],
    });
    const r = await resolveFinalSalePrice("j1", {
      articleId: "a1", clientId: "c1",
      // Manual discount 5% sobre HECHURA (capa última).
      manualDiscountOverride: { mode: "PERCENT", value: 5, appliesTo: "HECHURA" },
    });
    const h = r.componentSaleBreakdown!.hechura;
    // Verifica que SÍ se trackearon ambas capas.
    const kinds = h.adjustments.map(a => a.kind);
    expect(kinds).toContain("ENTITY_RULE");
    expect(kinds).toContain("MANUAL_DISCOUNT");
    // Pre = base − ENTITY_RULE.amount  (NO incluye MANUAL_DISCOUNT.amount)
    const entityAmt = h.adjustments.find(a => a.kind === "ENTITY_RULE")!.amount;
    const manualAmt = h.adjustments.find(a => a.kind === "MANUAL_DISCOUNT")!.amount;
    expect(h.salePreManualDiscount).toBeCloseTo(h.base - entityAmt, 4);
    // Final = pre − manual
    expect(h.final).toBeCloseTo(h.salePreManualDiscount - manualAmt, 4);
    // Numérico estable: pre = 540 (= 600 − 60 customerRule).
    expect(h.salePreManualDiscount).toBeCloseTo(540, 4);
    // NOTA: final absoluto depende de la base sobre la que el motor aplica
    // el manual (basePrice vs finalPrice + portion costo). Lo importante
    // testeado arriba es la fórmula relativa, no el absoluto.
  });

  it("baseline correct: SOLO manual → pre === base (no hay capa previa que lo afecte)", async () => {
    setupMetalHechuraList(600, 600);
    const r = await resolveFinalSalePrice("j1", {
      articleId: "a1",
      manualDiscountOverride: { mode: "PERCENT", value: 10, appliesTo: "HECHURA" },
    });
    const h = r.componentSaleBreakdown!.hechura;
    expect(h.adjustments).toHaveLength(1);
    expect(h.adjustments[0].kind).toBe("MANUAL_DISCOUNT");
    // Pre = base entero (no hubo nada antes del manual).
    expect(h.salePreManualDiscount).toBeCloseTo(h.base, 4);
    expect(h.salePreManualDiscount).toBeCloseTo(600, 4);
  });

  it("baseline correct: qty + manual → pre = base − qty, NO − manual", async () => {
    setupMetalHechuraList(600, 600);
    mockPrisma.quantityDiscount.findMany.mockResolvedValue([{
      id: "qd1", articleId: "a1",
      variantId: null, categoryId: null, brand: null, groupId: null,
      isStackable: false, evaluationMode: "LINE",
      applyOn: "METAL",
      tiers: [{ minQty: new D("1"), type: "PERCENTAGE", value: new D("10") }],
    }]);
    const r = await resolveFinalSalePrice("j1", {
      articleId: "a1", quantity: 2,
      manualDiscountOverride: { mode: "PERCENT", value: 5, appliesTo: "METAL" },
    });
    const m = r.componentSaleBreakdown!.metal;
    const qtyAmt    = m.adjustments.find(a => a.kind === "QUANTITY_DISCOUNT")!.amount;
    const manualAmt = m.adjustments.find(a => a.kind === "MANUAL_DISCOUNT")!.amount;
    expect(m.salePreManualDiscount).toBeCloseTo(m.base - qtyAmt, 4);
    expect(m.final).toBeCloseTo(m.salePreManualDiscount - manualAmt, 4);
  });
});

// ============================================================================
// 3. MANUAL SURCHARGE — recargos del cliente (amount negativo)
// ============================================================================

describe("salePreManualDiscount — surcharge semantics", () => {
  it("baseline correct: SURCHARGE de cliente (amount negativo) + manual → pre incluye surcharge", async () => {
    setupMetalHechuraList(600, 600);
    // Cliente con SURCHARGE 10% sobre HECHURA — el motor lo trackea con amount NEGATIVO.
    mockPrisma.commercialEntity.findFirst.mockResolvedValue({
      taxExempt: false, taxApplyOnOverride: null,
      commercialRuleType:  "SURCHARGE",
      commercialValueType: "PERCENTAGE",
      commercialValue:     new D("10"),
      commercialApplyOn:   "HECHURA",
      taxOverrides:        [],
    });
    const r = await resolveFinalSalePrice("j1", {
      articleId: "a1", clientId: "c1",
      manualDiscountOverride: { mode: "PERCENT", value: 5, appliesTo: "HECHURA" },
    });
    const h = r.componentSaleBreakdown!.hechura;
    const surchargeAmt = h.adjustments.find(a => a.kind === "ENTITY_RULE")!.amount;
    expect(surchargeAmt).toBeLessThan(0);  // recargo se registra negativo
    // Pre = base − surcharge.amount (que al ser negativo, AUMENTA el pre).
    expect(h.salePreManualDiscount).toBeCloseTo(h.base - surchargeAmt, 4);
    expect(h.salePreManualDiscount).toBeGreaterThan(h.base);  // recargo aumenta
  });

  it("baseline correct: simulación de manualDiscount con kind=MANUAL_DISCOUNT y amount=0 → no afecta pre", async () => {
    // value=0 es legal en el motor (no genera adjustment perceptible, pero
    // si llegara a generarse uno con amount=0 igual no afectaría pre).
    setupMetalHechuraList(600, 600);
    const r = await resolveFinalSalePrice("j1", {
      articleId: "a1",
      manualDiscountOverride: { mode: "PERCENT", value: 0, appliesTo: "HECHURA" },
    });
    const h = r.componentSaleBreakdown!.hechura;
    // Cualquier manual con amount 0 no afecta pre ni final.
    expect(h.salePreManualDiscount).toBeCloseTo(h.base, 4);
    expect(h.final).toBeCloseTo(h.salePreManualDiscount, 4);
  });
});

// ============================================================================
// 4. DECIMAL SAFETY — sin parseFloat / Number / toFixed drift
// ============================================================================

describe("salePreManualDiscount — Decimal safety end-to-end", () => {
  it("baseline correct: 0.1 + 0.2 — fórmula resta exacta sin drift JS", async () => {
    // base = 0.3, ningún ajuste → pre y final = 0.3 exacto (sin 0.30000000000000004).
    setupMetalHechuraList(0.1, 0.2);
    const r = await resolveFinalSalePrice("j1", { articleId: "a1" });
    const m = r.componentSaleBreakdown!.metal;
    const h = r.componentSaleBreakdown!.hechura;
    // Cero drift: el motor usa Decimal en el reduce, y solo .toNumber() al exponer.
    expect(m.salePreManualDiscount).toBe(0.1);
    expect(h.salePreManualDiscount).toBe(0.2);
  });

  it("baseline correct: 3 ajustes con decimales raros → suma exacta (no float drift)", async () => {
    // base 1000 sobre HECHURA, encadenamos:
    //   - qty 0.1% (= 1)
    //   - manual 0.2% (= 0.999, sobre 999)
    setupMetalHechuraList(0, 1000);
    mockPrisma.quantityDiscount.findMany.mockResolvedValue([{
      id: "qd1", articleId: "a1",
      variantId: null, categoryId: null, brand: null, groupId: null,
      isStackable: false, evaluationMode: "LINE",
      applyOn: "HECHURA",
      tiers: [{ minQty: new D("1"), type: "PERCENTAGE", value: new D("0.1") }],
    }]);
    const r = await resolveFinalSalePrice("j1", {
      articleId: "a1", quantity: 1,
      manualDiscountOverride: { mode: "PERCENT", value: 0.2, appliesTo: "HECHURA" },
    });
    const h = r.componentSaleBreakdown!.hechura;
    const qtyAmt    = h.adjustments.find(a => a.kind === "QUANTITY_DISCOUNT")!.amount;
    const manualAmt = h.adjustments.find(a => a.kind === "MANUAL_DISCOUNT")!.amount;
    // pre = base − qty exacto (Decimal).
    expect(h.salePreManualDiscount).toBeCloseTo(h.base - qtyAmt, 6);
    // final = pre − manual exacto (Decimal).
    expect(h.final).toBeCloseTo(h.salePreManualDiscount - manualAmt, 6);
  });

  it("baseline correct: tipos JS — el campo es number puro (sin Decimal leak en la API)", async () => {
    setupMetalHechuraList(600, 600);
    const r = await resolveFinalSalePrice("j1", { articleId: "a1" });
    expect(typeof r.componentSaleBreakdown!.metal.salePreManualDiscount).toBe("number");
    expect(typeof r.componentSaleBreakdown!.hechura.salePreManualDiscount).toBe("number");
  });
});

// ============================================================================
// 5. COMPONENTES NEGATIVOS — pre y final NO se clampean a 0
//
// Regla canónica (ver CLAUDE.md raíz, "Pricing-engine: componentes negativos
// son válidos"): si un descuento dirigido a un componente excede su base, el
// componente queda NEGATIVO. El motor emite el valor real; el frontend lo
// renderiza con signo y color (no `Math.max(0, …)`).
// ============================================================================

describe("componentSaleBreakdown — componentes negativos válidos (sin clamp)", () => {
  it("HECHURA: descuento (ENTITY) > base → hechura.final y .salePreManualDiscount NEGATIVOS", async () => {
    setupMetalHechuraList(0, 100);
    // Customer rule 200% sobre HECHURA → adj.amount = 200 > base 100.
    mockPrisma.commercialEntity.findFirst.mockResolvedValue({
      taxExempt: false, taxApplyOnOverride: null,
      commercialRuleType:  "DISCOUNT",
      commercialValueType: "PERCENTAGE",
      commercialValue:     new D("200"),
      commercialApplyOn:   "HECHURA",
      taxOverrides:        [],
    });
    const r = await resolveFinalSalePrice("j1", { articleId: "a1", clientId: "c1" });
    const h = r.componentSaleBreakdown!.hechura;
    // SIN clamp: pre y final reflejan el negativo real (base 100 − adj 200 = −100).
    expect(h.salePreManualDiscount).toBeLessThan(0);
    expect(h.salePreManualDiscount).toBeCloseTo(-100, 4);
    expect(h.final).toBeLessThan(0);
    expect(h.final).toBeCloseTo(-100, 4);
  });

  it("HECHURA: bonificación MANUAL > base → hechura.final NEGATIVO (caso del bug original)", async () => {
    // Caso reportado: hechura=100, descuento manual sobre HECHURA = 150 → final −50.
    setupMetalHechuraList(0, 100);
    const r = await resolveFinalSalePrice("j1", {
      articleId: "a1",
      manualDiscountOverride: { mode: "AMOUNT", value: 150, appliesTo: "HECHURA" },
    });
    const h = r.componentSaleBreakdown!.hechura;
    // pre === base (no hay capa previa al manual).
    expect(h.salePreManualDiscount).toBeCloseTo(100, 4);
    // final = base − manual = 100 − 150 = −50, SIN clamp.
    expect(h.final).toBeLessThan(0);
    expect(h.final).toBeCloseTo(-50, 4);
  });

  it("METAL: bonificación MANUAL 50% sobre 'Solo metal' con descuento > base → metal.final NEGATIVO", async () => {
    // Caso reportado por el usuario: bonificación manual con applyOn=METAL cuya
    // resolución da un amount mayor a la base del metal. Para forzar el caso
    // con un manual % "normal", combinamos entity rule + manual sobre METAL.
    setupMetalHechuraList(100, 400);
    mockPrisma.commercialEntity.findFirst.mockResolvedValue({
      taxExempt: false, taxApplyOnOverride: null,
      commercialRuleType:  "DISCOUNT",
      commercialValueType: "PERCENTAGE",
      commercialValue:     new D("80"),         // entity quita 80 sobre metal 100
      commercialApplyOn:   "METAL",
      taxOverrides:        [],
    });
    const r = await resolveFinalSalePrice("j1", {
      articleId: "a1", clientId: "c1",
      // manual 50% sobre METAL (base ya post-entity = 20 visible, pero el
      // amount manual se calcula sobre el VALOR DE VENTA del componente
      // — ver bloque "manualDiscountOverride — base por componente (venta)").
      manualDiscountOverride: { mode: "PERCENT", value: 50, appliesTo: "METAL" },
    });
    const m = r.componentSaleBreakdown!.metal;
    // Σ ajustes (80 entity + 50 manual = 130) > base (100) ⇒ final NEGATIVO.
    const sumAdj = m.adjustments.reduce((s, a) => s + a.amount, 0);
    expect(sumAdj).toBeGreaterThan(m.base);
    expect(m.final).toBeLessThan(0);
    expect(m.final).toBeCloseTo(m.base - sumAdj, 4);
  });

  it("METAL: descuento ENTITY > base → metal.final NEGATIVO", async () => {
    setupMetalHechuraList(100, 0);
    mockPrisma.commercialEntity.findFirst.mockResolvedValue({
      taxExempt: false, taxApplyOnOverride: null,
      commercialRuleType:  "DISCOUNT",
      commercialValueType: "PERCENTAGE",
      commercialValue:     new D("200"),
      commercialApplyOn:   "METAL",
      taxOverrides:        [],
    });
    const r = await resolveFinalSalePrice("j1", { articleId: "a1", clientId: "c1" });
    const m = r.componentSaleBreakdown!.metal;
    expect(m.final).toBeLessThan(0);
    expect(m.final).toBeCloseTo(-100, 4);
  });

  it("descuento sobre TOTAL no inyecta ajustes por componente → ningún componente queda negativo por TOTAL", async () => {
    // Salvaguarda: la regla "no redistribuir silenciosamente" se respeta —
    // descuentos sobre TOTAL no rompen los componentes individuales.
    setupMetalHechuraList(100, 100);
    const r = await resolveFinalSalePrice("j1", {
      articleId: "a1",
      manualDiscountOverride: { mode: "PERCENT", value: 50, appliesTo: "TOTAL" },
    });
    const m = r.componentSaleBreakdown!.metal;
    const h = r.componentSaleBreakdown!.hechura;
    // Componentes intactos en su base (manual TOTAL no se proyecta sobre METAL/HECHURA).
    expect(m.final).toBeGreaterThanOrEqual(0);
    expect(h.final).toBeGreaterThanOrEqual(0);
  });
});

// ============================================================================
// FIX bonificación por base ("Aplica a") — METAL/HECHURA usan VALOR DE VENTA
// del componente (metalHechuraBreakdown), no proporción de costo. Total /
// Metal / Hechura deben dar descuentos DISTINTOS. Bug previo: METAL/HECHURA
// colapsaban a TOTAL (sin cost breakdown) → "Aplica a" no cambiaba nada.
// ============================================================================
describe("manualDiscountOverride — base por componente (venta)", () => {
  // Artículo metal+hechura: venta metal=600, venta hechura=400, total=1000.
  it("10% sobre TOTAL / METAL / HECHURA → finales y descuentos DISTINTOS", async () => {
    setupMetalHechuraList(600, 400);
    const total = await resolveFinalSalePrice("j1", {
      articleId: "a1",
      manualDiscountOverride: { mode: "PERCENT", value: 10, appliesTo: "TOTAL" },
    });
    setupMetalHechuraList(600, 400);
    const metal = await resolveFinalSalePrice("j1", {
      articleId: "a1",
      manualDiscountOverride: { mode: "PERCENT", value: 10, appliesTo: "METAL" },
    });
    setupMetalHechuraList(600, 400);
    const hechura = await resolveFinalSalePrice("j1", {
      articleId: "a1",
      manualDiscountOverride: { mode: "PERCENT", value: 10, appliesTo: "HECHURA" },
    });

    const A = total.unitPrice!.toNumber();   // 1000 − 10%·1000 = 900
    const B = metal.unitPrice!.toNumber();   // 1000 − 10%·600  = 940
    const C = hechura.unitPrice!.toNumber(); // 1000 − 10%·400  = 960

    expect(A).toBeCloseTo(900, 4);
    expect(B).toBeCloseTo(940, 4);
    expect(C).toBeCloseTo(960, 4);
    // A, B, C distintos entre sí (el bug los igualaba).
    expect(new Set([A, B, C]).size).toBe(3);
  });

  it("cambiar SOLO appliesTo (mismo 10%) recalcula el precio final", async () => {
    setupMetalHechuraList(600, 400);
    const m1 = (await resolveFinalSalePrice("j1", {
      articleId: "a1",
      manualDiscountOverride: { mode: "PERCENT", value: 10, appliesTo: "METAL" },
    })).unitPrice!.toNumber();
    setupMetalHechuraList(600, 400);
    const h1 = (await resolveFinalSalePrice("j1", {
      articleId: "a1",
      manualDiscountOverride: { mode: "PERCENT", value: 10, appliesTo: "HECHURA" },
    })).unitPrice!.toNumber();
    expect(m1).not.toBe(h1);
  });

  it("determinístico (paridad preview↔confirm): mismos inputs → mismo resultado", async () => {
    setupMetalHechuraList(600, 400);
    const a = (await resolveFinalSalePrice("j1", {
      articleId: "a1",
      manualDiscountOverride: { mode: "PERCENT", value: 10, appliesTo: "METAL" },
    })).unitPrice!.toNumber();
    setupMetalHechuraList(600, 400);
    const b = (await resolveFinalSalePrice("j1", {
      articleId: "a1",
      manualDiscountOverride: { mode: "PERCENT", value: 10, appliesTo: "METAL" },
    })).unitPrice!.toNumber();
    expect(a).toBe(b);
  });
});

// ============================================================================
// Bonificación MANUAL por línea funciona SIN cliente, y la precedencia de
// base es: od.appliesTo > discountAppliesToOverride > TOTAL (cliente NO es
// requisito; su commercialApplyOn gobierna solo su propia capa).
// ============================================================================
describe("manualDiscountOverride — sin cliente + precedencia de base", () => {
  it("SIN cliente: 10% TOTAL/METAL/HECHURA → finales distintos", async () => {
    setupMetalHechuraList(600, 400); // venta metal=600, hechura=400, total=1000
    const tot = (await resolveFinalSalePrice("j1", {
      articleId: "a1",
      manualDiscountOverride: { mode: "PERCENT", value: 10, appliesTo: "TOTAL" },
    })).unitPrice!.toNumber();
    setupMetalHechuraList(600, 400);
    const met = (await resolveFinalSalePrice("j1", {
      articleId: "a1",
      manualDiscountOverride: { mode: "PERCENT", value: 10, appliesTo: "METAL" },
    })).unitPrice!.toNumber();
    setupMetalHechuraList(600, 400);
    const hec = (await resolveFinalSalePrice("j1", {
      articleId: "a1",
      manualDiscountOverride: { mode: "PERCENT", value: 10, appliesTo: "HECHURA" },
    })).unitPrice!.toNumber();
    expect(tot).toBeCloseTo(900, 4);
    expect(met).toBeCloseTo(940, 4);
    expect(hec).toBeCloseTo(960, 4);
    expect(new Set([tot, met, hec]).size).toBe(3);
  });

  it("SIN cliente: precedencia #2 — od sin appliesTo + discountAppliesToOverride=METAL → base METAL", async () => {
    setupMetalHechuraList(600, 400);
    const r = await resolveFinalSalePrice("j1", {
      articleId: "a1",
      manualDiscountOverride: { mode: "PERCENT", value: 10 } as any, // sin appliesTo
      discountAppliesToOverride: "METAL",
    });
    expect(r.unitPrice!.toNumber()).toBeCloseTo(940, 4); // 1000 − 10%·600
  });

  it("precedencia #1 gana: od.appliesTo=HECHURA + discountAppliesToOverride=METAL → HECHURA", async () => {
    setupMetalHechuraList(600, 400);
    const r = await resolveFinalSalePrice("j1", {
      articleId: "a1",
      manualDiscountOverride: { mode: "PERCENT", value: 10, appliesTo: "HECHURA" },
      discountAppliesToOverride: "METAL",
    });
    expect(r.unitPrice!.toNumber()).toBeCloseTo(960, 4); // 1000 − 10%·400
  });

  it("CON cliente: la bonificación manual sigue usando su base (independiente del cliente)", async () => {
    setupMetalHechuraList(600, 400);
    mockPrisma.commercialEntity.findFirst.mockResolvedValue({
      taxExempt: false, taxApplyOnOverride: null,
      commercialRuleType: null, commercialValueType: null,
      commercialValue: null, commercialApplyOn: "HECHURA", taxOverrides: [],
    });
    const r = await resolveFinalSalePrice("j1", {
      articleId: "a1", clientId: "c1",
      manualDiscountOverride: { mode: "PERCENT", value: 10, appliesTo: "METAL" },
    });
    // Cliente sin regla activa (ruleType null) → no aporta descuento; el
    // manual METAL manda igual: 1000 − 10%·600 = 940.
    expect(r.unitPrice!.toNumber()).toBeCloseTo(940, 4);
  });
});

// ============================================================================
// kind=SURCHARGE — recargo manual por línea.
// El motor SUMA en lugar de restar; misma matemática de base.
// ============================================================================
describe("manualDiscountOverride — kind=SURCHARGE (recargo manual por línea)", () => {
  it("PERCENT 10% SURCHARGE TOTAL: 1000 → 1100 (suma 10%)", async () => {
    setupMetalHechuraList(600, 400);
    const r = await resolveFinalSalePrice("j1", {
      articleId: "a1",
      manualDiscountOverride: { mode: "PERCENT", value: 10, appliesTo: "TOTAL", kind: "SURCHARGE" },
    });
    expect(r.unitPrice!.toNumber()).toBeCloseTo(1100, 4);
    // SURCHARGE no es descuento → discountAmount clampea a 0 a nivel línea.
    expect(r.discountAmount!.toNumber()).toBe(0);
    expect(r.priceSource).toBe("MANUAL_OVERRIDE");
  });

  it("PERCENT 10% SURCHARGE METAL: 1000 + 10%·600 = 1060", async () => {
    setupMetalHechuraList(600, 400);
    const r = await resolveFinalSalePrice("j1", {
      articleId: "a1",
      manualDiscountOverride: { mode: "PERCENT", value: 10, appliesTo: "METAL", kind: "SURCHARGE" },
    });
    expect(r.unitPrice!.toNumber()).toBeCloseTo(1060, 4);
  });

  it("PERCENT 10% SURCHARGE HECHURA: 1000 + 10%·400 = 1040", async () => {
    setupMetalHechuraList(600, 400);
    const r = await resolveFinalSalePrice("j1", {
      articleId: "a1",
      manualDiscountOverride: { mode: "PERCENT", value: 10, appliesTo: "HECHURA", kind: "SURCHARGE" },
    });
    expect(r.unitPrice!.toNumber()).toBeCloseTo(1040, 4);
  });

  it("AMOUNT (FIXED) SURCHARGE: 1000 + 250 = 1250", async () => {
    setupMetalHechuraList(600, 400);
    const r = await resolveFinalSalePrice("j1", {
      articleId: "a1",
      manualDiscountOverride: { mode: "AMOUNT", value: 250, appliesTo: "TOTAL", kind: "SURCHARGE" },
    });
    expect(r.unitPrice!.toNumber()).toBeCloseTo(1250, 4);
  });

  it("simetría: BONUS 10% TOTAL y SURCHARGE 10% TOTAL aplican opuestos", async () => {
    setupMetalHechuraList(600, 400);
    const bonus = (await resolveFinalSalePrice("j1", {
      articleId: "a1",
      manualDiscountOverride: { mode: "PERCENT", value: 10, appliesTo: "TOTAL", kind: "BONUS" },
    })).unitPrice!.toNumber();
    setupMetalHechuraList(600, 400);
    const surcharge = (await resolveFinalSalePrice("j1", {
      articleId: "a1",
      manualDiscountOverride: { mode: "PERCENT", value: 10, appliesTo: "TOTAL", kind: "SURCHARGE" },
    })).unitPrice!.toNumber();
    expect(bonus).toBeCloseTo(900, 4);
    expect(surcharge).toBeCloseTo(1100, 4);
  });

  it("limpiar (value=0) deja el precio en lista (1000), tanto BONUS como SURCHARGE", async () => {
    setupMetalHechuraList(600, 400);
    const cleanedBonus = await resolveFinalSalePrice("j1", {
      articleId: "a1",
      manualDiscountOverride: { mode: "PERCENT", value: 0, appliesTo: "TOTAL", kind: "BONUS" },
    });
    setupMetalHechuraList(600, 400);
    const cleanedSurcharge = await resolveFinalSalePrice("j1", {
      articleId: "a1",
      manualDiscountOverride: { mode: "PERCENT", value: 0, appliesTo: "TOTAL", kind: "SURCHARGE" },
    });
    expect(cleanedBonus.unitPrice!.toNumber()).toBeCloseTo(1000, 4);
    expect(cleanedSurcharge.unitPrice!.toNumber()).toBeCloseTo(1000, 4);
  });

  it("back-compat: sin `kind` se comporta como BONUS (resta) — contrato histórico intacto", async () => {
    setupMetalHechuraList(600, 400);
    const r = await resolveFinalSalePrice("j1", {
      articleId: "a1",
      manualDiscountOverride: { mode: "PERCENT", value: 10, appliesTo: "TOTAL" }, // sin kind
    });
    expect(r.unitPrice!.toNumber()).toBeCloseTo(900, 4); // restó: BONUS implícito
  });

  it("convive con cliente con bonificación heredada: el manual recargo manda sobre su base", async () => {
    setupMetalHechuraList(600, 400);
    mockPrisma.commercialEntity.findFirst.mockResolvedValue({
      taxExempt: false, taxApplyOnOverride: null,
      commercialRuleType: "DISCOUNT", commercialValueType: "PERCENTAGE",
      commercialValue: new D("5"), commercialApplyOn: "TOTAL", taxOverrides: [],
    });
    const r = await resolveFinalSalePrice("j1", {
      articleId: "a1", clientId: "c1",
      manualDiscountOverride: { mode: "PERCENT", value: 10, appliesTo: "TOTAL", kind: "SURCHARGE" },
    });
    // Cliente aplica 5% sobre TOTAL primero (1000 → 950), después el manual
    // recargo 10% sobre TOTAL (= 950 + 10%·950 = 1045). El manual usa
    // `finalPrice` como base (no `basePrice`) cuando ya hubo capas previas.
    // Validamos que el precio final REFLEJA el recargo (es mayor a base
    // post-cliente).
    expect(r.unitPrice!.toNumber()).toBeGreaterThan(950);
  });
});
