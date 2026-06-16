// src/lib/pricing-engine/__tests__/metal-hechura-with-cost-adjustment.test.ts
// =============================================================================
// DIAGNÓSTICO — Fase 1.
//
// Caso del usuario:
//   · Lista METAL_HECHURA con marginMetal=10, marginHechura=50.
//   · Artículo con cost lines de los 4 tipos (METAL/HECHURA/PRODUCT/SERVICE).
//   · Article.manualAdjustment = BONUS PERCENTAGE 25%.
//
// Expectativas del usuario:
//   · metalMarginPct === 10 (literal de la lista, no modificado por el ajuste).
//   · hechuraMarginPct === 50 (literal).
//   · PRODUCT y SERVICE caen dentro del bucket HECHURA (cost.ts:334-336).
//   · metalSale = (metalCost post-ajuste) × 1.10.
//   · hechuraSale = (hechuraCost post-ajuste) × 1.50.
//   · Factor efectivo visible al usuario = adjFactor × (1 + marginHechura/100)
//     = 0.75 × 1.50 = 1.125 ≈ 1.13 (esto explica el "1.13" reportado).
//   · No hay factor global único en mode METAL_HECHURA: cada bucket usa su
//     margen literal.
//
// ⚠️ REVISIÓN 2026-06-12 — La conclusión "el bug es 100% UX frontend" quedó
// SUPERSEDIDA. Auditoría posterior detectó que el factor de venta PER-LÍNEA del
// METAL (`computeMetalSaleFactor = metalSale/metalCost`, ambos POST) NO incluía
// `adjFactor`, mientras `metals[i].lineCost` es PRE → `Σ lineSale_metal ≠
// metalSale` (invariante violado) y el margen del metal no reflejaba el ajuste
// global, asimétrico con HECHURA/PRODUCT/SERVICE. Fix backend mínimo aplicado:
// los factores del metal multiplican `adjFactor` (helper `extractGlobalCost
// AdjFactor`), igual que `computeHechuraSaleFactor`. Solo cambia el sale-side
// per-línea de display; agregados/totales/snapshots/redondeo intactos. Tests
// del fix en el bloque "6. FIX BACKEND" al final del archivo.
// =============================================================================

import { describe, it, expect } from "vitest";
import { Prisma } from "@prisma/client";
import { calculateCostFromLines } from "../pricing-engine.cost.js";
import { applyPriceList } from "../pricing-engine.pricelist.js";
import {
  computeHechuraSaleFactor,
  computeMetalSaleFactor,
  computeMetalSaleFactorPre,
  extractGlobalCostAdjFactor,
  extractCompositionMetals,
} from "../../pricing-composition.js";
import type {
  CostLineInput,
  BatchCostContext,
  SalePriceResult,
} from "../pricing-engine.types.js";

const D = (v: number | string) => new Prisma.Decimal(String(v));

// ─────────────────────────────────────────────────────────────────────────────
// Helpers — armado del contexto sin DB
// ─────────────────────────────────────────────────────────────────────────────

function makeCtx(): BatchCostContext {
  return {
    baseCurrencyId: "base-1",
    defaultMermaPercent: "0",
    // 1 variante metal: precio=100/g, saleFactor=1, purity=0.75 (no afecta cost).
    metalVariantData: new Map([
      ["mv-1", { price: D(100), saleFactor: D(1), purity: D("0.75") }],
    ]),
    rateMap: new Map(),
    articleMetalVariantsMap: new Map(),
  };
}

function makePriceList(overrides: Record<string, any> = {}) {
  return {
    id:               "pl-1",
    name:             "Lista Test",
    mode:             "METAL_HECHURA",
    marginTotal:      null,
    marginMetal:      "10",
    marginHechura:    "50",
    costPerGram:      null,
    surcharge:        null,
    minimumPrice:     null,
    roundingTarget:   "NONE",
    roundingMode:     "NONE",
    roundingDirection:"NEAREST",
    validFrom:        null,
    validTo:          null,
    isActive:         true,
    ...overrides,
  };
}

// 4 cost lines representativas del caso:
//   METAL:    5g × 100/g = 500
//   HECHURA:  1 × 200    = 200
//   PRODUCT:  1 × 150    = 150
//   SERVICE:  1 × 100    = 100
// Total cruda = 950.
// Con BONUS 25%: adjusted = 950 × 0.75 = 712.5  → adjFactor = 0.75.
// metalCost post   = 500 × 0.75 = 375.
// hechuraCost post = 450 × 0.75 = 337.5.
function makeLines(): CostLineInput[] {
  return [
    { id: "cl-m1", type: "METAL",   quantity: 5, unitValue: 0,  metalVariantId: "mv-1", mermaPercent: 0 },
    { id: "cl-h1", type: "HECHURA", quantity: 1, unitValue: 200 },
    { id: "cl-p1", type: "PRODUCT", quantity: 1, unitValue: 150, catalogItemId: "art-P" },
    { id: "cl-s1", type: "SERVICE", quantity: 1, unitValue: 100, catalogItemId: "art-S" },
  ];
}

// =============================================================================
// 1. COST ENGINE — adjFactor afecta metalCost y hechuraCost por igual
// =============================================================================

describe("DIAGNÓSTICO — cost engine aplica adjFactor antes de la lista", () => {
  it("BONUS 25% sobre cost lines → metalCost/hechuraCost devueltos × 0.75", async () => {
    const cost = await calculateCostFromLines(
      "j-1", makeLines(),
      { kind: "BONUS", type: "PERCENTAGE", value: "25" },
      makeCtx(),
    );

    expect(cost.value!.toNumber()).toBeCloseTo(712.5, 4);
    expect(cost.metalCost!.toNumber()).toBeCloseTo(375, 4);     // 500 × 0.75
    expect(cost.hechuraCost!.toNumber()).toBeCloseTo(337.5, 4); // 450 × 0.75

    // PRODUCT y SERVICE están dentro del bucket hechura (no metal).
    // 337.5 = 0.75 × (200 HECHURA + 150 PRODUCT + 100 SERVICE) ✓
    expect(cost.partial).toBe(false);
  });

  it("Sin ajuste global → metalCost/hechuraCost === cost crudo", async () => {
    const cost = await calculateCostFromLines(
      "j-1", makeLines(),
      undefined,           // sin adjustment
      makeCtx(),
    );
    expect(cost.value!.toNumber()).toBeCloseTo(950, 4);
    expect(cost.metalCost!.toNumber()).toBeCloseTo(500, 4);
    expect(cost.hechuraCost!.toNumber()).toBeCloseTo(450, 4);
  });
});

// =============================================================================
// 2. PRICE LIST — METAL_HECHURA aplica marginMetal y marginHechura literales
// =============================================================================

describe("DIAGNÓSTICO — METAL_HECHURA preserva márgenes literales con adjFactor", () => {
  it("Caso del usuario: marginMetal=10, marginHechura=50, BONUS 25% sobre cost", async () => {
    const cost = await calculateCostFromLines(
      "j-1", makeLines(),
      { kind: "BONUS", type: "PERCENTAGE", value: "25" },
      makeCtx(),
    );
    const pl = makePriceList({ marginMetal: "10", marginHechura: "50" });

    // applyPriceList recibe los costos POST-ajuste y aplica margenes LITERALES.
    const result = applyPriceList(pl as any, {
      value:       cost.value,
      metalCost:   cost.metalCost ?? null,
      hechuraCost: cost.hechuraCost ?? null,
    });

    // Sale = costo post-ajuste × (1 + margenLiteral / 100)
    expect(result.metalHechuraDetail).not.toBeNull();
    const mh = result.metalHechuraDetail!;

    // metalSale = 375 × 1.10 = 412.5
    expect(mh.metalCost).toBeCloseTo(375, 4);
    expect(mh.metalSale).toBeCloseTo(412.5, 4);
    // hechuraSale = 337.5 × 1.50 = 506.25
    expect(mh.hechuraCost).toBeCloseTo(337.5, 4);
    expect(mh.hechuraSale).toBeCloseTo(506.25, 4);

    // Márgenes LITERALES de la lista — NO modificados por el ajuste de costo.
    expect(mh.metalMarginPct).toBe(10);
    expect(mh.hechuraMarginPct).toBe(50);

    // Total = 412.5 + 506.25 = 918.75
    expect(result.value!.toNumber()).toBeCloseTo(918.75, 4);
  });

  it("Sin ajuste de costo: factor visible coincide con margen bruto (1.10 / 1.50)", async () => {
    const cost = await calculateCostFromLines(
      "j-1", makeLines(),
      undefined,
      makeCtx(),
    );
    const pl = makePriceList({ marginMetal: "10", marginHechura: "50" });
    const result = applyPriceList(pl as any, {
      value: cost.value, metalCost: cost.metalCost ?? null, hechuraCost: cost.hechuraCost ?? null,
    });
    const mh = result.metalHechuraDetail!;
    // metalSale / metalCost = 550 / 500 = 1.10
    expect(mh.metalSale / mh.metalCost).toBeCloseTo(1.10, 4);
    // hechuraSale / hechuraCost = 675 / 450 = 1.50
    expect(mh.hechuraSale / mh.hechuraCost).toBeCloseTo(1.50, 4);
  });
});

// =============================================================================
// 3. FACTOR EFECTIVO — origen del "1.13" reportado por el usuario
// =============================================================================

describe("DIAGNÓSTICO — factor efectivo en hechura cuando hay adjFactor", () => {
  it("computeHechuraSaleFactor === adjFactor × (1 + marginHechura/100)", () => {
    // SalePriceResult sintético reproduciendo el caso del usuario:
    //   · adjFactor = 0.75 (BONUS 25%)
    //   · marginHechura = 50 → factor margen = 1.50
    //   · factor efectivo esperado = 0.75 × 1.50 = 1.125 ≈ 1.13
    const result: SalePriceResult = {
      steps: [
        {
          key:    "COST_LINES_FINAL",
          label:  "Total líneas de costo (con ajuste)",
          status: "ok",
          value:  712.5,
          meta:   { sumLines: "950" },
        } as any,
      ],
      metalHechuraBreakdown: {
        metalCost:        375,
        metalSale:        412.5,
        metalMarginPct:   10,
        hechuraCost:      337.5,
        hechuraSale:      506.25,
        hechuraMarginPct: 50,
      } as any,
    } as unknown as SalePriceResult;

    const factor = computeHechuraSaleFactor(result);
    expect(factor).toBeCloseTo(1.125, 4);
    // Explícitamente: NO es 1.50 (margen bruto) ni 1.0 + (50 × adjFactor)/100.
    expect(factor).not.toBeCloseTo(1.50, 1);
  });

  it("computeMetalSaleFactor SIN step COST_LINES_FINAL (adjFactor=1) === metalSale/metalCost = 1.10", () => {
    // Sin el step, no hay ajuste detectable → adjFactor=1 → factor = 1.10.
    // (El caso CON ajuste se valida en el bloque "6. FIX BACKEND".)
    const result: SalePriceResult = {
      steps: [],
      metalHechuraBreakdown: {
        metalCost: 375, metalSale: 412.5, metalMarginPct: 10,
        hechuraCost: 337.5, hechuraSale: 506.25, hechuraMarginPct: 50,
      } as any,
    } as unknown as SalePriceResult;

    const factor = computeMetalSaleFactor(result);
    // metalSale / metalCost = 412.5 / 375 = 1.10
    expect(factor).toBeCloseTo(1.10, 4);
  });

  it("Sin adjustment: factor hechura === margen bruto (1.50)", () => {
    const result: SalePriceResult = {
      steps: [
        { key: "COST_LINES_FINAL", value: 950, meta: { sumLines: "950" } } as any,
      ],
      metalHechuraBreakdown: {
        metalCost: 500, metalSale: 550, metalMarginPct: 10,
        hechuraCost: 450, hechuraSale: 675, hechuraMarginPct: 50,
      } as any,
    } as unknown as SalePriceResult;

    const factor = computeHechuraSaleFactor(result);
    expect(factor).toBeCloseTo(1.50, 4);
  });
});

// =============================================================================
// 4. PARIDAD AGREGADA — no hay factor global único en METAL_HECHURA
// =============================================================================

describe("DIAGNÓSTICO — METAL_HECHURA no usa factor global único", () => {
  it("metalSale + hechuraSale ≠ totalCost × algún_factor_único", async () => {
    const cost = await calculateCostFromLines(
      "j-1", makeLines(),
      { kind: "BONUS", type: "PERCENTAGE", value: "25" },
      makeCtx(),
    );
    const pl = makePriceList({ marginMetal: "10", marginHechura: "50" });
    const result = applyPriceList(pl as any, {
      value: cost.value, metalCost: cost.metalCost ?? null, hechuraCost: cost.hechuraCost ?? null,
    });
    const mh = result.metalHechuraDetail!;

    // Si existiera un único factor global, sería result.value / cost.value.
    const supposedGlobal = result.value!.toNumber() / cost.value!.toNumber();
    // metalSale / metalCost (1.10) ≠ supposedGlobal
    expect(Math.abs(mh.metalSale / mh.metalCost - supposedGlobal)).toBeGreaterThan(0.05);
    // hechuraSale / hechuraCost (1.50) ≠ supposedGlobal
    expect(Math.abs(mh.hechuraSale / mh.hechuraCost - supposedGlobal)).toBeGreaterThan(0.05);

    // El supposedGlobal queda en algún valor intermedio (no es ni 1.10 ni 1.50).
    expect(supposedGlobal).toBeGreaterThan(1.10);
    expect(supposedGlobal).toBeLessThan(1.50);
  });

  it("Total POST = metalSale + hechuraSale (no recálculo)", async () => {
    const cost = await calculateCostFromLines(
      "j-1", makeLines(),
      { kind: "BONUS", type: "PERCENTAGE", value: "25" },
      makeCtx(),
    );
    const pl = makePriceList({ marginMetal: "10", marginHechura: "50" });
    const result = applyPriceList(pl as any, {
      value: cost.value, metalCost: cost.metalCost ?? null, hechuraCost: cost.hechuraCost ?? null,
    });
    const mh = result.metalHechuraDetail!;

    expect(result.value!.toNumber()).toBeCloseTo(mh.metalSale + mh.hechuraSale, 2);
  });
});

// =============================================================================
// 5. CONFIRMACIÓN FINAL — el motor está CORRECTO; el 1.13 es real
// =============================================================================

describe("DIAGNÓSTICO — confirmación: motor backend es la fuente de verdad", () => {
  it("El '1.13' visible al usuario coincide con la fórmula del motor", async () => {
    const cost = await calculateCostFromLines(
      "j-1", makeLines(),
      { kind: "BONUS", type: "PERCENTAGE", value: "25" },
      makeCtx(),
    );
    const pl = makePriceList({ marginMetal: "10", marginHechura: "50" });
    const priceResult = applyPriceList(pl as any, {
      value: cost.value, metalCost: cost.metalCost ?? null, hechuraCost: cost.hechuraCost ?? null,
    });

    // Construir un SalePriceResult mínimo para computeHechuraSaleFactor.
    const sale: SalePriceResult = {
      steps: cost.steps as any,
      metalHechuraBreakdown: {
        metalCost: priceResult.metalHechuraDetail!.metalCost,
        metalSale: priceResult.metalHechuraDetail!.metalSale,
        metalMarginPct: 10,
        hechuraCost: priceResult.metalHechuraDetail!.hechuraCost,
        hechuraSale: priceResult.metalHechuraDetail!.hechuraSale,
        hechuraMarginPct: 50,
      } as any,
    } as unknown as SalePriceResult;

    const factorEfectivo = computeHechuraSaleFactor(sale);

    // El factor efectivo (1.125) = adjFactor (0.75) × margen bruto (1.50).
    expect(factorEfectivo).toBeCloseTo(1.125, 4);

    // Y se redondea a "1.13" cuando se muestra con 2 decimales (lo que ve el usuario).
    expect(factorEfectivo!.toFixed(2)).toBe("1.13");

    // Pero el margen BRUTO de la lista sigue siendo 50% (eso es lo que el
    // operador configuró). Confirma que la causa raíz es la presentación,
    // no el cálculo.
    expect(sale.metalHechuraBreakdown!.hechuraMarginPct).toBe(50);
  });
});

// =============================================================================
// 6. FIX BACKEND (2026-06-12) — METAL incluye adjFactor igual que HECHURA
//
// REVISIÓN del diagnóstico anterior: el factor del METAL `metalSale/metalCost`
// cancelaba el adjFactor (ambos POST), pero `metals[i].lineCost` es PRE → el
// `lineSale` per-línea NO incluía el ajuste global → `Σ lineSale ≠ metalSale`
// y el margen del metal no reflejaba la bonif/recargo (asimétrico con hechura).
// Fix: `computeMetalSaleFactor`/`Pre` ahora multiplican por `adjFactor`.
// =============================================================================
describe("FIX BACKEND — computeMetalSaleFactor incluye el Ajuste Global", () => {
  // adjFactor 0.75 (BONUS 25%): COST_LINES_FINAL value/sumLines = 712.5/950.
  const stepFinal = { key: "COST_LINES_FINAL", value: 712.5, meta: { sumLines: "950" } } as any;
  // metalCost POST 375 (= PRE 500 × 0.75); metalSale 412.5 (= 375 × 1.10).
  const brk = { metalCost: 375, metalSale: 412.5, metalMarginPct: 10,
                hechuraCost: 337.5, hechuraSale: 506.25, hechuraMarginPct: 50,
                metalSalePreRounding: 412.5 } as any;
  const withAdj: SalePriceResult = { steps: [stepFinal], metalHechuraBreakdown: brk } as any;

  it("extractGlobalCostAdjFactor lee adjFactor de COST_LINES_FINAL (0.75); sin step → 1", () => {
    expect(extractGlobalCostAdjFactor(withAdj)).toBeCloseTo(0.75, 6);
    expect(extractGlobalCostAdjFactor({ steps: [], metalHechuraBreakdown: brk } as any)).toBe(1);
  });

  it("computeMetalSaleFactor = (metalSale/metalCost) × adjFactor = 1.10 × 0.75 = 0.825", () => {
    expect(computeMetalSaleFactor(withAdj)).toBeCloseTo(0.825, 4);
    // Espejo de hechura: ambos multiplican adjFactor.
    expect(computeHechuraSaleFactor(withAdj)).toBeCloseTo(0.75 * 1.5, 4); // 1.125
  });

  it("computeMetalSaleFactorPre también incluye adjFactor", () => {
    expect(computeMetalSaleFactorPre(withAdj)).toBeCloseTo(0.825, 4);
  });

  it("INVARIANTE restaurado: Σ metals[i].lineSale === metalSale (con ajuste global)", () => {
    // Una cost-line METAL con lineCost PRE = 500 (= metalCost_PRE).
    const result: SalePriceResult = {
      steps: [
        stepFinal,
        { key: "COST_LINES_METAL", status: "ok", value: 500,
          meta: { variantId: "mv-1", qty: 5, merma: 0, costLineId: "cl-m1", metalId: "oro" } } as any,
      ],
      metalHechuraBreakdown: brk,
    } as any;
    const metals = extractCompositionMetals(
      result.steps, undefined,
      computeMetalSaleFactor(result), computeMetalSaleFactorPre(result),
    );
    expect(metals).toHaveLength(1);
    // lineSale = 500 × 0.825 = 412.5 === metalSale agregado.
    expect(metals[0].lineSale).toBeCloseTo(412.5, 2);
    const sumLineSale = metals.reduce((s, m) => s + (m.lineSale ?? 0), 0);
    expect(sumLineSale).toBeCloseTo(brk.metalSale, 2);
    // lineSalePreRounding idem.
    expect(metals[0].lineSalePreRounding).toBeCloseTo(412.5, 2);
  });

  it("Margen visual del metal refleja el ajuste, igual que hechura", () => {
    // Margen visual = (lineSale − lineCost_PRE) / lineCost_PRE.
    // METAL:   (412.5 − 500)/500   = −17.5%   (bonif 25% > margen metal 10%).
    // HECHURA: (506.25 − 450)/450  = +12.5%   (margen hechura 50% > bonif 25%).
    // Lo clave: AMBOS comparan venta POST contra costo PRE → criterio uniforme.
    const metalFactor   = computeMetalSaleFactor(withAdj)!;   // 0.825
    const hechuraFactor = computeHechuraSaleFactor(withAdj)!; // 1.125
    const metalMargenVisual   = metalFactor - 1;   // −0.175
    const hechuraMargenVisual = hechuraFactor - 1; // +0.125
    expect(metalMargenVisual).toBeCloseTo(-0.175, 4);
    expect(hechuraMargenVisual).toBeCloseTo(0.125, 4);
  });

  it("Sin ajuste global (adjFactor=1) → factor metal = metalSale/metalCost (cero regresión)", () => {
    const noAdj: SalePriceResult = {
      steps: [{ key: "COST_LINES_FINAL", value: 950, meta: { sumLines: "950" } } as any],
      metalHechuraBreakdown: { metalCost: 500, metalSale: 550, metalMarginPct: 10,
                               hechuraCost: 450, hechuraSale: 675, hechuraMarginPct: 50,
                               metalSalePreRounding: 550 } as any,
    } as any;
    expect(computeMetalSaleFactor(noAdj)).toBeCloseTo(1.10, 4);
    expect(computeMetalSaleFactorPre(noAdj)).toBeCloseTo(1.10, 4);
  });

  it("Sin metalHechuraBreakdown (combo / MARGIN_TOTAL) → null (no impacta combos)", () => {
    expect(computeMetalSaleFactor({ steps: [stepFinal] } as any)).toBeNull();
    expect(computeMetalSaleFactorPre({ steps: [stepFinal] } as any)).toBeNull();
  });
});
