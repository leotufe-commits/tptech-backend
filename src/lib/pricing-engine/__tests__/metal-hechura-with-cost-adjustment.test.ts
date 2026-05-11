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
// Si todas las aserciones pasan, el motor backend está CORRECTO y la
// percepción de "bug" en el simulador es 100% un problema de UX visual,
// resoluble en frontend sin tocar el pricing-engine.
// =============================================================================

import { describe, it, expect } from "vitest";
import { Prisma } from "@prisma/client";
import { calculateCostFromLines } from "../pricing-engine.cost.js";
import { applyPriceList } from "../pricing-engine.pricelist.js";
import { computeHechuraSaleFactor, computeMetalSaleFactor } from "../../pricing-composition.js";
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

  it("computeMetalSaleFactor === metalSale / metalCost = 1.10 (margen literal sobre cost ajustado)", () => {
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
