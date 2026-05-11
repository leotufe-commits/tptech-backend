// src/lib/__tests__/pricing-composition-line-sale.test.ts
// =============================================================================
// F1.5 #A+ — sale-side per fila para HECHURA / PRODUCT / SERVICE.
//
// Verifica:
//   1. lineSale per fila == lineCost × hechuraSaleFactor (passthrough exacto).
//   2. Σ lineSale (products + services + hechuras) === hechuraSale del breakdown.
//   3. Sin hechuraMarginPct (lista MARGIN_TOTAL sin desglose) → lineSale = null.
//   4. Con ajuste global de costo (BONUS/SURCHARGE), el factor lo incluye.
//   5. Snapshot legacy sin lineSale → frontend cae a "—" (cubierto en grid test).
// =============================================================================

import { describe, it, expect } from "vitest";
import { Prisma } from "@prisma/client";
import {
  extractCompositionHechuras,
  extractCompositionItems,
  extractCompositionMetals,
  computeHechuraSaleFactor,
  computeMetalSaleFactor,
} from "../pricing-composition.js";
import type { PricingStep } from "../pricing-engine/pricing-engine.js";
import type { SalePriceResult } from "../pricing-engine/pricing-engine.types.js";

const D = Prisma.Decimal;

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

function step(
  key: PricingStep["key"],
  value: number,
  meta: Record<string, unknown> = {},
  label = "Línea",
): PricingStep {
  return { key, label, status: "ok", value: new D(value), meta } as PricingStep;
}

function buildResult(args: {
  steps: PricingStep[];
  hechuraMarginPct: number | null;
  hechuraCost: number;
  hechuraSale: number;
  metalCost?: number;
  metalSale?: number;
  metalMarginPct?: number;
}): SalePriceResult {
  return {
    steps: args.steps,
    metalHechuraBreakdown: args.hechuraMarginPct == null ? null : {
      metalCost: args.metalCost ?? 0,
      metalSale: args.metalSale ?? 0,
      metalMarginPct: args.metalMarginPct ?? 0,
      hechuraCost: args.hechuraCost,
      hechuraSale: args.hechuraSale,
      hechuraMarginPct: args.hechuraMarginPct,
    } as any,
  } as unknown as SalePriceResult;
}

// =============================================================================
// 1. Passthrough exacto: lineSale = lineCost × (1 + margin/100)
// =============================================================================

describe("F1.5 #A+ — lineSale passthrough", () => {
  it("PRODUCT con margen 100% → lineSale = 2 × lineCost", () => {
    const steps = [
      step("COST_LINES_PRODUCT", 100, { qty: "1", unitValue: "100" }, "Piedra"),
    ];
    const factor = 1 + 100 / 100; // 2
    const [item] = extractCompositionItems(steps, "COST_LINES_PRODUCT", undefined, factor);
    expect(item.lineSale).toBe(200);
  });

  it("SERVICE con margen 50% → lineSale = 1.5 × lineCost", () => {
    const steps = [
      step("COST_LINES_SERVICE", 80, { qty: "1", unitValue: "80" }, "Engaste"),
    ];
    const [item] = extractCompositionItems(steps, "COST_LINES_SERVICE", undefined, 1.5);
    expect(item.lineSale).toBe(120);
  });

  it("HECHURA con factor null → lineSale null (no derivable)", () => {
    const steps = [
      step("COST_LINES_HECHURA", 200, { qty: "1", unitValue: "200" }, "Mano de obra"),
    ];
    const [item] = extractCompositionHechuras(steps, null);
    expect(item.lineSale).toBeNull();
  });

  it("PRODUCT con factor null → lineSale null", () => {
    const steps = [
      step("COST_LINES_PRODUCT", 100, { qty: "1", unitValue: "100" }, "X"),
    ];
    const [item] = extractCompositionItems(steps, "COST_LINES_PRODUCT", undefined, null);
    expect(item.lineSale).toBeNull();
  });
});

// =============================================================================
// 2. Paridad agregada: Σ lineSale === hechuraSale
// =============================================================================

describe("F1.5 #A+ — paridad agregada", () => {
  it("Σ products + services + hechuras lineSale === hechuraSale (sin ajuste global)", () => {
    // hechuraCost = 100 + 80 + 200 = 380. Margen 50% → hechuraSale = 570.
    const steps = [
      step("COST_LINES_PRODUCT", 100, { qty: "1", unitValue: "100" }, "P"),
      step("COST_LINES_SERVICE", 80,  { qty: "1", unitValue: "80"  }, "S"),
      step("COST_LINES_HECHURA", 200, { qty: "1", unitValue: "200" }, "H"),
    ];
    const factor = 1.5; // margen 50%
    const products = extractCompositionItems(steps, "COST_LINES_PRODUCT", undefined, factor);
    const services = extractCompositionItems(steps, "COST_LINES_SERVICE", undefined, factor);
    const hechuras = extractCompositionHechuras(steps, factor);

    const sumLineSale =
      products.reduce((acc, x) => acc + (x.lineSale ?? 0), 0) +
      services.reduce((acc, x) => acc + (x.lineSale ?? 0), 0) +
      hechuras.reduce((acc, x) => acc + (x.lineSale ?? 0), 0);
    expect(Math.abs(sumLineSale - 570)).toBeLessThan(0.001);
  });

  it("Paridad se mantiene con ajuste global de costo (BONUS PERCENTAGE 10%)", () => {
    // Líneas: 100 + 200 = 300. Adjusted: 270 (10% BONUS). adjFactor=0.9.
    // Margen 50% → hechuraSale = 270 × 1.5 = 405.
    const steps = [
      step("COST_LINES_PRODUCT", 100, { qty: "1", unitValue: "100" }, "P"),
      step("COST_LINES_HECHURA", 200, { qty: "1", unitValue: "200" }, "H"),
      step("COST_LINES_FINAL", 270, {
        adjustmentKind: "BONUS",
        adjustmentType: "PERCENTAGE",
        adjustmentValue: "10",
        sumLines: "300",
      }, "Total"),
    ];
    const result = buildResult({
      steps,
      hechuraMarginPct: 50,
      hechuraCost: 270,
      hechuraSale: 405,
    });
    const factor = computeHechuraSaleFactor(result);
    expect(factor).toBeCloseTo(0.9 * 1.5, 6); // = 1.35

    const products = extractCompositionItems(steps, "COST_LINES_PRODUCT", undefined, factor);
    const hechuras = extractCompositionHechuras(steps, factor);
    const sum = products.reduce((a, x) => a + (x.lineSale ?? 0), 0)
              + hechuras.reduce((a, x) => a + (x.lineSale ?? 0), 0);
    expect(Math.abs(sum - 405)).toBeLessThan(0.001);
  });
});

// =============================================================================
// 3. computeHechuraSaleFactor — derivación
// =============================================================================

describe("F1.5 #A+ — computeHechuraSaleFactor", () => {
  it("Sin breakdown → null", () => {
    const res = buildResult({
      steps: [],
      hechuraMarginPct: null,
      hechuraCost: 0, hechuraSale: 0,
    });
    expect(computeHechuraSaleFactor(res)).toBeNull();
  });

  it("Con margen y sin ajuste global → factor = 1 + margin/100", () => {
    const res = buildResult({
      steps: [],
      hechuraMarginPct: 25,
      hechuraCost: 100, hechuraSale: 125,
    });
    expect(computeHechuraSaleFactor(res)).toBeCloseTo(1.25, 6);
  });

  it("Sin COST_LINES_FINAL step → adjFactor=1 implícito", () => {
    const res = buildResult({
      steps: [
        step("COST_LINES_PRODUCT", 50, {}, "P"),
      ],
      hechuraMarginPct: 100,
      hechuraCost: 50, hechuraSale: 100,
    });
    expect(computeHechuraSaleFactor(res)).toBeCloseTo(2, 6);
  });
});

// =============================================================================
// 4. Retrocompat: extractors sin parámetro factor (callers viejos)
// =============================================================================

describe("F1.5 #A+ — retrocompat callers viejos", () => {
  it("extractCompositionItems sin 4to arg → lineSale=null (no rompe)", () => {
    const steps = [
      step("COST_LINES_PRODUCT", 100, { qty: "1", unitValue: "100" }, "X"),
    ];
    const [item] = extractCompositionItems(steps, "COST_LINES_PRODUCT");
    expect(item.lineSale).toBeNull();
    expect(item.totalValue).toBe(100);
  });

  it("extractCompositionHechuras sin 2do arg → lineSale=null", () => {
    const steps = [
      step("COST_LINES_HECHURA", 50, { qty: "1", unitValue: "50" }, "H"),
    ];
    const [item] = extractCompositionHechuras(steps);
    expect(item.lineSale).toBeNull();
    expect(item.lineCost).toBe(50);
  });

  it("extractCompositionMetals sin 3er arg → lineSale=null", () => {
    const steps = [
      step("COST_LINES_METAL", 100, { qty: "2", unitValue: "50", variantId: "mv-1" }, "Oro 18k"),
    ];
    const [item] = extractCompositionMetals(steps);
    expect(item.lineSale).toBeNull();
    expect(item.lineCost).toBe(100);
  });
});

// =============================================================================
// 5. F1.5 #A++ — METAL lineSale (passthrough metalSale/metalCost)
// =============================================================================

describe("F1.5 #A++ — METAL lineSale passthrough", () => {
  it("Una sola fila METAL: lineSale === metalSale del breakdown", () => {
    // metalCost=300, metalSale=600 → factor=2. lineSale = 300×2 = 600.
    const steps = [
      step("COST_LINES_METAL", 300, { qty: "5", unitValue: "60", variantId: "mv-1" }, "Oro 18k"),
    ];
    const result = buildResult({
      steps,
      hechuraMarginPct: 0, hechuraCost: 0, hechuraSale: 0,
      metalCost: 300, metalSale: 600, metalMarginPct: 100,
    });
    const factor = computeMetalSaleFactor(result);
    expect(factor).toBe(2);

    const [item] = extractCompositionMetals(steps, undefined, factor);
    expect(item.lineSale).toBe(600);
  });

  it("Múltiples filas METAL (4 metales): Σ lineSale === metalSale", () => {
    // Reproduce el caso del usuario: Oro 18k / 22k / 24k / Chafalonia 18k.
    // metalCost = 300+275+100+125 = 800. metalSale = 1200 (margen 50%).
    const steps = [
      step("COST_LINES_METAL", 300, { qty: "5", unitValue: "60",  variantId: "mv-18" }, "Oro 18k"),
      step("COST_LINES_METAL", 275, { qty: "3", unitValue: "91.66", variantId: "mv-22" }, "Oro 22k"),
      step("COST_LINES_METAL", 100, { qty: "1", unitValue: "100", variantId: "mv-24" }, "Oro 24k"),
      step("COST_LINES_METAL", 125, { qty: "1", unitValue: "125", variantId: "mv-cha" }, "Chafalonia 18k"),
    ];
    const result = buildResult({
      steps,
      hechuraMarginPct: 0, hechuraCost: 0, hechuraSale: 0,
      metalCost: 800, metalSale: 1200, metalMarginPct: 50,
    });
    const factor = computeMetalSaleFactor(result);
    expect(factor).toBeCloseTo(1.5, 6);

    const metals = extractCompositionMetals(steps, undefined, factor);
    expect(metals).toHaveLength(4);
    // Sale-side individual:
    expect(metals[0].lineSale).toBeCloseTo(450, 3);  // Oro 18k:  300×1.5
    expect(metals[1].lineSale).toBeCloseTo(412.5, 3); // Oro 22k:  275×1.5
    expect(metals[2].lineSale).toBeCloseTo(150, 3);  // Oro 24k:  100×1.5
    expect(metals[3].lineSale).toBeCloseTo(187.5, 3); // Chafa:    125×1.5
    // Paridad agregada:
    const sum = metals.reduce((acc, m) => acc + (m.lineSale ?? 0), 0);
    expect(Math.abs(sum - 1200)).toBeLessThan(0.001);
  });

  it("computeMetalSaleFactor: sin breakdown → null", () => {
    const res = buildResult({
      steps: [], hechuraMarginPct: null, hechuraCost: 0, hechuraSale: 0,
    });
    expect(computeMetalSaleFactor(res)).toBeNull();
  });

  it("computeMetalSaleFactor: metalCost=0 → null (división indefinida)", () => {
    const res = buildResult({
      steps: [], hechuraMarginPct: 0, hechuraCost: 0, hechuraSale: 0,
      metalCost: 0, metalSale: 0,
    });
    expect(computeMetalSaleFactor(res)).toBeNull();
  });

  it("Margen uniforme entre cost-lines: cada metal.lineSale/lineCost === metalMarginPct/100 + 1", () => {
    // El motor aplica un único metalMarginPct al bucket completo; cada fila
    // debe tener exactamente ese factor (no márgenes per-variante hoy).
    const steps = [
      step("COST_LINES_METAL", 100, { qty: "1", unitValue: "100", variantId: "mv-a" }, "Plata 925"),
      step("COST_LINES_METAL", 300, { qty: "3", unitValue: "100", variantId: "mv-b" }, "Plata 925"),
    ];
    const result = buildResult({
      steps,
      hechuraMarginPct: 0, hechuraCost: 0, hechuraSale: 0,
      metalCost: 400, metalSale: 1000, metalMarginPct: 150,
    });
    const factor = computeMetalSaleFactor(result);
    const metals = extractCompositionMetals(steps, undefined, factor);

    // Margen por fila = (sale - cost) / cost. Debe ser 150% en ambas.
    metals.forEach(m => {
      const margenPct = ((m.lineSale! - m.lineCost!) / m.lineCost!) * 100;
      expect(margenPct).toBeCloseTo(150, 3);
    });
  });
});
