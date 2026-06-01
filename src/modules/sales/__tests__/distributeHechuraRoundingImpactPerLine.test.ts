// src/modules/sales/__tests__/distributeHechuraRoundingImpactPerLine.test.ts
// =============================================================================
// Opción A — Tests del distribuidor del impacto monetario del Redondeo
// Comercial PER_DOCUMENT (bucket HECHURA / MONETARIO) a las líneas
// individuales. Espejo de `distributeMetalRoundingImpactPerLine` pero para el
// dominio monetario.
//
// Invariante verificado en TODOS los tests:
//   Σ líneas hechuraRoundingMonetaryImpact[i] === deltaSaldoMonetario
//
// Incluye el caso real de pantalla:
//   Hechura 192.506,46 → 192.500,00 (delta −6,46), 1 línea.
// =============================================================================

import { describe, it, expect } from "vitest";
import {
  distributeHechuraRoundingImpactPerLine,
  distributeMonetarySaldoPostPerLine,
  computeCommercialRoundingPerLineImpacts,
} from "../commercial-doc-rounding-wiring.js";

function sumDistributed(map: Map<number, number>): number {
  let s = 0;
  for (const v of map.values()) s += v;
  return Math.round(s * 100) / 100;
}

describe("distributeHechuraRoundingImpactPerLine — Opción A", () => {
  it("caso real de pantalla: 1 línea, hechura 192.506,46 → 192.500,00 (delta −6,46)", () => {
    const out = distributeHechuraRoundingImpactPerLine({
      deltaSaldoMonetario: -6.46,
      hechuraSaleByLineIdx: new Map([[0, 192506.46]]),
      lineCount: 1,
    });
    expect(out.get(0)).toBeCloseTo(-6.46, 2);
    expect(sumDistributed(out)).toBeCloseTo(-6.46, 2);
  });

  it("delta 0 → Map vacío (no hay impacto que repartir)", () => {
    const out = distributeHechuraRoundingImpactPerLine({
      deltaSaldoMonetario: 0,
      hechuraSaleByLineIdx: new Map([[0, 1000]]),
      lineCount: 1,
    });
    expect(out.size).toBe(0);
  });

  it("múltiples líneas / prorrateo proporcional a hechuraSale × qty", () => {
    // Línea 0 hechura 1000, línea 1 hechura 3000. Total 4000.
    // Delta −8 → línea 0 = −2, línea 1 = −6.
    const out = distributeHechuraRoundingImpactPerLine({
      deltaSaldoMonetario: -8,
      hechuraSaleByLineIdx: new Map([[0, 1000], [1, 3000]]),
      lineCount: 2,
    });
    expect(out.get(0)).toBeCloseTo(-2, 2);
    expect(out.get(1)).toBeCloseTo(-6, 2);
    expect(sumDistributed(out)).toBeCloseTo(-8, 2);
  });

  it("conservación exacta con residuo de redondeo (última línea absorbe)", () => {
    // 3 líneas iguales (100 c/u), delta 1,00 → 0,33 + 0,33 + 0,34.
    const out = distributeHechuraRoundingImpactPerLine({
      deltaSaldoMonetario: 1.0,
      hechuraSaleByLineIdx: new Map([[0, 100], [1, 100], [2, 100]]),
      lineCount: 3,
    });
    expect(sumDistributed(out)).toBeCloseTo(1.0, 2);
    // La última línea absorbe el residuo.
    expect(out.get(2)).toBeCloseTo(0.34, 2);
  });

  it("línea con hechura negativa (componente negativo válido) NO recibe peso negativo", () => {
    // Línea 0 hechura 1000 (peso), línea 1 hechura −500 (excluida del peso).
    // Todo el delta va a la línea 0.
    const out = distributeHechuraRoundingImpactPerLine({
      deltaSaldoMonetario: -4,
      hechuraSaleByLineIdx: new Map([[0, 1000], [1, -500]]),
      lineCount: 2,
    });
    expect(out.get(0)).toBeCloseTo(-4, 2);
    expect(out.get(1) ?? 0).toBeCloseTo(0, 2);
    expect(sumDistributed(out)).toBeCloseTo(-4, 2);
  });

  it("Σ base positiva = 0 (todas las hechuras ≤ 0) → reparto en partes iguales (conservación)", () => {
    const out = distributeHechuraRoundingImpactPerLine({
      deltaSaldoMonetario: 1.0,
      hechuraSaleByLineIdx: new Map([[0, 0], [1, -100]]),
      lineCount: 2,
    });
    // Conservación preservada aunque no haya base positiva.
    expect(sumDistributed(out)).toBeCloseTo(1.0, 2);
  });

  it("delta positivo (redondeo hacia arriba) se reparte con signo correcto", () => {
    const out = distributeHechuraRoundingImpactPerLine({
      deltaSaldoMonetario: 3.5,
      hechuraSaleByLineIdx: new Map([[0, 1000], [1, 1000]]),
      lineCount: 2,
    });
    expect(out.get(0)).toBeCloseTo(1.75, 2);
    expect(out.get(1)).toBeCloseTo(1.75, 2);
    expect(sumDistributed(out)).toBeCloseTo(3.5, 2);
  });
});

describe("distributeMonetarySaldoPostPerLine — Opción A (saldo físico POST)", () => {
  it("caso real: 1 línea, saldo post 185.500 → toda la línea recibe 185.500", () => {
    const out = distributeMonetarySaldoPostPerLine({
      saldoPost: 185500,
      hechuraSaleByLineIdx: new Map([[0, 185518.75]]),
      lineCount: 1,
    });
    expect(out.get(0)).toBeCloseTo(185500, 2);
    expect(sumDistributed(out)).toBeCloseTo(185500, 2);
  });

  it("múltiples líneas → reparte el saldo post proporcional a hechuraSale, conservando", () => {
    const out = distributeMonetarySaldoPostPerLine({
      saldoPost: 1000,
      hechuraSaleByLineIdx: new Map([[0, 250], [1, 750]]),
      lineCount: 2,
    });
    expect(out.get(0)).toBeCloseTo(250, 2);
    expect(out.get(1)).toBeCloseTo(750, 2);
    expect(sumDistributed(out)).toBeCloseTo(1000, 2);
  });

  it("línea pura metal (hechuraSale 0) recibe 0; la de hechura recibe todo", () => {
    const out = distributeMonetarySaldoPostPerLine({
      saldoPost: 500,
      hechuraSaleByLineIdx: new Map([[0, 0], [1, 1000]]),
      lineCount: 2,
    });
    expect(out.get(0) ?? 0).toBeCloseTo(0, 2);
    expect(out.get(1)).toBeCloseTo(500, 2);
  });

  it("conservación con residuo (3 líneas iguales)", () => {
    const out = distributeMonetarySaldoPostPerLine({
      saldoPost: 100,
      hechuraSaleByLineIdx: new Map([[0, 10], [1, 10], [2, 10]]),
      lineCount: 3,
    });
    expect(sumDistributed(out)).toBeCloseTo(100, 2);
  });
});

describe("computeCommercialRoundingPerLineImpacts — orquestador metal + hechura", () => {
  it("compone metal + hechura por línea con conservación de ambos dominios", () => {
    // 1 línea: metal padre Oro con monetaryEquivalent 0 (no redondea), hechura
    // delta −6,46 (el caso real de pantalla).
    const gramsPureByParentByLineIdx = new Map<string, Map<number, number>>([
      ["oro", new Map([[0, 1.2375]])],
    ]);
    const out = computeCommercialRoundingPerLineImpacts({
      breakdown: {
        metals:  [{ metalParentId: "oro", monetaryEquivalent: 0 }],
        hechura: { deltaSaldoMonetario: -6.46 },
      },
      gramsPureByParentByLineIdx,
      hechuraSaleByLineIdx: new Map([[0, 192506.46]]),
      lineCount: 1,
    });
    expect(out.get(0)!.metalImpact).toBeCloseTo(0, 2);
    expect(out.get(0)!.hechuraImpact).toBeCloseTo(-6.46, 2);
  });

  it("breakdown null → todas las líneas en 0 (sin impacto)", () => {
    const out = computeCommercialRoundingPerLineImpacts({
      breakdown: null,
      gramsPureByParentByLineIdx: new Map(),
      hechuraSaleByLineIdx: new Map([[0, 1000], [1, 2000]]),
      lineCount: 2,
    });
    expect(out.get(0)).toEqual({ metalImpact: 0, hechuraImpact: 0, monetarySaldoPost: null });
    expect(out.get(1)).toEqual({ metalImpact: 0, hechuraImpact: 0, monetarySaldoPost: null });
  });

  it("invariante de pantalla: METAL post + MONETARIO post = TOTAL post", () => {
    // Metal pre 333.281,25 (sin redondeo de metal → metalImpact 0).
    // Hechura pre 192.506,46, delta −6,46 → hechura post 192.500,00.
    // Total pre 525.787,71 → total post 525.781,25.
    const out = computeCommercialRoundingPerLineImpacts({
      breakdown: {
        metals:  [{ metalParentId: "oro", monetaryEquivalent: 0 }],
        hechura: { deltaSaldoMonetario: -6.46, postRoundingSaldoMonetario: 192500.0 },
      },
      gramsPureByParentByLineIdx: new Map([["oro", new Map([[0, 10]])]]),
      hechuraSaleByLineIdx: new Map([[0, 192506.46]]),
      lineCount: 1,
    });
    const metalPreSale   = 333281.25;
    const hechuraPreSale = 192506.46;
    const lineTotalWithTaxPre = 525787.71;
    const imp = out.get(0)!;

    // Descomposición FÍSICA — el MONETARIO post se lee DIRECTO del snapshot
    // distribuido por línea (no se deriva de total − metal).
    expect(imp.monetarySaldoPost).toBeCloseTo(192500.0, 2);

    const metalPost   = Math.round((metalPreSale + imp.metalImpact) * 100) / 100;
    const totalPost   = Math.round((lineTotalWithTaxPre + imp.metalImpact + imp.hechuraImpact) * 100) / 100;
    const monetarioPost = Math.round((totalPost - metalPost) * 100) / 100;

    expect(metalPost).toBeCloseTo(333281.25, 2);
    expect(monetarioPost).toBeCloseTo(192500.0, 2);
    expect(totalPost).toBeCloseTo(525781.25, 2);
    // Invariante exacto.
    expect(Math.round((metalPost + monetarioPost) * 100) / 100).toBeCloseTo(totalPost, 2);
    // Coherencia con la hechura post esperada.
    expect(Math.round((hechuraPreSale + imp.hechuraImpact) * 100) / 100).toBeCloseTo(192500.0, 2);
  });
});
