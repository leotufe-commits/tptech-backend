// src/modules/sales/__tests__/computeLineAutonomousCommercialMoney.test.ts
// =============================================================================
// Opción B (LINE-AUTONOMOUS) — Tests del dinero comercial POR LÍNEA.
//
// Regla funcional: cada card es autónomo. Agregar/quitar/modificar otra línea
// NO altera los 4 campos monetarios de una línea ya existente:
//   · metalRoundingMonetaryImpact
//   · lineMonetarySaldoPostCommercialRounding
//   · hechuraRoundingMonetaryImpact
//   · lineTotalWithTaxPostCommercialRounding
//
// Invariante POR LÍNEA:
//   (metalSaleSum + metalImpact) + saldoPost === totalPost
// =============================================================================

import { describe, it, expect } from "vitest";
import { computeLineAutonomousCommercialMoney } from "../commercial-doc-rounding-wiring.js";
import type { CommercialDocRoundingPartConfig } from "../../../lib/pricing-engine/commercial-document-rounding.js";

const ORO   = "metal-oro-id";
const PLATA = "metal-plata-id";

// HUNDRED NEAREST sobre el saldo monetario (como la lista del operador).
const HECHURA_HUNDRED: CommercialDocRoundingPartConfig = { mode: "HUNDRED", direction: "NEAREST" };

/** Construye el input para una línea. `metalsDelta` = deltaGrams por padre. */
function build(
  lines: ReadonlyArray<{
    metals: ReadonlyArray<{ parentId: string; deltaGrams: number }>;
    lineTotalWithTax: number;
    metalSaleSum: number;
  }>,
  refValueByParent: ReadonlyMap<string, number>,
) {
  const lineCommercialRoundingMetals = new Map<number, Array<{ metalParentId: string; deltaGrams: number }>>();
  const lineTotalWithTaxByIdx = new Map<number, number>();
  const metalSaleSumByIdx     = new Map<number, number>();
  lines.forEach((l, i) => {
    lineCommercialRoundingMetals.set(i, l.metals.map((m) => ({ metalParentId: m.parentId, deltaGrams: m.deltaGrams })));
    lineTotalWithTaxByIdx.set(i, l.lineTotalWithTax);
    metalSaleSumByIdx.set(i, l.metalSaleSum);
  });
  return computeLineAutonomousCommercialMoney({
    lineCommercialRoundingMetals,
    refValueByParent,
    lineTotalWithTaxByIdx,
    metalSaleSumByIdx,
    hechuraCfg: HECHURA_HUNDRED,
    lineCount: lines.length,
  });
}

// refValue del Oro (precio por gramo comercial). Plata aparte.
const REF = new Map<string, number>([[ORO, 105_000], [PLATA, 5_000]]);

// Artículo 1 (ANILLOS): saldo propio = lineTotalWithTax − metalSaleSum.
//   lineTotalWithTax = 518.781,25 ; metalSaleSum = 333.281,25
//   → saldoLínea = 185.500,00 (ya redondo) ; metal delta = +0,039 g
const ART1 = { metals: [{ parentId: ORO, deltaGrams: 0.039 }], lineTotalWithTax: 518_781.25, metalSaleSum: 333_281.25 };
// Artículo 2 (FIXTURE): saldo propio distinto. metal Oro + Plata.
const ART2 = {
  metals: [{ parentId: ORO, deltaGrams: 0.039 }, { parentId: PLATA, deltaGrams: -0.10 }],
  lineTotalWithTax: 60_000.00, metalSaleSum: 50_340.00, // saldoLínea = 9.660 → 9.700
};
// Artículo 3: otro saldo.
const ART3 = { metals: [{ parentId: ORO, deltaGrams: 0.05 }], lineTotalWithTax: 30_000.00, metalSaleSum: 25_475.00 }; // saldo 4.525 → 4.500

describe("computeLineAutonomousCommercialMoney — autonomía por línea", () => {
  it("Artículo 1 SOLO: saldo propio redondeado + impacto metal propio", () => {
    const out = build([ART1], REF);
    const m = out.get(0)!;
    // metalImpact = 0,039 × 105.000 = 4.095,00
    expect(m.metalRoundingMonetaryImpact).toBeCloseTo(4_095.00, 2);
    // saldoLínea PRE = 518.781,25 − 333.281,25 = 185.500,00
    expect(m.lineMonetarySaldoPreCommercialRounding).toBeCloseTo(185_500.00, 2);
    // saldoLínea = 518.781,25 − 333.281,25 = 185.500,00 → HUNDRED = 185.500,00
    expect(m.lineMonetarySaldoPostCommercialRounding).toBeCloseTo(185_500.00, 2);
    // hechuraImpact = 185.500 − 185.500 = 0
    expect(m.hechuraRoundingMonetaryImpact).toBeCloseTo(0, 2);
    // totalPost = 518.781,25 + 4.095 + 0 = 522.876,25
    expect(m.lineTotalWithTaxPostCommercialRounding).toBeCloseTo(522_876.25, 2);
  });

  it("CRÍTICO: agregar Artículo 2 NO cambia ningún campo del Artículo 1", () => {
    const solo = build([ART1], REF).get(0)!;
    const con2 = build([ART1, ART2], REF).get(0)!;
    expect(con2).toEqual(solo); // los 4 campos idénticos
  });

  it("CRÍTICO: agregar Artículo 3 NO cambia ningún campo del Artículo 1 ni del 2", () => {
    const dos      = build([ART1, ART2], REF);
    const tres     = build([ART1, ART2, ART3], REF);
    expect(tres.get(0)).toEqual(dos.get(0)!); // Art 1 estable
    expect(tres.get(1)).toEqual(dos.get(1)!); // Art 2 estable
  });

  it("invariante por línea: (metalSaleSum + metalImpact) + saldoPost === totalPost", () => {
    const out = build([ART1, ART2, ART3], REF);
    const cases: Array<[number, { metalSaleSum: number }]> = [
      [0, ART1], [1, ART2], [2, ART3],
    ];
    for (const [idx, art] of cases) {
      const m = out.get(idx)!;
      const metalComercialPost = Math.round((art.metalSaleSum + m.metalRoundingMonetaryImpact) * 100) / 100;
      const sum = Math.round((metalComercialPost + m.lineMonetarySaldoPostCommercialRounding) * 100) / 100;
      expect(sum).toBeCloseTo(m.lineTotalWithTaxPostCommercialRounding, 2);
    }
  });

  it("Σ cards ≠ documento es esperado (round per-línea no conserva)", () => {
    // Suma de saldos POST por línea vs round del saldo agregado.
    const out = build([ART1, ART2, ART3], REF);
    const sumCards =
      out.get(0)!.lineMonetarySaldoPostCommercialRounding +
      out.get(1)!.lineMonetarySaldoPostCommercialRounding +
      out.get(2)!.lineMonetarySaldoPostCommercialRounding;
    // 185.500 + 9.700 + 4.500 = 199.700
    expect(sumCards).toBeCloseTo(199_700.00, 2);
    // El saldo agregado crudo = 185.500 + 9.660 + 4.525 = 199.685 → HUNDRED = 199.700
    // (coincide acá por los números elegidos; el punto es que el card NO depende
    //  del agregado — usa el saldo propio de cada línea).
  });

  it("mode NONE en hechura ⇒ saldoPost = saldoLínea, hechuraImpact = 0", () => {
    const lineCommercialRoundingMetals = new Map([[0, [{ metalParentId: ORO, deltaGrams: 0 }]]]);
    const out = computeLineAutonomousCommercialMoney({
      lineCommercialRoundingMetals,
      refValueByParent: REF,
      lineTotalWithTaxByIdx: new Map([[0, 185_475.21]]),
      metalSaleSumByIdx:     new Map([[0, 0]]),
      hechuraCfg: { mode: "NONE", direction: "NEAREST" },
      lineCount: 1,
    });
    const m = out.get(0)!;
    expect(m.lineMonetarySaldoPostCommercialRounding).toBeCloseTo(185_475.21, 2);
    expect(m.hechuraRoundingMonetaryImpact).toBeCloseTo(0, 2);
    expect(m.metalRoundingMonetaryImpact).toBeCloseTo(0, 2);
  });
});
