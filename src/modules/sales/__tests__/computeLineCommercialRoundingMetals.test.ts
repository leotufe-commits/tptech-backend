// src/modules/sales/__tests__/computeLineCommercialRoundingMetals.test.ts
// =============================================================================
// Fix "Resumen Comercial del Artículo mezcla líneas" — Tests del cálculo de
// gramos comerciales POST-redondeo PER-LÍNEA.
//
// Regla funcional: cada card de artículo muestra SOLO los gramos de SU línea.
// Agregar una 2.ª línea NO debe modificar los gramos de la 1.ª.
//
// Fórmula (display-only, SSOT `computeCommercialPostGrams`):
//   gramsSale = gramsPure_línea × marginFactor_línea
//   postGrams = round(gramsSale)   (cfg.metal mode/direction)
// =============================================================================

import { describe, it, expect } from "vitest";
import {
  aggregateMetalsForCommercialDocRounding,
  computeLineCommercialRoundingMetals,
  computeLineAutonomousCommercialMoney,
} from "../commercial-doc-rounding-wiring.js";
import type { CommercialDocRoundingPartConfig } from "../../../lib/pricing-engine/commercial-document-rounding.js";

const ORO   = "metal-oro-id";
const PLATA = "metal-plata-id";

const DECIMAL_1_NEAREST: CommercialDocRoundingPartConfig = {
  mode: "DECIMAL_1", direction: "NEAREST",
};

/** Construye una línea para `aggregateMetalsForCommercialDocRounding`. */
function lineWith(
  quantity: number,
  metals: ReadonlyArray<{ parentId: string; name: string; gramsPerUnit: number; price: number }>,
) {
  return {
    quantity,
    metals: metals.map((m) => ({
      metalParentId:       m.parentId,
      metalParentName:     m.name,
      appliedGramsPerUnit: m.gramsPerUnit,
      quotePriceSnapshot:  m.price,
    })),
  };
}

function nameMap(...pairs: Array<[string, string]>): Map<string, string> {
  return new Map(pairs);
}

describe("computeLineCommercialRoundingMetals — gramos comerciales PER-LÍNEA", () => {
  it("monetización per-metal: monetaryImpact = deltaGrams × refValue + metalReferenceValue", () => {
    // Oro gramsPure 1,2375 × margen 1,10 = 1,36125 → round4 preGrams 1,3613 →
    // DECIMAL_1 = 1,40. delta = round4(1,40 − 1,3613) = +0,0387.
    // refValue 250.000 → impacto +9.675,00 (coincide con el caso real del operador).
    const agg = aggregateMetalsForCommercialDocRounding([
      lineWith(1, [{ parentId: ORO, name: "Oro Fino", gramsPerUnit: 1.2375, price: 100 }]),
    ]);
    const out = computeLineCommercialRoundingMetals({
      gramsPureByParentByLineIdx: agg.gramsPureByParentByLineIdx,
      metalNameById:              nameMap([ORO, "Oro Fino"]),
      refValueByParent:           new Map([[ORO, 250000]]),
      marginFactorByLineIdx:      new Map([[0, 1.10]]),
      metalCfg:                   DECIMAL_1_NEAREST,
      lineCount:                  1,
    });
    const m = out.get(0)![0];
    expect(m.metalReferenceValue).toBe(250000);
    expect(m.deltaGrams).toBeCloseTo(0.0387, 4);
    expect(m.monetaryImpact).toBeCloseTo(9675, 2); // 0,0387 × 250.000
    // Invariante: monetaryImpact === deltaGrams × metalReferenceValue.
    expect(m.monetaryImpact).toBeCloseTo(m.deltaGrams * m.metalReferenceValue, 2);
  });

  it("sin refValueByParent ⇒ metalReferenceValue 0, monetaryImpact 0 (back-compat)", () => {
    const agg = aggregateMetalsForCommercialDocRounding([
      lineWith(1, [{ parentId: ORO, name: "Oro Fino", gramsPerUnit: 1.2375, price: 100 }]),
    ]);
    const out = computeLineCommercialRoundingMetals({
      gramsPureByParentByLineIdx: agg.gramsPureByParentByLineIdx,
      metalNameById:              nameMap([ORO, "Oro Fino"]),
      marginFactorByLineIdx:      new Map([[0, 1.10]]),
      metalCfg:                   DECIMAL_1_NEAREST,
      lineCount:                  1,
    });
    const m = out.get(0)![0];
    expect(m.metalReferenceValue).toBe(0);
    expect(m.monetaryImpact).toBe(0);
  });

  it("una sola línea con Oro: postGrams = round(gramsPure × margen)", () => {
    // ANILLOS SOLITARIO — Oro: gramsPure_línea (post pureza+merma) × margen 1,10.
    // gramsPure = 1,2375 (= 1,5 × 0,750 × 1,10 merma) ; × 1,10 = 1,36125 → 1,40.
    const agg = aggregateMetalsForCommercialDocRounding([
      lineWith(1, [{ parentId: ORO, name: "Oro Fino", gramsPerUnit: 1.2375, price: 100 }]),
    ]);
    const out = computeLineCommercialRoundingMetals({
      gramsPureByParentByLineIdx: agg.gramsPureByParentByLineIdx,
      metalNameById:              nameMap([ORO, "Oro Fino"]),
      marginFactorByLineIdx:      new Map([[0, 1.10]]),
      metalCfg:                   DECIMAL_1_NEAREST,
      lineCount:                  1,
    });
    const line0 = out.get(0)!;
    expect(line0).toHaveLength(1);
    expect(line0[0].metalParentName).toBe("Oro Fino");
    expect(line0[0].preGrams).toBeCloseTo(1.3613, 4);  // 1,36125 round4
    expect(line0[0].postGrams).toBe(1.4);
    expect(line0[0].deltaGrams).toBeCloseTo(0.0387, 4);
  });

  it("CRÍTICO: agregar una 2.ª línea NO modifica los gramos de la 1.ª", () => {
    // Línea 0 = ANILLOS (Oro 1,2375 g pure). Línea 1 = FIXTURE multimetal
    // (Oro 1,2375 g pure + Plata 1,90 g pure). Ambas con margen 1,10.
    const agg = aggregateMetalsForCommercialDocRounding([
      lineWith(1, [{ parentId: ORO, name: "Oro Fino", gramsPerUnit: 1.2375, price: 100 }]),
      lineWith(1, [
        { parentId: ORO,   name: "Oro Fino", gramsPerUnit: 1.2375, price: 100 },
        { parentId: PLATA, name: "Plata",    gramsPerUnit: 1.90,   price: 10 },
      ]),
    ]);
    const out = computeLineCommercialRoundingMetals({
      gramsPureByParentByLineIdx: agg.gramsPureByParentByLineIdx,
      metalNameById:              nameMap([ORO, "Oro Fino"], [PLATA, "Plata"]),
      marginFactorByLineIdx:      new Map([[0, 1.10], [1, 1.10]]),
      metalCfg:                   DECIMAL_1_NEAREST,
      lineCount:                  2,
    });

    // Línea 0 (ANILLOS): SOLO Oro, y SOLO el de su línea → 1,40 (NO 2,70).
    const line0 = out.get(0)!;
    expect(line0).toHaveLength(1);
    expect(line0[0].metalParentName).toBe("Oro Fino");
    expect(line0[0].postGrams).toBe(1.4);

    // Línea 1 (FIXTURE): Oro 1,40 + Plata 2,10×... → Plata 1,90 × 1,10 = 2,09 → 2,10.
    const line1 = out.get(1)!;
    expect(line1).toHaveLength(2);
    const oro1   = line1.find((m) => m.metalParentId === ORO)!;
    const plata1 = line1.find((m) => m.metalParentId === PLATA)!;
    expect(oro1.postGrams).toBe(1.4);
    expect(plata1.preGrams).toBeCloseTo(2.09, 2);  // 1,90 × 1,10
    expect(plata1.postGrams).toBe(2.1);
  });

  it("Plata 2,10 g pure × 1,10 = 2,31 → 2,30 (ejemplo del operador)", () => {
    const agg = aggregateMetalsForCommercialDocRounding([
      lineWith(1, [{ parentId: PLATA, name: "Plata", gramsPerUnit: 2.10, price: 10 }]),
    ]);
    const out = computeLineCommercialRoundingMetals({
      gramsPureByParentByLineIdx: agg.gramsPureByParentByLineIdx,
      metalNameById:              nameMap([PLATA, "Plata"]),
      marginFactorByLineIdx:      new Map([[0, 1.10]]),
      metalCfg:                   DECIMAL_1_NEAREST,
      lineCount:                  1,
    });
    const m = out.get(0)![0];
    expect(m.preGrams).toBeCloseTo(2.31, 2);
    expect(m.postGrams).toBe(2.3);
  });

  it("margen por línea distinto: cada línea usa SU factor (no contamina)", () => {
    // Misma cantidad de Oro pure pero márgenes distintos por línea.
    const agg = aggregateMetalsForCommercialDocRounding([
      lineWith(1, [{ parentId: ORO, name: "Oro Fino", gramsPerUnit: 1.00, price: 100 }]),
      lineWith(1, [{ parentId: ORO, name: "Oro Fino", gramsPerUnit: 1.00, price: 100 }]),
    ]);
    const out = computeLineCommercialRoundingMetals({
      gramsPureByParentByLineIdx: agg.gramsPureByParentByLineIdx,
      metalNameById:              nameMap([ORO, "Oro Fino"]),
      marginFactorByLineIdx:      new Map([[0, 1.20], [1, 1.50]]),
      metalCfg:                   DECIMAL_1_NEAREST,
      lineCount:                  2,
    });
    expect(out.get(0)![0].preGrams).toBeCloseTo(1.20, 2); // 1,00 × 1,20
    expect(out.get(0)![0].postGrams).toBe(1.2);
    expect(out.get(1)![0].preGrams).toBeCloseTo(1.50, 2); // 1,00 × 1,50
    expect(out.get(1)![0].postGrams).toBe(1.5);
  });

  it("marginFactor faltante ⇒ 1 (sin margen); mode NONE ⇒ post = pre", () => {
    const agg = aggregateMetalsForCommercialDocRounding([
      lineWith(1, [{ parentId: ORO, name: "Oro Fino", gramsPerUnit: 1.2375, price: 100 }]),
    ]);
    const out = computeLineCommercialRoundingMetals({
      gramsPureByParentByLineIdx: agg.gramsPureByParentByLineIdx,
      metalNameById:              nameMap([ORO, "Oro Fino"]),
      marginFactorByLineIdx:      new Map(), // vacío → factor 1
      metalCfg:                   { mode: "NONE", direction: "NEAREST" },
      lineCount:                  1,
    });
    const m = out.get(0)![0];
    expect(m.preGrams).toBeCloseTo(1.2375, 4); // sin margen
    expect(m.postGrams).toBeCloseTo(1.2375, 4); // sin redondeo
    expect(m.deltaGrams).toBe(0);
  });

  it("líneas sin metal quedan con array vacío (nunca undefined)", () => {
    const agg = aggregateMetalsForCommercialDocRounding([
      lineWith(1, [{ parentId: ORO, name: "Oro Fino", gramsPerUnit: 1.00, price: 100 }]),
      lineWith(1, []), // línea sin metal (producto/servicio)
    ]);
    const out = computeLineCommercialRoundingMetals({
      gramsPureByParentByLineIdx: agg.gramsPureByParentByLineIdx,
      metalNameById:              nameMap([ORO, "Oro Fino"]),
      marginFactorByLineIdx:      new Map([[0, 1.10], [1, 1.10]]),
      metalCfg:                   DECIMAL_1_NEAREST,
      lineCount:                  2,
    });
    expect(out.get(0)).toHaveLength(1);
    expect(out.get(1)).toEqual([]);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Listas mixtas (Opción 1, 2026-06-03) — config de redondeo POR LÍNEA.
// Cada línea usa la config de SU lista; sin entrada → cae al default (`metalCfg`
// / `hechuraCfg`). Prueba que en mixto cada línea conserva su redondeo propio.
// ─────────────────────────────────────────────────────────────────────────────
describe("config por línea — metalCfgByLineIdx / hechuraCfgByLineIdx (mixto)", () => {
  const NONE: CommercialDocRoundingPartConfig = { mode: "NONE", direction: "NEAREST" };
  const HUNDRED_NEAREST: CommercialDocRoundingPartConfig = { mode: "HUNDRED", direction: "NEAREST" };

  it("metalCfgByLineIdx: línea 0 redondea (DECIMAL_1), línea 1 sin config (NONE) → no redondea", () => {
    // Ambas líneas mismo Oro (1,2375 g × 1,10 = 1,36125). L0 con DECIMAL_1 → 1,40;
    // L1 sin entrada en el map → usa metalCfg default NONE → postGrams = preGrams.
    const agg = aggregateMetalsForCommercialDocRounding([
      lineWith(1, [{ parentId: ORO, name: "Oro Fino", gramsPerUnit: 1.2375, price: 100 }]),
      lineWith(1, [{ parentId: ORO, name: "Oro Fino", gramsPerUnit: 1.2375, price: 100 }]),
    ]);
    const out = computeLineCommercialRoundingMetals({
      gramsPureByParentByLineIdx: agg.gramsPureByParentByLineIdx,
      metalNameById:              nameMap([ORO, "Oro Fino"]),
      marginFactorByLineIdx:      new Map([[0, 1.10], [1, 1.10]]),
      metalCfg:                   NONE,                               // default
      metalCfgByLineIdx:          new Map([[0, DECIMAL_1_NEAREST]]),  // solo L0 redondea
      lineCount:                  2,
    });
    expect(out.get(0)![0].postGrams).toBe(1.4);                       // L0 redondeada
    expect(out.get(1)![0].postGrams).toBeCloseTo(1.3613, 4);          // L1 sin redondeo (= pre)
    expect(out.get(1)![0].deltaGrams).toBe(0);
  });

  it("hechuraCfgByLineIdx: línea 0 redondea saldo (HUNDRED), línea 1 sin config → no redondea", () => {
    const metals = computeLineCommercialRoundingMetals({
      gramsPureByParentByLineIdx: new Map(),  // sin metales → solo importa el saldo
      metalNameById:              new Map(),
      marginFactorByLineIdx:      new Map(),
      metalCfg:                   NONE,
      lineCount:                  2,
    });
    const out = computeLineAutonomousCommercialMoney({
      lineCommercialRoundingMetals: metals,
      refValueByParent:             new Map(),
      lineTotalWithTaxByIdx:        new Map([[0, 185475.21], [1, 185475.21]]),
      metalSaleSumByIdx:            new Map([[0, 0], [1, 0]]),
      hechuraCfg:                   NONE,                               // default
      hechuraCfgByLineIdx:          new Map([[0, HUNDRED_NEAREST]]),    // solo L0 redondea
      lineCount:                    2,
    });
    // L0: saldo 185.475,21 → HUNDRED NEAREST → 185.500.
    expect(out.get(0)!.lineMonetarySaldoPostCommercialRounding).toBe(185500);
    // L1: sin config → NONE → saldo sin redondear.
    expect(out.get(1)!.lineMonetarySaldoPostCommercialRounding).toBeCloseTo(185475.21, 2);
  });

  it("sin los maps por línea → usa el cfg único (back-compat)", () => {
    const agg = aggregateMetalsForCommercialDocRounding([
      lineWith(1, [{ parentId: ORO, name: "Oro Fino", gramsPerUnit: 1.2375, price: 100 }]),
    ]);
    const out = computeLineCommercialRoundingMetals({
      gramsPureByParentByLineIdx: agg.gramsPureByParentByLineIdx,
      metalNameById:              nameMap([ORO, "Oro Fino"]),
      marginFactorByLineIdx:      new Map([[0, 1.10]]),
      metalCfg:                   DECIMAL_1_NEAREST,   // sin metalCfgByLineIdx
      lineCount:                  1,
    });
    expect(out.get(0)![0].postGrams).toBe(1.4);
  });
});
