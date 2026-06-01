// src/modules/sales/__tests__/distributeMetalRoundingImpactPerLine.test.ts
// =============================================================================
// Opción δ (R-COMMERCIAL-METAL-VISIBLE) — Tests del distribuidor del impacto
// monetario del Redondeo Comercial PER_DOCUMENT a las líneas individuales.
//
// Cubre los escenarios obligatorios:
//   1. 1 línea con un metal padre.
//   2. Múltiples líneas con el mismo metal padre.
//   3. Múltiples líneas con metales padre distintos.
//   4. Override de gramos / merma / margen (todos afectan gramsPure_per_line).
//
// Invariante verificado en TODOS los tests:
//   Σ líneas distributedImpact[i] === Σ metalEntries[*].monetaryEquivalent
// =============================================================================

import { describe, it, expect } from "vitest";
import {
  aggregateMetalsForCommercialDocRounding,
  distributeMetalRoundingImpactPerLine,
} from "../commercial-doc-rounding-wiring.js";

// ─── Helpers ─────────────────────────────────────────────────────────────────

const ORO   = "metal-oro-id";
const PLATA = "metal-plata-id";

function lineWith(
  quantity: number,
  metals: ReadonlyArray<{ parentId: string; gramsPerUnit: number; price: number }>,
) {
  return {
    quantity,
    metals: metals.map((m) => ({
      metalParentId:       m.parentId,
      metalParentName:     m.parentId,
      appliedGramsPerUnit: m.gramsPerUnit,
      quotePriceSnapshot:  m.price,
    })),
  };
}

function sumDistributed(map: Map<number, number>): number {
  let s = 0;
  for (const v of map.values()) s += v;
  return Math.round(s * 100) / 100;
}

// ─── Tests ───────────────────────────────────────────────────────────────────

describe("distributeMetalRoundingImpactPerLine — Opción δ", () => {
  it("1 línea / 1 metal padre → todo el impacto a esa línea", () => {
    const lines = [
      lineWith(1, [{ parentId: ORO, gramsPerUnit: 1.2375, price: 187500 }]),
    ];
    const agg = aggregateMetalsForCommercialDocRounding(lines);
    // Simulamos que el helper emitió monetaryEquivalent=-7031.25 (delta -0.0375g × 187500).
    const out = distributeMetalRoundingImpactPerLine({
      metalEntries: [{ metalParentId: ORO, monetaryEquivalent: -7031.25 }],
      gramsPureByParentByLineIdx: agg.gramsPureByParentByLineIdx,
      lineCount: 1,
    });
    expect(out.get(0)).toBeCloseTo(-7031.25, 2);
    expect(sumDistributed(out)).toBeCloseTo(-7031.25, 2);
  });

  it("múltiples líneas / mismo metal padre → prorrateo proporcional a gramsPure", () => {
    // Línea 0: 1g de Oro. Línea 1: 3g de Oro. Total: 4g.
    // Delta agregado: 2000$ → línea 0 = 500$, línea 1 = 1500$.
    const lines = [
      lineWith(1, [{ parentId: ORO, gramsPerUnit: 1, price: 100000 }]),
      lineWith(1, [{ parentId: ORO, gramsPerUnit: 3, price: 100000 }]),
    ];
    const agg = aggregateMetalsForCommercialDocRounding(lines);
    const out = distributeMetalRoundingImpactPerLine({
      metalEntries: [{ metalParentId: ORO, monetaryEquivalent: 2000 }],
      gramsPureByParentByLineIdx: agg.gramsPureByParentByLineIdx,
      lineCount: 2,
    });
    expect(out.get(0)).toBeCloseTo(500, 2);
    expect(out.get(1)).toBeCloseTo(1500, 2);
    expect(sumDistributed(out)).toBeCloseTo(2000, 2);  // conservación exacta
  });

  it("múltiples líneas / múltiples metales padre → distribución por padre", () => {
    // Línea 0: 2g Oro + 5g Plata.
    // Línea 1: 1g Oro.
    // Delta Oro: 300$ → 200$/100$. Delta Plata: 100$ → 100$/0$.
    const lines = [
      lineWith(1, [
        { parentId: ORO,   gramsPerUnit: 2, price: 100000 },
        { parentId: PLATA, gramsPerUnit: 5, price:  10000 },
      ]),
      lineWith(1, [
        { parentId: ORO,   gramsPerUnit: 1, price: 100000 },
      ]),
    ];
    const agg = aggregateMetalsForCommercialDocRounding(lines);
    const out = distributeMetalRoundingImpactPerLine({
      metalEntries: [
        { metalParentId: ORO,   monetaryEquivalent: 300 },
        { metalParentId: PLATA, monetaryEquivalent: 100 },
      ],
      gramsPureByParentByLineIdx: agg.gramsPureByParentByLineIdx,
      lineCount: 2,
    });
    // Línea 0: 200 (Oro) + 100 (Plata) = 300.
    // Línea 1: 100 (Oro) + 0  (Plata) = 100.
    expect(out.get(0)).toBeCloseTo(300, 2);
    expect(out.get(1)).toBeCloseTo(100, 2);
    expect(sumDistributed(out)).toBeCloseTo(400, 2);
  });

  it("conservación exacta cuando prorrateo produce rounding loss (última línea absorbe residuo)", () => {
    // Línea 0: 1g, Línea 1: 1g, Línea 2: 1g. Total: 3g.
    // Delta: 1.00$. Cada línea idealmente = 0.333...
    // Round(0.3333) = 0.33. Σ líneas = 0.99. Residuo 0.01 → última línea = 0.34.
    const lines = [
      lineWith(1, [{ parentId: ORO, gramsPerUnit: 1, price: 100000 }]),
      lineWith(1, [{ parentId: ORO, gramsPerUnit: 1, price: 100000 }]),
      lineWith(1, [{ parentId: ORO, gramsPerUnit: 1, price: 100000 }]),
    ];
    const agg = aggregateMetalsForCommercialDocRounding(lines);
    const out = distributeMetalRoundingImpactPerLine({
      metalEntries: [{ metalParentId: ORO, monetaryEquivalent: 1.00 }],
      gramsPureByParentByLineIdx: agg.gramsPureByParentByLineIdx,
      lineCount: 3,
    });
    expect(out.get(0)).toBeCloseTo(0.33, 2);
    expect(out.get(1)).toBeCloseTo(0.33, 2);
    expect(out.get(2)).toBeCloseTo(0.34, 2);   // residuo
    expect(sumDistributed(out)).toBeCloseTo(1.00, 2);  // conservación
  });

  it("override de gramos (quantityOverride mayor) cambia gramsPure → re-distribuye proporcionalmente", () => {
    // Mismo escenario que antes pero línea 0 ahora aporta 5g (override) en vez de 1g.
    // Total: 5g + 1g = 6g. Delta 600$ → línea 0 = 500$, línea 1 = 100$.
    const lines = [
      lineWith(1, [{ parentId: ORO, gramsPerUnit: 5, price: 100000 }]),  // override de 1 → 5
      lineWith(1, [{ parentId: ORO, gramsPerUnit: 1, price: 100000 }]),
    ];
    const agg = aggregateMetalsForCommercialDocRounding(lines);
    const out = distributeMetalRoundingImpactPerLine({
      metalEntries: [{ metalParentId: ORO, monetaryEquivalent: 600 }],
      gramsPureByParentByLineIdx: agg.gramsPureByParentByLineIdx,
      lineCount: 2,
    });
    expect(out.get(0)).toBeCloseTo(500, 2);
    expect(out.get(1)).toBeCloseTo(100, 2);
    expect(sumDistributed(out)).toBeCloseTo(600, 2);
  });

  it("override de merma se refleja vía gramsFineEquivalent (caller lo pasa como appliedGramsPerUnit)", () => {
    // El caller (sales.service) pasa `appliedGramsPerUnit = gramsFineEquivalent`
    // = gramsOriginal × purity × (1+merma/100). El distributor NO toca esa fórmula;
    // recibe el resultado ya con merma incluida.
    //
    // Test: línea 0 con merma alta (1g × 0.75 × 1.5 = 1.125g), línea 1 sin merma
    // (1g × 0.75 × 1.0 = 0.75g). Total: 1.875g.
    // Delta 1875$ → línea 0 = 1125$, línea 1 = 750$.
    const lines = [
      lineWith(1, [{ parentId: ORO, gramsPerUnit: 1.125, price: 100000 }]),  // con merma 50%
      lineWith(1, [{ parentId: ORO, gramsPerUnit: 0.75,  price: 100000 }]),  // sin merma
    ];
    const agg = aggregateMetalsForCommercialDocRounding(lines);
    const out = distributeMetalRoundingImpactPerLine({
      metalEntries: [{ metalParentId: ORO, monetaryEquivalent: 1875 }],
      gramsPureByParentByLineIdx: agg.gramsPureByParentByLineIdx,
      lineCount: 2,
    });
    expect(out.get(0)).toBeCloseTo(1125, 2);
    expect(out.get(1)).toBeCloseTo(750, 2);
    expect(sumDistributed(out)).toBeCloseTo(1875, 2);
  });

  it("override de margen NO afecta el distributor (margen vive en metalSale, no en gramsPure)", () => {
    // El margen modifica metalSale (= cost × (1+margen/100)) PERO NO los gramos físicos.
    // El distributor solo usa gramsPure, así que el reparto NO cambia con el margen.
    // Esta es la regla R6: el margen es comercial, no físico.
    //
    // Test: misma distribución de gramos → mismo reparto, independientemente del
    // margen aplicado en otra capa.
    const lines = [
      lineWith(1, [{ parentId: ORO, gramsPerUnit: 1, price: 100000 }]),
      lineWith(1, [{ parentId: ORO, gramsPerUnit: 3, price: 100000 }]),
    ];
    const agg = aggregateMetalsForCommercialDocRounding(lines);
    const out = distributeMetalRoundingImpactPerLine({
      metalEntries: [{ metalParentId: ORO, monetaryEquivalent: 400 }],
      gramsPureByParentByLineIdx: agg.gramsPureByParentByLineIdx,
      lineCount: 2,
    });
    // 1:3 proporción → 100$:300$.
    expect(out.get(0)).toBeCloseTo(100, 2);
    expect(out.get(1)).toBeCloseTo(300, 2);
    expect(sumDistributed(out)).toBeCloseTo(400, 2);
  });

  it("monetaryEquivalent = 0 (no hubo redondeo) → distribución vacía", () => {
    const lines = [
      lineWith(1, [{ parentId: ORO, gramsPerUnit: 1, price: 100000 }]),
    ];
    const agg = aggregateMetalsForCommercialDocRounding(lines);
    const out = distributeMetalRoundingImpactPerLine({
      metalEntries: [{ metalParentId: ORO, monetaryEquivalent: 0 }],
      gramsPureByParentByLineIdx: agg.gramsPureByParentByLineIdx,
      lineCount: 1,
    });
    expect(out.size).toBe(0);
  });

  it("metales sin aporte de líneas → impacto se descarta (no infla)", () => {
    // Edge case: snapshot trae un metal padre que ninguna línea aporta (defensa).
    const lines = [
      lineWith(1, [{ parentId: ORO, gramsPerUnit: 1, price: 100000 }]),
    ];
    const agg = aggregateMetalsForCommercialDocRounding(lines);
    const out = distributeMetalRoundingImpactPerLine({
      metalEntries: [
        { metalParentId: ORO,   monetaryEquivalent: 100 },
        { metalParentId: PLATA, monetaryEquivalent: 50 },   // ← ninguna línea aporta
      ],
      gramsPureByParentByLineIdx: agg.gramsPureByParentByLineIdx,
      lineCount: 1,
    });
    expect(out.get(0)).toBeCloseTo(100, 2);  // solo el de Oro
    expect(sumDistributed(out)).toBeCloseTo(100, 2);
  });
});
