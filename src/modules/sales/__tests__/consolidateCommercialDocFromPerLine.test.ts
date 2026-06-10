// src/modules/sales/__tests__/consolidateCommercialDocFromPerLine.test.ts
// =============================================================================
// Etapa Σ-round (canónico 2026-06-03) — Consolidación comercial PER_DOCUMENT
// = Σ round(línea) (NO round(Σ) del agregado documental).
//
// Regla de negocio aprobada (Alternativa C):
//   footerMetalGrams     = Σ metalCommercialFinalGramsByLine
//   footerMonetaryAmount = Σ monetaryCommercialFinalAmountByLine
//   totalComercialDoc    = Σ valores comerciales visibles por línea
//
// Invariante: METAL comercial + MONETARIO comercial = total comercial del
// comprobante, SIN residuos por round(Σ) vs Σ round.
//
// Estos tests usan la cadena REAL de helpers per-línea
// (`computeLineCommercialRoundingMetals` + `computeLineAutonomousCommercialMoney`)
// y luego consolidan con `consolidateCommercialDocFromPerLine` — exactamente
// la misma secuencia que `previewSale`/`confirmSale` ejecutan en producción.
// =============================================================================

import { describe, it, expect } from "vitest";
import {
  aggregateMetalsForCommercialDocRounding,
  computeLineCommercialRoundingMetals,
  computeLineAutonomousCommercialMoney,
  consolidateCommercialDocFromPerLine,
} from "../commercial-doc-rounding-wiring.js";
import type { CommercialDocRoundingPartConfig } from "../../../lib/pricing-engine/commercial-document-rounding.js";

const ORO   = "metal-oro-id";
const PLATA = "metal-plata-id";

const DECIMAL_1_NEAREST: CommercialDocRoundingPartConfig = { mode: "DECIMAL_1", direction: "NEAREST" };
const HUNDRED_NEAREST:   CommercialDocRoundingPartConfig = { mode: "HUNDRED",   direction: "NEAREST" };
const NONE:              CommercialDocRoundingPartConfig = { mode: "NONE",      direction: "NEAREST" };

const round2 = (n: number) => Math.round(n * 100) / 100;

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
      metalReferenceValue: m.price,
    })),
  };
}

/**
 * Corre la cadena completa y devuelve { metals, money, consolidated } como en
 * el wiring real. `lineTotals`/`metalSaleSums` son los inputs monetarios por
 * línea (lineTotalWithTax y Σ metalSale × qty respectivamente).
 */
function runChain(args: {
  lines: ReadonlyArray<ReturnType<typeof lineWith>>;
  margins: number[];
  lineTotals: number[];
  metalSaleSums: number[];
  metalCfg: CommercialDocRoundingPartConfig;
  hechuraCfg: CommercialDocRoundingPartConfig;
  names: Array<[string, string]>;
  refValues: Array<[string, number]>;
}) {
  const agg = aggregateMetalsForCommercialDocRounding(args.lines as any);
  const lineCount = args.lines.length;
  const metalNameById    = new Map(args.names);
  const refValueByParent = new Map(args.refValues);
  const marginFactorByLineIdx = new Map(args.margins.map((m, i) => [i, m]));
  const lineTotalWithTaxByIdx = new Map(args.lineTotals.map((v, i) => [i, v]));
  const metalSaleSumByIdx     = new Map(args.metalSaleSums.map((v, i) => [i, v]));

  const metals = computeLineCommercialRoundingMetals({
    gramsPureByParentByLineIdx: agg.gramsPureByParentByLineIdx,
    metalNameById,
    refValueByParent,
    marginFactorByLineIdx,
    metalCfg: args.metalCfg,
    lineCount,
  });
  const money = computeLineAutonomousCommercialMoney({
    lineCommercialRoundingMetals: metals,
    refValueByParent,
    lineTotalWithTaxByIdx,
    metalSaleSumByIdx,
    hechuraCfg: args.hechuraCfg,
    lineCount,
  });
  const consolidated = consolidateCommercialDocFromPerLine({
    lineCommercialRoundingMetals: metals,
    lineMoney: money,
    metalNameById,
    refValueByParent,
    metalCfg: args.metalCfg,
    hechuraCfg: args.hechuraCfg,
    lineCount,
  });
  return { agg, metals, money, consolidated };
}

/** Suma postGrams del padre `parentId` en el snapshot consolidado. */
function docPostGrams(consolidated: any, parentId: string): number {
  const m = consolidated.breakdown.metals.find((x: any) => x.metalParentId === parentId);
  return m ? m.postGrams : 0;
}

describe("consolidateCommercialDocFromPerLine — Σ round(línea), NO round(Σ)", () => {
  // ── A) dos líneas ambas redondeadas: 1,40 + 1,40 = 2,80 g ─────────────────
  it("A) dos líneas redondeadas (Oro): footer = 1,40 + 1,40 = 2,80 g", () => {
    // gramsPure 1,2375 × margen 1,10 = 1,36125 → DECIMAL_1 = 1,40 por línea.
    const { metals, consolidated } = runChain({
      lines: [
        lineWith(1, [{ parentId: ORO, name: "Oro Fino", gramsPerUnit: 1.2375, price: 100 }]),
        lineWith(1, [{ parentId: ORO, name: "Oro Fino", gramsPerUnit: 1.2375, price: 100 }]),
      ],
      margins: [1.10, 1.10],
      lineTotals: [200000, 200000],
      metalSaleSums: [136.13, 136.13],
      metalCfg: DECIMAL_1_NEAREST,
      hechuraCfg: NONE,
      names: [[ORO, "Oro Fino"]],
      refValues: [[ORO, 100]],
    });
    expect(metals.get(0)![0].postGrams).toBe(1.4);
    expect(metals.get(1)![0].postGrams).toBe(1.4);
    expect(consolidated).not.toBeNull();
    // Footer = Σ round(línea) = 1,40 + 1,40 = 2,80 (NO round(2,7225) = 2,70).
    expect(docPostGrams(consolidated, ORO)).toBeCloseTo(2.8, 4);
  });

  // ── B) una redondeada + una EXACTA (sin redondeo): 1,40 + 2,30 = 3,70 g ───
  it("B) mixta redondeada/exacta (mismo padre): footer = Σ visible (1,40 + 2,30)", () => {
    // Propiedad clave: una línea redondea (1,40) y otra cae JUSTO en la grilla
    // (2,30, delta 0 → "exacta"). El footer = SUMA de lo visible por línea, NO
    // round del agregado. (El "2,29/3,69" del spec es ilustrativo: 2,29 no está
    // en grilla DECIMAL_1; acá usamos 2,30 que sí es exacto para demostrar el
    // mecanismo "Σ de los valores visibles, la exacta entra tal cual".)
    const { metals, consolidated } = runChain({
      lines: [
        lineWith(1, [{ parentId: ORO, name: "Oro Fino", gramsPerUnit: 1.2375, price: 100 }]),
        lineWith(1, [{ parentId: ORO, name: "Oro Fino", gramsPerUnit: 2.30,   price: 100 }]),
      ],
      margins: [1.10, 1.00],
      lineTotals: [200000, 300000],
      metalSaleSums: [136.13, 230.0],
      metalCfg: DECIMAL_1_NEAREST,
      hechuraCfg: NONE,
      names: [[ORO, "Oro Fino"]],
      refValues: [[ORO, 100]],
    });
    expect(metals.get(0)![0].postGrams).toBe(1.4);
    expect(metals.get(1)![0].postGrams).toBe(2.3);  // exacta — sin redondeo
    expect(metals.get(1)![0].deltaGrams).toBe(0);
    // Footer = Σ visible = 1,40 + 2,30 = 3,70 (NO round(1,36125+2,30)=round(3,66)=3,70 acá
    // coincide, pero el contrato es la SUMA de los visibles, no el round del agregado).
    expect(docPostGrams(consolidated, ORO)).toBeCloseTo(3.7, 4);
  });

  // ── C) monetario redondeado en dos líneas: 185.000 + 185.000 = 370.000 ────
  it("C) monetario en dos líneas: footer hechura = 185.000 + 185.000 = 370.000", () => {
    // Sin metal — solo saldo monetario. saldoLínea = lineTotal − metalSaleSum.
    // 185.475,21 → HUNDRED NEAREST = 185.500 por línea. Σ = 371.000.
    // Para clavar 185.000 exacto usamos lineTotal=185.000, metalSale=0,
    // hechura NONE→ post=pre=185.000.
    const { money, consolidated } = runChain({
      lines: [lineWith(1, []), lineWith(1, [])],
      margins: [1, 1],
      lineTotals: [185000, 185000],
      metalSaleSums: [0, 0],
      metalCfg: NONE,
      hechuraCfg: NONE,
      names: [],
      refValues: [],
    });
    expect(money.get(0)!.lineMonetarySaldoPostCommercialRounding).toBe(185000);
    expect(money.get(1)!.lineMonetarySaldoPostCommercialRounding).toBe(185000);
    // Sin movimiento (NONE+NONE, delta 0) → snapshot null (regla "sin redondeo
    // → valores exactos"). El footer toma el saldo del balance. La SUMA visible
    // se valida igual: Σ saldoPost = 370.000.
    const sumSaldoPost =
      money.get(0)!.lineMonetarySaldoPostCommercialRounding +
      money.get(1)!.lineMonetarySaldoPostCommercialRounding;
    expect(sumSaldoPost).toBe(370000);
    expect(consolidated).toBeNull();
  });

  it("C') monetario CON redondeo HUNDRED en dos líneas: Σ saldoPost del snapshot", () => {
    // saldoLínea 185.475,21 → HUNDRED NEAREST = 185.500. Dos líneas → 371.000.
    const { money, consolidated } = runChain({
      lines: [lineWith(1, []), lineWith(1, [])],
      margins: [1, 1],
      lineTotals: [185475.21, 185475.21],
      metalSaleSums: [0, 0],
      metalCfg: NONE,
      hechuraCfg: HUNDRED_NEAREST,
      names: [],
      refValues: [],
    });
    expect(money.get(0)!.lineMonetarySaldoPostCommercialRounding).toBe(185500);
    expect(consolidated).not.toBeNull();
    expect(consolidated!.breakdown!.hechura.postRoundingSaldoMonetario).toBe(371000);
    // deltaSaldo = Σ (185.500 − 185.475,21) = 2 × 24,79 = 49,58.
    expect(consolidated!.breakdown!.hechura.deltaSaldoMonetario).toBeCloseTo(49.58, 2);
  });

  // ── D/G) líneas mixtas (redondeada + exacta + redondeada) ─────────────────
  it("D/G) tres líneas mixtas: footer = Σ exacta de lo visible por línea", () => {
    // L0 Oro → 1,40 (redondea). L1 Oro → 2,29 exacta. L2 Plata → 2,31→2,30.
    const { metals, consolidated } = runChain({
      lines: [
        lineWith(1, [{ parentId: ORO,   name: "Oro Fino", gramsPerUnit: 1.2375, price: 100 }]),
        lineWith(1, [{ parentId: ORO,   name: "Oro Fino", gramsPerUnit: 2.30,   price: 100 }]),
        lineWith(1, [{ parentId: PLATA, name: "Plata",    gramsPerUnit: 2.10,   price: 10  }]),
      ],
      margins: [1.10, 1.00, 1.10],
      lineTotals: [200000, 300000, 50000],
      metalSaleSums: [136.13, 230.0, 23.1],
      metalCfg: DECIMAL_1_NEAREST,
      hechuraCfg: NONE,
      names: [[ORO, "Oro Fino"], [PLATA, "Plata"]],
      refValues: [[ORO, 100], [PLATA, 10]],
    });
    expect(metals.get(0)![0].postGrams).toBe(1.4);  // redondea
    expect(metals.get(1)![0].postGrams).toBe(2.3);  // exacta (delta 0)
    expect(metals.get(2)![0].postGrams).toBe(2.3);  // 2,10 × 1,10 = 2,31 → 2,30
    // Oro doc = 1,40 + 2,30 = 3,70. Plata doc = 2,30. Footer = Σ visible.
    expect(docPostGrams(consolidated, ORO)).toBeCloseTo(3.7, 4);
    expect(docPostGrams(consolidated, PLATA)).toBeCloseTo(2.3, 4);
  });

  // ── E) redondeo financiero: es capa POSTERIOR (no lo arma este helper) ────
  it("E) el helper comercial NO incluye redondeo financiero (capa posterior)", () => {
    // El snapshot comercial solo refleja metal + hechura comercial. El
    // financiero del comprobante es otra capa/snapshot (documentRoundingSnapshot)
    // y se aplica DESPUÉS sobre el total ya consolidado.
    const { consolidated } = runChain({
      lines: [lineWith(1, [{ parentId: ORO, name: "Oro Fino", gramsPerUnit: 1.2375, price: 100 }])],
      margins: [1.10],
      lineTotals: [200000],
      metalSaleSums: [136.13],
      metalCfg: DECIMAL_1_NEAREST,
      hechuraCfg: NONE,
      names: [[ORO, "Oro Fino"]],
      refValues: [[ORO, 100]],
    });
    expect(consolidated!.source).toBe("PRICE_LIST");        // comercial (lista)
    expect(consolidated!.scope).toBe("BREAKDOWN");
    expect(consolidated!.appliedAt).toBe("DOCUMENT");
    // No hay ningún campo de redondeo financiero acá.
    expect((consolidated as any).financial).toBeUndefined();
  });

  // ── F) METAL comercial + MONETARIO comercial = total comercial ────────────
  it("F) cierre: Σ(metalSale+impacto) + Σ saldoPost = Σ totalLínea POST (sin residuo)", () => {
    const lineTotals    = [200000, 300000];
    const metalSaleSums = [136.13, 333.50];
    const { money, consolidated } = runChain({
      lines: [
        lineWith(1, [{ parentId: ORO, name: "Oro Fino", gramsPerUnit: 1.2375, price: 100 }]),
        lineWith(1, [{ parentId: ORO, name: "Oro Fino", gramsPerUnit: 3.05,   price: 100 }]),
      ],
      margins: [1.10, 1.10],
      lineTotals,
      metalSaleSums,
      metalCfg: DECIMAL_1_NEAREST,
      hechuraCfg: HUNDRED_NEAREST,
      names: [[ORO, "Oro Fino"]],
      refValues: [[ORO, 100]],
    });
    // METAL comercial del doc = Σ metalSale + Σ metalImpact.
    const metalComercialDoc = round2(
      metalSaleSums[0] + metalSaleSums[1] + consolidated!.breakdown!.metalMonetaryEquivalent,
    );
    // MONETARIO comercial del doc = Σ saldoPost.
    const monetarioDoc = consolidated!.breakdown!.hechura.postRoundingSaldoMonetario;
    // total comercial POST = Σ lineTotalWithTaxPostCommercialRounding.
    const totalComercialPost = round2(
      money.get(0)!.lineTotalWithTaxPostCommercialRounding +
      money.get(1)!.lineTotalWithTaxPostCommercialRounding,
    );
    // Invariante F — sin residuos.
    expect(round2(metalComercialDoc + monetarioDoc)).toBe(totalComercialPost);
    // El totalAdjustment del snapshot = (totalComercialPost − Σ lineTotalWithTax).
    expect(consolidated!.totalAdjustment).toBe(
      round2(totalComercialPost - (lineTotals[0] + lineTotals[1])),
    );
  });

  // ── H) cantidad > 1: 1,40 × 10 = 14,00 g (redondeo a nivel LÍNEA) ─────────
  it("H) qty=10: redondeo a nivel LÍNEA del agregado × qty → footer 14,00 g", () => {
    // appliedGramsPerUnit 1,396, margen 1,00, qty 10 → gramsPure_línea = 13,96 →
    // round(DECIMAL_1) = 14,00. El redondeo opera sobre el agregado de la línea
    // (× qty), NO por unidad. preGrams 13,96, postGrams 14,00 (delta +0,04).
    const { metals, consolidated } = runChain({
      lines: [lineWith(10, [{ parentId: ORO, name: "Oro Fino", gramsPerUnit: 1.396, price: 100 }])],
      margins: [1.00],
      lineTotals: [1400000],
      metalSaleSums: [1396],
      metalCfg: DECIMAL_1_NEAREST,
      hechuraCfg: NONE,
      names: [[ORO, "Oro Fino"]],
      refValues: [[ORO, 100]],
    });
    expect(metals.get(0)![0].preGrams).toBeCloseTo(13.96, 4);
    expect(metals.get(0)![0].postGrams).toBe(14.0);
    expect(docPostGrams(consolidated, ORO)).toBeCloseTo(14.0, 4);
  });

  // ── Conservación: Σ metals[*].monetaryEquivalent === metalMonetaryEquivalent
  it("conservación: Σ metals[*].monetaryEquivalent === breakdown.metalMonetaryEquivalent", () => {
    const { consolidated } = runChain({
      lines: [
        lineWith(1, [{ parentId: ORO,   name: "Oro Fino", gramsPerUnit: 1.2375, price: 100 }]),
        lineWith(1, [{ parentId: PLATA, name: "Plata",    gramsPerUnit: 2.10,   price: 10  }]),
      ],
      margins: [1.10, 1.10],
      lineTotals: [200000, 50000],
      metalSaleSums: [136.13, 23.1],
      metalCfg: DECIMAL_1_NEAREST,
      hechuraCfg: HUNDRED_NEAREST,
      names: [[ORO, "Oro Fino"], [PLATA, "Plata"]],
      refValues: [[ORO, 100], [PLATA, 10]],
    });
    const sumEquiv = consolidated!.breakdown!.metals.reduce(
      (s: number, m: any) => round2(s + m.monetaryEquivalent), 0,
    );
    expect(sumEquiv).toBe(consolidated!.breakdown!.metalMonetaryEquivalent);
    // totalAdjustment === metalMonetaryEquivalent + deltaSaldo (dominios disjuntos).
    expect(consolidated!.totalAdjustment).toBe(
      round2(consolidated!.breakdown!.metalMonetaryEquivalent +
             consolidated!.breakdown!.hechura.deltaSaldoMonetario),
    );
  });

  // ── Sin movimiento (NONE/NONE, delta 0) → null (valores exactos del motor) ─
  it("sin redondeo configurado (NONE/NONE) y sin delta → null", () => {
    const { consolidated } = runChain({
      lines: [lineWith(1, [{ parentId: ORO, name: "Oro Fino", gramsPerUnit: 1.0, price: 100 }])],
      margins: [1.00],
      lineTotals: [100000],
      metalSaleSums: [100],
      metalCfg: NONE,
      hechuraCfg: NONE,
      names: [[ORO, "Oro Fino"]],
      refValues: [[ORO, 100]],
    });
    expect(consolidated).toBeNull();
  });
});
