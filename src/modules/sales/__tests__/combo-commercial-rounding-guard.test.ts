// src/modules/sales/__tests__/combo-commercial-rounding-guard.test.ts
// =============================================================================
// BLINDAJE COMBO — regla canónica: COMBO_COMMERCIAL = SALDO_UNIFICADO_MONETARIO.
//
// El combo comercial es una unidad comercial autónoma; sus componentes solo
// construyen su precio. Para el Redondeo Comercial, el combo NUNCA entra al
// dominio metal físico: su guard en `sales.service.ts` (preview + confirm)
// fuerza `metals: []` en la entrada de `aggregateMetalsForCommercialDocRounding`
// cuando `priceSource === "COMBO_COMPONENTS"` o `commercialMode ===
// "COMBO_COMMERCIAL"` (preview: `costMode === "COMBO"`).
//
// Estos tests verifican el CONTRATO que el guard produce (línea con metals:[])
// y la distribución monetaria con base = lineTotalWithTax completo (Punto 2).
// =============================================================================

import { describe, it, expect } from "vitest";
import {
  aggregateMetalsForCommercialDocRounding,
  distributeHechuraRoundingImpactPerLine,
  computeLineAutonomousCommercialMoney,
  comboAwareMetalSaleSum,
  type ResolvedLineForCommercialAgg,
} from "../commercial-doc-rounding-wiring.js";
import type { CommercialDocRoundingPartConfig } from "../../../lib/pricing-engine/commercial-document-rounding.js";

const goldMetal = {
  metalParentId:       "oro",
  metalParentName:     "Oro Fino",
  appliedGramsPerUnit: 2.0,
  quotePriceSnapshot:  100000,
  metalReferenceValue: 120000,
};

describe("BLINDAJE COMBO — combo no aporta al dominio metal físico", () => {
  it("Punto 1/2 — línea combo (metals:[]) NO contribuye a metalsByParent ni gramsPure", () => {
    // idx 0 = combo (el guard ya lo dejó en metals:[]); idx 1 = artículo normal.
    const lines: ResolvedLineForCommercialAgg[] = [
      { quantity: 1, metals: [] },           // combo blindado
      { quantity: 1, metals: [goldMetal] },  // artículo normal con oro
    ];
    const agg = aggregateMetalsForCommercialDocRounding(lines);

    // Solo el oro del artículo normal aparece — el combo no aporta nada.
    expect(agg.metalsByParent).toHaveLength(1);
    expect(agg.metalsByParent[0].metalParentId).toBe("oro");
    expect(agg.metalsByParent[0].gramsPure).toBeCloseTo(2.0, 3);

    // El gramsPure por línea NO tiene entrada para la línea 0 (combo).
    const oroByLine = agg.gramsPureByParentByLineIdx.get("oro");
    expect(oroByLine?.has(0)).toBe(false);  // combo nunca aporta gramos
    expect(oroByLine?.get(1)).toBeCloseTo(2.0, 3);
  });

  it("Punto 5 — artículo normal con metales conserva su agregado intacto", () => {
    // Sin combos: el agregado es idéntico al comportamiento histórico.
    const lines: ResolvedLineForCommercialAgg[] = [
      { quantity: 2, metals: [goldMetal] },
    ];
    const agg = aggregateMetalsForCommercialDocRounding(lines);
    expect(agg.metalsByParent).toHaveLength(1);
    expect(agg.metalsByParent[0].gramsPure).toBeCloseTo(4.0, 3); // 2 g × qty 2
    expect(agg.gramsPureByParentByLineIdx.get("oro")?.get(0)).toBeCloseTo(4.0, 3);
  });

  it("combo SOLO (todas las líneas combo) → agregado metálico vacío", () => {
    const lines: ResolvedLineForCommercialAgg[] = [
      { quantity: 1, metals: [] },
      { quantity: 3, metals: [] },
    ];
    const agg = aggregateMetalsForCommercialDocRounding(lines);
    expect(agg.metalsByParent).toHaveLength(0);
    expect(agg.metalValuationSum).toBe(0);
    expect(agg.gramsPureByParentByLineIdx.size).toBe(0);
  });
});

describe("BLINDAJE COMBO — Punto 2: bucket monetario con base lineTotalWithTax completo", () => {
  it("combo pondera por su valor comercial TOTAL, no por una porción hechura", () => {
    // idx 0 = combo: base = lineTotalWithTax completo (300.000).
    // idx 1 = artículo normal: base = hechuraSale (100.000).
    // delta monetario −8 → reparto 3:1 → combo −6, normal −2 (residuo).
    const base = new Map<number, number>([
      [0, 300000], // combo: lineTotalWithTax completo
      [1, 100000], // normal: hechuraSale
    ]);
    const out = distributeHechuraRoundingImpactPerLine({
      deltaSaldoMonetario: -8,
      hechuraSaleByLineIdx: base,
      lineCount: 2,
    });
    expect(out.get(0)).toBeCloseTo(-6, 2); // combo 75%
    expect(out.get(1)).toBeCloseTo(-2, 2); // normal 25% (residuo)
    // Punto 7 — conservación: el total documental NO cambia (Σ = delta).
    const sum = (out.get(0) ?? 0) + (out.get(1) ?? 0);
    expect(Math.round(sum * 100) / 100).toBeCloseTo(-8, 2);
  });

  it("Punto 7 — cambiar la base del combo NO altera el delta total repartido", () => {
    const delta = 5.0;
    // Mismo delta, distinta base del combo (hechura parcial vs total) → Σ igual.
    const conHechuraParcial = distributeHechuraRoundingImpactPerLine({
      deltaSaldoMonetario: delta,
      hechuraSaleByLineIdx: new Map([[0, 50000], [1, 100000]]),
      lineCount: 2,
    });
    const conTotalCompleto = distributeHechuraRoundingImpactPerLine({
      deltaSaldoMonetario: delta,
      hechuraSaleByLineIdx: new Map([[0, 300000], [1, 100000]]),
      lineCount: 2,
    });
    const sumA = (conHechuraParcial.get(0) ?? 0) + (conHechuraParcial.get(1) ?? 0);
    const sumB = (conTotalCompleto.get(0) ?? 0) + (conTotalCompleto.get(1) ?? 0);
    // El reparto por línea cambia, pero el total es el mismo (= delta).
    expect(Math.round(sumA * 100) / 100).toBeCloseTo(delta, 2);
    expect(Math.round(sumB * 100) / 100).toBeCloseTo(delta, 2);
    // Y el peso del combo (idx 0) SÍ cambia entre ambas bases.
    expect(conTotalCompleto.get(0)).not.toBeCloseTo(conHechuraParcial.get(0) ?? 0, 2);
  });
});

// =============================================================================
// BLINDAJE COMBO — Redondeo Comercial DESGLOSADO POST-IMPUESTOS (metalSaleSum=0)
//
// Contrato canónico: COMBO_COMMERCIAL = saldo monetario PURO. Su `metalSale`
// estimado (derivado por proporción de costo) NO vive en el bucket metal físico
// (el combo no aporta gramos) → NO debe restarse del saldo. Por eso
// `sales.service.ts` pasa `metalSaleSum = 0` para combos a
// `computeLineAutonomousCommercialMoney`, vía `comboAwareMetalSaleSum`.
//
// Efecto: el combo redondea su `lineTotalWithTax` COMPLETO (post-impuestos),
// igual que un artículo tradicional pura-hechura con lista DESGLOSADA. El bucket
// metal queda en 0 y el saldo monetario = total → "card = footer", post-tax.
// =============================================================================
describe("BLINDAJE COMBO — comboAwareMetalSaleSum (helper SSOT)", () => {
  it("combo ⇒ 0 (saldo = lineTotalWithTax completo)", () => {
    expect(comboAwareMetalSaleSum(true, 333281.25)).toBe(0);
  });
  it("no-combo ⇒ metalSale tal cual (su metal vive en el bucket de gramos)", () => {
    expect(comboAwareMetalSaleSum(false, 333281.25)).toBe(333281.25);
  });
  it("no-combo con valor no finito ⇒ 0 defensivo", () => {
    expect(comboAwareMetalSaleSum(false, Number.NaN)).toBe(0);
  });
});

describe("BLINDAJE COMBO — Resumen Comercial DESGLOSADO redondea POST-impuestos completo", () => {
  const HUNDRED: CommercialDocRoundingPartConfig = { mode: "HUNDRED", direction: "NEAREST" };
  // Números reales del caso auditado: total post-tax 518.781,25; metalSale
  // estimado del combo (pre-tax) 333.281,25; lista DESGLOSADA hechura HUNDRED.
  const LINE_TOTAL_WITH_TAX = 518781.25;
  const COMBO_METAL_SALE_EST = 333281.25;

  it("combo (metalSaleSum=0) ⇒ redondea el TOTAL post-impuestos COMPLETO; METAL=0", () => {
    const money = computeLineAutonomousCommercialMoney({
      lineCommercialRoundingMetals: new Map([[0, []]]),  // combo: bucket metal vacío
      refValueByParent:             new Map(),
      lineTotalWithTaxByIdx:        new Map([[0, LINE_TOTAL_WITH_TAX]]),
      metalSaleSumByIdx:            new Map([[0, comboAwareMetalSaleSum(true, COMBO_METAL_SALE_EST)]]),
      hechuraCfg:                   HUNDRED,
      lineCount:                    1,
    }).get(0)!;

    expect(money.metalRoundingMonetaryImpact).toBe(0);                                   // combo sin dominio metal
    expect(money.lineMonetarySaldoPreCommercialRounding).toBeCloseTo(518781.25, 2);      // saldo = total COMPLETO
    expect(money.lineMonetarySaldoPostCommercialRounding).toBeCloseTo(518800, 2);        // round100 POST-tax del total
    expect(money.hechuraRoundingMonetaryImpact).toBeCloseTo(18.75, 2);
    expect(money.lineTotalWithTaxPostCommercialRounding).toBeCloseTo(518800, 2);         // card = footer
    // Invariante DESGLOSADO: METAL post + MONETARIO post = TOTAL línea post.
    expect(money.metalRoundingMonetaryImpact + money.lineMonetarySaldoPostCommercialRounding)
      .toBeCloseTo(money.lineTotalWithTaxPostCommercialRounding, 2);
  });

  it("regresión (bug): sin guard, el combo redondea una base PARCIAL y el redondeo se pierde", () => {
    // metalSaleSum = metalSale interno (333.281,25) → saldo parcial 185.500 (ya
    // múltiplo de 100) → el redondeo comercial del combo "desaparece".
    const money = computeLineAutonomousCommercialMoney({
      lineCommercialRoundingMetals: new Map([[0, []]]),
      refValueByParent:             new Map(),
      lineTotalWithTaxByIdx:        new Map([[0, LINE_TOTAL_WITH_TAX]]),
      metalSaleSumByIdx:            new Map([[0, COMBO_METAL_SALE_EST]]),  // SIN guard
      hechuraCfg:                   HUNDRED,
      lineCount:                    1,
    }).get(0)!;

    expect(money.lineMonetarySaldoPreCommercialRounding).toBeCloseTo(185500, 2);
    expect(money.lineTotalWithTaxPostCommercialRounding).toBeCloseTo(518781.25, 2);  // NO redondeado
    // Demuestra la divergencia que el guard evita (518.781,25 ≠ 518.800):
    expect(money.lineTotalWithTaxPostCommercialRounding).not.toBeCloseTo(518800, 2);
  });

  it("artículo tradicional (no-combo con metal en su bucket) NO se ve afectado por el guard", () => {
    // El metal del tradicional vive en el bucket de gramos (redondea allí), por
    // eso su saldo = total − metalSale ES la base correcta. El guard no lo toca.
    const traditionalMetalSale = comboAwareMetalSaleSum(false, COMBO_METAL_SALE_EST);
    const money = computeLineAutonomousCommercialMoney({
      // deltaGrams 0 → metalImpact 0, pero el bucket metal NO está vacío (es un
      // artículo con metal; su saldo descuenta metalSale).
      lineCommercialRoundingMetals: new Map([[0, [{ metalParentId: "oro", deltaGrams: 0 }]]]),
      refValueByParent:             new Map([["oro", 100000]]),
      lineTotalWithTaxByIdx:        new Map([[0, LINE_TOTAL_WITH_TAX]]),
      metalSaleSumByIdx:            new Map([[0, traditionalMetalSale]]),
      hechuraCfg:                   HUNDRED,
      lineCount:                    1,
    }).get(0)!;

    expect(traditionalMetalSale).toBe(COMBO_METAL_SALE_EST);                              // guard no toca al tradicional
    expect(money.lineMonetarySaldoPreCommercialRounding).toBeCloseTo(185500, 2);          // saldo = total − metalSale
  });
});
