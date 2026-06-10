// src/modules/sales/__tests__/mixed-list-monetary-rounding-contract.test.ts
// =============================================================================
// CONTRATO — Redondeo comercial MONETARIO único (post-tax) en listas mixtas.
//
// Regla aprobada (Opción α):
//   "Una línea debe comportarse exactamente igual que si estuviera sola con su
//    misma lista. La presencia de otras listas NO altera su pipeline comercial."
//
// Pipeline ÚNICO permitido para el saldo monetario:
//      Saldo  →  Impuestos  →  Redondeo Comercial  →  Total Línea
//
// PROHIBIDO:  Saldo → Redondeo → Impuestos           (pre-tax)
// PROHIBIDO:  Saldo → Redondeo → Impuestos → Redondeo (doble — origen del 186.100)
//
// Este test NO usa DB. Ejercita los helpers REALES del motor exactamente como
// el servicio debería cablearlos en Opción α:
//   · `applyPriceList`                         (redondeo pre-tax PER_LINE)
//   · `computeLineAutonomousCommercialMoney`   (redondeo post-tax POR LÍNEA)
//   · `consolidateCommercialDocFromPerLine`    (Σ totalPost por línea)
//
// Modelo numérico (estructuralmente equivalente a 185.500 vs 186.100):
//   hechura cruda = 1560 ; impuesto t = 30% ; redondeo HUNDRED NEAREST.
//   · post-tax (único, correcto):  round100(1560 × 1.30) = round100(2028) = 2000
//   · pre-tax  → doble (bug):       round100( round100(1560) × 1.30 )
//                                  = round100(1600 × 1.30) = round100(2080) = 2100
//   La diferencia de 100 reproduce, a escala, la diferencia de 600 del caso real.
//
// =============================================================================

import { describe, it, expect } from "vitest";
import { Prisma } from "@prisma/client";
import { applyPriceList } from "../../../lib/pricing-engine/pricing-engine.pricelist.js";
import { applyCommercialRoundingMonetary } from "../../../lib/pricing-engine/commercial-document-rounding.js";
import {
  computeLineAutonomousCommercialMoney,
  consolidateCommercialDocFromPerLine,
} from "../commercial-doc-rounding-wiring.js";
import type { CommercialDocRoundingPartConfig } from "../../../lib/pricing-engine/commercial-document-rounding.js";

const D = (v: number | string) => new Prisma.Decimal(String(v));

// ── Parámetros del modelo ────────────────────────────────────────────────────
const HECHURA_CRUDA   = 1560;
const TAX_FACTOR       = 1.30;               // impuesto 30%
const HUNDRED: CommercialDocRoundingPartConfig = { mode: "HUNDRED", direction: "NEAREST" };
const NONE:    CommercialDocRoundingPartConfig = { mode: "NONE",    direction: "NEAREST" };

const SINGLE_POST_TAX = 2000;   // round100(1560 × 1.30) — valor CORRECTO
const DOUBLE_ROUNDED  = 2100;   // round100(round100(1560) × 1.30) — bug 186.100-family

const round2 = (n: number) => Math.round(n * 100) / 100;

/** Lista Desglosada (METAL_HECHURA) con redondeo HUNDRED sobre hechura. */
function listDesglosada(over: Record<string, any> = {}) {
  return {
    id:                       "pl-desglosada",
    name:                     "Lista Desglosada HUNDRED",
    mode:                     "METAL_HECHURA",
    marginTotal:              null,
    marginMetal:              "0",
    marginHechura:            "0",
    costPerGram:              null,
    surcharge:                null,
    minimumPrice:             null,
    roundingTarget:           "METAL",      // habilita per-component
    roundingMode:             "NONE",
    roundingDirection:        "NEAREST",
    roundingApplyOn:          "PRICE",
    roundingModeHechura:      "HUNDRED",    // ← redondeo hechura activo (pre-tax)
    roundingDirectionHechura: "NEAREST",
    validFrom:                null,
    validTo:                  null,
    isActive:                 true,
    commercialRoundingMetalDomain:    "MONETARY",
    commercialPhysicalRoundingConfig: null,
    ...over,
  };
}

/** Cost breakdown: solo hechura (metal = 0) → aísla el saldo MONETARIO. */
function costHechura(hechuraCost: number) {
  return {
    value:               D(hechuraCost),
    metalCost:           D(0),
    hechuraCost:         D(hechuraCost),
    totalGrams:          D(0),
    metalGramsWithMerma: D(0),
    metalPurity:         D(0),
    partial:             false,
    mode:                "COST_LINES",
    metalsByParent:      [],
  } as any;
}

/** Saldo monetario POST por línea vía el helper REAL del servicio. */
function lineMoneyPostTax(lineTotalWithTax: number, hechuraCfg: CommercialDocRoundingPartConfig) {
  const money = computeLineAutonomousCommercialMoney({
    lineCommercialRoundingMetals: new Map(),               // sin metal
    refValueByParent:             new Map(),
    lineTotalWithTaxByIdx:        new Map([[0, lineTotalWithTax]]),
    metalSaleSumByIdx:            new Map([[0, 0]]),
    hechuraCfg,
    lineCount:                    1,
  });
  return money.get(0)!;
}

describe("Contrato MIXTO — pipeline monetario único (post-tax)", () => {
  // ───────────────────────────────────────────────────────────────────────────
  // 1) Línea limpia (suppress) → un solo redondeo post-tax = 2000 (correcto)
  // ───────────────────────────────────────────────────────────────────────────
  it("ESCENARIO A (Desglosada sola / homogénea): hechura limpia → redondeo ÚNICO post-tax", () => {
    // Opción α suprime el redondeo PER_LINE → hechura cruda (1560).
    const priced = applyPriceList(
      listDesglosada(),
      costHechura(HECHURA_CRUDA),
      { suppressLineHechuraRounding: true },
    );
    expect(priced.metalHechuraDetail!.hechuraSale).toBe(HECHURA_CRUDA); // sin redondeo pre-tax

    const lineTotalWithTax = round2(priced.metalHechuraDetail!.hechuraSale * TAX_FACTOR);
    const money = lineMoneyPostTax(lineTotalWithTax, HUNDRED);

    expect(money.lineMonetarySaldoPostCommercialRounding).toBe(SINGLE_POST_TAX); // 2000
    expect(money.lineTotalWithTaxPostCommercialRounding).toBe(SINGLE_POST_TAX);
  });

  // ───────────────────────────────────────────────────────────────────────────
  // 2) Línea contaminada (sin suppress) → DOBLE redondeo = 2100 (bug 186.100)
  // ───────────────────────────────────────────────────────────────────────────
  it("DEMUESTRA EL BUG: sin supresión, hechura redondea pre-tax → doble redondeo ≠ post-tax único", () => {
    const priced = applyPriceList(listDesglosada(), costHechura(HECHURA_CRUDA)); // SIN flags
    expect(priced.metalHechuraDetail!.hechuraSale).toBe(1600); // redondeada pre-tax (HUNDRED)

    const lineTotalWithTax = round2(priced.metalHechuraDetail!.hechuraSale * TAX_FACTOR); // 2080
    const money = lineMoneyPostTax(lineTotalWithTax, HUNDRED);

    expect(money.lineMonetarySaldoPostCommercialRounding).toBe(DOUBLE_ROUNDED);   // 2100
    expect(money.lineMonetarySaldoPostCommercialRounding).not.toBe(SINGLE_POST_TAX);
  });

  // ───────────────────────────────────────────────────────────────────────────
  // 3) Opción α en MIXTO: la línea Desglosada limpia da el MISMO valor que sola
  // ───────────────────────────────────────────────────────────────────────────
  it("ESCENARIO C (Unificada + Desglosada): la Desglosada limpia da el MISMO 2000 que sola", () => {
    // En MIXTO, Opción α suprime el redondeo PER_LINE SOLO de la línea Desglosada,
    // usando la lista REAL de esa línea (no la 'lista efectiva' del documento).
    const pricedMixed = applyPriceList(
      listDesglosada(),
      costHechura(HECHURA_CRUDA),
      { suppressLineHechuraRounding: true }, // ← resuelto por la lista propia de la línea
    );
    const lineTotalWithTax = round2(pricedMixed.metalHechuraDetail!.hechuraSale * TAX_FACTOR);
    const moneyMixed = lineMoneyPostTax(lineTotalWithTax, HUNDRED);

    expect(moneyMixed.lineMonetarySaldoPostCommercialRounding).toBe(SINGLE_POST_TAX); // 2000
  });

  // ───────────────────────────────────────────────────────────────────────────
  // 4) INDEPENDENCIA: la presencia de otra línea NO altera la Desglosada
  // ───────────────────────────────────────────────────────────────────────────
  it("La línea Desglosada produce el MISMO total sola y acompañada por una Unificada", () => {
    const desgloLineTotalWithTax  = round2(HECHURA_CRUDA * TAX_FACTOR);      // limpia
    const unifLineTotalWithTax    = 1234.56;                                 // Unificada (NONE)

    // Sola
    const alone = computeLineAutonomousCommercialMoney({
      lineCommercialRoundingMetals: new Map(),
      refValueByParent:             new Map(),
      lineTotalWithTaxByIdx:        new Map([[0, desgloLineTotalWithTax]]),
      metalSaleSumByIdx:            new Map([[0, 0]]),
      hechuraCfg:                   HUNDRED,
      lineCount:                    1,
    });

    // Acompañada (línea 1 = Unificada con config NONE propia)
    const accompanied = computeLineAutonomousCommercialMoney({
      lineCommercialRoundingMetals: new Map(),
      refValueByParent:             new Map(),
      lineTotalWithTaxByIdx:        new Map([[0, desgloLineTotalWithTax], [1, unifLineTotalWithTax]]),
      metalSaleSumByIdx:            new Map([[0, 0], [1, 0]]),
      hechuraCfg:                   HUNDRED,
      hechuraCfgByLineIdx:          new Map([[0, HUNDRED], [1, NONE]]), // cada línea su config
      lineCount:                    2,
    });

    expect(accompanied.get(0)!.lineMonetarySaldoPostCommercialRounding)
      .toBe(alone.get(0)!.lineMonetarySaldoPostCommercialRounding); // 2000 == 2000
    expect(accompanied.get(0)!.lineMonetarySaldoPostCommercialRounding).toBe(SINGLE_POST_TAX);
  });

  // ───────────────────────────────────────────────────────────────────────────
  // 5) REGRESIÓN — consolidar Σ totalPost por línea (no Σ saldoPost heterogéneo)
  // ───────────────────────────────────────────────────────────────────────────
  it("GUARD anti-83.059,70: consolidación = Σ totalPost por línea, cada una cerrada con SU config", () => {
    const desgloLineTotalWithTax = round2(HECHURA_CRUDA * TAX_FACTOR); // limpia → 2028
    const unifLineTotalWithTax   = 1234.56;                            // Unificada NONE

    const money = computeLineAutonomousCommercialMoney({
      lineCommercialRoundingMetals: new Map(),
      refValueByParent:             new Map(),
      lineTotalWithTaxByIdx:        new Map([[0, desgloLineTotalWithTax], [1, unifLineTotalWithTax]]),
      metalSaleSumByIdx:            new Map([[0, 0], [1, 0]]),
      hechuraCfg:                   HUNDRED,
      hechuraCfgByLineIdx:          new Map([[0, HUNDRED], [1, NONE]]),
      lineCount:                    2,
    });

    const line0 = money.get(0)!;
    const line1 = money.get(1)!;

    // Línea 0 (Desglosada) cerrada en HUNDRED.
    expect(line0.lineTotalWithTaxPostCommercialRounding).toBe(SINGLE_POST_TAX); // 2000
    // Línea 1 (Unificada NONE) conserva sus centavos legítimamente — NO se fuerza a HUNDRED.
    expect(line1.lineTotalWithTaxPostCommercialRounding).toBe(1234.56);

    // El total documental = Σ totalPost (cada línea ya cerrada). Los centavos del
    // total provienen SOLO de la línea NONE — NO de mezclar un saldoPost parcial.
    const sumTotalPost = round2(
      line0.lineTotalWithTaxPostCommercialRounding + line1.lineTotalWithTaxPostCommercialRounding,
    );
    expect(sumTotalPost).toBe(3234.56);

    // El bug 83.059,70 nacía de Σ saldoPost mezclando buckets — acá la línea 0 NO
    // aporta centavos: su contribución es múltiplo de 100.
    expect(line0.lineMonetarySaldoPostCommercialRounding % 100).toBe(0);
  });

  // ───────────────────────────────────────────────────────────────────────────
  // 6) PREVIEW === CONFIRM — el helper es determinístico (misma entrada → salida)
  // ───────────────────────────────────────────────────────────────────────────
  it("PREVIEW === CONFIRM: misma entrada produce exactamente la misma salida", () => {
    const lineTotalWithTax = round2(HECHURA_CRUDA * TAX_FACTOR);
    const a = lineMoneyPostTax(lineTotalWithTax, HUNDRED);
    const b = lineMoneyPostTax(lineTotalWithTax, HUNDRED);
    expect(a).toEqual(b);
    expect(a.lineMonetarySaldoPostCommercialRounding).toBe(SINGLE_POST_TAX);
  });
});
