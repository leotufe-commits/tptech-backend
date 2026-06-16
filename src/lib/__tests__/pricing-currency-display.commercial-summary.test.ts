// src/lib/__tests__/pricing-currency-display.commercial-summary.test.ts
// ============================================================================
// FASE 5 — Guard anti-regresión del contrato multimoneda del Resumen Comercial.
//
// Caso real: `lineCommercialSummary` (contrato FASE 1) y `commercialRoundingContext`
// (snapshot del redondeo comercial replicado por línea) NO pasaban por la capa
// única de conversión → en documento dolarizado el card comercial mostraba
// moneda BASE.
//
// Estos tests fijan el contrato (a través del export `convertSalesLineInPlace`):
//   1. Todos los MONTOS de ambos objetos se convierten con rate ≠ 1.
//   2. Los GRAMOS (visibleGrams / pre/post/deltaGrams / metalsPostGrams) NO se
//      convierten (permanecen físicos).
//   3. La metadata (mode/source/scope/ids/names/appliedAt) NO se altera.
// ============================================================================

import { describe, it, expect } from "vitest";
import { convertSalesLineInPlace } from "../pricing-currency-display.js";

// rate = 2 → cada monto convertido = original / 2 (números exactos para asserts).
const RATE = 2;

// `lineCommercialDisplaySummary` tiene el MISMO shape que `lineCommercialSummary`
// (es el primario display-only que el card prioriza). Reusamos la fábrica.
function makeSummary() {
  return {
    mode: "BREAKDOWN",
    metals: {
      visibleGrams: 1.2,
      monetaryAmount: 1000,
      roundingImpact: 50,
      byParent: [
        { metalParentId: "oro-fino", metalParentName: "Oro Fino", visibleGrams: 1.2, monetaryAmount: 1000, roundingImpact: 50 },
      ],
    },
    monetary: { amount: 600, roundingImpact: 20 },
    totalLineAmount: 1600,
    source: { strategy: "PER_DOCUMENT", appliedListMode: null, appliedPriceListId: null, documentContext: "SHARED_LIST", generatedBy: "test" },
  };
}

function makeLine() {
  return {
    // Primario que el card prioriza (display-only). Debe convertirse igual.
    lineCommercialDisplaySummary: makeSummary(),
    lineCommercialSummary: {
      mode: "BREAKDOWN",
      metals: {
        visibleGrams: 1.2,            // físico — NO convertir
        monetaryAmount: 1000,         // monto — /2
        roundingImpact: 50,           // monto — /2
        byParent: [
          {
            metalParentId: "oro-fino",
            metalParentName: "Oro Fino",
            visibleGrams: 1.2,        // físico — NO convertir
            monetaryAmount: 1000,     // monto — /2
            roundingImpact: 50,       // monto — /2
          },
        ],
      },
      monetary: { amount: 600, roundingImpact: 20 }, // montos — /2
      totalLineAmount: 1600,                          // monto — /2
      source: { strategy: "PER_DOCUMENT", appliedListMode: null, appliedPriceListId: null, documentContext: "SHARED_LIST", generatedBy: "test" },
    },
    commercialRoundingContext: {
      source: "PRICE_LIST",
      scope: "BREAKDOWN",
      appliedAt: "DOCUMENT",
      appliedToLineCount: 3,
      totalAdjustment: -100,          // monto — /2
      breakdown: {
        metals: [
          {
            metalParentId: "oro-fino",
            metalParentName: "Oro Fino",
            preGrams: 1.238,          // físico — NO
            postGrams: 1.2,           // físico — NO
            deltaGrams: -0.038,       // físico — NO
            metalPricePerGram: 70000, // precio/gramo (monto) — /2
            monetaryEquivalent: -2650,// monto — /2
            preAmount: 86660,         // monto — /2
            postAmount: 84000,        // monto — /2
            mode: "DECIMAL_1",
            direction: "NEAREST",
          },
        ],
        metalMonetaryEquivalent: -2650, // monto — /2
        combinedAdjustment: -100,        // monto — /2
        hechura: {
          preRoundingSaldoMonetario: 185475.21,  // monto — /2
          postRoundingSaldoMonetario: 185500,     // monto — /2
          deltaSaldoMonetario: 24.79,             // monto — /2
          mode: "HUNDRED",
          direction: "NEAREST",
          source: "PRICE_LIST_HECHURA",
        },
        metalsPostGrams: [
          { metalParentId: "oro-fino", metalParentName: "Oro Fino", preGrams: 1.238, postGrams: 1.2 }, // físicos — NO
        ],
      },
      fallback: null,
    },
    // Resumen Comercial AUTÓNOMO de la línea (familia `lineOwn*`) — los CUATRO
    // campos MONETARIOS. Todos deben convertirse (rate ≠ 1 → /2).
    lineOwnMetalRoundingMonetaryImpact: -2650,
    lineOwnHechuraRoundingMonetaryImpact: 24.79,
    lineOwnTotalWithTaxPostCommercialRounding: 518781.25,
    lineOwnMonetarySaldoPostCommercialRounding: 185500,
    // composition.metals[] — el card deriva saleAmountLinePre desde
    // `lineSalePreRounding` (PRE redondeo comercial). Montos /2; gramos intactos.
    composition: {
      metals: [
        {
          metalParentId: "oro-fino",
          metalName: "Oro Fino",
          appliedGrams: 1.2,            // físico — NO
          appliedMermaPct: 3,           // % — NO
          lineSale: 333281.25,          // monto — /2 (ya cubierto pre-FASE5)
          lineSalePreRounding: 340312.5,// monto — /2 (campo agregado este cierre)
          quotePrice: 70000,            // precio/gramo — /2
          lineCost: 250000,             // monto — /2
        },
      ],
    },
  };
}

describe("FASE 5 — conversión multimoneda de lineCommercialSummary / commercialRoundingContext", () => {
  it("convierte TODOS los montos con rate ≠ 1 y NO toca gramos ni metadata", () => {
    const line = makeLine();
    convertSalesLineInPlace(line as any, RATE);

    // PRIMARIO display-only — debe convertirse igual que el fallback.
    const d = line.lineCommercialDisplaySummary;
    expect(d.metals!.monetaryAmount).toBeCloseTo(500, 6);
    expect(d.metals!.roundingImpact).toBeCloseTo(25, 6);
    expect(d.metals!.byParent[0].monetaryAmount).toBeCloseTo(500, 6);
    expect(d.monetary.amount).toBeCloseTo(300, 6);
    expect(d.monetary.roundingImpact).toBeCloseTo(10, 6);
    expect(d.totalLineAmount).toBeCloseTo(800, 6);
    // gramos / metadata intactos en el primario
    expect(d.metals!.visibleGrams).toBe(1.2);
    expect(d.metals!.byParent[0].visibleGrams).toBe(1.2);
    expect(d.mode).toBe("BREAKDOWN");
    expect(d.metals!.byParent[0].metalParentName).toBe("Oro Fino");

    const s = line.lineCommercialSummary;
    // montos /2
    expect(s.metals!.monetaryAmount).toBeCloseTo(500, 6);
    expect(s.metals!.roundingImpact).toBeCloseTo(25, 6);
    expect(s.metals!.byParent[0].monetaryAmount).toBeCloseTo(500, 6);
    expect(s.metals!.byParent[0].roundingImpact).toBeCloseTo(25, 6);
    expect(s.monetary.amount).toBeCloseTo(300, 6);
    expect(s.monetary.roundingImpact).toBeCloseTo(10, 6);
    expect(s.totalLineAmount).toBeCloseTo(800, 6);
    // gramos / metadata intactos
    expect(s.metals!.visibleGrams).toBe(1.2);
    expect(s.metals!.byParent[0].visibleGrams).toBe(1.2);
    expect(s.mode).toBe("BREAKDOWN");
    expect(s.metals!.byParent[0].metalParentName).toBe("Oro Fino");
    expect(s.source.strategy).toBe("PER_DOCUMENT");

    const c = line.commercialRoundingContext;
    // montos /2
    expect(c.totalAdjustment).toBeCloseTo(-50, 6);
    const m = c.breakdown.metals[0];
    expect(m.metalPricePerGram).toBeCloseTo(35000, 6);
    expect(m.monetaryEquivalent).toBeCloseTo(-1325, 6);
    expect(m.preAmount).toBeCloseTo(43330, 6);
    expect(m.postAmount).toBeCloseTo(42000, 6);
    expect(c.breakdown.metalMonetaryEquivalent).toBeCloseTo(-1325, 6);
    expect(c.breakdown.combinedAdjustment).toBeCloseTo(-50, 6);
    expect(c.breakdown.hechura.preRoundingSaldoMonetario).toBeCloseTo(92737.605, 6);
    expect(c.breakdown.hechura.postRoundingSaldoMonetario).toBeCloseTo(92750, 6);
    expect(c.breakdown.hechura.deltaSaldoMonetario).toBeCloseTo(12.395, 6);
    // gramos físicos intactos
    expect(m.preGrams).toBe(1.238);
    expect(m.postGrams).toBe(1.2);
    expect(m.deltaGrams).toBe(-0.038);
    expect(c.breakdown.metalsPostGrams[0].preGrams).toBe(1.238);
    expect(c.breakdown.metalsPostGrams[0].postGrams).toBe(1.2);
    // metadata intacta
    expect(c.scope).toBe("BREAKDOWN");
    expect(c.appliedAt).toBe("DOCUMENT");
    expect(c.appliedToLineCount).toBe(3);
    expect(m.mode).toBe("DECIMAL_1");
    expect(c.breakdown.hechura.source).toBe("PRICE_LIST_HECHURA");

    // Resumen Comercial AUTÓNOMO — los CUATRO campos monetarios /2.
    expect(line.lineOwnMetalRoundingMonetaryImpact).toBeCloseTo(-1325, 6);
    expect(line.lineOwnHechuraRoundingMonetaryImpact).toBeCloseTo(12.395, 6);
    expect(line.lineOwnTotalWithTaxPostCommercialRounding).toBeCloseTo(259390.625, 6); // 518781.25 / 2
    expect(line.lineOwnMonetarySaldoPostCommercialRounding).toBeCloseTo(92750, 6);      // 185500 / 2

    // composition.metals[] — montos /2 (incl. lineSalePreRounding del cierre),
    // gramos y % intactos.
    const cm = line.composition.metals[0];
    expect(cm.lineSalePreRounding).toBeCloseTo(170156.25, 6); // 340312.5 / 2
    expect(cm.lineSale).toBeCloseTo(166640.625, 6);            // 333281.25 / 2
    expect(cm.quotePrice).toBeCloseTo(35000, 6);
    expect(cm.lineCost).toBeCloseTo(125000, 6);
    expect(cm.appliedGrams).toBe(1.2);     // físico intacto
    expect(cm.appliedMermaPct).toBe(3);    // % intacto
  });

  // ──────────────────────────────────────────────────────────────────────────
  // GUARD del contrato: el Resumen Comercial AUTÓNOMO de la línea (familia
  // `lineOwn*`) tiene EXACTAMENTE estos cuatro campos monetarios. TODOS deben
  // convertirse BASE → display en `convertSalesLineInPlace`. Si agregás un
  // nuevo campo `lineOwn*` monetario, sumalo a esta lista Y a la función de
  // conversión — de lo contrario el card mostrará "símbolo nuevo, importe viejo".
  // ──────────────────────────────────────────────────────────────────────────
  const AUTONOMOUS_MONETARY_FIELDS = [
    "lineOwnMetalRoundingMonetaryImpact",
    "lineOwnHechuraRoundingMonetaryImpact",
    "lineOwnTotalWithTaxPostCommercialRounding",
    "lineOwnMonetarySaldoPostCommercialRounding",
  ] as const;

  it("convierte TODOS los campos monetarios del Resumen Comercial autónomo (familia lineOwn*)", () => {
    const line: Record<string, number> = {};
    for (const f of AUTONOMOUS_MONETARY_FIELDS) line[f] = 1000;
    convertSalesLineInPlace(line as any, RATE);
    for (const f of AUTONOMOUS_MONETARY_FIELDS) {
      // Si quedó en 1000 (sin /2) el campo NO se está convirtiendo → regresión.
      expect(line[f], `${f} debe convertirse BASE → display`).toBeCloseTo(500, 6);
    }
  });

  it("rate = 1 (sin conversión) → no muta nada", () => {
    const line = makeLine();
    convertSalesLineInPlace(line as any, 1);
    expect(line.lineCommercialDisplaySummary.totalLineAmount).toBe(1600);
    expect(line.lineCommercialSummary.totalLineAmount).toBe(1600);
    expect(line.lineOwnMetalRoundingMonetaryImpact).toBe(-2650);
    expect(line.lineOwnHechuraRoundingMonetaryImpact).toBe(24.79);
    expect(line.lineOwnTotalWithTaxPostCommercialRounding).toBe(518781.25);
    expect(line.lineOwnMonetarySaldoPostCommercialRounding).toBe(185500);
    expect(line.composition.metals[0].lineSalePreRounding).toBe(340312.5);
    expect(line.composition.metals[0].lineSale).toBe(333281.25);
    expect(line.commercialRoundingContext.totalAdjustment).toBe(-100);
    expect(line.commercialRoundingContext.breakdown.metals[0].monetaryEquivalent).toBe(-2650);
  });
});
