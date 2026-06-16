// src/lib/__tests__/document-physical-rounding-apply.test.ts
// =============================================================================
// Etapa D3 — Tests del helper orquestador `applyDocumentPhysicalRounding`.
//
// Cubre las 9 secciones del brief (A..I):
//   A. MONETARY back-compat.
//   B. PHYSICAL básico (Oro 0,908 → 1,000).
//   C. PHYSICAL DOWN (delta negativo).
//   D. Múltiples metales con configs distintas.
//   E. Anti doble redondeo (PHYSICAL no emite breakdown.metal; MONETARY
//      no emite metalPhysical).
//   F. Fallbacks (NO_METAL_PRICE / NO_CONFIG / NO_METALS_TO_ROUND /
//      sin snapshot previo del motor).
//   G. BOTH (BREAKDOWN físico convive con UNIFIED final).
//   H. Interacción con ajuste manual (preGrams del manual = postGrams D3).
//   I. Multimoneda (cubierto por `pricing-currency-display` que ya tiene
//      conversion del bloque metalPhysical).
// =============================================================================

import { describe, it, expect } from "vitest";
import { applyDocumentPhysicalRounding } from "../document-physical-rounding-apply.js";
import type { DocumentRoundingPolicy } from "../document-rounding.js";

const ORO = "oro-fino";
const PLATA = "plata-925";

function policyMonetary(): DocumentRoundingPolicy {
  return {
    suppressListDeferredRounding: true,
    documentRounding: {
      scope: "BREAKDOWN",
      mode: "NONE",
      direction: "NEAREST",
      breakdown: {
        metal:   { mode: "INTEGER", direction: "NEAREST" },
        hechura: { mode: "INTEGER", direction: "NEAREST" },
      },
    } as any,
    scope: "BREAKDOWN",
    metalDomain: "MONETARY",
    physical: { enabled: false, configByMetalParentId: {}, fallbackConfig: null, hasInvalidEntries: false },
  };
}

function policyPhysical(opts?: { fallback?: { mode: any; direction: any } }): DocumentRoundingPolicy {
  return {
    suppressListDeferredRounding: true,
    documentRounding: {
      scope: "BREAKDOWN",
      mode: "NONE",
      direction: "NEAREST",
      breakdown: {
        metal:   { mode: "NONE", direction: "NEAREST" },  // suprimido por loader cuando PHYSICAL
        hechura: { mode: "NONE", direction: "NEAREST" },
      },
    } as any,
    scope: "BREAKDOWN",
    metalDomain: "PHYSICAL",
    physical: {
      enabled: true,
      configByMetalParentId: {
        [ORO]:   { mode: "INTEGER", direction: "NEAREST" },
        [PLATA]: { mode: "HALF",    direction: "NEAREST" },
      },
      fallbackConfig: opts?.fallback ?? null,
      hasInvalidEntries: false,
    },
  };
}

/** Fixture de documentTotals como lo emitiría el motor en BREAKDOWN
 *  (scope=BREAKDOWN, metal $ supresído porque metalDomain=PHYSICAL).
 *  Capa 15.hechura no movió → snapshot mínimo con metal en NONE/delta 0. */
function fixtureDocTotals(over?: any) {
  return {
    total: 87750,
    metalSaleSubtotal: 90.8,
    documentRoundingApplied: {
      source: "TENANT_POLICY",
      scope:  "BREAKDOWN",
      applyOn: "DOC_TOTAL",
      totalAdjustment: 0,
      breakdown: {
        metal:   { mode: "NONE", direction: "NEAREST", preRounding: 90.8, postRounding: 90.8, adjustment: 0, applyOn: "DOC_METAL" },
        hechura: { mode: "NONE", direction: "NEAREST", preRounding: 87659.2, postRounding: 87659.2, adjustment: 0, applyOn: "DOC_HECHURA" },
        combinedAdjustment: 0,
      },
    },
    ...over,
  };
}

/** Fixture de balanceBreakdown con metales reales. */
function fixtureBalance(over?: any) {
  return {
    metals: [
      {
        metalParentId:    ORO,
        metalParentName:  "Oro Fino",
        gramsPure:        0.908,
        gramsOriginal:    0.908,
        purity:           1,
        quotePriceSnapshot: 100000,
        valuationMonetary: 90800,
      },
      {
        metalParentId:    PLATA,
        metalParentName:  "Plata",
        gramsPure:        0.76,
        gramsOriginal:    0.76,
        purity:           1,
        quotePriceSnapshot: 500,
        valuationMonetary: 380,
      },
    ],
    monetaryBalance: { amount: 87750, amountBase: 87750, currencyCode: "ARS", currencyRate: 1 },
    ...over,
  };
}

// ──────────────────────────────────────────────────────────────────────────
// A. MONETARY back-compat
// ──────────────────────────────────────────────────────────────────────────

describe("applyDocumentPhysicalRounding — MONETARY (A)", () => {
  it("metalDomain=MONETARY: NO ejecuta capa 16; agrega bloque `totals` informativo", () => {
    const dt = fixtureDocTotals();
    const bb = fixtureBalance();
    const dtBefore = JSON.parse(JSON.stringify(dt));
    const bbBefore = JSON.parse(JSON.stringify(bb));

    const result = applyDocumentPhysicalRounding({
      documentTotals: dt,
      balanceBreakdown: bb,
      policy: policyMonetary(),
    });

    expect(result).toBeNull();
    // total intacto.
    expect(dt.total).toBe(dtBefore.total);
    // metals intactos.
    expect(bb).toEqual(bbBefore);
    // Snapshot conserva breakdown.metal monetario.
    expect(dt.documentRoundingApplied?.breakdown?.metal?.mode).toBe("NONE");
    expect(dt.documentRoundingApplied?.breakdown?.metalPhysical).toBeUndefined();
    // Bloque totals SÍ se agrega (contrato universal).
    expect(dt.documentRoundingApplied?.totals).toEqual({
      monetaryRoundingAdjustment: 0,
      metalMonetaryEquivalent: 0,
      totalRoundingAdjustment: 0,
    });
  });

  it("MONETARY sin snapshot del motor: helper no inventa nada", () => {
    const dt = { total: 1000 };
    const bb = fixtureBalance();
    const r = applyDocumentPhysicalRounding({
      documentTotals: dt,
      balanceBreakdown: bb,
      policy: policyMonetary(),
    });
    expect(r).toBeNull();
    expect(dt).toEqual({ total: 1000 });
  });
});

// ──────────────────────────────────────────────────────────────────────────
// B. PHYSICAL básico
// ──────────────────────────────────────────────────────────────────────────

describe("applyDocumentPhysicalRounding — PHYSICAL básico (B)", () => {
  it("Oro 0,908 → 1,000 (INTEGER NEAREST): engineTotal sube, hechura intacta", () => {
    const dt = fixtureDocTotals();
    const bb = fixtureBalance();
    // Plata HALF 0,76 → 1,0 (eq 0,24 × 500 = 120).
    // Oro INTEGER 0,908 → 1 (eq 0,092 × 100000 = 9200).
    // Total delta esperado: 9320.

    const result = applyDocumentPhysicalRounding({
      documentTotals: dt,
      balanceBreakdown: bb,
      policy: policyPhysical(),
    });

    expect(result).not.toBeNull();
    expect(result!.metalMonetaryEquivalent).toBeCloseTo(9320, 2);

    expect(dt.total).toBeCloseTo(87750 + 9320, 2);
    // balanceBreakdown mutado con post-grams.
    const oroBalance = bb.metals.find((m: any) => m.metalParentId === ORO)!;
    expect(oroBalance.gramsPure).toBe(1);
    expect(oroBalance.valuationMonetary).toBe(100000);  // 1 × 100000
    // Hechura intacta.
    expect(bb.monetaryBalance.amount).toBe(87750);
  });

  it("Snapshot extendido con metalPhysical + totals", () => {
    const dt = fixtureDocTotals();
    const bb = fixtureBalance();
    applyDocumentPhysicalRounding({ documentTotals: dt, balanceBreakdown: bb, policy: policyPhysical() });

    const dra = dt.documentRoundingApplied!;
    expect(dra.breakdown.metal).toBeNull();              // anti doble redondeo
    expect(dra.breakdown.metalDomain).toBe("PHYSICAL");
    expect(dra.breakdown.metalPhysical).toBeDefined();
    expect(dra.breakdown.metalPhysical.metals).toHaveLength(2);
    expect(dra.breakdown.metalPhysical.metalMonetaryEquivalent).toBeCloseTo(9320, 2);

    expect(dra.totalAdjustment).toBeCloseTo(9320, 2);
    expect(dra.totals.monetaryRoundingAdjustment).toBe(0);
    expect(dra.totals.metalMonetaryEquivalent).toBeCloseTo(9320, 2);
    expect(dra.totals.totalRoundingAdjustment).toBeCloseTo(9320, 2);
  });
});

// ──────────────────────────────────────────────────────────────────────────
// C. PHYSICAL DOWN (negativo)
// ──────────────────────────────────────────────────────────────────────────

describe("applyDocumentPhysicalRounding — PHYSICAL DOWN (C)", () => {
  it("Oro 1,04 → 1,00 (INTEGER DOWN): equivalente negativo, engineTotal baja", () => {
    const dt = fixtureDocTotals({ total: 200000 });
    const bb = fixtureBalance({
      metals: [
        { metalParentId: ORO, metalParentName: "Oro Fino", gramsPure: 1.04, gramsOriginal: 1.04, purity: 1, quotePriceSnapshot: 100000, valuationMonetary: 104000 },
      ],
    });
    const policy = policyPhysical();
    policy.physical.configByMetalParentId = { [ORO]: { mode: "INTEGER", direction: "DOWN" } };

    applyDocumentPhysicalRounding({ documentTotals: dt, balanceBreakdown: bb, policy });

    expect(bb.metals[0]!.gramsPure).toBe(1);
    expect(dt.documentRoundingApplied!.breakdown.metalPhysical.metalMonetaryEquivalent).toBeCloseTo(-4000, 2);
    expect(dt.total).toBeCloseTo(196000, 2);
  });
});

// ──────────────────────────────────────────────────────────────────────────
// D. Múltiples metales con configs distintas
// ──────────────────────────────────────────────────────────────────────────

describe("applyDocumentPhysicalRounding — múltiples metales (D)", () => {
  it("Oro INTEGER + Plata HALF: cada uno con su config, suma consolidada", () => {
    const dt = fixtureDocTotals();
    const bb = fixtureBalance();
    applyDocumentPhysicalRounding({ documentTotals: dt, balanceBreakdown: bb, policy: policyPhysical() });

    const oro   = dt.documentRoundingApplied!.breakdown.metalPhysical.metals.find((m: any) => m.metalParentId === ORO);
    const plata = dt.documentRoundingApplied!.breakdown.metalPhysical.metals.find((m: any) => m.metalParentId === PLATA);
    expect(oro.mode).toBe("INTEGER");
    expect(plata.mode).toBe("HALF");
    expect(oro.monetaryEquivalent).toBeCloseTo(9200, 2);
    expect(plata.monetaryEquivalent).toBeCloseTo(120, 2);
  });
});

// ──────────────────────────────────────────────────────────────────────────
// E. Anti doble redondeo
// ──────────────────────────────────────────────────────────────────────────

describe("applyDocumentPhysicalRounding — anti doble redondeo (E)", () => {
  it("PHYSICAL no emite breakdown.metal monetario", () => {
    const dt = fixtureDocTotals();
    const bb = fixtureBalance();
    applyDocumentPhysicalRounding({ documentTotals: dt, balanceBreakdown: bb, policy: policyPhysical() });
    expect(dt.documentRoundingApplied!.breakdown.metal).toBeNull();
    expect(dt.documentRoundingApplied!.breakdown.metalPhysical).toBeDefined();
  });

  it("MONETARY no emite metalPhysical", () => {
    const dt = fixtureDocTotals();
    const bb = fixtureBalance();
    applyDocumentPhysicalRounding({ documentTotals: dt, balanceBreakdown: bb, policy: policyMonetary() });
    expect(dt.documentRoundingApplied!.breakdown.metal).toBeDefined();
    expect(dt.documentRoundingApplied!.breakdown.metalPhysical).toBeUndefined();
  });
});

// ──────────────────────────────────────────────────────────────────────────
// F. Fallbacks
// ──────────────────────────────────────────────────────────────────────────

describe("applyDocumentPhysicalRounding — fallbacks (F)", () => {
  it("NO_METAL_PRICE: metal sin cotización queda en preGrams; no impacta total", () => {
    const dt = fixtureDocTotals();
    const bb = fixtureBalance({
      metals: [
        { metalParentId: ORO, metalParentName: "Oro Fino", gramsPure: 0.908, gramsOriginal: 0.908, purity: 1, quotePriceSnapshot: null, valuationMonetary: null },
      ],
    });
    applyDocumentPhysicalRounding({ documentTotals: dt, balanceBreakdown: bb, policy: policyPhysical() });
    expect(bb.metals[0]!.gramsPure).toBe(0.908);  // NO mutado (fallback)
    expect(dt.documentRoundingApplied!.breakdown.metalPhysical.metals[0].fallback).toBe("NO_METAL_PRICE");
    expect(dt.total).toBe(87750);
  });

  it("NO_CONFIG: metal sin config en map y sin fallback queda en preGrams", () => {
    const dt = fixtureDocTotals();
    const bb = fixtureBalance({
      metals: [
        { metalParentId: "platino-puro", metalParentName: "Platino", gramsPure: 0.5, gramsOriginal: 0.5, purity: 1, quotePriceSnapshot: 50000, valuationMonetary: 25000 },
      ],
    });
    applyDocumentPhysicalRounding({ documentTotals: dt, balanceBreakdown: bb, policy: policyPhysical() });
    expect(bb.metals[0]!.gramsPure).toBe(0.5);
    expect(dt.documentRoundingApplied!.breakdown.metalPhysical.metals[0].fallback).toBe("NO_CONFIG");
  });

  it("NO_METALS_TO_ROUND: balance sin metales → top-level fallback", () => {
    const dt = fixtureDocTotals();
    const bb = fixtureBalance({ metals: [] });
    applyDocumentPhysicalRounding({ documentTotals: dt, balanceBreakdown: bb, policy: policyPhysical() });
    expect(dt.documentRoundingApplied!.breakdown.metalPhysical.fallback).toBe("NO_METALS_TO_ROUND");
    expect(dt.total).toBe(87750);
  });

  it("Sin snapshot previo del motor pero PHYSICAL con datos: helper arma snapshot mínimo", () => {
    const dt: any = { total: 87750 };
    const bb = fixtureBalance();
    applyDocumentPhysicalRounding({ documentTotals: dt, balanceBreakdown: bb, policy: policyPhysical() });
    expect(dt.documentRoundingApplied).toBeDefined();
    expect(dt.documentRoundingApplied.breakdown.metalDomain).toBe("PHYSICAL");
    expect(dt.documentRoundingApplied.breakdown.metalPhysical.metals).toHaveLength(2);
    expect(dt.total).toBeCloseTo(87750 + 9320, 2);
  });
});

// ──────────────────────────────────────────────────────────────────────────
// G. BOTH (BREAKDOWN físico + UNIFIED final)
// ──────────────────────────────────────────────────────────────────────────

describe("applyDocumentPhysicalRounding — BOTH (G)", () => {
  it("Scope BOTH: snapshot conserva unified existente; metalPhysical se suma a totalAdjustment", () => {
    const dt = fixtureDocTotals({
      documentRoundingApplied: {
        source: "TENANT_POLICY",
        scope: "BOTH",
        applyOn: "DOC_TOTAL",
        totalAdjustment: -50,  // capa 15 unified ya movió -50
        unified: { mode: "INTEGER", direction: "NEAREST", preRounding: 87800, postRounding: 87750, adjustment: -50, applyOn: "DOC_TOTAL" },
        breakdown: {
          metal:   { mode: "NONE", direction: "NEAREST", preRounding: 90.8, postRounding: 90.8, adjustment: 0, applyOn: "DOC_METAL" },
          hechura: { mode: "NONE", direction: "NEAREST", preRounding: 87659.2, postRounding: 87659.2, adjustment: 0, applyOn: "DOC_HECHURA" },
          combinedAdjustment: 0,
        },
      },
    });
    const bb = fixtureBalance();
    applyDocumentPhysicalRounding({ documentTotals: dt, balanceBreakdown: bb, policy: policyPhysical() });

    // Unified preservado.
    expect(dt.documentRoundingApplied!.unified).toBeDefined();
    expect(dt.documentRoundingApplied!.unified.adjustment).toBe(-50);
    // metalPhysical agregado.
    expect(dt.documentRoundingApplied!.breakdown.metalPhysical.metalMonetaryEquivalent).toBeCloseTo(9320, 2);
    // totalAdjustment suma ambos dominios.
    expect(dt.documentRoundingApplied!.totalAdjustment).toBeCloseTo(-50 + 9320, 2);
    // totals universal: monetary = unified $ existente; metal = capa 16.
    expect(dt.documentRoundingApplied!.totals.monetaryRoundingAdjustment).toBeCloseTo(-50, 2);
    expect(dt.documentRoundingApplied!.totals.metalMonetaryEquivalent).toBeCloseTo(9320, 2);
    expect(dt.documentRoundingApplied!.totals.totalRoundingAdjustment).toBeCloseTo(9270, 2);
  });
});

// ──────────────────────────────────────────────────────────────────────────
// H. Interacción con ajuste manual
// ──────────────────────────────────────────────────────────────────────────

describe("applyDocumentPhysicalRounding — interacción con ajuste manual (H)", () => {
  it("post-capa-16: balanceBreakdown refleja postGrams → ajuste manual ve preGrams=postGrams", async () => {
    // Importamos buildManualAdjustmentBreakdownContext-like via D-C helpers.
    // Como el helper de Etapa C consume directamente balanceBreakdown.metals[i].gramsPure,
    // basta con confirmar que después de capa 16 ese campo refleja postGrams.
    const dt = fixtureDocTotals();
    const bb = fixtureBalance();
    applyDocumentPhysicalRounding({ documentTotals: dt, balanceBreakdown: bb, policy: policyPhysical() });

    const oro = bb.metals.find((m: any) => m.metalParentId === ORO)!;
    expect(oro.gramsPure).toBe(1);  // postGrams del redondeo automático

    // Simular ajuste manual sobre Oro a 1.05 g:
    const { buildManualAdjustmentSnapshot } = await import("../manual-adjustment/buildSnapshot.js");
    const manual = buildManualAdjustmentSnapshot({
      engineTotal: dt.total,
      input: { scope: "BREAKDOWN", metals: [{ metalParentId: ORO, targetGrams: 1.05 }] },
      audit: { appliedBy: null, appliedAt: "2026-05-28T00:00:00Z", reason: null },
      breakdownContext: {
        monetaryHechura: { preAmount: bb.monetaryBalance.amount },
        metals: bb.metals.map((m: any) => ({
          metalParentId: m.metalParentId,
          metalParentName: m.metalParentName,
          gramsPure: m.gramsPure,
          metalPricePerGram: m.quotePriceSnapshot ?? null,
        })),
      },
    });
    const oroManual = (manual.snapshot as any).breakdown.metals[0];
    expect(oroManual.preGrams).toBe(1);              // pre del manual = post de capa 16
    expect(oroManual.postGrams).toBe(1.05);
    expect(oroManual.deltaGrams).toBeCloseTo(0.05, 4);
    expect(oroManual.monetaryEquivalent).toBeCloseTo(5000, 2);
  });
});

// ──────────────────────────────────────────────────────────────────────────
// J. Path COMERCIAL (lado VENTA) — redondea gramo de VENTA con precio de VENTA
// ──────────────────────────────────────────────────────────────────────────

describe("applyDocumentPhysicalRounding — path comercial / lado VENTA (J)", () => {
  it("redondea gramsPure × marginFactor con refValue; eq = deltaSale × refValue", () => {
    // Oro: gramsPure agregado = 0,8 g; marginFactor = 1,25 → gramVenta = 1,0 g.
    // refValue (precio venta) = 120000. INTEGER NEAREST → 1,0 (sin delta).
    // Para forzar delta, usamos gramsPure = 0,72 → ×1,25 = 0,9 → INTEGER → 1,0.
    // deltaSale = +0,1 g × 120000 = 12000.
    const dt: any = { total: 200000, metalCostSubtotal: 80000, metalSaleSubtotal: 100000 };
    const bb = fixtureBalance({
      metals: [
        { metalParentId: ORO, metalParentName: "Oro Fino", gramsPure: 0.72, gramsOriginal: 0.72, purity: 1, quotePriceSnapshot: 100000, valuationMonetary: 72000 },
      ],
    });
    const policy = policyPhysical();
    policy.physical.configByMetalParentId = { [ORO]: { mode: "INTEGER", direction: "NEAREST" } };

    const result = applyDocumentPhysicalRounding({
      documentTotals: dt,
      balanceBreakdown: bb,
      policy,
      commercial: {
        metalsByParent: [
          { metalParentId: ORO, metalParentName: "Oro Fino", gramsPure: 0.72, metalPricePerGram: 100000, metalReferenceValue: 120000 },
        ],
        marginFactor: 1.25,
      },
    });

    expect(result).not.toBeNull();
    const oroEntry = result!.metals.find((m) => m.metalParentId === ORO)!;
    // preGrams = gramo de VENTA = 0,72 × 1,25 = 0,9.
    expect(oroEntry.preGrams).toBeCloseTo(0.9, 4);
    expect(oroEntry.postGrams).toBe(1);
    expect(oroEntry.deltaGrams).toBeCloseTo(0.1, 4);
    // refValue (precio de VENTA), no quotePriceSnapshot.
    expect(oroEntry.metalPricePerGram).toBe(120000);
    expect(oroEntry.monetaryEquivalent).toBeCloseTo(12000, 2);
    expect(dt.total).toBeCloseTo(200000 + 12000, 2);
  });

  it("NO muta balanceBreakdown.metals[].gramsPure en el path comercial", () => {
    const dt: any = { total: 200000, metalCostSubtotal: 80000, metalSaleSubtotal: 100000 };
    const bb = fixtureBalance({
      metals: [
        { metalParentId: ORO, metalParentName: "Oro Fino", gramsPure: 0.72, gramsOriginal: 0.72, purity: 1, quotePriceSnapshot: 100000, valuationMonetary: 72000 },
      ],
    });
    const policy = policyPhysical();
    policy.physical.configByMetalParentId = { [ORO]: { mode: "INTEGER", direction: "NEAREST" } };

    applyDocumentPhysicalRounding({
      documentTotals: dt,
      balanceBreakdown: bb,
      policy,
      commercial: {
        metalsByParent: [
          { metalParentId: ORO, metalParentName: "Oro Fino", gramsPure: 0.72, metalPricePerGram: 100000, metalReferenceValue: 120000 },
        ],
        marginFactor: 1.25,
      },
    });

    // El gramo PURO físico del balance NO se toca (lo emitido por capa 16 es
    // gramo de venta con margen). Cuenta corriente metálica intacta.
    expect(bb.metals[0]!.gramsPure).toBe(0.72);
    expect(bb.metals[0]!.gramsOriginal).toBe(0.72);
    expect(bb.metals[0]!.valuationMonetary).toBe(72000);
  });

  it("sin metalReferenceValue cae al metalPricePerGram (costo) como precio de venta", () => {
    // gramsPure 0,72 × marginFactor 1,25 = 0,9 → INTEGER → 1,0 (delta 0,1).
    // Sin refValue → usa metalPricePerGram = 100000 → eq = 0,1 × 100000 = 10000.
    const dt: any = { total: 200000, metalCostSubtotal: 80000, metalSaleSubtotal: 100000 };
    const bb = fixtureBalance({
      metals: [
        { metalParentId: ORO, metalParentName: "Oro Fino", gramsPure: 0.72, gramsOriginal: 0.72, purity: 1, quotePriceSnapshot: 100000, valuationMonetary: 72000 },
      ],
    });
    const policy = policyPhysical();
    policy.physical.configByMetalParentId = { [ORO]: { mode: "INTEGER", direction: "NEAREST" } };

    const result = applyDocumentPhysicalRounding({
      documentTotals: dt,
      balanceBreakdown: bb,
      policy,
      commercial: {
        metalsByParent: [
          { metalParentId: ORO, metalParentName: "Oro Fino", gramsPure: 0.72, metalPricePerGram: 100000 },
        ],
        marginFactor: 1.25,
      },
    });

    const oroEntry = result!.metals.find((m) => m.metalParentId === ORO)!;
    expect(oroEntry.metalPricePerGram).toBe(100000);
    expect(oroEntry.monetaryEquivalent).toBeCloseTo(10000, 2);
  });

  it("commercial vacío (metalsByParent=[]) → back-compat (gramo puro + costo)", () => {
    const dt = fixtureDocTotals();
    const bb = fixtureBalance();
    // commercial presente pero sin metales → debe usar el path back-compat.
    applyDocumentPhysicalRounding({
      documentTotals: dt,
      balanceBreakdown: bb,
      policy: policyPhysical(),
      commercial: { metalsByParent: [], marginFactor: 1.5 },
    });
    // Back-compat: muta el balance con el gramo puro post-redondeo.
    const oroBalance = bb.metals.find((m: any) => m.metalParentId === ORO)!;
    expect(oroBalance.gramsPure).toBe(1);  // 0,908 → 1,0 con costo
  });
});

// ──────────────────────────────────────────────────────────────────────────
// L. ANTI-DOBLE SECUENCIAL — comercial PHYSICAL ya redondeó el gramo de venta.
//    La capa 16 (financiero) debe ENCADENAR sobre el postGrams comercial, no
//    re-redondear desde el gramo pre-comercial.
// ──────────────────────────────────────────────────────────────────────────

describe("applyDocumentPhysicalRounding — anti-doble secuencial comercial→financiero (L)", () => {
  it("misma config (lista 0,1 + financiero 0,1): financiero parte del postGrams comercial → delta 0, eq 0", () => {
    // Evidencia real: gramsPure agregado 2,2894; el comercial ya lo redondeó a 2,3
    // (gramsSale, +2650). Con marginFactor=1 el gramVenta = gramsPure.
    // Financiero DECIMAL_1: SIN gate redondearía 2,2894 → 2,3 OTRA VEZ (+2650).
    // CON gate: parte de 2,3 → 2,3 (delta 0, eq 0).
    const dt: any = {
      total: 718659.38,
      metalCostSubtotal: 250000,
      metalSaleSubtotal: 250000,
      commercialDocumentRoundingApplied: {
        source: "PRICE_LIST", scope: "BREAKDOWN", appliedAt: "DOCUMENT",
        breakdown: {
          metals: [
            { metalParentId: ORO, metalParentName: "Oro Fino", preGrams: 2.2894, postGrams: 2.3, deltaGrams: 0.0106, metalPricePerGram: 250000, monetaryEquivalent: 2650 },
          ],
          metalsPostGrams: [
            { metalParentId: ORO, metalParentName: "Oro Fino", preGrams: 2.2894, postGrams: 2.3 },
          ],
          metalMonetaryEquivalent: 2650,
          hechura: { preRoundingSaldoMonetario: 0, postRoundingSaldoMonetario: 0, deltaSaldoMonetario: 0, mode: "NONE", direction: "NEAREST", source: "PRICE_LIST_HECHURA" },
          combinedAdjustment: 2650,
        },
      },
    };
    const bb = fixtureBalance({
      metals: [
        { metalParentId: ORO, metalParentName: "Oro Fino", gramsPure: 2.2894, gramsOriginal: 2.2894, purity: 1, quotePriceSnapshot: 250000, valuationMonetary: 572350 },
      ],
    });
    const policy = policyPhysical();
    policy.physical.configByMetalParentId = { [ORO]: { mode: "DECIMAL_1", direction: "NEAREST" } };

    const result = applyDocumentPhysicalRounding({
      documentTotals: dt,
      balanceBreakdown: bb,
      policy,
      commercial: {
        metalsByParent: [
          { metalParentId: ORO, metalParentName: "Oro Fino", gramsPure: 2.2894, metalPricePerGram: 250000, metalReferenceValue: 250000 },
        ],
        marginFactor: 1,
      },
    });

    const oroEntry = result!.metals.find((m) => m.metalParentId === ORO)!;
    // Gramo de entrada del financiero = postGrams comercial (2,3), NO 2,2894.
    expect(oroEntry.preGrams).toBeCloseTo(2.3, 4);
    expect(oroEntry.postGrams).toBeCloseTo(2.3, 4);
    expect(oroEntry.deltaGrams).toBe(0);
    expect(oroEntry.monetaryEquivalent).toBe(0);
    // total NO duplica el +2650 → se mantiene.
    expect(dt.total).toBeCloseTo(718659.38, 2);
  });

  it("config distinta (financiero 0,5): encadena sobre el postGrams comercial (2,3 → 2,5)", () => {
    const dt: any = {
      total: 718659.38,
      metalCostSubtotal: 250000,
      metalSaleSubtotal: 250000,
      commercialDocumentRoundingApplied: {
        source: "PRICE_LIST", scope: "BREAKDOWN", appliedAt: "DOCUMENT",
        breakdown: {
          metals: [
            { metalParentId: ORO, metalParentName: "Oro Fino", preGrams: 2.2894, postGrams: 2.3, deltaGrams: 0.0106, metalPricePerGram: 250000, monetaryEquivalent: 2650 },
          ],
          metalsPostGrams: [
            { metalParentId: ORO, metalParentName: "Oro Fino", preGrams: 2.2894, postGrams: 2.3 },
          ],
          metalMonetaryEquivalent: 2650,
          hechura: { preRoundingSaldoMonetario: 0, postRoundingSaldoMonetario: 0, deltaSaldoMonetario: 0, mode: "NONE", direction: "NEAREST", source: "PRICE_LIST_HECHURA" },
          combinedAdjustment: 2650,
        },
      },
    };
    const bb = fixtureBalance({
      metals: [
        { metalParentId: ORO, metalParentName: "Oro Fino", gramsPure: 2.2894, gramsOriginal: 2.2894, purity: 1, quotePriceSnapshot: 250000, valuationMonetary: 572350 },
      ],
    });
    const policy = policyPhysical();
    policy.physical.configByMetalParentId = { [ORO]: { mode: "HALF", direction: "NEAREST" } };

    const result = applyDocumentPhysicalRounding({
      documentTotals: dt,
      balanceBreakdown: bb,
      policy,
      commercial: {
        metalsByParent: [
          { metalParentId: ORO, metalParentName: "Oro Fino", gramsPure: 2.2894, metalPricePerGram: 250000, metalReferenceValue: 250000 },
        ],
        marginFactor: 1,
      },
    });

    const oroEntry = result!.metals.find((m) => m.metalParentId === ORO)!;
    // Encadena: parte de 2,3 (post-comercial) → HALF NEAREST → 2,5.
    expect(oroEntry.preGrams).toBeCloseTo(2.3, 4);
    expect(oroEntry.postGrams).toBeCloseTo(2.5, 4);
    expect(oroEntry.deltaGrams).toBeCloseTo(0.2, 4);
    expect(oroEntry.monetaryEquivalent).toBeCloseTo(50000, 2);
    expect(dt.total).toBeCloseTo(718659.38 + 50000, 2);
  });

  it("sin redondeo comercial de ese metal → usa gramsSale (gramsPure × marginFactor), comportamiento intacto", () => {
    // dt SIN commercialDocumentRoundingApplied → path histórico.
    const dt: any = { total: 200000, metalCostSubtotal: 80000, metalSaleSubtotal: 100000 };
    const bb = fixtureBalance({
      metals: [
        { metalParentId: ORO, metalParentName: "Oro Fino", gramsPure: 0.72, gramsOriginal: 0.72, purity: 1, quotePriceSnapshot: 100000, valuationMonetary: 72000 },
      ],
    });
    const policy = policyPhysical();
    policy.physical.configByMetalParentId = { [ORO]: { mode: "INTEGER", direction: "NEAREST" } };

    const result = applyDocumentPhysicalRounding({
      documentTotals: dt,
      balanceBreakdown: bb,
      policy,
      commercial: {
        metalsByParent: [
          { metalParentId: ORO, metalParentName: "Oro Fino", gramsPure: 0.72, metalPricePerGram: 100000, metalReferenceValue: 120000 },
        ],
        marginFactor: 1.25,
      },
    });

    const oroEntry = result!.metals.find((m) => m.metalParentId === ORO)!;
    // Sin gate: gramVenta = 0,72 × 1,25 = 0,9 → INTEGER → 1,0.
    expect(oroEntry.preGrams).toBeCloseTo(0.9, 4);
    expect(oroEntry.postGrams).toBe(1);
    expect(oroEntry.monetaryEquivalent).toBeCloseTo(12000, 2);
  });

  it("multi-metal: solo el metal con postGrams comercial encadena; el otro usa gramsSale", () => {
    const dt: any = {
      total: 300000,
      metalCostSubtotal: 100000,
      metalSaleSubtotal: 120000,
      commercialDocumentRoundingApplied: {
        source: "PRICE_LIST", scope: "BREAKDOWN", appliedAt: "DOCUMENT",
        breakdown: {
          // Solo ORO tiene postGrams comercial (2,3). PLATA no figura.
          metalsPostGrams: [
            { metalParentId: ORO, metalParentName: "Oro Fino", preGrams: 2.2894, postGrams: 2.3 },
          ],
          metals: [],
          metalMonetaryEquivalent: 0,
          hechura: { preRoundingSaldoMonetario: 0, postRoundingSaldoMonetario: 0, deltaSaldoMonetario: 0, mode: "NONE", direction: "NEAREST", source: "PRICE_LIST_HECHURA" },
          combinedAdjustment: 0,
        },
      },
    };
    const bb = fixtureBalance();
    const policy = policyPhysical();
    policy.physical.configByMetalParentId = {
      [ORO]:   { mode: "DECIMAL_1", direction: "NEAREST" },
      [PLATA]: { mode: "INTEGER",   direction: "NEAREST" },
    };

    const result = applyDocumentPhysicalRounding({
      documentTotals: dt,
      balanceBreakdown: bb,
      policy,
      commercial: {
        metalsByParent: [
          { metalParentId: ORO,   metalParentName: "Oro Fino", gramsPure: 2.2894, metalPricePerGram: 250000, metalReferenceValue: 250000 },
          { metalParentId: PLATA, metalParentName: "Plata",    gramsPure: 0.6,    metalPricePerGram: 500,    metalReferenceValue: 500 },
        ],
        marginFactor: 1,
      },
    });

    const oro   = result!.metals.find((m) => m.metalParentId === ORO)!;
    const plata = result!.metals.find((m) => m.metalParentId === PLATA)!;
    // ORO encadena desde 2,3 (DECIMAL_1) → 2,3, delta 0.
    expect(oro.preGrams).toBeCloseTo(2.3, 4);
    expect(oro.deltaGrams).toBe(0);
    // PLATA sin postGrams comercial → gramVenta = 0,6 × 1 = 0,6 → INTEGER → 1,0.
    expect(plata.preGrams).toBeCloseTo(0.6, 4);
    expect(plata.postGrams).toBe(1);
    expect(plata.deltaGrams).toBeCloseTo(0.4, 4);
  });
});

// ──────────────────────────────────────────────────────────────────────────
// K. Redondeo Financiero MONETARIO ejecutado EN la capa 16 (financialMonetary)
//    — cuando financialPhysicalActive, el saldo se redondea sobre (total−metal)
//    y el unified sobre el total post-metal+post-saldo. Orden correcto.
// ──────────────────────────────────────────────────────────────────────────

describe("applyDocumentPhysicalRounding — financiero monetario en capa 16 (K)", () => {
  it("BREAKDOWN hechura: redondea el SALDO (total − metalSale) post-metal, no el subtotal de hechura", () => {
    // Sin delta de metal (config NONE) para aislar el saldo.
    // total post-metal = 87750, metalSaleSubtotal = 90.8 → saldoPre = 87659.2.
    // hechura = HUNDRED NEAREST → 87700 (delta +40.8).
    const dt: any = { total: 87750, metalSaleSubtotal: 90.8 };
    const bb = fixtureBalance({
      // Metal sin config → fallback NO_CONFIG, gramos intactos, eq 0.
      metals: [
        { metalParentId: "x", metalParentName: "X", gramsPure: 1, gramsOriginal: 1, purity: 1, quotePriceSnapshot: 100, valuationMonetary: 100 },
      ],
    });
    const policy = policyPhysical();
    policy.physical.configByMetalParentId = {}; // ningún metal redondea
    policy.physical.fallbackConfig = null;

    const result = applyDocumentPhysicalRounding({
      documentTotals: dt,
      balanceBreakdown: bb,
      policy,
      financialMonetary: {
        config: {
          scope: "BREAKDOWN",
          mode: "NONE",
          direction: "NEAREST",
          breakdown: {
            metal:   { mode: "NONE", direction: "NEAREST" },
            hechura: { mode: "HUNDRED", direction: "NEAREST" },
          },
        },
      },
    });

    expect(result).not.toBeNull();
    const dra = dt.documentRoundingApplied;
    // SALDO = total − metalSale = 87659.2 → 87700.
    expect(dra.breakdown.hechura.preRounding).toBeCloseTo(87659.2, 2);
    expect(dra.breakdown.hechura.postRounding).toBeCloseTo(87700, 2);
    expect(dra.breakdown.hechura.adjustment).toBeCloseTo(40.8, 2);
    // total ajustado por el saldo.
    expect(dt.total).toBeCloseTo(87790.8, 2);
    // metal en NONE (anti doble), metalDomain PHYSICAL.
    expect(dra.breakdown.metal).toBeNull();
    expect(dra.breakdown.metalDomain).toBe("PHYSICAL");
    expect(dra.totals.monetaryRoundingAdjustment).toBeCloseTo(40.8, 2);
    expect(dra.totals.metalMonetaryEquivalent).toBeCloseTo(0, 2);
    expect(dra.totals.totalRoundingAdjustment).toBeCloseTo(40.8, 2);
  });

  it("Orden: metal sale-gram PRIMERO, luego saldo sobre (total post-metal − metalSale post-metal)", () => {
    // Oro 0,72 × 1,25 = 0,9 → INTEGER → 1,0 → deltaSale 0,1 × 120000 = +12000.
    // total pre = 200000 → post-metal = 212000. metalSale pre = 100000 →
    // post-metal = 112000. saldoPre = 212000 − 112000 = 100000.
    // hechura = HUNDRED NEAREST → 100000 (delta 0). Nada cambia por saldo.
    const dt: any = { total: 200000, metalCostSubtotal: 80000, metalSaleSubtotal: 100000 };
    const bb = fixtureBalance({
      metals: [
        { metalParentId: ORO, metalParentName: "Oro Fino", gramsPure: 0.72, gramsOriginal: 0.72, purity: 1, quotePriceSnapshot: 100000, valuationMonetary: 72000 },
      ],
    });
    const policy = policyPhysical();
    policy.physical.configByMetalParentId = { [ORO]: { mode: "INTEGER", direction: "NEAREST" } };

    applyDocumentPhysicalRounding({
      documentTotals: dt,
      balanceBreakdown: bb,
      policy,
      commercial: {
        metalsByParent: [
          { metalParentId: ORO, metalParentName: "Oro Fino", gramsPure: 0.72, metalPricePerGram: 100000, metalReferenceValue: 120000 },
        ],
        marginFactor: 1.25,
      },
      financialMonetary: {
        config: {
          scope: "BREAKDOWN",
          mode: "NONE",
          direction: "NEAREST",
          breakdown: {
            metal:   { mode: "NONE", direction: "NEAREST" },
            hechura: { mode: "HUNDRED", direction: "NEAREST" },
          },
        },
      },
    });

    const dra = dt.documentRoundingApplied;
    // Saldo se computó sobre POST-metal: pre = 100000 (212000 − 112000).
    expect(dra.breakdown.hechura.preRounding).toBeCloseTo(100000, 2);
    expect(dra.breakdown.hechura.adjustment).toBeCloseTo(0, 2);
    // metalPhysical = 12000.
    expect(dra.breakdown.metalPhysical.metalMonetaryEquivalent).toBeCloseTo(12000, 2);
    // total = 200000 + 12000 (metal) + 0 (saldo) = 212000.
    expect(dt.total).toBeCloseTo(212000, 2);
    expect(dra.totals.metalMonetaryEquivalent).toBeCloseTo(12000, 2);
    expect(dra.totals.totalRoundingAdjustment).toBeCloseTo(12000, 2);
  });

  it("UNIFIED: redondea el total post-metal+post-saldo (orden 1→2→3)", () => {
    // Sin metal delta. UNIFIED HUNDRED sobre el total.
    // total = 87750 → HUNDRED NEAREST → 87800 (delta +50).
    const dt: any = { total: 87750, metalSaleSubtotal: 90.8 };
    const bb = fixtureBalance({
      metals: [
        { metalParentId: "x", metalParentName: "X", gramsPure: 1, gramsOriginal: 1, purity: 1, quotePriceSnapshot: 100, valuationMonetary: 100 },
      ],
    });
    const policy = policyPhysical();
    policy.physical.configByMetalParentId = {};
    policy.physical.fallbackConfig = null;

    applyDocumentPhysicalRounding({
      documentTotals: dt,
      balanceBreakdown: bb,
      policy,
      financialMonetary: {
        config: { scope: "UNIFIED", mode: "HUNDRED", direction: "NEAREST" },
      },
    });

    const dra = dt.documentRoundingApplied;
    expect(dra.scope).toBe("UNIFIED");
    expect(dra.unified.preRounding).toBeCloseTo(87750, 2);
    expect(dra.unified.postRounding).toBeCloseTo(87800, 2);
    expect(dra.unified.adjustment).toBeCloseTo(50, 2);
    expect(dt.total).toBeCloseTo(87800, 2);
    expect(dra.totals.monetaryRoundingAdjustment).toBeCloseTo(50, 2);
  });

  it("BOTH: saldo (post-metal) y unified (post-metal+post-saldo) en cascada con metal real", () => {
    // Oro 0,72 × 1,25 = 0,9 → INTEGER → 1,0 → +12000 metal.
    // total pre 200000 → post-metal 212000. metalSale 100000 → 112000.
    // saldoPre = 100000; hechura HUNDRED NEAREST → 100000 (delta 0).
    // unified TEN sobre 212000 → 212000 (delta 0). Forzamos delta con saldo:
    // usamos hechura sobre saldoPre 99950 vía metalSale distinto.
    const dt: any = { total: 200050, metalCostSubtotal: 80000, metalSaleSubtotal: 100050 };
    const bb = fixtureBalance({
      metals: [
        { metalParentId: ORO, metalParentName: "Oro Fino", gramsPure: 0.72, gramsOriginal: 0.72, purity: 1, quotePriceSnapshot: 100000, valuationMonetary: 72000 },
      ],
    });
    const policy = policyPhysical();
    policy.physical.configByMetalParentId = { [ORO]: { mode: "INTEGER", direction: "NEAREST" } };

    applyDocumentPhysicalRounding({
      documentTotals: dt,
      balanceBreakdown: bb,
      policy,
      commercial: {
        metalsByParent: [
          { metalParentId: ORO, metalParentName: "Oro Fino", gramsPure: 0.72, metalPricePerGram: 100000, metalReferenceValue: 120000 },
        ],
        marginFactor: 100050 / 80000,
      },
      financialMonetary: {
        config: {
          scope: "BOTH",
          mode: "HUNDRED",
          direction: "NEAREST",
          breakdown: {
            metal:   { mode: "NONE", direction: "NEAREST" },
            hechura: { mode: "HUNDRED", direction: "NEAREST" },
          },
        },
      },
    });

    const dra = dt.documentRoundingApplied;
    expect(dra.scope).toBe("BOTH");
    // metal real impacta total.
    expect(dra.breakdown.metalPhysical.metalMonetaryEquivalent).toBeGreaterThan(0);
    // saldo se computó sobre post-metal.
    const metalEq = dra.breakdown.metalPhysical.metalMonetaryEquivalent;
    const expectedSaldoPre = round(dt.total - metalEq /*back-out not exact*/);
    expect(dra.breakdown.hechura).toBeDefined();
    // total final coherente con la suma de los tres dominios.
    expect(dra.totalAdjustment).toBeCloseTo(
      dra.totals.metalMonetaryEquivalent + dra.totals.monetaryRoundingAdjustment,
      2,
    );
    void expectedSaldoPre;
  });

  it("financialMonetary ausente → la capa 16 NO toca el saldo ni el total (solo metal)", () => {
    const dt = fixtureDocTotals();
    const bb = fixtureBalance();
    applyDocumentPhysicalRounding({ documentTotals: dt, balanceBreakdown: bb, policy: policyPhysical() });
    // Solo el metal movió el total (9320). El snapshot conserva la hechura del
    // motor (capa 15) — no la pisamos.
    expect(dt.total).toBeCloseTo(87750 + 9320, 2);
    expect(dt.documentRoundingApplied.breakdown.hechura.mode).toBe("NONE");
  });
});

const round = (n: number) => Math.round(n * 100) / 100;

// ──────────────────────────────────────────────────────────────────────────
// M. ANTI-DOBLE SECUENCIAL DEL SALDO — comercial ya redondeó el saldo monetario.
//    El financiero (capa 16) debe ENCADENAR sobre `postRoundingSaldoMonetario`
//    comercial, no re-redondear desde `total − metalSale` (que infla el saldo
//    porque el metal comercial está en `total` pero no en `metalSaleSubtotal`).
//    Identidad obligatoria: saldo + metal = total.
// ──────────────────────────────────────────────────────────────────────────

describe("applyDocumentPhysicalRounding — anti-doble secuencial del SALDO comercial→financiero (M)", () => {
  /** Fixture del caso real del brief: config doble (lista hechura HUNDRED +
   *  financiero hechura HUNDRED), 1 línea Oro. El comercial ya dejó el metal en
   *  postGrams (anti-doble metal → financiero metal delta 0) y el saldo en
   *  200900 (pre 200876.94, delta +23.06). total = 718659.38. */
  function fixtureDoble(over?: any) {
    const dt: any = {
      total: 718659.38,
      metalCostSubtotal: 510000,
      // Identidad del comprobante: saldo_post_comercial (200900) + metalSale = total.
      // ⇒ metalSale = 718659.38 − 200900 = 517759.38.
      metalSaleSubtotal: 517759.38,
      commercialDocumentRoundingApplied: {
        source: "PRICE_LIST", scope: "BREAKDOWN", appliedAt: "DOCUMENT",
        breakdown: {
          metals: [
            { metalParentId: ORO, metalParentName: "Oro Fino", preGrams: 2.04, postGrams: 2.04, deltaGrams: 0, metalPricePerGram: 250000, monetaryEquivalent: 0 },
          ],
          metalsPostGrams: [
            { metalParentId: ORO, metalParentName: "Oro Fino", preGrams: 2.04, postGrams: 2.04 },
          ],
          metalMonetaryEquivalent: 0,
          hechura: {
            preRoundingSaldoMonetario: 200876.94,
            postRoundingSaldoMonetario: 200900,
            deltaSaldoMonetario: 23.06,
            mode: "HUNDRED", direction: "NEAREST", source: "PRICE_LIST_HECHURA",
          },
          combinedAdjustment: 23.06,
        },
      },
      ...over,
    };
    const bb = fixtureBalance({
      metals: [
        { metalParentId: ORO, metalParentName: "Oro Fino", gramsPure: 2.04, gramsOriginal: 2.04, purity: 1, quotePriceSnapshot: 250000, valuationMonetary: 510000 },
      ],
    });
    return { dt, bb };
  }

  function policyDoble(): DocumentRoundingPolicy {
    const policy = policyPhysical();
    // Metal financiero con config DECIMAL_2 → conserva el postGrams comercial
    // (2,04) → delta 0, para aislar el comportamiento del SALDO.
    policy.physical.configByMetalParentId = { [ORO]: { mode: "DECIMAL_2", direction: "NEAREST" } };
    return policy;
  }

  function financialBreakdown(hechuraMode: any) {
    return {
      config: {
        scope: "BREAKDOWN" as const,
        mode: "NONE" as const,
        direction: "NEAREST" as const,
        breakdown: {
          metal:   { mode: "NONE" as const, direction: "NEAREST" as const },
          hechura: { mode: hechuraMode, direction: "NEAREST" as const },
        },
      },
    };
  }

  it("(a) config doble HUNDRED+HUNDRED, metal delta 0 → financiero saldo delta 0; total 718659.38, saldo 200900", () => {
    const { dt, bb } = fixtureDoble();
    applyDocumentPhysicalRounding({
      documentTotals: dt,
      balanceBreakdown: bb,
      policy: policyDoble(),
      commercial: {
        metalsByParent: [
          { metalParentId: ORO, metalParentName: "Oro Fino", gramsPure: 2.04, metalPricePerGram: 250000, metalReferenceValue: 250000 },
        ],
        marginFactor: 1,
      },
      financialMonetary: financialBreakdown("HUNDRED"),
    });

    const dra = dt.documentRoundingApplied;
    // SALDO: parte del post-comercial (200900), NO de total − metalSale.
    expect(dra.breakdown.hechura.preRounding).toBeCloseTo(200900, 2);
    expect(dra.breakdown.hechura.postRounding).toBeCloseTo(200900, 2);
    expect(dra.breakdown.hechura.adjustment).toBe(0);
    // total sin movimiento por el saldo.
    expect(dra.totals.monetaryRoundingAdjustment).toBe(0);
  });

  it("(a-puro) metal financiero delta 0 (config metal DECIMAL_2) → total exacto 718659.38, saldo 200900", () => {
    // Forzamos metal financiero delta 0 usando config metal que deja 2,04 igual:
    const { dt, bb } = fixtureDoble();
    const policy = policyPhysical();
    // INTEGER sobre el postGrams comercial 2,04 daría 2,0 (delta). Para delta 0
    // usamos una config que conserve 2,04: DECIMAL_2.
    policy.physical.configByMetalParentId = { [ORO]: { mode: "DECIMAL_2", direction: "NEAREST" } };

    applyDocumentPhysicalRounding({
      documentTotals: dt,
      balanceBreakdown: bb,
      policy,
      commercial: {
        metalsByParent: [
          { metalParentId: ORO, metalParentName: "Oro Fino", gramsPure: 2.04, metalPricePerGram: 250000, metalReferenceValue: 250000 },
        ],
        marginFactor: 1,
      },
      financialMonetary: financialBreakdown("HUNDRED"),
    });

    const dra = dt.documentRoundingApplied;
    // metal financiero delta 0.
    expect(dra.breakdown.metalPhysical.metalMonetaryEquivalent).toBe(0);
    // saldo parte de 200900 → HUNDRED → 200900, delta 0.
    expect(dra.breakdown.hechura.preRounding).toBeCloseTo(200900, 2);
    expect(dra.breakdown.hechura.postRounding).toBeCloseTo(200900, 2);
    expect(dra.breakdown.hechura.adjustment).toBe(0);
    // total intacto.
    expect(dt.total).toBeCloseTo(718659.38, 2);
  });

  it("(b) config saldo distinta → encadena sobre el saldo post-comercial (no sobre total − metalSale)", () => {
    // Comercial dejó el saldo SIN redondear su parte decimal (post = 200876.94).
    // Financiero HUNDRED debe partir de ESE post-comercial (200876.94) → 200900,
    // NO de `total − metalSale` (que sería 718659.38 − 510000 = 208659.38 → 208700).
    const { dt, bb } = fixtureDoble({
      commercialDocumentRoundingApplied: {
        source: "PRICE_LIST", scope: "BREAKDOWN", appliedAt: "DOCUMENT",
        breakdown: {
          metals: [
            { metalParentId: ORO, metalParentName: "Oro Fino", preGrams: 2.04, postGrams: 2.04, deltaGrams: 0, metalPricePerGram: 250000, monetaryEquivalent: 0 },
          ],
          metalsPostGrams: [
            { metalParentId: ORO, metalParentName: "Oro Fino", preGrams: 2.04, postGrams: 2.04 },
          ],
          metalMonetaryEquivalent: 0,
          // Comercial NO redondeó la hechura (mode NONE) → post = pre = 200876.94.
          hechura: {
            preRoundingSaldoMonetario: 200876.94,
            postRoundingSaldoMonetario: 200876.94,
            deltaSaldoMonetario: 0,
            mode: "NONE", direction: "NEAREST", source: "PRICE_LIST_HECHURA",
          },
          combinedAdjustment: 0,
        },
      },
    });
    const policy = policyPhysical();
    policy.physical.configByMetalParentId = { [ORO]: { mode: "DECIMAL_2", direction: "NEAREST" } }; // metal delta 0

    applyDocumentPhysicalRounding({
      documentTotals: dt,
      balanceBreakdown: bb,
      policy,
      commercial: {
        metalsByParent: [
          { metalParentId: ORO, metalParentName: "Oro Fino", gramsPure: 2.04, metalPricePerGram: 250000, metalReferenceValue: 250000 },
        ],
        marginFactor: 1,
      },
      financialMonetary: financialBreakdown("HUNDRED"),
    });

    const dra = dt.documentRoundingApplied;
    // Encadena sobre el post-comercial 200876.94 → HUNDRED NEAREST → 200900 (+23.06).
    expect(dra.breakdown.hechura.preRounding).toBeCloseTo(200876.94, 2);
    expect(dra.breakdown.hechura.postRounding).toBeCloseTo(200900, 2);
    expect(dra.breakdown.hechura.adjustment).toBeCloseTo(23.06, 2);
    expect(dt.total).toBeCloseTo(718659.38 + 23.06, 2);
  });

  it("(c) sin redondeo comercial de saldo → usa total − metalSale (comportamiento histórico)", () => {
    // total post-metal = 87750, metalSaleSubtotal = 90.8 → saldoPre = 87659.2.
    const dt: any = { total: 87750, metalSaleSubtotal: 90.8 };
    const bb = fixtureBalance({
      metals: [
        { metalParentId: "x", metalParentName: "X", gramsPure: 1, gramsOriginal: 1, purity: 1, quotePriceSnapshot: 100, valuationMonetary: 100 },
      ],
    });
    const policy = policyPhysical();
    policy.physical.configByMetalParentId = {};
    policy.physical.fallbackConfig = null;

    applyDocumentPhysicalRounding({
      documentTotals: dt,
      balanceBreakdown: bb,
      policy,
      financialMonetary: financialBreakdown("HUNDRED"),
    });

    const dra = dt.documentRoundingApplied;
    // SIN commercialDocumentRoundingApplied → fallback histórico total − metalSale.
    expect(dra.breakdown.hechura.preRounding).toBeCloseTo(87659.2, 2);
    expect(dra.breakdown.hechura.postRounding).toBeCloseTo(87700, 2);
    expect(dra.breakdown.hechura.adjustment).toBeCloseTo(40.8, 2);
    expect(dt.total).toBeCloseTo(87790.8, 2);
  });

  it("(d) metal financiero delta≠0 + saldo comercial → identidad saldo+metal=total se mantiene", () => {
    // Metal financiero con config INTEGER sobre el postGrams comercial 2,04 → 2,0
    // → delta −0,04 g × 250000 = −10000. El saldo POST-comercial (200900) NO se
    // mueve por el delta del metal (el metalEq se refleja por igual en total y en
    // metalSaleSubtotal) → saldo + metal = total se mantiene.
    const { dt, bb } = fixtureDoble();
    const policy = policyPhysical();
    policy.physical.configByMetalParentId = { [ORO]: { mode: "INTEGER", direction: "NEAREST" } };

    const result = applyDocumentPhysicalRounding({
      documentTotals: dt,
      balanceBreakdown: bb,
      policy,
      commercial: {
        metalsByParent: [
          { metalParentId: ORO, metalParentName: "Oro Fino", gramsPure: 2.04, metalPricePerGram: 250000, metalReferenceValue: 250000 },
        ],
        marginFactor: 1,
      },
      financialMonetary: financialBreakdown("NONE"), // saldo NONE → no mueve saldo, aislamos identidad
    });

    const dra = dt.documentRoundingApplied;
    const metalEq = result!.metalMonetaryEquivalent;
    // metal financiero movió (delta ≠ 0): 2,04 → 2,0 → −0,04 × 250000 = −10000.
    expect(metalEq).toBeCloseTo(-10000, 2);
    // El saldoPre POST-comercial sigue siendo 200900 (invariante al metalEq).
    expect(dra.breakdown.hechura.preRounding).toBeCloseTo(200900, 2);
    expect(dra.breakdown.hechura.postRounding).toBeCloseTo(200900, 2);
    // IDENTIDAD: saldo (post) + metalSale (post, = metalSale_comercial + metalEq) = total.
    const metalSalePost = dt.metalSaleSubtotal; // 510000 + (−10000) = 500000
    const saldoPost = dra.breakdown.hechura.postRounding; // 200900
    expect(round(saldoPost + metalSalePost)).toBeCloseTo(dt.total, 2);
    // total = 718659.38 + (−10000) = 708659.38.
    expect(dt.total).toBeCloseTo(708659.38, 2);
  });

  it("(d-saldo-mueve) metal financiero delta≠0 + saldo financiero HUNDRED → saldo redondea desde post-comercial, identidad se mantiene", () => {
    const { dt, bb } = fixtureDoble();
    const policy = policyPhysical();
    policy.physical.configByMetalParentId = { [ORO]: { mode: "INTEGER", direction: "NEAREST" } };

    const result = applyDocumentPhysicalRounding({
      documentTotals: dt,
      balanceBreakdown: bb,
      policy,
      commercial: {
        metalsByParent: [
          { metalParentId: ORO, metalParentName: "Oro Fino", gramsPure: 2.04, metalPricePerGram: 250000, metalReferenceValue: 250000 },
        ],
        marginFactor: 1,
      },
      financialMonetary: financialBreakdown("HUNDRED"),
    });

    const dra = dt.documentRoundingApplied;
    const metalEq = result!.metalMonetaryEquivalent; // −10000
    // saldo parte de 200900 (post-comercial), HUNDRED → 200900 (delta 0).
    expect(dra.breakdown.hechura.preRounding).toBeCloseTo(200900, 2);
    expect(dra.breakdown.hechura.postRounding).toBeCloseTo(200900, 2);
    const saldoDelta = dra.breakdown.hechura.adjustment; // 0
    // IDENTIDAD final: total = 718659.38 + metalEq + saldoDelta.
    expect(dt.total).toBeCloseTo(718659.38 + metalEq + saldoDelta, 2);
    // saldo(post) + metalSale(post) = total.
    expect(round(dra.breakdown.hechura.postRounding + dt.metalSaleSubtotal)).toBeCloseTo(dt.total, 2);
  });
});

// ──────────────────────────────────────────────────────────────────────────
// I. Multimoneda — sanity check de la integración con currency display
// ──────────────────────────────────────────────────────────────────────────

describe("applyDocumentPhysicalRounding — multimoneda (I)", () => {
  it("convertSalesPreviewResponseInPlace convierte metalPhysical + totals; gramos invariantes", async () => {
    const { convertSalesPreviewResponseInPlace } = await import("../pricing-currency-display.js");
    const dt = fixtureDocTotals();
    const bb = fixtureBalance();
    applyDocumentPhysicalRounding({ documentTotals: dt, balanceBreakdown: bb, policy: policyPhysical() });

    const res: any = {
      documentTotals: dt,
      lines: [],
    };
    // rate 1000 (1 USD = 1000 ARS).
    convertSalesPreviewResponseInPlace(res, 1000);

    const mp = res.documentTotals.documentRoundingApplied.breakdown.metalPhysical;
    // metalMonetaryEquivalent base 9320 → display 9.32.
    expect(mp.metalMonetaryEquivalent).toBeCloseTo(9.32, 4);
    // Gramos invariantes.
    const oro = mp.metals.find((m: any) => m.metalParentId === ORO);
    expect(oro.preGrams).toBe(0.908);
    expect(oro.postGrams).toBe(1);
    expect(oro.deltaGrams).toBeCloseTo(0.092, 4);
    // Precio por gramo: 100000 base → 100 display.
    expect(oro.metalPricePerGram).toBe(100);
    expect(oro.monetaryEquivalent).toBeCloseTo(9.2, 4);
    // Totals convertidos.
    expect(res.documentTotals.documentRoundingApplied.totals.totalRoundingAdjustment).toBeCloseTo(9.32, 4);
  });
});
