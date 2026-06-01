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
