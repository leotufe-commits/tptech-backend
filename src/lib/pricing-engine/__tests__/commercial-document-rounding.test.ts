// src/lib/pricing-engine/__tests__/commercial-document-rounding.test.ts
//
// Tests aislados del helper puro `applyCommercialDocumentRounding`.
//
// El helper NO se integra todavía en computeSaleDocumentTotals — esto valida
// la matemática en aislamiento antes de tocar el motor. Cubre:
//   · UNIFIED post-tax (NEAREST / UP / DOWN / NONE / sin movimiento).
//   · BREAKDOWN metal físico + saldo monetario (caso 182091.10 → 182100).
//   · Que el delta físico de metal NO contamine el saldo monetario.
//   · Fallbacks: ALL_NONE, NO_METALS_BREAKDOWN_DATA.
//   · Anti-doble: el snapshot expone pre/post/delta auditables.
//   · NO_SHARED_LIST se serializa por el caller — verificamos el shape.

import { describe, it, expect } from "vitest";
import {
  applyCommercialDocumentRounding,
  type CommercialDocRoundingArgs,
  type CommercialDocRoundingApplied,
  type CommercialDocMetalParentInput,
} from "../commercial-document-rounding.js";

// ─────────────────────────────────────────────────────────────────────────────
// UNIFIED — post-tax
// ─────────────────────────────────────────────────────────────────────────────

describe("applyCommercialDocumentRounding — UNIFIED post-tax", () => {
  function unifiedArgs(
    total: number,
    mode: "NONE" | "INTEGER" | "DECIMAL_1" | "DECIMAL_2" | "TEN" | "HUNDRED",
    direction: "NEAREST" | "UP" | "DOWN",
  ): CommercialDocRoundingArgs {
    return {
      totalComercialPostTax: total,
      metalValuationSum:     0,
      config:                { scope: "UNIFIED", mode, direction },
    };
  }

  it("HUNDRED NEAREST: 182091.10 → 182100 (delta +8.90)", () => {
    const r = applyCommercialDocumentRounding(unifiedArgs(182091.10, "HUNDRED", "NEAREST"));
    expect(r.totalPostCommercial).toBe(182100);
    expect(r.applied).not.toBeNull();
    expect(r.applied!.scope).toBe("UNIFIED");
    expect(r.applied!.unified).toEqual({
      pre:        182091.10,
      post:       182100,
      adjustment: 8.90,
      mode:       "HUNDRED",
      direction:  "NEAREST",
    });
    expect(r.applied!.totalAdjustment).toBe(8.90);
  });

  it("DECIMAL_1 NEAREST: 182.09 → 182.10 (delta +0.01)", () => {
    const r = applyCommercialDocumentRounding(unifiedArgs(182.09, "DECIMAL_1", "NEAREST"));
    expect(r.totalPostCommercial).toBe(182.10);
    expect(r.applied!.totalAdjustment).toBe(0.01);
  });

  it("HUNDRED UP: 100.01 → 200 (delta +99.99)", () => {
    const r = applyCommercialDocumentRounding(unifiedArgs(100.01, "HUNDRED", "UP"));
    expect(r.totalPostCommercial).toBe(200);
    expect(r.applied!.totalAdjustment).toBe(99.99);
  });

  it("HUNDRED DOWN: 199.99 → 100 (delta -99.99)", () => {
    const r = applyCommercialDocumentRounding(unifiedArgs(199.99, "HUNDRED", "DOWN"));
    expect(r.totalPostCommercial).toBe(100);
    expect(r.applied!.totalAdjustment).toBe(-99.99);
  });

  it("mode NONE: applied != null con fallback ALL_NONE y totalAdjustment = 0", () => {
    const r = applyCommercialDocumentRounding(unifiedArgs(123.45, "NONE", "NEAREST"));
    expect(r.totalPostCommercial).toBe(123.45);
    expect(r.applied).not.toBeNull();
    expect(r.applied!.fallback).toBe("ALL_NONE");
    expect(r.applied!.totalAdjustment).toBe(0);
    expect(r.applied!.unified).toBeUndefined();
  });

  it("sin movimiento (valor ya redondeado): applied = null", () => {
    const r = applyCommercialDocumentRounding(unifiedArgs(200, "HUNDRED", "NEAREST"));
    expect(r.totalPostCommercial).toBe(200);
    expect(r.applied).toBeNull();
  });

  it("input con basura de coma flotante (182091.09999999998) redondea limpio", () => {
    const r = applyCommercialDocumentRounding(
      unifiedArgs(182091.09999999998, "HUNDRED", "NEAREST"),
    );
    expect(r.totalPostCommercial).toBe(182100);
    // El helper round2 normaliza el float antes del redondeo.
    expect(r.applied!.unified!.pre).toBe(182091.10);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// BREAKDOWN — metal físico + saldo monetario
// ─────────────────────────────────────────────────────────────────────────────

describe("applyCommercialDocumentRounding — BREAKDOWN", () => {
  // Cotización ficticia: 1g de Oro Fino = $80.000.
  const ORO_PRICE_PER_GRAM = 80000;

  function metalsOro(gramsPure: number): CommercialDocMetalParentInput[] {
    return [{
      metalParentId:     "OroFino",
      metalParentName:   "Oro Fino",
      gramsPure,
      metalPricePerGram: ORO_PRICE_PER_GRAM,
    }];
  }

  it("CASO PRINCIPAL — saldo monetario 182091.10 → 182100 (HUNDRED NEAREST)", () => {
    // Setup: 1.2375 g de oro (=$99.000) + saldo monetario residual = 182091.10
    // → totalComercial = 99000 + 182091.10 = 281091.10
    const r = applyCommercialDocumentRounding({
      totalComercialPostTax: 281091.10,
      metalValuationSum:     99000,
      metalsByParent:        metalsOro(1.2375),
      config: {
        scope:   "BREAKDOWN",
        // Caso del user: solo hechura redondea, metal queda como está.
        metal:   { mode: "NONE",    direction: "NEAREST" },
        hechura: { mode: "HUNDRED", direction: "NEAREST" },
      },
    });
    expect(r.applied).not.toBeNull();
    expect(r.applied!.scope).toBe("BREAKDOWN");
    const bd = r.applied!.breakdown!;
    expect(bd.hechura.preRoundingSaldoMonetario).toBe(182091.10);
    expect(bd.hechura.postRoundingSaldoMonetario).toBe(182100);
    expect(bd.hechura.deltaSaldoMonetario).toBe(8.90);
    expect(bd.hechura.mode).toBe("HUNDRED");
    expect(bd.hechura.direction).toBe("NEAREST");
    expect(bd.hechura.source).toBe("PRICE_LIST_HECHURA");
    // El metal con mode=NONE: ninguna entry, equivalente monetario = 0
    expect(bd.metals).toEqual([]);
    expect(bd.metalMonetaryEquivalent).toBe(0);
    expect(bd.combinedAdjustment).toBe(8.90);
    expect(r.applied!.totalAdjustment).toBe(8.90);
    expect(r.totalPostCommercial).toBe(281100);
  });

  it("metal físico: 1.2375 g → 1.2 g (DECIMAL_1 NEAREST) — delta físico aporta -$3000", () => {
    const r = applyCommercialDocumentRounding({
      totalComercialPostTax: 281091.10,
      metalValuationSum:     99000,
      metalsByParent:        metalsOro(1.2375),
      config: {
        scope:   "BREAKDOWN",
        metal:   { mode: "DECIMAL_1", direction: "NEAREST" },  // 1.2375 → 1.2
        hechura: { mode: "NONE",      direction: "NEAREST" },
      },
    });
    const bd = r.applied!.breakdown!;
    expect(bd.metals.length).toBe(1);
    expect(bd.metals[0]).toEqual({
      metalParentId:      "OroFino",
      metalParentName:    "Oro Fino",
      preGrams:           1.2375,
      postGrams:          1.2,
      deltaGrams:         -0.0375,
      metalPricePerGram:  ORO_PRICE_PER_GRAM,
      monetaryEquivalent: -3000,         // -0.0375 × 80000
      preAmount:          99000,         // 1.2375 × 80000
      postAmount:         96000,         // 1.2    × 80000
      mode:               "DECIMAL_1",
      direction:          "NEAREST",
    });
    // Invariante: postAmount = preAmount + monetaryEquivalent
    expect(bd.metals[0].postAmount).toBe(
      bd.metals[0].preAmount! + bd.metals[0].monetaryEquivalent,
    );
    expect(bd.metalMonetaryEquivalent).toBe(-3000);
    expect(bd.hechura.deltaSaldoMonetario).toBe(0);
    expect(bd.combinedAdjustment).toBe(-3000);
    expect(r.totalPostCommercial).toBe(278091.10);
  });

  it("metal + hechura combinados: ambos redondean en el mismo doc", () => {
    const r = applyCommercialDocumentRounding({
      totalComercialPostTax: 281091.10,
      metalValuationSum:     99000,
      metalsByParent:        metalsOro(1.2375),
      config: {
        scope:   "BREAKDOWN",
        metal:   { mode: "DECIMAL_1", direction: "NEAREST" },  // -$3000
        hechura: { mode: "HUNDRED",   direction: "NEAREST" },  // +$8.90
      },
    });
    const bd = r.applied!.breakdown!;
    expect(bd.metalMonetaryEquivalent).toBe(-3000);
    expect(bd.hechura.deltaSaldoMonetario).toBe(8.90);
    expect(bd.combinedAdjustment).toBe(-2991.10);
    expect(r.totalPostCommercial).toBe(278100);
  });

  it("INVARIANTE: el delta físico de metal NO contamina el saldo monetario", () => {
    // Mismo total y saldo, dos configs distintas para el metal — el saldo
    // residual debe ser idéntico en ambos casos.
    const baseArgs = {
      totalComercialPostTax: 281091.10,
      metalValuationSum:     99000,
      metalsByParent:        metalsOro(1.2375),
    };
    const conMetal = applyCommercialDocumentRounding({
      ...baseArgs,
      config: {
        scope:   "BREAKDOWN",
        metal:   { mode: "DECIMAL_1", direction: "NEAREST" },
        hechura: { mode: "HUNDRED",   direction: "NEAREST" },
      },
    });
    const sinMetal = applyCommercialDocumentRounding({
      ...baseArgs,
      config: {
        scope:   "BREAKDOWN",
        metal:   { mode: "NONE",    direction: "NEAREST" },
        hechura: { mode: "HUNDRED", direction: "NEAREST" },
      },
    });
    expect(conMetal.applied!.breakdown!.hechura.preRoundingSaldoMonetario)
      .toBe(sinMetal.applied!.breakdown!.hechura.preRoundingSaldoMonetario);
    expect(conMetal.applied!.breakdown!.hechura.postRoundingSaldoMonetario)
      .toBe(sinMetal.applied!.breakdown!.hechura.postRoundingSaldoMonetario);
    expect(conMetal.applied!.breakdown!.hechura.deltaSaldoMonetario)
      .toBe(sinMetal.applied!.breakdown!.hechura.deltaSaldoMonetario);
  });

  it("varios metales padre: cada uno redondea por separado", () => {
    const r = applyCommercialDocumentRounding({
      totalComercialPostTax: 500000,
      metalValuationSum:     300000,  // 1g Oro $80000 + 100g Plata $2200
      metalsByParent: [
        { metalParentId: "OroFino", metalParentName: "Oro Fino", gramsPure: 1.0375, metalPricePerGram: 80000 },
        { metalParentId: "Plata",   metalParentName: "Plata",    gramsPure: 100.025, metalPricePerGram: 2200 },
      ],
      config: {
        scope:   "BREAKDOWN",
        metal:   { mode: "DECIMAL_1", direction: "NEAREST" },
        hechura: { mode: "NONE",      direction: "NEAREST" },
      },
    });
    const bd = r.applied!.breakdown!;
    expect(bd.metals.length).toBe(2);
    // Oro: 1.0375 → 1.0 (delta -0.0375 × 80000 = -3000)
    // Plata: 100.025 → 100.0 (delta -0.025 × 2200 = -55)
    const oro   = bd.metals.find(m => m.metalParentId === "OroFino")!;
    const plata = bd.metals.find(m => m.metalParentId === "Plata")!;
    expect(oro.deltaGrams).toBe(-0.0375);
    expect(oro.monetaryEquivalent).toBe(-3000);
    expect(oro.preAmount).toBe(83000);   // 1.0375 × 80000
    expect(oro.postAmount).toBe(80000);  // 1.0    × 80000
    expect(plata.deltaGrams).toBe(-0.025);
    expect(plata.monetaryEquivalent).toBe(-55);
    expect(plata.preAmount).toBe(220055);  // 100.025 × 2200
    expect(plata.postAmount).toBe(220000); // 100.0   × 2200
    expect(bd.metalMonetaryEquivalent).toBe(-3055);
  });

  it("INVARIANTE preAmount/postAmount: postAmount = preAmount + monetaryEquivalent (todos los metales)", () => {
    const r = applyCommercialDocumentRounding({
      totalComercialPostTax: 500000,
      metalValuationSum:     300000,
      metalsByParent: [
        { metalParentId: "OroFino", metalParentName: "Oro Fino", gramsPure: 1.0375,  metalPricePerGram: 80000 },
        { metalParentId: "Plata",   metalParentName: "Plata",    gramsPure: 100.025, metalPricePerGram: 2200  },
      ],
      config: {
        scope:   "BREAKDOWN",
        metal:   { mode: "DECIMAL_1", direction: "NEAREST" },
        hechura: { mode: "NONE",      direction: "NEAREST" },
      },
    });
    const metals = r.applied!.breakdown!.metals;
    for (const m of metals) {
      expect(typeof m.preAmount).toBe("number");
      expect(typeof m.postAmount).toBe("number");
      // El motor redondea a 2 decimales — usamos toBeCloseTo para tolerar
      // residuo de coma flotante en la verificación del invariante.
      expect(m.postAmount!).toBeCloseTo(m.preAmount! + m.monetaryEquivalent, 2);
    }
  });

  it("fallback ALL_NONE (metal=NONE + hechura=NONE): snapshot informativo", () => {
    const r = applyCommercialDocumentRounding({
      totalComercialPostTax: 100,
      metalValuationSum:     50,
      metalsByParent:        metalsOro(0.5),
      config: {
        scope:   "BREAKDOWN",
        metal:   { mode: "NONE", direction: "NEAREST" },
        hechura: { mode: "NONE", direction: "NEAREST" },
      },
    });
    expect(r.applied).not.toBeNull();
    expect(r.applied!.fallback).toBe("ALL_NONE");
    expect(r.applied!.totalAdjustment).toBe(0);
    expect(r.applied!.breakdown).toBeUndefined();
    expect(r.totalPostCommercial).toBe(100);
  });

  it("fallback NO_METALS_BREAKDOWN_DATA (metal activo pero sin metales)", () => {
    const r = applyCommercialDocumentRounding({
      totalComercialPostTax: 100,
      metalValuationSum:     0,
      metalsByParent:        [],   // ← vacío
      config: {
        scope:   "BREAKDOWN",
        metal:   { mode: "DECIMAL_1", direction: "NEAREST" },  // pide redondear metal
        hechura: { mode: "NONE",      direction: "NEAREST" },
      },
    });
    expect(r.applied).not.toBeNull();
    expect(r.applied!.fallback).toBe("NO_METALS_BREAKDOWN_DATA");
    expect(r.applied!.totalAdjustment).toBe(0);
  });

  it("sin movimiento (todo redondeado de antemano + sin fallback): applied = null", () => {
    const r = applyCommercialDocumentRounding({
      totalComercialPostTax: 281100,
      metalValuationSum:     99000,
      metalsByParent:        metalsOro(1.2),       // 1.2 ya está redondeado
      config: {
        scope:   "BREAKDOWN",
        metal:   { mode: "DECIMAL_1", direction: "NEAREST" },
        hechura: { mode: "HUNDRED",   direction: "NEAREST" },
      },
    });
    expect(r.applied).toBeNull();
    expect(r.totalPostCommercial).toBe(281100);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Determinismo (preview = confirm)
// ─────────────────────────────────────────────────────────────────────────────

describe("applyCommercialDocumentRounding — determinismo", () => {
  it("mismo input → mismo output byte a byte (clave para preview/confirm parity)", () => {
    const args: CommercialDocRoundingArgs = {
      totalComercialPostTax: 281091.10,
      metalValuationSum:     99000,
      metalsByParent: [{
        metalParentId:     "OroFino",
        metalParentName:   "Oro Fino",
        gramsPure:         1.2375,
        metalPricePerGram: 80000,
      }],
      config: {
        scope:   "BREAKDOWN",
        metal:   { mode: "DECIMAL_1", direction: "NEAREST" },
        hechura: { mode: "HUNDRED",   direction: "NEAREST" },
      },
    };
    const a = applyCommercialDocumentRounding(args);
    const b = applyCommercialDocumentRounding(args);
    expect(JSON.stringify(a)).toBe(JSON.stringify(b));
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// NO_SHARED_LIST — el caller lo emite, validamos shape compatible
// ─────────────────────────────────────────────────────────────────────────────

describe("applyCommercialDocumentRounding — fallback NO_SHARED_LIST (caller-side)", () => {
  it("el shape del snapshot acepta el fallback emitido por el caller", () => {
    // Cuando las líneas tienen distintas listas, el caller NO llama al helper
    // y persiste manualmente este shape. Verificamos que es type-compatible.
    const callerEmitted: CommercialDocRoundingApplied = {
      source:          "PRICE_LIST",
      scope:           "UNIFIED",
      totalAdjustment: 0,
      fallback:        "NO_SHARED_LIST",
    };
    expect(callerEmitted.fallback).toBe("NO_SHARED_LIST");
    expect(callerEmitted.totalAdjustment).toBe(0);
  });
});
