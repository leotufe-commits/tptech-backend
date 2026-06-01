// src/modules/sales/__tests__/manual-adjustment-breakdown.test.ts
// =============================================================================
// Etapa C — Validación del sanitizer + helper buildSnapshot para scope
// "BREAKDOWN" (ajuste manual por metal + hechura monetaria).
//
// Reglas (POLICY §R-Rounding-1 capa 17 + §R-Rounding-13):
//   · Etapa C es SOLO MANUAL. Redondeo físico de gramos = etapa futura.
//   · Sanitizer: targetGrams ≥ 0, deltaGrams finito, monetaryAmount finito,
//     entries vacías filtradas, todo cero → null.
//   · Helper: snapshot UNIFIED y BREAKDOWN comparten contrato de totals
//     (monetaryAdjustment + metalMonetaryEquivalent + totalMonetaryAdjustment).
//   · Sale.total = max(0, engineTotal + totals.totalMonetaryAdjustment).
//   · Gramos invariantes — NUNCA se convierten.
// =============================================================================

import { describe, it, expect } from "vitest";
import { sanitizeManualAdjustmentInput } from "../sales.controller.js";
import { buildManualAdjustmentSnapshot } from "../../../lib/manual-adjustment/buildSnapshot.js";
import type {
  ManualAdjustmentAudit,
  ManualAdjustmentBreakdownContext,
  ManualAdjustmentSnapshotBreakdown,
} from "../../../lib/manual-adjustment/types.js";

const AUDIT: ManualAdjustmentAudit = {
  appliedBy: { userId: "u-1", userName: "Roberto" },
  appliedAt: "2026-05-28T18:00:00.000Z",
  reason:    null,
};

const CTX: ManualAdjustmentBreakdownContext = {
  monetaryHechura: { preAmount: 13955 },
  metals: [
    { metalParentId: "oro-fino",  metalParentName: "Oro Fino", gramsPure: 0.908, metalPricePerGram: 100000 },
    { metalParentId: "plata-925", metalParentName: "Plata",    gramsPure: 2.44,  metalPricePerGram: 500 },
  ],
};

// ─────────────────────────────────────────────────────────────────────────
// Sanitizer
// ─────────────────────────────────────────────────────────────────────────

describe("sanitizeManualAdjustmentInput — BREAKDOWN válido", () => {
  it("shape estándar { scope, metals, monetaryAmount, reason }", () => {
    const out = sanitizeManualAdjustmentInput({
      scope: "BREAKDOWN",
      metals: [
        { metalParentId: "oro-fino", targetGrams: 1, reason: "  ajuste cierre  " },
      ],
      monetaryAmount: 45,
      reason: "fin de día",
    });
    expect(out).toEqual({
      scope:  "BREAKDOWN",
      metals: [
        { metalParentId: "oro-fino", targetGrams: 1, reason: "ajuste cierre" },
      ],
      monetaryAmount: 45,
      reason: "fin de día",
    });
  });

  it("acepta breakdown anidado { scope, breakdown: { metals, monetaryAmount } }", () => {
    const out = sanitizeManualAdjustmentInput({
      scope: "BREAKDOWN",
      breakdown: {
        metals: [{ metalParentId: "oro", deltaGrams: 0.05 }],
        monetaryAmount: -10,
      },
    });
    expect(out?.scope).toBe("BREAKDOWN");
    expect((out as any).metals).toEqual([{ metalParentId: "oro", deltaGrams: 0.05, reason: null }]);
    expect((out as any).monetaryAmount).toBe(-10);
  });

  it("filtra entries sin instrucción útil (sin target ni delta)", () => {
    const out = sanitizeManualAdjustmentInput({
      scope: "BREAKDOWN",
      metals: [
        { metalParentId: "oro", targetGrams: 1.5 },
        { metalParentId: "plata" }, // ← filtrada
      ],
    });
    expect((out as any).metals).toHaveLength(1);
    expect((out as any).metals[0].metalParentId).toBe("oro");
  });

  it("todo vacío → null (ni gramos significativos ni monetaryAmount)", () => {
    expect(
      sanitizeManualAdjustmentInput({ scope: "BREAKDOWN", metals: [] }),
    ).toBeNull();
    expect(
      sanitizeManualAdjustmentInput({
        scope: "BREAKDOWN",
        metals: [{ metalParentId: "oro", deltaGrams: 0.00001 }],
      }),
    ).toBeNull();
  });
});

describe("sanitizeManualAdjustmentInput — BREAKDOWN rechazos", () => {
  it("targetGrams negativo → 400", () => {
    expect(() =>
      sanitizeManualAdjustmentInput({
        scope: "BREAKDOWN",
        metals: [{ metalParentId: "oro", targetGrams: -0.5 }],
      }),
    ).toThrowError(/targetGrams.*negativ/i);
  });

  it("targetGrams NaN → 400", () => {
    expect(() =>
      sanitizeManualAdjustmentInput({
        scope: "BREAKDOWN",
        metals: [{ metalParentId: "oro", targetGrams: Number.NaN }],
      }),
    ).toThrowError(/targetGrams/);
  });

  it("deltaGrams Infinity → 400", () => {
    expect(() =>
      sanitizeManualAdjustmentInput({
        scope: "BREAKDOWN",
        metals: [{ metalParentId: "oro", deltaGrams: Infinity }],
      }),
    ).toThrowError(/deltaGrams/);
  });

  it("monetaryAmount NaN → 400", () => {
    expect(() =>
      sanitizeManualAdjustmentInput({
        scope: "BREAKDOWN",
        metals: [],
        monetaryAmount: Number.NaN,
      }),
    ).toThrowError(/monetaryAmount/i);
  });

  it("metalParentId con tipo inválido (number) → 400", () => {
    expect(() =>
      sanitizeManualAdjustmentInput({
        scope: "BREAKDOWN",
        metals: [{ metalParentId: 123 as any, targetGrams: 1 }],
      }),
    ).toThrowError(/metalParentId/);
  });
});

// ─────────────────────────────────────────────────────────────────────────
// Helper buildManualAdjustmentSnapshot — BREAKDOWN
// ─────────────────────────────────────────────────────────────────────────

describe("buildManualAdjustmentSnapshot — BREAKDOWN solo metales (targetGrams)", () => {
  it("caso documental: Oro 0.908 g → 1.000 g a 100.000 $/g → equivalente 9.200", () => {
    const out = buildManualAdjustmentSnapshot({
      engineTotal: 87750,
      input: {
        scope: "BREAKDOWN",
        metals: [{ metalParentId: "oro-fino", targetGrams: 1 }],
      },
      audit: AUDIT,
      breakdownContext: CTX,
    });
    expect(out.snapshot?.scope).toBe("BREAKDOWN");
    const snap = out.snapshot as ManualAdjustmentSnapshotBreakdown;
    expect(snap.breakdown.metals).toHaveLength(1);
    const oro = snap.breakdown.metals[0];
    expect(oro.preGrams).toBe(0.908);
    expect(oro.postGrams).toBe(1);
    expect(oro.deltaGrams).toBeCloseTo(0.092, 4);
    expect(oro.metalPricePerGram).toBe(100000);
    expect(oro.monetaryEquivalent).toBeCloseTo(9200, 2);

    expect(snap.totals.monetaryAdjustment).toBe(0);
    expect(snap.totals.metalMonetaryEquivalent).toBeCloseTo(9200, 2);
    expect(snap.totals.totalMonetaryAdjustment).toBeCloseTo(9200, 2);

    expect(out.finalTotal).toBeCloseTo(87750 + 9200, 2);
  });
});

describe("buildManualAdjustmentSnapshot — BREAKDOWN deltaGrams", () => {
  it("Plata delta +0.06 g a 500 $/g → equivalente 30", () => {
    const out = buildManualAdjustmentSnapshot({
      engineTotal: 1220,
      input: {
        scope: "BREAKDOWN",
        metals: [{ metalParentId: "plata-925", deltaGrams: 0.06 }],
      },
      audit: AUDIT,
      breakdownContext: CTX,
    });
    const snap = out.snapshot as ManualAdjustmentSnapshotBreakdown;
    expect(snap.breakdown.metals[0].postGrams).toBeCloseTo(2.5, 4);
    expect(snap.breakdown.metals[0].monetaryEquivalent).toBeCloseTo(30, 2);
    expect(snap.totals.totalMonetaryAdjustment).toBeCloseTo(30, 2);
    expect(out.finalTotal).toBeCloseTo(1250, 2);
  });

  it("targetGrams gana sobre deltaGrams si ambos vienen", () => {
    const out = buildManualAdjustmentSnapshot({
      engineTotal: 1000,
      input: {
        scope: "BREAKDOWN",
        metals: [{ metalParentId: "plata-925", targetGrams: 3, deltaGrams: 100 }],
      },
      audit: AUDIT,
      breakdownContext: CTX,
    });
    const snap = out.snapshot as ManualAdjustmentSnapshotBreakdown;
    expect(snap.breakdown.metals[0].postGrams).toBe(3);
  });
});

describe("buildManualAdjustmentSnapshot — BREAKDOWN monetaryAmount", () => {
  it("Hechura 13955 + 45 → 14000", () => {
    const out = buildManualAdjustmentSnapshot({
      engineTotal: 13955,
      input: { scope: "BREAKDOWN", monetaryAmount: 45 },
      audit: AUDIT,
      breakdownContext: CTX,
    });
    const snap = out.snapshot as ManualAdjustmentSnapshotBreakdown;
    expect(snap.breakdown.monetary.preAmount).toBe(13955);
    expect(snap.breakdown.monetary.amount).toBe(45);
    expect(snap.breakdown.monetary.postAmount).toBe(14000);
    expect(snap.totals.monetaryAdjustment).toBe(45);
    expect(snap.totals.metalMonetaryEquivalent).toBe(0);
    expect(snap.totals.totalMonetaryAdjustment).toBe(45);
    expect(out.finalTotal).toBe(14000);
  });
});

describe("buildManualAdjustmentSnapshot — BREAKDOWN mixto (metales + hechura)", () => {
  it("Oro +0.092 g (eq 9200) + Hechura +45 → totalMonetaryAdjustment 9245", () => {
    const out = buildManualAdjustmentSnapshot({
      engineTotal: 87750,
      input: {
        scope: "BREAKDOWN",
        metals:        [{ metalParentId: "oro-fino", targetGrams: 1 }],
        monetaryAmount: 45,
      },
      audit: AUDIT,
      breakdownContext: CTX,
    });
    const snap = out.snapshot as ManualAdjustmentSnapshotBreakdown;
    expect(snap.totals.monetaryAdjustment).toBe(45);
    expect(snap.totals.metalMonetaryEquivalent).toBeCloseTo(9200, 2);
    expect(snap.totals.totalMonetaryAdjustment).toBeCloseTo(9245, 2);
    expect(out.finalTotal).toBeCloseTo(96995, 2);
  });
});

describe("buildManualAdjustmentSnapshot — BREAKDOWN clamp y degradación", () => {
  it("delta cero efectivo en gramos → entry filtrada, snapshot=null si no hay hechura", () => {
    const out = buildManualAdjustmentSnapshot({
      engineTotal: 1000,
      input: {
        scope: "BREAKDOWN",
        metals: [{ metalParentId: "oro-fino", targetGrams: 0.908 }], // = preGrams
      },
      audit: AUDIT,
      breakdownContext: CTX,
    });
    expect(out.snapshot).toBeNull();
    expect(out.finalTotal).toBe(1000);
  });

  it("clamp a 0 cuando engineTotal + delta < 0; recorta el monetario, NO los gramos", () => {
    const out = buildManualAdjustmentSnapshot({
      engineTotal: 100,
      input: {
        scope: "BREAKDOWN",
        metals: [{ metalParentId: "plata-925", deltaGrams: 0.06 }], // eq 30
        monetaryAmount: -500,
      },
      audit: AUDIT,
      breakdownContext: CTX,
    });
    const snap = out.snapshot as ManualAdjustmentSnapshotBreakdown;
    expect(out.finalTotal).toBe(0);
    // Gramos NO se recortan — el delta de plata se preserva.
    expect(snap.breakdown.metals[0].deltaGrams).toBeCloseTo(0.06, 4);
    expect(snap.breakdown.metals[0].monetaryEquivalent).toBeCloseTo(30, 2);
    // El monetario sí se recorta: 100 + 30 + amount efectivo = 0 → amount = -130
    expect(snap.totals.totalMonetaryAdjustment).toBeCloseTo(-100, 2);
    expect(snap.breakdown.monetary.amount).toBeCloseTo(-130, 2);
  });

  it("sin breakdownContext → snapshot=null (no fabricamos metales)", () => {
    const out = buildManualAdjustmentSnapshot({
      engineTotal: 1000,
      input: {
        scope: "BREAKDOWN",
        metals: [{ metalParentId: "oro-fino", targetGrams: 1 }],
      },
      audit: AUDIT,
    });
    expect(out.snapshot).toBeNull();
    expect(out.finalTotal).toBe(1000);
  });

  it("metalPricePerGram null en context → equivalente 0 pero entry persiste", () => {
    const out = buildManualAdjustmentSnapshot({
      engineTotal: 1000,
      input: {
        scope: "BREAKDOWN",
        metals: [{ metalParentId: "oro-fino", targetGrams: 1 }],
      },
      audit: AUDIT,
      breakdownContext: {
        monetaryHechura: { preAmount: 1000 },
        metals: [
          {
            metalParentId: "oro-fino",
            metalParentName: "Oro Fino",
            gramsPure: 0.908,
            metalPricePerGram: null,
          },
        ],
      },
    });
    const snap = out.snapshot as ManualAdjustmentSnapshotBreakdown;
    expect(snap.breakdown.metals[0].metalPricePerGram).toBe(0);
    expect(snap.breakdown.metals[0].monetaryEquivalent).toBe(0);
    expect(out.finalTotal).toBe(1000); // sin movimiento monetario
  });
});

describe("buildManualAdjustmentSnapshot — UNIFIED sigue funcionando + nuevos totals", () => {
  it("UNIFIED expone totals.metalMonetaryEquivalent=0 y totalMonetaryAdjustment=amount", () => {
    const out = buildManualAdjustmentSnapshot({
      engineTotal: 473500,
      input:       { scope: "UNIFIED", amount: -500 },
      audit:       AUDIT,
    });
    expect(out.snapshot?.scope).toBe("UNIFIED");
    expect(out.snapshot!.totals.monetaryAdjustment).toBe(-500);
    expect(out.snapshot!.totals.metalMonetaryEquivalent).toBe(0);
    expect(out.snapshot!.totals.totalMonetaryAdjustment).toBe(-500);
    expect(out.finalTotal).toBe(473000);
  });
});

// =============================================================================
// Regla CRÍTICA — Equivalencia monetaria de ajustes de metal
//
// Los ajustes en gramos sobre un metal padre impactan Sale.total y los
// displays financieros vía monetaryEquivalent, EXACTAMENTE igual que el
// redondeo BREAKDOWN. PERO el valor NUNCA se mueve a breakdown.monetary.amount
// (hechura). Los dos dominios quedan PARALELOS y solo se consolidan en
// totalMonetaryAdjustment. POLICY §R-Rounding-1.
// =============================================================================

describe("buildManualAdjustmentSnapshot — Equivalencia monetaria de metales (regla crítica)", () => {
  it("Ajuste SOLO de metal: monetaryEquivalent vive en metals[i], NO en breakdown.monetary.amount", () => {
    // Caso documental: Oro 0,908 g → 1,000 g, cotización 100.000 $/g.
    const out = buildManualAdjustmentSnapshot({
      engineTotal: 87750,
      input: {
        scope: "BREAKDOWN",
        metals: [{ metalParentId: "oro-fino", targetGrams: 1 }],
      },
      audit: AUDIT,
      breakdownContext: CTX,
    });
    const snap = out.snapshot as ManualAdjustmentSnapshotBreakdown;
    // Dominio METAL — el equivalente vive acá.
    expect(snap.breakdown.metals[0].monetaryEquivalent).toBeCloseTo(9200, 2);
    expect(snap.totals.metalMonetaryEquivalent).toBeCloseTo(9200, 2);
    // Dominio HECHURA — INTACTO. El ajuste físico NO se reasigna a hechura.
    expect(snap.breakdown.monetary.preAmount).toBe(CTX.monetaryHechura.preAmount);
    expect(snap.breakdown.monetary.amount).toBe(0);
    expect(snap.breakdown.monetary.postAmount).toBe(CTX.monetaryHechura.preAmount);
    expect(snap.totals.monetaryAdjustment).toBe(0);
    // Consolidación financiera — solo en totalMonetaryAdjustment.
    expect(snap.totals.totalMonetaryAdjustment).toBeCloseTo(9200, 2);
    // Impacto en Sale.total — paralelo al redondeo BREAKDOWN.
    expect(out.finalTotal).toBeCloseTo(87750 + 9200, 2);
  });

  it("Ajuste mixto: cada dominio mantiene SU monto, totalMonetaryAdjustment los suma", () => {
    // Oro +0,092 g (eq +9200) + hechura +45.
    // monetaryAdjustment debe ser EXACTAMENTE 45 (no contaminado por metal).
    // metalMonetaryEquivalent debe ser EXACTAMENTE 9200 (no contaminado por hechura).
    const out = buildManualAdjustmentSnapshot({
      engineTotal: 87750,
      input: {
        scope: "BREAKDOWN",
        metals:        [{ metalParentId: "oro-fino", targetGrams: 1 }],
        monetaryAmount: 45,
      },
      audit: AUDIT,
      breakdownContext: CTX,
    });
    const snap = out.snapshot as ManualAdjustmentSnapshotBreakdown;
    // Dominios DISJUNTOS.
    expect(snap.totals.monetaryAdjustment).toBe(45);
    expect(snap.breakdown.monetary.amount).toBe(45);
    expect(snap.totals.metalMonetaryEquivalent).toBeCloseTo(9200, 2);
    expect(snap.breakdown.metals[0].monetaryEquivalent).toBeCloseTo(9200, 2);
    // Solo la suma final mezcla.
    expect(snap.totals.totalMonetaryAdjustment).toBeCloseTo(9245, 2);
  });

  it("Ajuste negativo de metal: equivalente negativo NO se cuela a hechura", () => {
    // Plata 2,44 g → 2,40 g (delta -0,04 g a 500 $/g = -20 $).
    const out = buildManualAdjustmentSnapshot({
      engineTotal: 1000,
      input: {
        scope: "BREAKDOWN",
        metals: [{ metalParentId: "plata-925", targetGrams: 2.40 }],
      },
      audit: AUDIT,
      breakdownContext: CTX,
    });
    const snap = out.snapshot as ManualAdjustmentSnapshotBreakdown;
    expect(snap.breakdown.metals[0].deltaGrams).toBeCloseTo(-0.04, 4);
    expect(snap.breakdown.metals[0].monetaryEquivalent).toBeCloseTo(-20, 2);
    // Hechura: SIN CAMBIO.
    expect(snap.breakdown.monetary.amount).toBe(0);
    expect(snap.totals.monetaryAdjustment).toBe(0);
    // Consolidado.
    expect(snap.totals.metalMonetaryEquivalent).toBeCloseTo(-20, 2);
    expect(snap.totals.totalMonetaryAdjustment).toBeCloseTo(-20, 2);
    expect(out.finalTotal).toBeCloseTo(980, 2);
  });

  it("Múltiples metales: cada uno aporta su equivalente, monetary.amount sigue en 0", () => {
    // Oro +0,092 g (eq +9200) + Plata +0,06 g (eq +30).
    const out = buildManualAdjustmentSnapshot({
      engineTotal: 10000,
      input: {
        scope: "BREAKDOWN",
        metals: [
          { metalParentId: "oro-fino",  targetGrams: 1 },
          { metalParentId: "plata-925", targetGrams: 2.5 },
        ],
      },
      audit: AUDIT,
      breakdownContext: CTX,
    });
    const snap = out.snapshot as ManualAdjustmentSnapshotBreakdown;
    // Cada metal mantiene su monetaryEquivalent propio.
    const oro   = snap.breakdown.metals.find((m) => m.metalParentId === "oro-fino")!;
    const plata = snap.breakdown.metals.find((m) => m.metalParentId === "plata-925")!;
    expect(oro.monetaryEquivalent).toBeCloseTo(9200, 2);
    expect(plata.monetaryEquivalent).toBeCloseTo(30, 2);
    // Hechura intacta.
    expect(snap.breakdown.monetary.amount).toBe(0);
    expect(snap.totals.monetaryAdjustment).toBe(0);
    // Total de metales consolidado.
    expect(snap.totals.metalMonetaryEquivalent).toBeCloseTo(9230, 2);
    expect(snap.totals.totalMonetaryAdjustment).toBeCloseTo(9230, 2);
  });
});
