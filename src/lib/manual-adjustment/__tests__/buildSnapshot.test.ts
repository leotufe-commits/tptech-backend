// src/lib/manual-adjustment/__tests__/buildSnapshot.test.ts
// =============================================================================
// Tests del helper puro `buildManualAdjustmentSnapshot` (Etapa 1 — UNIFIED).
//
// Reglas oficiales (POLICY §R-Rounding-1 capa 17):
//   · Pure function — mismo input → mismo output (determinístico).
//   · NO toca motor, NO recalcula impuestos.
//   · finalTotal NUNCA negativo (clamp a 0).
//   · Si finalTotal clampea a 0, el snapshot refleja el ajuste EFECTIVO.
//   · Sin ajuste (amount=0 / null / undefined) → snapshot=null, passthrough.
// =============================================================================

import { describe, it, expect } from "vitest";
import { buildManualAdjustmentSnapshot } from "../buildSnapshot.js";
import type { ManualAdjustmentInput, ManualAdjustmentAudit } from "../types.js";

const AUDIT: ManualAdjustmentAudit = {
  appliedBy: { userId: "u-1", userName: "Roberto" },
  appliedAt: "2026-05-28T18:00:00.000Z",
  reason:    null,
};

describe("buildManualAdjustmentSnapshot — sin ajuste", () => {
  it("input null → snapshot=null, finalTotal=engineTotal", () => {
    const out = buildManualAdjustmentSnapshot({
      engineTotal: 473500,
      input:       null,
      audit:       AUDIT,
    });
    expect(out.snapshot).toBeNull();
    expect(out.engineTotal).toBe(473500);
    expect(out.finalTotal).toBe(473500);
  });

  it("input undefined → snapshot=null", () => {
    const out = buildManualAdjustmentSnapshot({
      engineTotal: 100,
      input:       undefined,
      audit:       AUDIT,
    });
    expect(out.snapshot).toBeNull();
    expect(out.finalTotal).toBe(100);
  });

  it("amount=0 → snapshot=null (considerado sin ajuste)", () => {
    const out = buildManualAdjustmentSnapshot({
      engineTotal: 1000,
      input:       { scope: "UNIFIED", amount: 0 },
      audit:       AUDIT,
    });
    expect(out.snapshot).toBeNull();
    expect(out.finalTotal).toBe(1000);
  });

  it("amount=NaN → snapshot=null (defensive)", () => {
    const out = buildManualAdjustmentSnapshot({
      engineTotal: 1000,
      input:       { scope: "UNIFIED", amount: NaN },
      audit:       AUDIT,
    });
    expect(out.snapshot).toBeNull();
    expect(out.finalTotal).toBe(1000);
  });
});

describe("buildManualAdjustmentSnapshot — ajuste negativo (cierre comercial)", () => {
  it("caso del documento: 473.500 + (-500) → 473.000", () => {
    const out = buildManualAdjustmentSnapshot({
      engineTotal: 473500,
      input:       { scope: "UNIFIED", amount: -500 },
      audit:       AUDIT,
    });
    expect(out.engineTotal).toBe(473500);
    expect(out.finalTotal).toBe(473000);
    expect(out.snapshot).toMatchObject({
      scope: "UNIFIED",
      unified: { preAmount: 473500, postAmount: 473000, amount: -500 },
      totals:  { monetaryAdjustment: -500 },
    });
  });

  it("preAmount === engineTotal, postAmount === finalTotal (invariante)", () => {
    const out = buildManualAdjustmentSnapshot({
      engineTotal: 1234.56,
      input:       { scope: "UNIFIED", amount: -34.56 },
      audit:       AUDIT,
    });
    expect(out.snapshot!.unified!.preAmount).toBe(out.engineTotal);
    expect(out.snapshot!.unified!.postAmount).toBe(out.finalTotal);
  });
});

describe("buildManualAdjustmentSnapshot — ajuste positivo (recargo)", () => {
  it("473.500 + 500 → 474.000", () => {
    const out = buildManualAdjustmentSnapshot({
      engineTotal: 473500,
      input:       { scope: "UNIFIED", amount: 500 },
      audit:       AUDIT,
    });
    expect(out.finalTotal).toBe(474000);
    expect(out.snapshot!.unified!.amount).toBe(500);
    expect(out.snapshot!.totals.monetaryAdjustment).toBe(500);
  });
});

describe("buildManualAdjustmentSnapshot — clamp defensivo", () => {
  it("ajuste mayor al engineTotal: finalTotal=0, amount efectivo limita el delta", () => {
    const out = buildManualAdjustmentSnapshot({
      engineTotal: 100,
      input:       { scope: "UNIFIED", amount: -200 },
      audit:       AUDIT,
    });
    expect(out.finalTotal).toBe(0);
    // El amount efectivo refleja la realidad — no el tipeado (-200) sino lo
    // que efectivamente movió (-100).
    expect(out.snapshot!.unified!.amount).toBe(-100);
    expect(out.snapshot!.totals.monetaryAdjustment).toBe(-100);
    expect(out.snapshot!.unified!.postAmount).toBe(0);
  });

  it("engineTotal=0 con ajuste positivo: finalTotal=amount", () => {
    const out = buildManualAdjustmentSnapshot({
      engineTotal: 0,
      input:       { scope: "UNIFIED", amount: 100 },
      audit:       AUDIT,
    });
    expect(out.finalTotal).toBe(100);
    expect(out.snapshot!.unified!.amount).toBe(100);
  });

  it("engineTotal=0 con ajuste negativo: finalTotal=0, amount efectivo=0", () => {
    const out = buildManualAdjustmentSnapshot({
      engineTotal: 0,
      input:       { scope: "UNIFIED", amount: -100 },
      audit:       AUDIT,
    });
    expect(out.finalTotal).toBe(0);
    expect(out.snapshot!.unified!.amount).toBe(0);
  });
});

describe("buildManualAdjustmentSnapshot — determinismo (preview/confirm parity)", () => {
  it("mismo input → mismo output (excepto audit.appliedAt)", () => {
    const input: ManualAdjustmentInput = { scope: "UNIFIED", amount: -123.45 };
    const a = buildManualAdjustmentSnapshot({ engineTotal: 5000, input, audit: AUDIT });
    const b = buildManualAdjustmentSnapshot({ engineTotal: 5000, input, audit: AUDIT });
    expect(a.snapshot!.unified).toEqual(b.snapshot!.unified);
    expect(a.snapshot!.totals).toEqual(b.snapshot!.totals);
    expect(a.finalTotal).toBe(b.finalTotal);
    expect(a.engineTotal).toBe(b.engineTotal);
  });
});

describe("buildManualAdjustmentSnapshot — audit", () => {
  it("audit propagado al snapshot", () => {
    const out = buildManualAdjustmentSnapshot({
      engineTotal: 1000,
      input:       { scope: "UNIFIED", amount: -10, reason: "cierre caja" },
      audit:       {
        appliedBy: { userId: "u-99", userName: "Ana" },
        appliedAt: "2026-05-28T20:30:00.000Z",
        reason:    "cierre caja",
      },
    });
    expect(out.snapshot!.audit.appliedBy?.userName).toBe("Ana");
    expect(out.snapshot!.audit.reason).toBe("cierre caja");
    expect(out.snapshot!.audit.appliedAt).toBe("2026-05-28T20:30:00.000Z");
  });

  it("audit=null usa default con appliedBy=null y appliedAt=now", () => {
    const out = buildManualAdjustmentSnapshot({
      engineTotal: 1000,
      input:       { scope: "UNIFIED", amount: -10 },
      audit:       null,
    });
    expect(out.snapshot!.audit.appliedBy).toBeNull();
    expect(out.snapshot!.audit.appliedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });
});
