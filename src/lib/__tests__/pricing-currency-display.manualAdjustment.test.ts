// src/lib/__tests__/pricing-currency-display.manualAdjustment.test.ts
// =============================================================================
// Etapa A — Verifica que la conversión multimoneda del snapshot de ajuste
// manual + engineTotal + finalTotal funcione correctamente.
//
// Gotcha canónica del proyecto (CLAUDE.md raíz):
//   "Cuando se agrega un campo monetario nuevo al response del preview, hay
//    que sumarlo a `convert*InPlace`. Sin eso, ese campo queda en BASE
//    mientras el resto del response viene en DISPLAY → mezcla de monedas."
//
// Estos tests son el guard de regresión.
// =============================================================================

import { describe, it, expect } from "vitest";
import {
  convertManualAdjustmentSnapshotInPlace,
  convertSalesPreviewResponseInPlace,
} from "../pricing-currency-display.js";

describe("convertManualAdjustmentSnapshotInPlace — campos monetarios", () => {
  it("convierte unified.preAmount/postAmount/amount + totals.monetaryAdjustment", () => {
    // rate = 1000 (1 USD = 1000 ARS). engineTotal=100.000 base, ajuste=-500 base.
    const snapshot: any = {
      scope: "UNIFIED",
      unified: { preAmount: 100000, postAmount: 99500, amount: -500 },
      totals:  { monetaryAdjustment: -500 },
      audit:   { appliedBy: { userId: "u-1", userName: "Ana" }, appliedAt: "2026-05-28T00:00:00.000Z", reason: "cierre" },
    };
    convertManualAdjustmentSnapshotInPlace(snapshot, 1000);
    expect(snapshot.unified.preAmount).toBe(100);
    expect(snapshot.unified.postAmount).toBe(99.5);
    expect(snapshot.unified.amount).toBe(-0.5);
    expect(snapshot.totals.monetaryAdjustment).toBe(-0.5);
  });

  it("NO convierte scope ni audit (strings/ids/timestamps)", () => {
    const snapshot: any = {
      scope: "UNIFIED",
      unified: { preAmount: 1000, postAmount: 900, amount: -100 },
      totals:  { monetaryAdjustment: -100 },
      audit:   {
        appliedBy: { userId: "u-99", userName: "Roberto" },
        appliedAt: "2026-05-28T18:30:00.000Z",
        reason:    "ajuste",
      },
    };
    convertManualAdjustmentSnapshotInPlace(snapshot, 10);
    expect(snapshot.scope).toBe("UNIFIED");
    expect(snapshot.audit.appliedBy.userId).toBe("u-99");
    expect(snapshot.audit.appliedBy.userName).toBe("Roberto");
    expect(snapshot.audit.appliedAt).toBe("2026-05-28T18:30:00.000Z");
    expect(snapshot.audit.reason).toBe("ajuste");
  });

  it("rate=1 → no-op (snapshot intacto)", () => {
    const snapshot: any = {
      scope: "UNIFIED",
      unified: { preAmount: 100000, postAmount: 99500, amount: -500 },
      totals:  { monetaryAdjustment: -500 },
      audit:   { appliedBy: null, appliedAt: "x", reason: null },
    };
    const copy = JSON.parse(JSON.stringify(snapshot));
    convertManualAdjustmentSnapshotInPlace(snapshot, 1);
    expect(snapshot).toEqual(copy);
  });

  it("snapshot null/undefined → no-op (no tira)", () => {
    expect(() => convertManualAdjustmentSnapshotInPlace(null, 10)).not.toThrow();
    expect(() => convertManualAdjustmentSnapshotInPlace(undefined, 10)).not.toThrow();
  });

  it("snapshot parcial (sin totals) no rompe", () => {
    const snapshot: any = {
      scope:   "UNIFIED",
      unified: { preAmount: 100, postAmount: 50, amount: -50 },
      audit:   { appliedBy: null, appliedAt: "x", reason: null },
    };
    expect(() => convertManualAdjustmentSnapshotInPlace(snapshot, 10)).not.toThrow();
    expect(snapshot.unified.amount).toBe(-5);
  });
});

describe("convertSalesPreviewResponseInPlace — integración Etapa A", () => {
  it("convierte engineTotal y finalTotal top-level del response", () => {
    const res: any = {
      lines: [],
      documentTotals: { total: 100000 },
      engineTotal: 100000,
      finalTotal:  99500,
      manualAdjustment: {
        scope: "UNIFIED",
        unified: { preAmount: 100000, postAmount: 99500, amount: -500 },
        totals:  { monetaryAdjustment: -500 },
        audit:   { appliedBy: null, appliedAt: "x", reason: null },
      },
    };
    convertSalesPreviewResponseInPlace(res, 1000);
    expect(res.engineTotal).toBe(100);
    expect(res.finalTotal).toBe(99.5);
    expect(res.manualAdjustment.unified.preAmount).toBe(100);
    expect(res.manualAdjustment.unified.postAmount).toBe(99.5);
    expect(res.manualAdjustment.unified.amount).toBe(-0.5);
    expect(res.manualAdjustment.totals.monetaryAdjustment).toBe(-0.5);
  });

  it("invariante simétrica: engineTotal + delta === finalTotal (post-conversión)", () => {
    const res: any = {
      lines: [],
      documentTotals: { total: 100000 },
      engineTotal: 100000,
      finalTotal:  99500,
      manualAdjustment: {
        scope: "UNIFIED",
        unified: { preAmount: 100000, postAmount: 99500, amount: -500 },
        totals:  { monetaryAdjustment: -500 },
        audit:   { appliedBy: null, appliedAt: "x", reason: null },
      },
    };
    convertSalesPreviewResponseInPlace(res, 1000);
    // En moneda display: 100 + (-0.5) === 99.5
    expect(res.engineTotal + res.manualAdjustment.totals.monetaryAdjustment).toBeCloseTo(res.finalTotal, 4);
  });

  it("sin manualAdjustment (preview vainilla) no rompe la conversión", () => {
    const res: any = {
      lines: [],
      documentTotals: { total: 100000 },
      engineTotal: 100000,
      finalTotal:  100000,
      manualAdjustment: null,
    };
    expect(() => convertSalesPreviewResponseInPlace(res, 10)).not.toThrow();
    expect(res.engineTotal).toBe(10000);
    expect(res.finalTotal).toBe(10000);
    expect(res.manualAdjustment).toBeNull();
  });
});

// =============================================================================
// Etapa C — BREAKDOWN
// =============================================================================

describe("convertManualAdjustmentSnapshotInPlace — BREAKDOWN", () => {
  it("convierte breakdown.monetary + breakdown.metals[].monetaryEquivalent + metalPricePerGram + totals", () => {
    const snapshot: any = {
      scope: "BREAKDOWN",
      breakdown: {
        metals: [
          {
            metalParentId:      "oro-fino",
            metalParentName:    "Oro Fino",
            preGrams:           0.908,
            postGrams:          1,
            deltaGrams:         0.092,
            metalPricePerGram:  100000, // BASE
            monetaryEquivalent: 9200,   // BASE
          },
        ],
        monetary: { preAmount: 13955, amount: 45, postAmount: 14000 },
      },
      totals: {
        monetaryAdjustment:      45,
        metalMonetaryEquivalent: 9200,
        totalMonetaryAdjustment: 9245,
      },
      audit: { appliedBy: null, appliedAt: "x", reason: null },
    };
    convertManualAdjustmentSnapshotInPlace(snapshot, 1000); // 1 USD = 1000 ARS
    // Monetarios convertidos
    expect(snapshot.breakdown.monetary.preAmount).toBe(13.955);
    expect(snapshot.breakdown.monetary.amount).toBe(0.045);
    expect(snapshot.breakdown.monetary.postAmount).toBe(14);
    expect(snapshot.breakdown.metals[0].metalPricePerGram).toBe(100);
    expect(snapshot.breakdown.metals[0].monetaryEquivalent).toBe(9.2);
    expect(snapshot.totals.monetaryAdjustment).toBe(0.045);
    expect(snapshot.totals.metalMonetaryEquivalent).toBe(9.2);
    expect(snapshot.totals.totalMonetaryAdjustment).toBe(9.245);
  });

  it("gramos NUNCA se convierten (preGrams/postGrams/deltaGrams invariantes)", () => {
    const snapshot: any = {
      scope: "BREAKDOWN",
      breakdown: {
        metals: [
          {
            metalParentId:      "oro-fino",
            metalParentName:    "Oro Fino",
            preGrams:           0.908,
            postGrams:          1,
            deltaGrams:         0.092,
            metalPricePerGram:  100000,
            monetaryEquivalent: 9200,
          },
        ],
        monetary: { preAmount: 0, amount: 0, postAmount: 0 },
      },
      totals: { monetaryAdjustment: 0, metalMonetaryEquivalent: 9200, totalMonetaryAdjustment: 9200 },
      audit: { appliedBy: null, appliedAt: "x", reason: null },
    };
    convertManualAdjustmentSnapshotInPlace(snapshot, 1000);
    expect(snapshot.breakdown.metals[0].preGrams).toBe(0.908);
    expect(snapshot.breakdown.metals[0].postGrams).toBe(1);
    expect(snapshot.breakdown.metals[0].deltaGrams).toBe(0.092);
    // Strings / IDs intactos.
    expect(snapshot.breakdown.metals[0].metalParentId).toBe("oro-fino");
    expect(snapshot.breakdown.metals[0].metalParentName).toBe("Oro Fino");
  });
});

// =============================================================================
// Bug #1 — convertSalesPreviewInputInPlace convierte el manualAdjustment
// display→base ANTES de que el motor consuma el input.
// =============================================================================

import { convertSalesPreviewInputInPlace } from "../pricing-currency-display.js";

describe("convertSalesPreviewInputInPlace — manualAdjustment (Bug #1)", () => {
  it("UNIFIED: amount display→base (operador tipea en USD, motor lee en ARS base)", () => {
    const input: any = {
      manualAdjustment: { scope: "UNIFIED", amount: -500, reason: null },
    };
    convertSalesPreviewInputInPlace(input, 1000); // 1 USD = 1000 ARS
    expect(input.manualAdjustment.amount).toBe(-500000);
  });

  it("UNIFIED shape rico { unified: { amount } } también se convierte", () => {
    const input: any = {
      manualAdjustment: { scope: "UNIFIED", unified: { amount: -500 } },
    };
    convertSalesPreviewInputInPlace(input, 1000);
    expect(input.manualAdjustment.unified.amount).toBe(-500000);
  });

  it("BREAKDOWN: monetaryAmount display→base; gramos NO se convierten", () => {
    const input: any = {
      manualAdjustment: {
        scope: "BREAKDOWN",
        metals: [
          { metalParentId: "oro", targetGrams: 1.5 },
          { metalParentId: "plata", deltaGrams: -0.06 },
        ],
        monetaryAmount: 45, // USD
      },
    };
    convertSalesPreviewInputInPlace(input, 1000);
    expect(input.manualAdjustment.monetaryAmount).toBe(45000); // base
    // Gramos invariantes
    expect(input.manualAdjustment.metals[0].targetGrams).toBe(1.5);
    expect(input.manualAdjustment.metals[1].deltaGrams).toBe(-0.06);
  });

  it("rate=1 (sin conversión) → no-op", () => {
    const input: any = {
      manualAdjustment: { scope: "UNIFIED", amount: -500 },
    };
    convertSalesPreviewInputInPlace(input, 1);
    expect(input.manualAdjustment.amount).toBe(-500);
  });

  it("sin manualAdjustment → no rompe", () => {
    const input: any = { shippingAmount: 100 };
    expect(() => convertSalesPreviewInputInPlace(input, 10)).not.toThrow();
    expect(input.shippingAmount).toBe(1000);
  });
});
