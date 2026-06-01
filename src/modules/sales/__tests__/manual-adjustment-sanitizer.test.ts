// src/modules/sales/__tests__/manual-adjustment-sanitizer.test.ts
// =============================================================================
// Etapa A — Validación del sanitizer del contrato `manualAdjustment` que
// reciben los endpoints de `sales` (preview / create / update). Reglas:
//   · Solo scope="UNIFIED" se acepta. Cualquier otro → 400 (`err.status = 400`).
//   · `amount=0` / ausente / NaN / no finito → `null` (sin ajuste).
//   · `reason` se trimea; vacío → `null`.
//   · Shape rico (`{ scope, unified:{amount} }`) y plano (`{ scope, amount }`)
//     se normalizan al plano.
//
// POLICY §R-Rounding-1 capa 17 — CLAUDE.md §Etapa A.
// =============================================================================

import { describe, it, expect } from "vitest";
import { sanitizeManualAdjustmentInput } from "../sales.controller.js";

describe("sanitizeManualAdjustmentInput — sin ajuste", () => {
  it("null → null", () => {
    expect(sanitizeManualAdjustmentInput(null)).toBeNull();
  });

  it("undefined → null", () => {
    expect(sanitizeManualAdjustmentInput(undefined)).toBeNull();
  });

  it("amount=0 → null (considerado 'sin ajuste')", () => {
    expect(
      sanitizeManualAdjustmentInput({ scope: "UNIFIED", amount: 0 }),
    ).toBeNull();
  });

  it("amount muy cercano a 0 (dentro de EPS) → null", () => {
    expect(
      sanitizeManualAdjustmentInput({ scope: "UNIFIED", amount: 0.001 }),
    ).toBeNull();
  });

  it("amount NaN → null (defensivo)", () => {
    expect(
      sanitizeManualAdjustmentInput({ scope: "UNIFIED", amount: NaN }),
    ).toBeNull();
  });

  it("amount Infinity → null (defensivo)", () => {
    expect(
      sanitizeManualAdjustmentInput({ scope: "UNIFIED", amount: Infinity }),
    ).toBeNull();
  });
});

describe("sanitizeManualAdjustmentInput — scopes rechazados", () => {
  it("scope='BREAKDOWN' ya está soportado (Etapa C) — NO se rechaza", () => {
    // Etapa A solo aceptaba UNIFIED. Etapa C permite BREAKDOWN. El sanitizer
    // no rechaza BREAKDOWN por scope; el gate "documento debe estar en modo
    // BREAKDOWN" lo aplica el service contra el balanceMode resuelto.
    const out = sanitizeManualAdjustmentInput({
      scope: "BREAKDOWN",
      metals: [],
      monetaryAmount: -100,
    });
    expect(out).toEqual({
      scope: "BREAKDOWN",
      metals: [],
      monetaryAmount: -100,
      reason: null,
    });
  });

  it("scope='BOTH' → 400 (no soportado)", () => {
    expect(() =>
      sanitizeManualAdjustmentInput({ scope: "BOTH", amount: -100 }),
    ).toThrowError(/UNIFIED.*BREAKDOWN/i);
  });

  it("scope='LINE' → 400 (scope inventado)", () => {
    expect(() =>
      sanitizeManualAdjustmentInput({ scope: "LINE", amount: -100 }),
    ).toThrowError(/UNIFIED.*BREAKDOWN/i);
  });

  it("scope omitido pero presente unified.amount → asume UNIFIED y sanea", () => {
    const out = sanitizeManualAdjustmentInput({ unified: { amount: -500 } });
    expect(out).toEqual({ scope: "UNIFIED", amount: -500, reason: null });
  });

  it("raw no-objeto (string, number) → 400", () => {
    expect(() => sanitizeManualAdjustmentInput("foo" as any)).toThrowError();
    expect(() => sanitizeManualAdjustmentInput(123 as any)).toThrowError();
  });
});

describe("sanitizeManualAdjustmentInput — formas válidas", () => {
  it("shape plano { scope, amount }", () => {
    const out = sanitizeManualAdjustmentInput({
      scope:  "UNIFIED",
      amount: -250.5,
    });
    expect(out).toEqual({ scope: "UNIFIED", amount: -250.5, reason: null });
  });

  it("shape rico { scope, unified:{amount} } se normaliza", () => {
    const out = sanitizeManualAdjustmentInput({
      scope:   "UNIFIED",
      unified: { amount: 123.45 },
    });
    expect(out).toEqual({ scope: "UNIFIED", amount: 123.45, reason: null });
  });

  it("reason con espacios se trimea", () => {
    const out = sanitizeManualAdjustmentInput({
      scope:  "UNIFIED",
      amount: -100,
      reason: "   cierre comercial   ",
    });
    expect(out?.reason).toBe("cierre comercial");
  });

  it("reason vacío tras trim → null", () => {
    const out = sanitizeManualAdjustmentInput({
      scope:  "UNIFIED",
      amount: -100,
      reason: "   ",
    });
    expect(out?.reason).toBeNull();
  });

  it("ajuste positivo (recargo manual)", () => {
    const out = sanitizeManualAdjustmentInput({
      scope:  "UNIFIED",
      amount: 999.99,
    });
    expect(out?.scope).toBe("UNIFIED");
    expect((out as any).amount).toBe(999.99);
  });

  it("ajuste negativo grande (cierre comercial)", () => {
    const out = sanitizeManualAdjustmentInput({
      scope:  "UNIFIED",
      amount: -1000000,
    });
    expect((out as any).amount).toBe(-1000000);
  });
});

describe("sanitizeManualAdjustmentInput — context en el error 400", () => {
  it("el mensaje incluye el contexto pasado por el caller", () => {
    try {
      sanitizeManualAdjustmentInput(
        { scope: "BREAKDOWN", amount: 1 },
        "sales.preview.manualAdjustment",
      );
    } catch (e: any) {
      expect(e.message).toContain("sales.preview.manualAdjustment");
      expect(e.status).toBe(400);
    }
  });
});
