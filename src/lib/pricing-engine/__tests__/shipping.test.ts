// src/lib/pricing-engine/__tests__/shipping.test.ts
// =============================================================================
// SPRINT 3 — Capa 10 del orden inmutable: envío.
//
// Garantiza que `resolveShippingAmount` es la única fuente de verdad y que
// produce los mismos montos para articles/pricing-preview y sales/preview.
// =============================================================================

import { describe, it, expect } from "vitest";
import { resolveShippingAmount } from "../pricing-engine.shipping.js";

describe("resolveShippingAmount — POLICY.md §5", () => {
  it("FREE → amount = 0", () => {
    const r = resolveShippingAmount({ mode: "FREE", value: null, weight: null });
    expect(r).toEqual({ mode: "FREE", amount: 0, label: "Envío gratis" });
  });

  it("FIXED → amount = value redondeado a 2 decimales", () => {
    const r = resolveShippingAmount({ mode: "FIXED", value: 500, weight: null });
    expect(r).toEqual({ mode: "FIXED", amount: 500, label: "Envío fijo" });
  });

  it("FIXED con value decimal → redondea a 2", () => {
    const r = resolveShippingAmount({ mode: "FIXED", value: 123.456, weight: null });
    expect(r?.amount).toBe(123.46);
  });

  it("BY_WEIGHT → amount = value × weight redondeado a 2", () => {
    const r = resolveShippingAmount({ mode: "BY_WEIGHT", value: 100, weight: 2 });
    expect(r).toEqual({ mode: "BY_WEIGHT", amount: 200, label: "Envío por peso" });
  });

  it("BY_WEIGHT con peso fraccionario", () => {
    const r = resolveShippingAmount({ mode: "BY_WEIGHT", value: 250, weight: 0.75 });
    expect(r?.amount).toBe(187.5);
  });

  it("input null/undefined → null", () => {
    expect(resolveShippingAmount(null)).toBeNull();
    expect(resolveShippingAmount(undefined)).toBeNull();
  });

  it("input sin mode → null", () => {
    // @ts-expect-error — testing defensive behavior
    expect(resolveShippingAmount({ value: 100 })).toBeNull();
  });

  it("FIXED con value inválido → throws 400", () => {
    expect(() => resolveShippingAmount({ mode: "FIXED", value: null, weight: null }))
      .toThrowError(/value/i);
    try {
      resolveShippingAmount({ mode: "FIXED", value: -50, weight: null });
      expect.fail("debería haber lanzado");
    } catch (err: any) {
      expect(err.status).toBe(400);
    }
  });

  it("BY_WEIGHT sin weight → throws 400", () => {
    expect(() => resolveShippingAmount({ mode: "BY_WEIGHT", value: 100, weight: null }))
      .toThrowError(/weight/i);
  });

  it("BY_WEIGHT sin value → throws 400", () => {
    expect(() => resolveShippingAmount({ mode: "BY_WEIGHT", value: null, weight: 5 }))
      .toThrowError(/value/i);
  });

  it("FREE ignora value/weight inválidos", () => {
    // FREE no requiere validación de los otros campos.
    const r = resolveShippingAmount({ mode: "FREE", value: -999, weight: NaN });
    expect(r?.amount).toBe(0);
  });
});
