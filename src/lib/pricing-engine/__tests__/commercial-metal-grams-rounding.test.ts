// src/lib/pricing-engine/__tests__/commercial-metal-grams-rounding.test.ts
// =============================================================================
// Fix del bug de punto flotante en el redondeo físico COMERCIAL de gramos del
// metal. `Math.round(value / step)` fallaba en los puntos medios (.X5) y bordes
// de step por el ruido binario:
//   1.65 / 0.1 = 16.499999999999996 → Math.round = 16 → 1.60  (MAL)
//   1.60 / 0.1 = 16.000000000000004 → Math.ceil  = 17 → 1.70  (MAL en UP)
// El fix limpia el cociente antes de redondear → half-up comercial real.
//
// Se valida vía `computeCommercialPostGrams` (SSOT que usan Factura y Simulador,
// PER_DOCUMENT). Con marginFactor=1 ⇒ preGrams = gramsPure → se prueba el
// redondeo puro. NO toca redondeo monetario ni financiero.
// =============================================================================

import { describe, it, expect } from "vitest";
import {
  computeCommercialPostGrams,
  type CommercialDocRoundingPartConfig,
} from "../commercial-document-rounding.js";

const D1_NEAREST: CommercialDocRoundingPartConfig = { mode: "DECIMAL_1", direction: "NEAREST" };

/** Redondea `grams` (marginFactor=1 ⇒ preGrams=grams) y devuelve postGrams. */
function post(grams: number, cfg: CommercialDocRoundingPartConfig = D1_NEAREST): number {
  return computeCommercialPostGrams(grams, 1, cfg).postGrams;
}

describe("Redondeo físico comercial de gramos — DECIMAL_1 NEAREST (half-up, FP-safe)", () => {
  // Casos pedidos por el operador.
  it.each([
    [1.64, 1.6],
    [1.65, 1.7],  // ← bug original (daba 1.6)
    [1.66, 1.7],
    [2.04, 2.0],
    [2.05, 2.1],  // ← half-point
    [2.06, 2.1],
    [2.14, 2.1],
    [2.15, 2.2],  // ← half-point
    [2.16, 2.2],
    [1.36125, 1.4], // Oro — regresión (no es half-point, ya andaba)
  ])("%f g → %f g", (input, expected) => {
    expect(post(input)).toBeCloseTo(expected, 4);
  });

  it("valores ya redondos NO se mueven (1,60 → 1,60; 2,00 → 2,00)", () => {
    expect(post(1.6)).toBeCloseTo(1.6, 4);
    expect(post(2.0)).toBeCloseTo(2.0, 4);
    expect(post(2.1)).toBeCloseTo(2.1, 4);
  });

  it("Plata del caso real: 1,50 g × margen 10% = 1,65 → 1,70", () => {
    // gramsPure = 1.50 (pureza 1, merma 0), marginFactor 1.10 → preGrams 1.65.
    const r = computeCommercialPostGrams(1.5, 1.1, D1_NEAREST);
    expect(r.preGrams).toBeCloseTo(1.65, 4);
    expect(r.postGrams).toBeCloseTo(1.7, 4);
    expect(r.deltaGrams).toBeCloseTo(0.05, 4);
  });

  it("dirección UP también FP-safe: 1,60 NO sube a 1,70", () => {
    expect(post(1.6, { mode: "DECIMAL_1", direction: "UP" })).toBeCloseTo(1.6, 4);
    expect(post(1.61, { mode: "DECIMAL_1", direction: "UP" })).toBeCloseTo(1.7, 4);
  });

  it("dirección DOWN: 1,69 → 1,60 ; 1,70 → 1,70", () => {
    expect(post(1.69, { mode: "DECIMAL_1", direction: "DOWN" })).toBeCloseTo(1.6, 4);
    expect(post(1.7,  { mode: "DECIMAL_1", direction: "DOWN" })).toBeCloseTo(1.7, 4);
  });

  it("otros steps: INTEGER NEAREST (2,5 → 3) y DECIMAL_2 (1,005 → 1,01)", () => {
    expect(post(2.5, { mode: "INTEGER",  direction: "NEAREST" })).toBeCloseTo(3, 4);
    expect(post(1.005, { mode: "DECIMAL_2", direction: "NEAREST" })).toBeCloseTo(1.01, 4);
  });

  it("mode NONE: postGrams = preGrams (sin redondeo)", () => {
    expect(post(1.65, { mode: "NONE", direction: "NEAREST" })).toBeCloseTo(1.65, 4);
  });
});
