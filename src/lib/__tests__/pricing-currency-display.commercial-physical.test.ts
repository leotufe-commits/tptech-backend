// src/lib/__tests__/pricing-currency-display.commercial-physical.test.ts
// =============================================================================
// Etapa C-comercial / C4-fix (POLICY §R-Rounding-14) — Tests de la extensión
// de `convertMetalHechuraBreakdownInPlace` para los nuevos campos del
// Comercial PHYSICAL.
//
// Contrato:
//   · `metalSalePreRounding` / `hechuraSalePreRounding`
//   · `metalSaleRoundingDelta` / `hechuraSaleRoundingDelta`
//   · `physical.metalMonetaryEquivalent`
//   · `physical.metals[].metalPricePerGram`
//   · `physical.metals[].monetaryEquivalent`
// SE CONVIERTEN (montos en moneda base → moneda display).
//
// `physical.metals[].{preGrams,postGrams,deltaGrams}` (gramos físicos)
// y `mode/direction/source/fallback` (strings/literals) NUNCA se convierten.
// =============================================================================

import { describe, it, expect } from "vitest";
import { convertMetalHechuraBreakdownInPlace } from "../pricing-currency-display.js";

function buildBreakdown() {
  return {
    metalCost:               45400,
    metalSale:               100000,
    metalMarginPct:          100,
    hechuraCost:             15000,
    hechuraSale:             15000,
    hechuraMarginPct:        0,
    metalGramsBase:          0.908,
    metalGramsSale:          1.816,
    metalPricePerGram:       100000,
    // C4-fix — auditoría del redondeo comercial.
    metalSalePreRounding:    90800,
    hechuraSalePreRounding:  14987.5,
    metalSaleRoundingDelta:  9200,
    hechuraSaleRoundingDelta:12.5,
    // Snapshot PHYSICAL.
    physical: {
      metals: [
        {
          metalParentId:      "oro-fino",
          metalParentName:    "Oro Fino",
          preGrams:           0.908,
          postGrams:          1.000,
          deltaGrams:         0.092,
          metalPricePerGram:  100000,
          monetaryEquivalent: 9200,
          mode:               "INTEGER",
          direction:          "NEAREST",
          source:             "COMMERCIAL_PHYSICAL_ROUNDING",
          fallback:           null,
        },
      ],
      metalMonetaryEquivalent: 9200,
      fallback:                null,
    },
  };
}

describe("convertMetalHechuraBreakdownInPlace — rate=1 es no-op", () => {
  it("no muta nada cuando rate=1", () => {
    const mhb = buildBreakdown();
    const snapshot = JSON.parse(JSON.stringify(mhb));
    convertMetalHechuraBreakdownInPlace(mhb, 1);
    expect(mhb).toEqual(snapshot);
  });
});

describe("convertMetalHechuraBreakdownInPlace — campos pre/delta convertidos", () => {
  // NOTA semántica del helper: `convertFromBase(n, rate) = n / rate`.
  // `rate` = "1 unidad display equivale a `rate` unidades base".
  // Si rate=2 (USD↔ARS hipotético, 1 USD = 2 ARS), el monto en display = base/2.
  it("rate=2 divide los 4 campos de auditoría (base → display)", () => {
    const mhb = buildBreakdown();
    convertMetalHechuraBreakdownInPlace(mhb, 2);
    expect(mhb.metalSalePreRounding).toBe(45400);
    expect(mhb.hechuraSalePreRounding).toBe(7493.75);
    expect(mhb.metalSaleRoundingDelta).toBe(4600);
    expect(mhb.hechuraSaleRoundingDelta).toBe(6.25);
  });

  it("rate=0.5 multiplica por 2 (base → display)", () => {
    const mhb = buildBreakdown();
    convertMetalHechuraBreakdownInPlace(mhb, 0.5);
    expect(mhb.metalSalePreRounding).toBe(181600);
    expect(mhb.metalSaleRoundingDelta).toBe(18400);
  });

  it("campos faltantes (null/undefined) NO se convierten — degradación segura", () => {
    const mhb: any = buildBreakdown();
    mhb.metalSalePreRounding   = null;
    mhb.metalSaleRoundingDelta = undefined;
    convertMetalHechuraBreakdownInPlace(mhb, 2);
    expect(mhb.metalSalePreRounding).toBeNull();
    expect(mhb.metalSaleRoundingDelta).toBeUndefined();
  });
});

describe("convertMetalHechuraBreakdownInPlace — physical convertido (montos sí, gramos no)", () => {
  it("convierte metalMonetaryEquivalent y por-entry: metalPricePerGram + monetaryEquivalent", () => {
    const mhb = buildBreakdown();
    convertMetalHechuraBreakdownInPlace(mhb, 2);
    // rate=2 ⇒ base/2.
    expect(mhb.physical!.metalMonetaryEquivalent).toBe(4600);
    expect(mhb.physical!.metals[0]!.metalPricePerGram).toBe(50000);
    expect(mhb.physical!.metals[0]!.monetaryEquivalent).toBe(4600);
  });

  it("preserva los gramos físicos sin tocarlos", () => {
    const mhb = buildBreakdown();
    convertMetalHechuraBreakdownInPlace(mhb, 2);
    expect(mhb.physical!.metals[0]!.preGrams).toBe(0.908);
    expect(mhb.physical!.metals[0]!.postGrams).toBe(1.000);
    expect(mhb.physical!.metals[0]!.deltaGrams).toBe(0.092);
  });

  it("preserva strings (mode, direction, source, fallback)", () => {
    const mhb = buildBreakdown();
    convertMetalHechuraBreakdownInPlace(mhb, 2);
    const entry = mhb.physical!.metals[0]!;
    expect(entry.mode).toBe("INTEGER");
    expect(entry.direction).toBe("NEAREST");
    expect(entry.source).toBe("COMMERCIAL_PHYSICAL_ROUNDING");
    expect(entry.fallback).toBeNull();
    expect(mhb.physical!.fallback).toBeNull();
    // Y los nombres también.
    expect(entry.metalParentId).toBe("oro-fino");
    expect(entry.metalParentName).toBe("Oro Fino");
  });

  it("physical=null no rompe", () => {
    const mhb: any = buildBreakdown();
    mhb.physical = null;
    expect(() => convertMetalHechuraBreakdownInPlace(mhb, 2)).not.toThrow();
    expect(mhb.metalSale).toBe(50000); // 100.000 / 2 — sigue convirtiendo el resto
  });

  it("physical.metals con entry nulo no rompe", () => {
    const mhb: any = buildBreakdown();
    mhb.physical.metals = [null, mhb.physical.metals[0], undefined];
    expect(() => convertMetalHechuraBreakdownInPlace(mhb, 2)).not.toThrow();
    expect(mhb.physical.metals[1].monetaryEquivalent).toBe(4600);
  });
});

describe("convertMetalHechuraBreakdownInPlace — paridad con campos clásicos", () => {
  it("convierte los clásicos en simultáneo (metalCost/metalSale/etc.)", () => {
    const mhb = buildBreakdown();
    convertMetalHechuraBreakdownInPlace(mhb, 2);
    // base/2 — semántica del helper.
    expect(mhb.metalCost).toBe(22700);
    expect(mhb.metalSale).toBe(50000);
    expect(mhb.hechuraCost).toBe(7500);
    expect(mhb.hechuraSale).toBe(7500);
    expect(mhb.metalPricePerGram).toBe(50000);
    // Gramos clásicos también permanecen.
    expect(mhb.metalGramsBase).toBe(0.908);
    expect(mhb.metalGramsSale).toBe(1.816);
    // Porcentajes intactos.
    expect(mhb.metalMarginPct).toBe(100);
    expect(mhb.hechuraMarginPct).toBe(0);
  });
});
