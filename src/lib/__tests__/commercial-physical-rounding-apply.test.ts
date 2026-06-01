// src/lib/__tests__/commercial-physical-rounding-apply.test.ts
// =============================================================================
// Etapa C-comercial / C2 (POLICY §R-Rounding-14) — Tests del helper PURO
// `applyCommercialPhysicalRoundingForMetal(s)` + paridad matemática contra
// `roundDocumentMetalGrams` (financiero).
//
// Cobertura de los 7 escenarios pedidos en el brief de C2:
//   (1)  0,908 g  INTEGER NEAREST  → 1,000 g  Δ +0,092
//   (2)  1,526 g  INTEGER NEAREST  → 2,000 g  Δ +0,474
//   (3)  1,400 g  INTEGER DOWN     → 1,000 g  Δ −0,400
//   (4)  1,400 g  INTEGER UP       → 2,000 g  Δ +0,600
//   (5)  monetaryEquivalent = deltaGrams × metalPricePerGram (round2).
//   (6)  source = "COMMERCIAL_PHYSICAL_ROUNDING".
//   (7)  paridad: misma entrada → mismo resultado físico que el helper
//        Financiero (`roundDocumentMetalGrams` con sourceTag financiero).
//
// Helpers puros — sin DB, sin async, sin Prisma. Mismo input → mismo output.
// =============================================================================

import { describe, it, expect } from "vitest";
import {
  applyCommercialPhysicalRoundingForMetal,
  applyCommercialPhysicalRoundingForMetals,
} from "../commercial-physical-rounding-apply.js";
import { roundDocumentMetalGrams } from "../document-physical-rounding.js";

const ORO_PRICE = 100000; // metalPricePerGram canónico para los tests

function call(
  preGrams: number,
  mode: "INTEGER" | "HALF" | "QUARTER" | "DECIMAL_1" | "DECIMAL_2" | "NONE",
  direction: "NEAREST" | "UP" | "DOWN",
  metalPricePerGram: number | null = ORO_PRICE,
) {
  return applyCommercialPhysicalRoundingForMetal({
    metalParentId:     "oro-fino",
    metalParentName:   "Oro Fino",
    preGrams,
    metalPricePerGram,
    roundingMode:      mode,
    roundingDirection: direction,
  });
}

// ──────────────────────────────────────────────────────────────────────────
// Casos 1–4 — comportamiento del redondeo físico (sub-step gramos)
// ──────────────────────────────────────────────────────────────────────────

describe("C2 — casos canónicos del brief", () => {
  it("(1) 0,908 g  INTEGER NEAREST → 1,000 g (Δ +0,092)", () => {
    const r = call(0.908, "INTEGER", "NEAREST");
    expect(r.preGrams).toBe(0.908);
    expect(r.postGrams).toBe(1.000);
    expect(r.deltaGrams).toBeCloseTo(0.092, 4);
    expect(r.mode).toBe("INTEGER");
    expect(r.direction).toBe("NEAREST");
    expect(r.fallback).toBeNull();
  });

  it("(2) 1,526 g  INTEGER NEAREST → 2,000 g (Δ +0,474)", () => {
    const r = call(1.526, "INTEGER", "NEAREST");
    expect(r.preGrams).toBe(1.526);
    expect(r.postGrams).toBe(2.000);
    expect(r.deltaGrams).toBeCloseTo(0.474, 4);
    expect(r.fallback).toBeNull();
  });

  it("(3) 1,400 g  INTEGER DOWN → 1,000 g (Δ −0,400)", () => {
    const r = call(1.400, "INTEGER", "DOWN");
    expect(r.preGrams).toBe(1.400);
    expect(r.postGrams).toBe(1.000);
    expect(r.deltaGrams).toBeCloseTo(-0.400, 4);
    expect(r.direction).toBe("DOWN");
    expect(r.fallback).toBeNull();
  });

  it("(4) 1,400 g  INTEGER UP → 2,000 g (Δ +0,600)", () => {
    const r = call(1.400, "INTEGER", "UP");
    expect(r.preGrams).toBe(1.400);
    expect(r.postGrams).toBe(2.000);
    expect(r.deltaGrams).toBeCloseTo(0.600, 4);
    expect(r.direction).toBe("UP");
    expect(r.fallback).toBeNull();
  });
});

// ──────────────────────────────────────────────────────────────────────────
// Caso 5 — monetaryEquivalent = deltaGrams × metalPricePerGram (round2)
// ──────────────────────────────────────────────────────────────────────────

describe("C2 — caso 5: monetaryEquivalent", () => {
  it("0,908 → 1,000 con price = 100.000 → equivalente +9.200", () => {
    const r = call(0.908, "INTEGER", "NEAREST", 100000);
    expect(r.metalPricePerGram).toBe(100000);
    // 0,092 × 100000 = 9200 exacto
    expect(r.monetaryEquivalent).toBe(9200);
  });

  it("1,400 → 1,000 DOWN con price = 95.000 → equivalente −38.000", () => {
    const r = call(1.400, "INTEGER", "DOWN", 95000);
    // -0,400 × 95000 = -38000
    expect(r.monetaryEquivalent).toBe(-38000);
  });

  it("round2: 1,526 → 2,000 con price = 95.123 → 0,474 × 95.123 = 45.088,302 → 45.088,30", () => {
    const r = call(1.526, "INTEGER", "NEAREST", 95123);
    // 0,474 * 95123 = 45088.302 → round2 = 45088.30
    expect(r.monetaryEquivalent).toBeCloseTo(45088.30, 2);
  });

  it("metalPricePerGram=null → fallback NO_METAL_PRICE; equivalente 0; no redondea", () => {
    const r = call(0.908, "INTEGER", "NEAREST", null);
    expect(r.fallback).toBe("NO_METAL_PRICE");
    expect(r.preGrams).toBe(0.908);
    expect(r.postGrams).toBe(0.908);
    expect(r.deltaGrams).toBe(0);
    expect(r.monetaryEquivalent).toBe(0);
    expect(r.metalPricePerGram).toBe(0);
  });
});

// ──────────────────────────────────────────────────────────────────────────
// Caso 6 — source = "COMMERCIAL_PHYSICAL_ROUNDING"
// ──────────────────────────────────────────────────────────────────────────

describe("C2 — caso 6: source tag", () => {
  it("entry unitaria viene con source = COMMERCIAL_PHYSICAL_ROUNDING", () => {
    const r = call(0.908, "INTEGER", "NEAREST");
    expect(r.source).toBe("COMMERCIAL_PHYSICAL_ROUNDING");
  });

  it("entry de batch también", () => {
    const out = applyCommercialPhysicalRoundingForMetals({
      metals: [
        { metalParentId: "oro-fino", metalParentName: "Oro Fino", grams: 0.908, metalPricePerGram: ORO_PRICE },
        { metalParentId: "plata",    metalParentName: "Plata",    grams: 1.526, metalPricePerGram: 500 },
      ],
      configByMetalParentId: {
        "oro-fino": { mode: "INTEGER", direction: "NEAREST" },
        "plata":    { mode: "HALF",    direction: "DOWN" },
      },
    });
    expect(out.metals).toHaveLength(2);
    for (const e of out.metals) {
      expect(e.source).toBe("COMMERCIAL_PHYSICAL_ROUNDING");
    }
  });

  it("NUNCA emite DOCUMENT_PHYSICAL_ROUNDING desde el helper comercial", () => {
    const out = applyCommercialPhysicalRoundingForMetals({
      metals: [{ metalParentId: null, metalParentName: "Oro Fino", grams: 0.908, metalPricePerGram: ORO_PRICE }],
      configByMetalParentId: {},
      fallbackConfig: { mode: "INTEGER", direction: "NEAREST" },
    });
    expect(out.metals[0]!.source).toBe("COMMERCIAL_PHYSICAL_ROUNDING");
    expect(out.metals[0]!.source).not.toBe("DOCUMENT_PHYSICAL_ROUNDING");
  });
});

// ──────────────────────────────────────────────────────────────────────────
// Caso 7 — PARIDAD financiero vs comercial: misma matemática
// ──────────────────────────────────────────────────────────────────────────

describe("C2 — caso 7: paridad financiero ↔ comercial", () => {
  // Set de inputs canónicos que cubre los 4 casos del brief + uno con
  // múltiples metales + uno con HALF + uno con fallback config.
  const FIXTURES = [
    { grams: 0.908, price: 100000, mode: "INTEGER",   direction: "NEAREST" },
    { grams: 1.526, price: 100000, mode: "INTEGER",   direction: "NEAREST" },
    { grams: 1.400, price: 95000,  mode: "INTEGER",   direction: "DOWN"    },
    { grams: 1.400, price: 95000,  mode: "INTEGER",   direction: "UP"      },
    { grams: 0.74,  price: 100000, mode: "HALF",      direction: "NEAREST" },
    { grams: 0.62,  price: 100000, mode: "QUARTER",   direction: "NEAREST" },
    { grams: 1.044, price: 100000, mode: "DECIMAL_1", direction: "NEAREST" },
  ] as const;

  it.each(FIXTURES)(
    "misma entrada → mismo resultado físico/monetario (grams=$grams, mode=$mode, dir=$direction)",
    ({ grams, price, mode, direction }) => {
      // Caller financiero (sin sourceTag → default DOCUMENT_PHYSICAL_ROUNDING).
      const fin = roundDocumentMetalGrams({
        metals: [{
          metalParentId:     "oro-fino",
          metalParentName:   "Oro Fino",
          grams,
          metalPricePerGram: price,
        }],
        configByMetalParentId: {},
        fallbackConfig:        { mode, direction },
      });
      // Caller comercial (sourceTag forzado a COMMERCIAL_PHYSICAL_ROUNDING).
      const com = applyCommercialPhysicalRoundingForMetal({
        metalParentId:     "oro-fino",
        metalParentName:   "Oro Fino",
        preGrams:          grams,
        metalPricePerGram: price,
        roundingMode:      mode,
        roundingDirection: direction,
      });

      // Igualdad punto-a-punto excepto el `source` literal.
      expect(com.preGrams).toBe(fin.metals[0]!.preGrams);
      expect(com.postGrams).toBe(fin.metals[0]!.postGrams);
      expect(com.deltaGrams).toBe(fin.metals[0]!.deltaGrams);
      expect(com.metalPricePerGram).toBe(fin.metals[0]!.metalPricePerGram);
      expect(com.monetaryEquivalent).toBe(fin.metals[0]!.monetaryEquivalent);
      expect(com.mode).toBe(fin.metals[0]!.mode);
      expect(com.direction).toBe(fin.metals[0]!.direction);
      expect(com.fallback).toBe(fin.metals[0]!.fallback);

      // El único delta es el source — confirma que comparten algoritmo.
      expect(com.source).toBe("COMMERCIAL_PHYSICAL_ROUNDING");
      expect(fin.metals[0]!.source).toBe("DOCUMENT_PHYSICAL_ROUNDING");
    },
  );

  it("paridad batch — varios metales padre simultáneos", () => {
    const inputMetals = [
      { metalParentId: "oro-fino", metalParentName: "Oro Fino", grams: 0.908, metalPricePerGram: 100000 },
      { metalParentId: "plata",    metalParentName: "Plata",    grams: 3.108, metalPricePerGram: 500 },
    ];
    const cfg = {
      "oro-fino": { mode: "INTEGER" as const, direction: "NEAREST" as const },
      "plata":    { mode: "HALF"    as const, direction: "DOWN"    as const },
    };
    const fin = roundDocumentMetalGrams({
      metals: inputMetals,
      configByMetalParentId: cfg,
    });
    const com = applyCommercialPhysicalRoundingForMetals({
      metals: inputMetals,
      configByMetalParentId: cfg,
    });
    expect(com.metals).toHaveLength(fin.metals.length);
    for (let i = 0; i < com.metals.length; i++) {
      const a = com.metals[i]!;
      const b = fin.metals[i]!;
      expect(a.preGrams).toBe(b.preGrams);
      expect(a.postGrams).toBe(b.postGrams);
      expect(a.deltaGrams).toBe(b.deltaGrams);
      expect(a.monetaryEquivalent).toBe(b.monetaryEquivalent);
      expect(a.source).toBe("COMMERCIAL_PHYSICAL_ROUNDING");
      expect(b.source).toBe("DOCUMENT_PHYSICAL_ROUNDING");
    }
    expect(com.metalMonetaryEquivalent).toBe(fin.metalMonetaryEquivalent);
  });
});

// ──────────────────────────────────────────────────────────────────────────
// Smoke tests adicionales del shape (asegurar contrato de snapshot)
// ──────────────────────────────────────────────────────────────────────────

describe("C2 — shape del entry coincide con contrato canónico", () => {
  it("entry tiene todas las claves del contrato (preGrams/postGrams/deltaGrams/metalPricePerGram/monetaryEquivalent/source/mode/direction/fallback)", () => {
    const r = call(0.908, "INTEGER", "NEAREST");
    const keys = Object.keys(r).sort();
    expect(keys).toEqual([
      "deltaGrams",
      "direction",
      "fallback",
      "metalParentId",
      "metalParentName",
      "metalPricePerGram",
      "mode",
      "monetaryEquivalent",
      "postGrams",
      "preGrams",
      "source",
    ]);
  });
});
