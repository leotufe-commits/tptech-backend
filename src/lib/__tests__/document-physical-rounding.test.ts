// src/lib/__tests__/document-physical-rounding.test.ts
// =============================================================================
// Etapa D1 — Tests del helper puro `roundDocumentMetalGrams`.
//
// 20 casos mínimos del brief + edge cases. Helper es puro y determinístico:
//   · No DB, no async, no side effects.
//   · No muta input.
//   · Mismo input → mismo output.
//
// POLICY §R-Rounding-13 (Etapa D, diseño oficial).
// =============================================================================

import { describe, it, expect } from "vitest";
import {
  roundDocumentMetalGrams,
  type PhysicalMetalInput,
  type PhysicalMetalRoundingConfig,
  type RoundDocumentMetalGramsInput,
} from "../document-physical-rounding.js";

const ORO   = "oro-fino";
const PLATA = "plata-925";

function makeInput(over: Partial<RoundDocumentMetalGramsInput> = {}): RoundDocumentMetalGramsInput {
  return {
    metals: [],
    configByMetalParentId: {},
    ...over,
  };
}

function makeMetal(over: Partial<PhysicalMetalInput> = {}): PhysicalMetalInput {
  return {
    metalParentId:    ORO,
    metalParentName:  "Oro Fino",
    grams:            0.908,
    metalPricePerGram: 100000,
    ...over,
  };
}

const CFG_INT_NEAR: PhysicalMetalRoundingConfig   = { mode: "INTEGER",   direction: "NEAREST" };
const CFG_INT_UP:   PhysicalMetalRoundingConfig   = { mode: "INTEGER",   direction: "UP" };
const CFG_INT_DN:   PhysicalMetalRoundingConfig   = { mode: "INTEGER",   direction: "DOWN" };
const CFG_DEC1:     PhysicalMetalRoundingConfig   = { mode: "DECIMAL_1", direction: "NEAREST" };
const CFG_DEC2:     PhysicalMetalRoundingConfig   = { mode: "DECIMAL_2", direction: "NEAREST" };
const CFG_HALF:     PhysicalMetalRoundingConfig   = { mode: "HALF",      direction: "NEAREST" };
const CFG_QUART:    PhysicalMetalRoundingConfig   = { mode: "QUARTER",   direction: "NEAREST" };
const CFG_NONE:     PhysicalMetalRoundingConfig   = { mode: "NONE",      direction: "NEAREST" };

// ──────────────────────────────────────────────────────────────────────────
// CASOS BASE — Modes & directions
// ──────────────────────────────────────────────────────────────────────────

describe("roundDocumentMetalGrams — INTEGER", () => {
  it("(1) INTEGER NEAREST: 0,908 → 1,000", () => {
    const out = roundDocumentMetalGrams(makeInput({
      metals: [makeMetal({ grams: 0.908 })],
      configByMetalParentId: { [ORO]: CFG_INT_NEAR },
    }));
    expect(out.metals).toHaveLength(1);
    expect(out.metals[0]!.preGrams).toBe(0.908);
    expect(out.metals[0]!.postGrams).toBe(1);
    expect(out.metals[0]!.deltaGrams).toBeCloseTo(0.092, 4);
    expect(out.metals[0]!.monetaryEquivalent).toBeCloseTo(9200, 2);
    expect(out.metalMonetaryEquivalent).toBeCloseTo(9200, 2);
    expect(out.fallback).toBeNull();
  });

  it("(2) INTEGER DOWN: 0,908 → 0,000", () => {
    const out = roundDocumentMetalGrams(makeInput({
      metals: [makeMetal({ grams: 0.908 })],
      configByMetalParentId: { [ORO]: CFG_INT_DN },
    }));
    expect(out.metals[0]!.postGrams).toBe(0);
    expect(out.metals[0]!.deltaGrams).toBeCloseTo(-0.908, 4);
    expect(out.metals[0]!.monetaryEquivalent).toBeCloseTo(-90800, 2);
  });

  it("(3) INTEGER UP: 0,908 → 1,000", () => {
    const out = roundDocumentMetalGrams(makeInput({
      metals: [makeMetal({ grams: 0.908 })],
      configByMetalParentId: { [ORO]: CFG_INT_UP },
    }));
    expect(out.metals[0]!.postGrams).toBe(1);
    expect(out.metals[0]!.deltaGrams).toBeCloseTo(0.092, 4);
  });

  it("INTEGER UP: 0,1 → 1,0 (diferencia con NEAREST)", () => {
    const out = roundDocumentMetalGrams(makeInput({
      metals: [makeMetal({ grams: 0.1 })],
      configByMetalParentId: { [ORO]: CFG_INT_UP },
    }));
    expect(out.metals[0]!.postGrams).toBe(1);
  });

  it("INTEGER DOWN: 1,9 → 1,0 (diferencia con NEAREST)", () => {
    const out = roundDocumentMetalGrams(makeInput({
      metals: [makeMetal({ grams: 1.9 })],
      configByMetalParentId: { [ORO]: CFG_INT_DN },
    }));
    expect(out.metals[0]!.postGrams).toBe(1);
  });
});

describe("roundDocumentMetalGrams — DECIMAL_1 / DECIMAL_2", () => {
  it("(4) DECIMAL_1 NEAREST: 0,94 → 0,9", () => {
    const out = roundDocumentMetalGrams(makeInput({
      metals: [makeMetal({ grams: 0.94 })],
      configByMetalParentId: { [ORO]: CFG_DEC1 },
    }));
    expect(out.metals[0]!.postGrams).toBe(0.9);
  });

  it("(4 bis) DECIMAL_1 UP: 0,94 → 1,0", () => {
    const out = roundDocumentMetalGrams(makeInput({
      metals: [makeMetal({ grams: 0.94 })],
      configByMetalParentId: { [ORO]: { mode: "DECIMAL_1", direction: "UP" } },
    }));
    expect(out.metals[0]!.postGrams).toBe(1);
  });

  it("(4 ter) DECIMAL_1 DOWN: 0,94 → 0,9", () => {
    const out = roundDocumentMetalGrams(makeInput({
      metals: [makeMetal({ grams: 0.94 })],
      configByMetalParentId: { [ORO]: { mode: "DECIMAL_1", direction: "DOWN" } },
    }));
    expect(out.metals[0]!.postGrams).toBe(0.9);
  });

  it("(5) DECIMAL_2 NEAREST: 0,908 → 0,91 (conserva 2 decimales)", () => {
    const out = roundDocumentMetalGrams(makeInput({
      metals: [makeMetal({ grams: 0.908 })],
      configByMetalParentId: { [ORO]: CFG_DEC2 },
    }));
    expect(out.metals[0]!.postGrams).toBe(0.91);
    expect(out.metals[0]!.deltaGrams).toBeCloseTo(0.002, 4);
  });

  it("DECIMAL_2 NEAREST: 0,904 → 0,90", () => {
    const out = roundDocumentMetalGrams(makeInput({
      metals: [makeMetal({ grams: 0.904 })],
      configByMetalParentId: { [ORO]: CFG_DEC2 },
    }));
    expect(out.metals[0]!.postGrams).toBe(0.9);
  });
});

describe("roundDocumentMetalGrams — HALF", () => {
  it("(6) HALF NEAREST: 0,74 → 0,5", () => {
    const out = roundDocumentMetalGrams(makeInput({
      metals: [makeMetal({ grams: 0.74 })],
      configByMetalParentId: { [ORO]: CFG_HALF },
    }));
    expect(out.metals[0]!.postGrams).toBe(0.5);
  });

  it("(6 bis) HALF NEAREST: 0,76 → 1,0", () => {
    const out = roundDocumentMetalGrams(makeInput({
      metals: [makeMetal({ grams: 0.76 })],
      configByMetalParentId: { [ORO]: CFG_HALF },
    }));
    expect(out.metals[0]!.postGrams).toBe(1);
  });
});

describe("roundDocumentMetalGrams — QUARTER", () => {
  it("(7) QUARTER NEAREST: 0,62 → 0,5", () => {
    const out = roundDocumentMetalGrams(makeInput({
      metals: [makeMetal({ grams: 0.62 })],
      configByMetalParentId: { [ORO]: CFG_QUART },
    }));
    expect(out.metals[0]!.postGrams).toBe(0.5);
  });

  it("(7 bis) QUARTER NEAREST: 0,63 → 0,75", () => {
    const out = roundDocumentMetalGrams(makeInput({
      metals: [makeMetal({ grams: 0.63 })],
      configByMetalParentId: { [ORO]: CFG_QUART },
    }));
    expect(out.metals[0]!.postGrams).toBe(0.75);
  });
});

// ──────────────────────────────────────────────────────────────────────────
// CASOS MIXTOS, FALLBACKS, EDGE
// ──────────────────────────────────────────────────────────────────────────

describe("roundDocumentMetalGrams — Múltiples metales con distintas configs", () => {
  it("(8) Oro INTEGER + Plata HALF: cada uno con su config; sum consolidado", () => {
    const out = roundDocumentMetalGrams(makeInput({
      metals: [
        makeMetal({ metalParentId: ORO,   metalParentName: "Oro Fino", grams: 0.908, metalPricePerGram: 100000 }),
        makeMetal({ metalParentId: PLATA, metalParentName: "Plata",    grams: 0.76,  metalPricePerGram: 500 }),
      ],
      configByMetalParentId: {
        [ORO]:   CFG_INT_NEAR,
        [PLATA]: CFG_HALF,
      },
    }));
    expect(out.metals).toHaveLength(2);
    const oro   = out.metals.find((m) => m.metalParentId === ORO)!;
    const plata = out.metals.find((m) => m.metalParentId === PLATA)!;
    expect(oro.postGrams).toBe(1);
    expect(oro.monetaryEquivalent).toBeCloseTo(9200, 2);
    expect(plata.postGrams).toBe(1);
    expect(plata.deltaGrams).toBeCloseTo(0.24, 4);
    expect(plata.monetaryEquivalent).toBeCloseTo(120, 2);
    expect(out.metalMonetaryEquivalent).toBeCloseTo(9320, 2);
    expect(out.fallback).toBeNull();
  });
});

describe("roundDocumentMetalGrams — Fallbacks per metal", () => {
  it("(9) metalPricePerGram null → NO_METAL_PRICE, sin impactar metalMonetaryEquivalent", () => {
    const out = roundDocumentMetalGrams(makeInput({
      metals: [makeMetal({ grams: 0.908, metalPricePerGram: null })],
      configByMetalParentId: { [ORO]: CFG_INT_NEAR },
    }));
    const e = out.metals[0]!;
    expect(e.fallback).toBe("NO_METAL_PRICE");
    expect(e.postGrams).toBe(0.908);          // no se redondeó
    expect(e.deltaGrams).toBe(0);
    expect(e.metalPricePerGram).toBe(0);      // convención de snapshot
    expect(e.monetaryEquivalent).toBe(0);
    expect(out.metalMonetaryEquivalent).toBe(0);
  });

  it("(10) config faltante sin fallback → NO_CONFIG, passthrough", () => {
    const out = roundDocumentMetalGrams(makeInput({
      metals: [makeMetal({ grams: 0.908 })],
      configByMetalParentId: {},  // sin entry para ORO
      // sin fallbackConfig
    }));
    const e = out.metals[0]!;
    expect(e.fallback).toBe("NO_CONFIG");
    expect(e.postGrams).toBe(0.908);
    expect(e.deltaGrams).toBe(0);
    expect(e.mode).toBe("NONE");
  });

  it("(11) config faltante CON fallbackConfig → usa fallback", () => {
    const out = roundDocumentMetalGrams(makeInput({
      metals: [makeMetal({ grams: 0.908 })],
      configByMetalParentId: {},
      fallbackConfig: CFG_INT_NEAR,
    }));
    const e = out.metals[0]!;
    expect(e.fallback).toBeNull();
    expect(e.postGrams).toBe(1);
    expect(e.deltaGrams).toBeCloseTo(0.092, 4);
    expect(e.mode).toBe("INTEGER");
  });

  it("(12) grams negativo → INVALID_GRAMS, no redondea", () => {
    const out = roundDocumentMetalGrams(makeInput({
      metals: [makeMetal({ grams: -0.5 })],
      configByMetalParentId: { [ORO]: CFG_INT_NEAR },
    }));
    const e = out.metals[0]!;
    expect(e.fallback).toBe("INVALID_GRAMS");
    expect(e.postGrams).toBe(0);   // safePre clamp
    expect(e.deltaGrams).toBe(0);
    expect(e.monetaryEquivalent).toBe(0);
  });

  it("grams NaN → INVALID_GRAMS", () => {
    const out = roundDocumentMetalGrams(makeInput({
      metals: [makeMetal({ grams: Number.NaN })],
      configByMetalParentId: { [ORO]: CFG_INT_NEAR },
    }));
    expect(out.metals[0]!.fallback).toBe("INVALID_GRAMS");
  });

  it("grams Infinity → INVALID_GRAMS", () => {
    const out = roundDocumentMetalGrams(makeInput({
      metals: [makeMetal({ grams: Infinity })],
      configByMetalParentId: { [ORO]: CFG_INT_NEAR },
    }));
    expect(out.metals[0]!.fallback).toBe("INVALID_GRAMS");
  });
});

describe("roundDocumentMetalGrams — Top-level fallback", () => {
  it("(13) metals vacío → NO_METALS_TO_ROUND, metalMonetaryEquivalent=0", () => {
    const out = roundDocumentMetalGrams(makeInput({ metals: [] }));
    expect(out.metals).toEqual([]);
    expect(out.metalMonetaryEquivalent).toBe(0);
    expect(out.fallback).toBe("NO_METALS_TO_ROUND");
  });

  it("input sin array metals (defensa) → NO_BREAKDOWN_DATA", () => {
    const out = roundDocumentMetalGrams({ metals: null as any, configByMetalParentId: {} });
    expect(out.metals).toEqual([]);
    expect(out.fallback).toBe("NO_BREAKDOWN_DATA");
  });
});

// ──────────────────────────────────────────────────────────────────────────
// INMUTABILIDAD + EQUIVALENTES POS/NEG + SUMAS + NONE + EMPATES + DETERMINISMO
// ──────────────────────────────────────────────────────────────────────────

describe("roundDocumentMetalGrams — Inmutabilidad y semántica", () => {
  it("(14) NO muta input", () => {
    const inputMetals: PhysicalMetalInput[] = [
      makeMetal({ grams: 0.908 }),
      makeMetal({ metalParentId: PLATA, metalParentName: "Plata", grams: 0.76, metalPricePerGram: 500 }),
    ];
    const cfg = { [ORO]: CFG_INT_NEAR, [PLATA]: CFG_HALF };
    const fbCfg = { ...CFG_DEC1 };

    const input: RoundDocumentMetalGramsInput = {
      metals: inputMetals,
      configByMetalParentId: cfg,
      fallbackConfig: fbCfg,
    };
    const snapshot = JSON.parse(JSON.stringify(input));

    roundDocumentMetalGrams(input);

    expect(input).toEqual(snapshot);  // input intacto
  });

  it("(15) monetaryEquivalent POSITIVO (delta + × price +)", () => {
    const out = roundDocumentMetalGrams(makeInput({
      metals: [makeMetal({ grams: 0.908, metalPricePerGram: 100000 })],
      configByMetalParentId: { [ORO]: CFG_INT_NEAR },
    }));
    expect(out.metals[0]!.monetaryEquivalent).toBeGreaterThan(0);
    expect(out.metals[0]!.monetaryEquivalent).toBeCloseTo(9200, 2);
  });

  it("(16) monetaryEquivalent NEGATIVO (delta -)", () => {
    const out = roundDocumentMetalGrams(makeInput({
      metals: [makeMetal({ grams: 1.04, metalPricePerGram: 100000 })],
      configByMetalParentId: { [ORO]: CFG_INT_NEAR },
    }));
    // 1.04 NEAREST INTEGER → 1.0; delta -0.04; eq -4000
    expect(out.metals[0]!.postGrams).toBe(1);
    expect(out.metals[0]!.deltaGrams).toBeCloseTo(-0.04, 4);
    expect(out.metals[0]!.monetaryEquivalent).toBeCloseTo(-4000, 2);
  });

  it("(17) metalMonetaryEquivalent suma correctamente metales positivos y negativos", () => {
    const out = roundDocumentMetalGrams(makeInput({
      metals: [
        makeMetal({ metalParentId: ORO,   grams: 0.908, metalPricePerGram: 100000 }), // +9200
        makeMetal({ metalParentId: PLATA, grams: 1.04,  metalPricePerGram: 500 }),    // -20
      ],
      configByMetalParentId: { [ORO]: CFG_INT_NEAR, [PLATA]: CFG_INT_NEAR },
    }));
    const sum = out.metals.reduce((acc, m) => acc + m.monetaryEquivalent, 0);
    expect(out.metalMonetaryEquivalent).toBeCloseTo(Math.round(sum * 100) / 100, 2);
    expect(out.metalMonetaryEquivalent).toBeCloseTo(9180, 2);
  });

  it("(18) mode NONE NO redondea (passthrough sin fallback)", () => {
    const out = roundDocumentMetalGrams(makeInput({
      metals: [makeMetal({ grams: 0.908 })],
      configByMetalParentId: { [ORO]: CFG_NONE },
    }));
    const e = out.metals[0]!;
    expect(e.mode).toBe("NONE");
    expect(e.fallback).toBeNull();
    expect(e.postGrams).toBe(0.908);
    expect(e.deltaGrams).toBe(0);
    expect(e.monetaryEquivalent).toBe(0);
  });
});

describe("roundDocumentMetalGrams — Empates NEAREST (half-up)", () => {
  it("(19) INTEGER NEAREST: 0,5 → 1 (empate sube)", () => {
    const out = roundDocumentMetalGrams(makeInput({
      metals: [makeMetal({ grams: 0.5 })],
      configByMetalParentId: { [ORO]: CFG_INT_NEAR },
    }));
    expect(out.metals[0]!.postGrams).toBe(1);
  });

  it("INTEGER NEAREST: 0,4999 → 0 (justo por debajo del empate)", () => {
    const out = roundDocumentMetalGrams(makeInput({
      metals: [makeMetal({ grams: 0.4999 })],
      configByMetalParentId: { [ORO]: CFG_INT_NEAR },
    }));
    expect(out.metals[0]!.postGrams).toBe(0);
  });

  it("DECIMAL_1 NEAREST: 0,05 → 0,1 (empate sube)", () => {
    const out = roundDocumentMetalGrams(makeInput({
      metals: [makeMetal({ grams: 0.05 })],
      configByMetalParentId: { [ORO]: CFG_DEC1 },
    }));
    expect(out.metals[0]!.postGrams).toBe(0.1);
  });

  it("HALF NEAREST: 0,25 → 0,5 (empate al 0,5 más cercano)", () => {
    const out = roundDocumentMetalGrams(makeInput({
      metals: [makeMetal({ grams: 0.25 })],
      configByMetalParentId: { [ORO]: CFG_HALF },
    }));
    expect(out.metals[0]!.postGrams).toBe(0.5);
  });

  it("QUARTER NEAREST: 0,125 → 0,25 (empate al 0,25 más cercano)", () => {
    const out = roundDocumentMetalGrams(makeInput({
      metals: [makeMetal({ grams: 0.125 })],
      configByMetalParentId: { [ORO]: CFG_QUART },
    }));
    expect(out.metals[0]!.postGrams).toBe(0.25);
  });
});

describe("roundDocumentMetalGrams — Determinismo", () => {
  it("(20) mismo input → mismo output (deep equal)", () => {
    const inputA = makeInput({
      metals: [
        makeMetal({ grams: 0.908 }),
        makeMetal({ metalParentId: PLATA, metalParentName: "Plata", grams: 0.76, metalPricePerGram: 500 }),
      ],
      configByMetalParentId: { [ORO]: CFG_INT_NEAR, [PLATA]: CFG_HALF },
    });
    const inputB = makeInput({
      metals: [
        makeMetal({ grams: 0.908 }),
        makeMetal({ metalParentId: PLATA, metalParentName: "Plata", grams: 0.76, metalPricePerGram: 500 }),
      ],
      configByMetalParentId: { [ORO]: CFG_INT_NEAR, [PLATA]: CFG_HALF },
    });
    const a = roundDocumentMetalGrams(inputA);
    const b = roundDocumentMetalGrams(inputB);
    expect(a).toEqual(b);
  });

  it("dos llamadas seguidas con el mismo input dan idéntico resultado", () => {
    const input = makeInput({
      metals: [makeMetal({ grams: 0.908 })],
      configByMetalParentId: { [ORO]: CFG_INT_NEAR },
    });
    const a = roundDocumentMetalGrams(input);
    const b = roundDocumentMetalGrams(input);
    expect(a).toEqual(b);
  });
});

// ──────────────────────────────────────────────────────────────────────────
// EXTRA — coherencia auditable de cada entry
// ──────────────────────────────────────────────────────────────────────────

describe("roundDocumentMetalGrams — Coherencia del snapshot", () => {
  it("cada entry siempre tiene source='DOCUMENT_PHYSICAL_ROUNDING'", () => {
    const out = roundDocumentMetalGrams(makeInput({
      metals: [
        makeMetal({ grams: 0.908 }),
        makeMetal({ metalParentId: PLATA, metalParentName: "Plata", grams: 0.76, metalPricePerGram: 500 }),
        makeMetal({ metalParentId: null,  metalParentName: "Cobre", grams: 0.5,  metalPricePerGram: null }),
      ],
      configByMetalParentId: { [ORO]: CFG_INT_NEAR, [PLATA]: CFG_HALF },
      fallbackConfig: CFG_DEC1,
    }));
    for (const m of out.metals) {
      expect(m.source).toBe("DOCUMENT_PHYSICAL_ROUNDING");
    }
  });

  it("metalParentId null + fallbackConfig + price null → entry con NO_METAL_PRICE", () => {
    const out = roundDocumentMetalGrams(makeInput({
      metals: [makeMetal({ metalParentId: null, metalParentName: "Cobre", grams: 0.5, metalPricePerGram: null })],
      configByMetalParentId: {},
      fallbackConfig: CFG_INT_NEAR,
    }));
    const e = out.metals[0]!;
    expect(e.metalParentId).toBeNull();
    expect(e.mode).toBe("INTEGER");
    expect(e.fallback).toBe("NO_METAL_PRICE");
  });

  it("metalParentId null sin fallbackConfig → NO_CONFIG (no asume nada)", () => {
    const out = roundDocumentMetalGrams(makeInput({
      metals: [makeMetal({ metalParentId: null, metalParentName: "Cobre", grams: 0.5, metalPricePerGram: 1000 })],
      configByMetalParentId: { "cobre-puro": CFG_INT_NEAR },  // no matchea (id es null)
    }));
    expect(out.metals[0]!.fallback).toBe("NO_CONFIG");
  });
});
