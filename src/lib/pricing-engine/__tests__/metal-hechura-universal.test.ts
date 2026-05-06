// src/lib/pricing-engine/__tests__/metal-hechura-universal.test.ts
// ============================================================================
// FASE 1 — tests del helper `deriveMetalHechuraBreakdown`.
//
// El helper es la fuente única backend para `SalePriceResult.metalHechuraBreakdown`
// en TODOS los modos de lista (no solo METAL_HECHURA). Estos tests fijan:
//
//   1. Cada `source` posible se elige correctamente según el contexto.
//   2. La invariante `|metalSale + hechuraSale − basePrice| ≤ 0.01` se cumple
//      en todos los casos donde el helper devuelve un breakdown.
//   3. `*Estimated = false` solo cuando vino el `exactBreakdown` (METAL_HECHURA).
//   4. Cuando el helper no puede armar el breakdown, devuelve `null`.
//
// Capa pura: sin DB, sin mocks. El helper recibe inputs numéricos.
// ============================================================================

import { describe, it, expect } from "vitest";
import {
  deriveMetalHechuraBreakdown,
  type DeriveMetalHechuraInput,
  type MetalHechuraExactDetail,
} from "../pricing-engine.js";

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

const baseInput = (over: Partial<DeriveMetalHechuraInput> = {}): DeriveMetalHechuraInput => ({
  metalCost:      0,
  hechuraCost:    0,
  costTotal:      0,
  basePrice:      null,
  priceSource:    "PRICE_LIST",
  commercialMode: null,
  exactBreakdown: null,
  ...over,
});

/** Verifica la invariante `metalSale + hechuraSale ≈ basePrice` con
 *  tolerancia de 0.01. Falla con mensaje claro si no se cumple. */
function expectInvariant(b: NonNullable<ReturnType<typeof deriveMetalHechuraBreakdown>>, basePrice: number) {
  const sum = b.metalSale + b.hechuraSale;
  expect(Math.abs(sum - basePrice)).toBeLessThanOrEqual(0.01);
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. METAL_HECHURA — caso exacto (lista MH con desglose por componente)
// ─────────────────────────────────────────────────────────────────────────────

describe("deriveMetalHechuraBreakdown — METAL_HECHURA exacto", () => {
  const exact: MetalHechuraExactDetail = {
    metalSale:        650,
    hechuraSale:      350,
    metalMarginPct:   30,
    hechuraMarginPct: 75,
    metalGramsBase:   1.07,
    metalGramsSale:   1.18,
    metalPricePerGram: 467.29,
  };

  it("source='METAL_HECHURA', estimated=false, valores tal cual del exact", () => {
    const r = deriveMetalHechuraBreakdown(baseInput({
      metalCost:      500,
      hechuraCost:    200,
      costTotal:      700,
      basePrice:      1000,
      priceSource:    "PRICE_LIST",
      exactBreakdown: exact,
    }))!;
    expect(r.source).toBe("METAL_HECHURA");
    expect(r.metalSaleEstimated).toBe(false);
    expect(r.hechuraSaleEstimated).toBe(false);
    expect(r.metalSale).toBe(650);
    expect(r.hechuraSale).toBe(350);
    expect(r.metalMarginPct).toBe(30);
    expect(r.hechuraMarginPct).toBe(75);
    expect(r.metalGramsBase).toBe(1.07);
    expect(r.metalCost).toBe(500);
    expect(r.hechuraCost).toBe(200);
    expectInvariant(r, 1000);
  });

  it("METAL_HECHURA gana sobre commercialMode COMBO_COMMERCIAL", () => {
    // Si el motor ya resolvió METAL_HECHURA exacto, lo respetamos sin
    // importar el commercialMode (caso teórico de combo con lista MH).
    const r = deriveMetalHechuraBreakdown(baseInput({
      metalCost:      500,
      hechuraCost:    200,
      costTotal:      700,
      basePrice:      1000,
      commercialMode: "COMBO_COMMERCIAL",
      exactBreakdown: exact,
    }))!;
    expect(r.source).toBe("METAL_HECHURA");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. PROPORTIONAL_COST — MARGIN_TOTAL / COST_PER_GRAM / MANUAL con cost > 0
// ─────────────────────────────────────────────────────────────────────────────

describe("deriveMetalHechuraBreakdown — PROPORTIONAL_COST", () => {
  it("MARGIN_TOTAL: factor proporcional, source y estimated correctos", () => {
    // basePrice/cost = 1700/1000 = 1.7
    const r = deriveMetalHechuraBreakdown(baseInput({
      metalCost:    700,
      hechuraCost:  300,
      costTotal:    1000,
      basePrice:    1700,
      priceSource:  "PRICE_LIST",
    }))!;
    expect(r.source).toBe("PROPORTIONAL_COST");
    expect(r.metalSaleEstimated).toBe(true);
    expect(r.hechuraSaleEstimated).toBe(true);
    expect(r.metalSale).toBeCloseTo(1190, 2);   // 700 × 1.7
    expect(r.hechuraSale).toBeCloseTo(510, 2);  // 300 × 1.7
    expectInvariant(r, 1700);
  });

  it("COST_PER_GRAM: misma proporcionalidad", () => {
    const r = deriveMetalHechuraBreakdown(baseInput({
      metalCost:    400,
      hechuraCost:  100,
      costTotal:    500,
      basePrice:    750,
      priceSource:  "PRICE_LIST",
    }))!;
    expect(r.source).toBe("PROPORTIONAL_COST");
    expect(r.metalSale).toBeCloseTo(600, 2);
    expect(r.hechuraSale).toBeCloseTo(150, 2);
    expectInvariant(r, 750);
  });

  it("MANUAL_OVERRIDE con costo > 0 → PROPORTIONAL_COST (no MANUAL_AS_HECHURA)", () => {
    const r = deriveMetalHechuraBreakdown(baseInput({
      metalCost:    500,
      hechuraCost:  500,
      costTotal:    1000,
      basePrice:    1500,
      priceSource:  "MANUAL_OVERRIDE",
    }))!;
    expect(r.source).toBe("PROPORTIONAL_COST");
    expect(r.metalSale).toBeCloseTo(750, 2);
    expect(r.hechuraSale).toBeCloseTo(750, 2);
    expectInvariant(r, 1500);
  });

  it("hechuraCost=0 (todo metal) → metalSale=basePrice, hechuraSale=0", () => {
    const r = deriveMetalHechuraBreakdown(baseInput({
      metalCost:    1000,
      hechuraCost:  0,
      costTotal:    1000,
      basePrice:    1500,
      priceSource:  "PRICE_LIST",
    }))!;
    expect(r.source).toBe("PROPORTIONAL_COST");
    expect(r.metalSale).toBeCloseTo(1500, 2);
    expect(r.hechuraSale).toBe(0);
    expectInvariant(r, 1500);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. SERVICE_AS_HECHURA — artículo sin metal
// ─────────────────────────────────────────────────────────────────────────────

describe("deriveMetalHechuraBreakdown — SERVICE_AS_HECHURA", () => {
  it("metalCost=0 + hechuraCost>0 → todo a hechura, source=SERVICE_AS_HECHURA", () => {
    const r = deriveMetalHechuraBreakdown(baseInput({
      metalCost:    0,
      hechuraCost:  500,
      costTotal:    500,
      basePrice:    900,
      priceSource:  "PRICE_LIST",
    }))!;
    expect(r.source).toBe("SERVICE_AS_HECHURA");
    expect(r.metalSale).toBe(0);
    expect(r.hechuraSale).toBe(900);
    expect(r.metalSaleEstimated).toBe(true);
    expect(r.hechuraSaleEstimated).toBe(true);
    expectInvariant(r, 900);
  });

  it("metalCost=0 con MANUAL_OVERRIDE → SERVICE_AS_HECHURA gana antes de MANUAL_AS_HECHURA", () => {
    // Regla: si hay hechuraCost > 0, queremos SERVICE_AS_HECHURA aunque sea manual.
    // Si hechuraCost también es 0 → cae a MANUAL_AS_HECHURA (siguiente test).
    const r = deriveMetalHechuraBreakdown(baseInput({
      metalCost:    0,
      hechuraCost:  300,
      costTotal:    300,
      basePrice:    500,
      priceSource:  "MANUAL_OVERRIDE",
    }))!;
    expect(r.source).toBe("SERVICE_AS_HECHURA");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 4. MANUAL_AS_HECHURA — manual sin costo útil
// ─────────────────────────────────────────────────────────────────────────────

describe("deriveMetalHechuraBreakdown — MANUAL_AS_HECHURA", () => {
  it("MANUAL_OVERRIDE + costTotal=0 → MANUAL_AS_HECHURA, todo a hechura", () => {
    const r = deriveMetalHechuraBreakdown(baseInput({
      metalCost:    0,
      hechuraCost:  0,
      costTotal:    0,
      basePrice:    1234.56,
      priceSource:  "MANUAL_OVERRIDE",
    }))!;
    expect(r.source).toBe("MANUAL_AS_HECHURA");
    expect(r.metalSale).toBe(0);
    expect(r.hechuraSale).toBe(1234.56);
    expectInvariant(r, 1234.56);
  });

  it("MANUAL_FALLBACK + costTotal=0 → MANUAL_AS_HECHURA", () => {
    const r = deriveMetalHechuraBreakdown(baseInput({
      metalCost:    0,
      hechuraCost:  0,
      costTotal:    0,
      basePrice:    750,
      priceSource:  "MANUAL_FALLBACK",
    }))!;
    expect(r.source).toBe("MANUAL_AS_HECHURA");
    expect(r.metalSale).toBe(0);
    expect(r.hechuraSale).toBe(750);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 5. COMBO_COMPONENTS — combo con desglose acumulado
// ─────────────────────────────────────────────────────────────────────────────

describe("deriveMetalHechuraBreakdown — COMBO_COMPONENTS", () => {
  it("Combo con metal + hechura proporciona breakdown estimado", () => {
    // Componente A: metal 600, hechura 400 → costo 1000
    // Componente B: metal 0, hechura 200 → costo 200
    // Σ → metalCost 600, hechuraCost 600, costTotal 1200
    // basePrice 1800 → factor 1.5 → metalSale 900, hechuraSale 900
    const r = deriveMetalHechuraBreakdown(baseInput({
      metalCost:      600,
      hechuraCost:    600,
      costTotal:      1200,
      basePrice:      1800,
      priceSource:    "PRICE_LIST",
      commercialMode: "COMBO_COMMERCIAL",
    }))!;
    expect(r.source).toBe("COMBO_COMPONENTS");
    expect(r.metalSale).toBeCloseTo(900, 2);
    expect(r.hechuraSale).toBeCloseTo(900, 2);
    expect(r.metalSaleEstimated).toBe(true);
    expectInvariant(r, 1800);
  });

  it("Combo de servicios puros (todo hechura) → SERVICE_AS_HECHURA NO se aplica con commercialMode=COMBO", () => {
    // Combo con dos componentes service (metalCost=0, hechuraCost>0).
    // commercialMode=COMBO_COMMERCIAL gana → COMBO_COMPONENTS, no SERVICE_AS_HECHURA.
    const r = deriveMetalHechuraBreakdown(baseInput({
      metalCost:      0,
      hechuraCost:    500,
      costTotal:      500,
      basePrice:      750,
      commercialMode: "COMBO_COMMERCIAL",
    }))!;
    expect(r.source).toBe("COMBO_COMPONENTS");
    expect(r.metalSale).toBe(0);
    expect(r.hechuraSale).toBeCloseTo(750, 2);
  });

  it("Combo con costTotal=0 (todos los componentes partial) → null", () => {
    // No se puede derivar ratio.
    const r = deriveMetalHechuraBreakdown(baseInput({
      metalCost:      0,
      hechuraCost:    0,
      costTotal:      0,
      basePrice:      1000,
      commercialMode: "COMBO_COMMERCIAL",
    }));
    expect(r).toBeNull();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 6. NONE — el helper devuelve null
// ─────────────────────────────────────────────────────────────────────────────

describe("deriveMetalHechuraBreakdown — null cases", () => {
  it("sin basePrice → null", () => {
    const r = deriveMetalHechuraBreakdown(baseInput({
      metalCost:   500,
      hechuraCost: 200,
      costTotal:   700,
      basePrice:   null,
    }));
    expect(r).toBeNull();
  });

  it("PRICE_LIST con costTotal=0 y todos los costos 0 → null (no hay forma de derivar)", () => {
    const r = deriveMetalHechuraBreakdown(baseInput({
      metalCost:    0,
      hechuraCost:  0,
      costTotal:    0,
      basePrice:    1000,
      priceSource:  "PRICE_LIST",
    }));
    expect(r).toBeNull();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 7. Invariante metalSale + hechuraSale ≈ basePrice — barrido amplio
// ─────────────────────────────────────────────────────────────────────────────

describe("deriveMetalHechuraBreakdown — invariante de suma", () => {
  const cases: Array<{ name: string; input: DeriveMetalHechuraInput; basePrice: number }> = [
    {
      name: "MARGIN_TOTAL típico",
      input: baseInput({ metalCost: 700, hechuraCost: 300, costTotal: 1000, basePrice: 1700, priceSource: "PRICE_LIST" }),
      basePrice: 1700,
    },
    {
      name: "metalCost ≫ hechuraCost",
      input: baseInput({ metalCost: 9500, hechuraCost: 500, costTotal: 10000, basePrice: 13000, priceSource: "PRICE_LIST" }),
      basePrice: 13000,
    },
    {
      name: "hechuraCost ≫ metalCost",
      input: baseInput({ metalCost: 100, hechuraCost: 9900, costTotal: 10000, basePrice: 11500, priceSource: "PRICE_LIST" }),
      basePrice: 11500,
    },
    {
      name: "basePrice = costTotal (margen 0)",
      input: baseInput({ metalCost: 400, hechuraCost: 600, costTotal: 1000, basePrice: 1000, priceSource: "MANUAL_OVERRIDE" }),
      basePrice: 1000,
    },
    {
      name: "Combo con asimetría",
      input: baseInput({ metalCost: 333.33, hechuraCost: 666.67, costTotal: 1000, basePrice: 1450, commercialMode: "COMBO_COMMERCIAL" }),
      basePrice: 1450,
    },
    {
      name: "Servicio puro",
      input: baseInput({ metalCost: 0, hechuraCost: 800, costTotal: 800, basePrice: 1200, priceSource: "PRICE_LIST" }),
      basePrice: 1200,
    },
    {
      name: "Manual sin costo",
      input: baseInput({ metalCost: 0, hechuraCost: 0, costTotal: 0, basePrice: 999.99, priceSource: "MANUAL_FALLBACK" }),
      basePrice: 999.99,
    },
  ];

  for (const c of cases) {
    it(`invariante OK — ${c.name}`, () => {
      const r = deriveMetalHechuraBreakdown(c.input);
      expect(r).not.toBeNull();
      expectInvariant(r!, c.basePrice);
    });
  }
});
