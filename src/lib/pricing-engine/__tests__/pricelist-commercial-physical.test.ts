// src/lib/pricing-engine/__tests__/pricelist-commercial-physical.test.ts
// =============================================================================
// Etapa C-comercial / C3 (POLICY §R-Rounding-14) — Tests del motor de lista
// con redondeo COMERCIAL PHYSICAL integrado.
//
// FIX ORDEN MARGEN→REDONDEO (2026-06-02): el redondeo comercial físico por
// línea ahora opera sobre los GRAMOS COMERCIALES (post-margen), alineado con
// PER_DOCUMENT. Antes redondeaba `gramsPure` PRE-margen; ahora redondea
// `gramsPure × marginFactor`. El precio (`metalPricePerGram`) es la cotización
// de COSTO (`meta.quotePrice`), por eso el margen vive en los gramos y el
// `monetaryEquivalent = Δgramos × precioCosto` cierra coherente con `metalSale`.
//
// Cubre:
//   1. Lista MONETARY (default) → comportamiento legacy intacto (sin physical).
//   2. Lista PHYSICAL post-margen → caso canónico 1,2375 × 10% → 1,36125 → 1,40.
//   3. Equivalente monetario impacta `metalSale` coherentemente.
//   4. Dos líneas iguales cerradas → Σ postGrams = 2,80 (documento suma líneas).
//   5. Hechura sigue redondeando MONETARIAMENTE (regla canónica).
//   6. Snapshot `metalHechuraDetail.physical` con shape canónico.
//   7. Múltiples metales padre en la misma línea, cada uno post-margen.
//   8. Sin `metalsByParent` → fallback limpio al path MONETARY.
//
// Tests PUROS del motor de lista (`applyPriceList`). No tocan Prisma.
// =============================================================================

import { describe, it, expect } from "vitest";
import { Prisma } from "@prisma/client";
import { applyPriceList } from "../pricing-engine.pricelist.js";

const D = (v: number | string) => new Prisma.Decimal(String(v));

// Cotización de COSTO por gramo fino (= `meta.quotePrice` en datos reales).
const ORO_COST_PER_GRAM = 50000;

function basePriceList(over: Record<string, any> = {}) {
  return {
    id:                       "pl1",
    name:                     "Lista Test",
    mode:                     "METAL_HECHURA",
    marginTotal:              null,
    marginMetal:              "100",  // 100% sobre metal (default; PHYSICAL lo pisa con 10%)
    marginHechura:            "0",    // 0% sobre hechura (hechura = costo)
    costPerGram:              null,
    surcharge:                null,
    minimumPrice:             null,
    roundingTarget:           "METAL",
    roundingMode:             "INTEGER",
    roundingDirection:        "NEAREST",
    roundingApplyOn:          "PRICE",
    roundingModeHechura:      "NONE",
    roundingDirectionHechura: "NEAREST",
    validFrom:                null,
    validTo:                  null,
    isActive:                 true,
    commercialRoundingMetalDomain:    "MONETARY",
    commercialPhysicalRoundingConfig: null,
    ...over,
  };
}

// Costo MONETARY (legacy) — Oro Fino 0,908 g, margen 100% (precio venta = 2×).
function baseCost(over: Record<string, any> = {}) {
  return {
    value:       D(45400 + 15000),
    metalCost:   D(45400),
    hechuraCost: D(15000),
    totalGrams:  D(0.908),
    metalGramsWithMerma: D(0.908),
    metalPurity: D(1),
    metalsByParent: [{
      metalParentId:     "oro-fino",
      metalParentName:   "Oro Fino",
      gramsPure:         0.908,
      metalPricePerGram: 100000,   // MONETARY no usa este precio para gramos
    }],
    ...over,
  };
}

// ──────────────────────────────────────────────────────────────────────────
// Helpers PHYSICAL — precio de COSTO + margen explícito (post-margen).
// ──────────────────────────────────────────────────────────────────────────

/** Lista PHYSICAL con margen de metal configurable (default 10%). */
function physicalList(over: Record<string, any> = {}, marginMetal = "10") {
  return basePriceList({
    marginMetal,
    commercialRoundingMetalDomain: "PHYSICAL",
    commercialPhysicalRoundingConfig: {
      byMetalParentId: { "oro-fino": { mode: "DECIMAL_1", direction: "NEAREST" } },
    },
    ...over,
  });
}

/** Costo PHYSICAL con gramos puros (con merma) y cotización de COSTO. */
function physicalCost(gramsPure: number, over: Record<string, any> = {}) {
  const metalCost = gramsPure * ORO_COST_PER_GRAM;
  return {
    value:       D(metalCost + 15000),
    metalCost:   D(metalCost),
    hechuraCost: D(15000),
    totalGrams:  D(gramsPure),
    metalGramsWithMerma: D(gramsPure),
    metalPurity: D(1),
    metalsByParent: [{
      metalParentId:     "oro-fino",
      metalParentName:   "Oro Fino",
      gramsPure,
      metalPricePerGram: ORO_COST_PER_GRAM,
    }],
    ...over,
  };
}

// ──────────────────────────────────────────────────────────────────────────
// (1) Lista MONETARY (legacy) — comportamiento intacto (fix NO la toca)
// ──────────────────────────────────────────────────────────────────────────

describe("C3 — lista MONETARY: comportamiento legacy intacto", () => {
  it("redondea metalSale en pesos (INTEGER NEAREST sobre 90.800 → 90.800); physical=null", () => {
    const r = applyPriceList(basePriceList(), baseCost() as any);
    expect(r.value).not.toBeNull();
    expect(r.metalHechuraDetail?.metalSale).toBe(90800);
    expect(r.metalHechuraDetail?.physical).toBeNull();
    expect(r.metalHechuraDetail?.metalSalePreRounding).toBeUndefined();
  });

  it("MONETARY ignora metalsByParent — la entrada de C3 no contamina legacy", () => {
    const r = applyPriceList(
      basePriceList({
        commercialRoundingMetalDomain: "MONETARY",
        commercialPhysicalRoundingConfig: {
          byMetalParentId: { "oro-fino": { mode: "INTEGER", direction: "NEAREST" } },
        },
      }),
      baseCost() as any,
    );
    expect(r.metalHechuraDetail?.physical).toBeNull();
  });

  it("MONETARY con metalSale fraccionario redondea $: 90.755,5 → 90.756 (INTEGER NEAREST)", () => {
    const r = applyPriceList(
      basePriceList(),
      baseCost({
        metalCost: D(45377.75),    // × 2 = 90755.5
        value:     D(45377.75 + 15000),
      }) as any,
    );
    expect(r.metalHechuraDetail?.metalSale).toBe(90756);
    expect(r.metalHechuraDetail?.metalSalePreRounding).toBeCloseTo(90755.5, 2);
    expect(r.metalHechuraDetail?.metalSaleRoundingDelta).toBeCloseTo(0.5, 2);
    expect(r.metalHechuraDetail?.physical).toBeNull();
  });
});

// ──────────────────────────────────────────────────────────────────────────
// (2) Lista PHYSICAL POST-MARGEN — caso canónico del FIX (Test 1 del spec)
// ──────────────────────────────────────────────────────────────────────────

describe("C3 — PHYSICAL post-margen (FIX 2026-06-02): redondea DESPUÉS del margen", () => {
  it("Test 1 — 1,2375 g × 10% margen = 1,36125 → DECIMAL_1 NEAREST → 1,40 (NO 1,2375 → 1,20)", () => {
    const r = applyPriceList(physicalList(), physicalCost(1.2375) as any);
    expect(r.metalHechuraDetail?.physical).not.toBeNull();
    const entry = r.metalHechuraDetail!.physical!.metals[0]!;

    // El redondeo opera sobre los gramos COMERCIALES (post-margen ≈ 1,36125),
    // NO sobre los físicos pre-margen (1,2375).
    expect(entry.preGrams).toBeGreaterThan(1.36);
    expect(entry.preGrams).toBeLessThan(1.3625);
    expect(entry.postGrams).toBe(1.4);
    expect(entry.deltaGrams).toBeGreaterThan(0);   // redondeó hacia arriba
    expect(entry.metalPricePerGram).toBe(ORO_COST_PER_GRAM);
    expect(entry.source).toBe("COMMERCIAL_PHYSICAL_ROUNDING");

    // metalSale_pre = 1,2375 × 50.000 × 1,10 = 68.062,5 → cierra ≈ 1,40 ×
    // 50.000 = 70.000 tras sumar el equivalente del Δ comercial. El residuo
    // de ~2,5 viene de la cuantización de `preGrams` a 4 decimales (idéntica a
    // PER_DOCUMENT): Δgramos = 1,40 − round4(1,36125).
    expect(r.metalHechuraDetail?.metalSalePreRounding).toBeCloseTo(68062.5, 1);
    expect(r.metalHechuraDetail?.metalSale).toBeCloseTo(70000, -1);   // ±5 por cuantización
    expect(r.metalHechuraDetail!.metalSale).toBeGreaterThan(r.metalHechuraDetail!.metalSalePreRounding!);
  });

  it("comportamiento ANTERIOR (pre-margen) ya NO ocurre: no redondea 1,2375 → 1,20", () => {
    const r = applyPriceList(physicalList(), physicalCost(1.2375) as any);
    const entry = r.metalHechuraDetail!.physical!.metals[0]!;
    expect(entry.preGrams).not.toBeCloseTo(1.2375, 3);
    expect(entry.postGrams).not.toBe(1.2);
  });
});

// ──────────────────────────────────────────────────────────────────────────
// (3) Dos líneas iguales cerradas → Σ postGrams = 2,80 (Test 2 del spec)
// ──────────────────────────────────────────────────────────────────────────

describe("C3 — dos líneas iguales: documento suma líneas cerradas", () => {
  it("Test 2 — Línea1 1,40 + Línea2 1,40 = 2,80 (cada línea cierra con su redondeo)", () => {
    const l1 = applyPriceList(physicalList(), physicalCost(1.2375) as any);
    const l2 = applyPriceList(physicalList(), physicalCost(1.2375) as any);
    const g1 = l1.metalHechuraDetail!.physical!.metals[0]!.postGrams;
    const g2 = l2.metalHechuraDetail!.physical!.metals[0]!.postGrams;
    expect(g1).toBe(1.4);
    expect(g2).toBe(1.4);
    // Consolidación por suma de líneas cerradas (scope por línea).
    expect(g1 + g2).toBeCloseTo(2.8, 4);
  });
});

// ──────────────────────────────────────────────────────────────────────────
// (4) Hechura sigue MONETARIA — incluso con metal PHYSICAL post-margen
// ──────────────────────────────────────────────────────────────────────────

describe("C3 — hechura sigue monetaria (regla canónica)", () => {
  it("metal PHYSICAL post-margen + hechura HUNDRED NEAREST: la hechura redondea en pesos", () => {
    const r = applyPriceList(
      physicalList({
        roundingModeHechura:      "HUNDRED",
        roundingDirectionHechura: "NEAREST",
      }),
      physicalCost(1.2375, {
        hechuraCost: D(14987.5),                     // margen hechura 0 ⇒ 14987.5
        value:       D(1.2375 * ORO_COST_PER_GRAM + 14987.5),
      }) as any,
    );
    // Hechura: 14987.5 → 15000 (HUNDRED NEAREST).
    expect(r.metalHechuraDetail?.hechuraSale).toBe(15000);
    expect(r.metalHechuraDetail?.hechuraSalePreRounding).toBeCloseTo(14987.5, 2);
    // Metal: snapshot physical solo para METAL (no hechura).
    expect(r.metalHechuraDetail!.physical!.metals).toHaveLength(1);
    expect(r.metalHechuraDetail!.physical!.metals[0]!.metalParentId).toBe("oro-fino");
    expect(r.metalHechuraDetail!.physical!.metals[0]!.postGrams).toBe(1.4);
  });
});

// ──────────────────────────────────────────────────────────────────────────
// (5) Snapshot shape canónico — todos los campos del contrato
// ──────────────────────────────────────────────────────────────────────────

describe("C3 — snapshot physical con shape canónico", () => {
  it("metals[i] tiene el shape completo del contrato", () => {
    const r = applyPriceList(physicalList(), physicalCost(1.2375) as any);
    const entry = r.metalHechuraDetail!.physical!.metals[0]!;
    const keys = Object.keys(entry).sort();
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
    expect(r.metalHechuraDetail!.physical!.fallback).toBeNull();
  });
});

// ──────────────────────────────────────────────────────────────────────────
// (6) Múltiples metales padre — cada uno redondea post-margen con su config
// ──────────────────────────────────────────────────────────────────────────

describe("C3 — múltiples metales padre (post-margen)", () => {
  it("Oro Fino + Plata en la misma línea — cada uno redondea sus gramos comerciales", () => {
    // Oro 1,2375 g (×1,10 = 1,36125 → DECIMAL_1 → 1,40)
    // Plata 4,0 g  (×1,10 = 4,40   → HALF      → 4,50)
    const oroCost   = 1.2375 * ORO_COST_PER_GRAM;   // 61.875
    const plataCost = 4.0 * 1000;                   // 4.000
    const r = applyPriceList(
      physicalList({
        commercialPhysicalRoundingConfig: {
          byMetalParentId: {
            "oro-fino": { mode: "DECIMAL_1", direction: "NEAREST" },
            "plata":    { mode: "HALF",      direction: "NEAREST" },
          },
        },
      }),
      physicalCost(1.2375, {
        metalCost:           D(oroCost + plataCost),
        value:               D(oroCost + plataCost + 15000),
        totalGrams:          D(1.2375 + 4.0),
        metalGramsWithMerma: D(1.2375 + 4.0),
        metalsByParent: [
          { metalParentId: "oro-fino", metalParentName: "Oro Fino", gramsPure: 1.2375, metalPricePerGram: ORO_COST_PER_GRAM },
          { metalParentId: "plata",    metalParentName: "Plata",    gramsPure: 4.0,    metalPricePerGram: 1000 },
        ],
      }) as any,
    );
    expect(r.metalHechuraDetail!.physical!.metals).toHaveLength(2);
    const byId = Object.fromEntries(
      r.metalHechuraDetail!.physical!.metals.map((m) => [m.metalParentId, m]),
    );
    // Oro: 1,36125 → 1,40 (post-margen).
    expect(byId["oro-fino"]!.postGrams).toBe(1.4);
    // Plata: 4,40 → 4,50 (HALF NEAREST, post-margen).
    expect(byId["plata"]!.postGrams).toBe(4.5);
  });
});

// ──────────────────────────────────────────────────────────────────────────
// (7) Sin metales — fallback limpio (cae a MONETARY)
// ──────────────────────────────────────────────────────────────────────────

describe("C3 — sin metalsByParent → fallback limpio", () => {
  it("PHYSICAL + metalsByParent=null → physical=null (cae a MONETARY, sin romper)", () => {
    const r = applyPriceList(
      physicalList(),
      physicalCost(1.2375, { metalsByParent: null }) as any,
    );
    expect(r.metalHechuraDetail?.physical).toBeNull();
  });

  it("PHYSICAL + metalsByParent=[] → physical=null", () => {
    const r = applyPriceList(
      physicalList(),
      physicalCost(1.2375, { metalsByParent: [] }) as any,
    );
    expect(r.metalHechuraDetail?.physical).toBeNull();
  });

  it("PHYSICAL + config vacía (NO_CONFIG) → metals[] con fallback NO_CONFIG, sin mover gramos", () => {
    const r = applyPriceList(
      physicalList({ commercialPhysicalRoundingConfig: null }),
      physicalCost(1.2375) as any,
    );
    expect(r.metalHechuraDetail?.physical).not.toBeNull();
    const entry = r.metalHechuraDetail!.physical!.metals[0]!;
    expect(entry.fallback).toBe("NO_CONFIG");
    expect(entry.postGrams).toBe(entry.preGrams);
    expect(entry.deltaGrams).toBe(0);
    expect(entry.monetaryEquivalent).toBe(0);
  });
});
