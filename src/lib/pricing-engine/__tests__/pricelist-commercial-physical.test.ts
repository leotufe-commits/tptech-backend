// src/lib/pricing-engine/__tests__/pricelist-commercial-physical.test.ts
// =============================================================================
// Etapa C-comercial / C3 (POLICY §R-Rounding-14) — Tests del motor de lista
// con redondeo COMERCIAL PHYSICAL integrado.
//
// Cubre los 8 escenarios obligatorios del brief:
//   1. Lista MONETARY (default) → resultado idéntico al actual (sin
//      `physical`, sin pre/delta del nuevo path).
//   2. Lista PHYSICAL → Oro Fino 0,908 → 1,000.
//   3. Lista PHYSICAL → Oro Fino 1,526 → 2,000.
//   4. Equivalente monetario impacta `metalSale`.
//   5. Hechura sigue redondeando MONETARIAMENTE (regla canónica).
//   6. Snapshot `metalHechuraDetail.physical` presente con shape canónico.
//   7. Múltiples metales padre en la misma línea (Oro Fino + Plata).
//   8. Sin `metalsByParent` (línea sin metales o motor legacy) → fallback
//      limpio al path MONETARY (no rompe).
//
// Tests PUROS del motor de lista (`applyPriceList`). No tocan Prisma — solo
// construyen un `CostBreakdown` y un `PriceListData` de prueba.
// =============================================================================

import { describe, it, expect } from "vitest";
import { Prisma } from "@prisma/client";
import { applyPriceList } from "../pricing-engine.pricelist.js";

const D = (v: number | string) => new Prisma.Decimal(String(v));

function basePriceList(over: Record<string, any> = {}) {
  return {
    id:                       "pl1",
    name:                     "Lista Test",
    mode:                     "METAL_HECHURA",
    marginTotal:              null,
    marginMetal:              "100",  // 100% sobre metal
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

// Caso canónico del brief — Oro Fino 0,908 g.
// metalCost = 0,908 × 50.000 = 45.400 ⇒ con margen 100% ⇒ metalSale = 90.800.
// metalPricePerGram en venta = 100.000 ⇒ Δ +0,092 g = +9.200 $.
const ORO_PRICE_BASE = 50000;
const ORO_PRICE_SALE = 100000;

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
      metalPricePerGram: ORO_PRICE_SALE,
    }],
    ...over,
  };
}

// ──────────────────────────────────────────────────────────────────────────
// (1) Lista MONETARY (legacy) — comportamiento intacto
// ──────────────────────────────────────────────────────────────────────────

describe("C3 — lista MONETARY: comportamiento legacy intacto", () => {
  it("redondea metalSale en pesos (INTEGER NEAREST sobre 90.800 → 90.800); physical=null", () => {
    const r = applyPriceList(basePriceList(), baseCost() as any);
    expect(r.value).not.toBeNull();
    // 90.800 ya es entero ⇒ no se mueve.
    expect(r.metalHechuraDetail?.metalSale).toBe(90800);
    expect(r.metalHechuraDetail?.physical).toBeNull();
    // No emite campos pre-rounding/delta cuando no actuó.
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
// (2) Lista PHYSICAL — 0,908 → 1,000
// ──────────────────────────────────────────────────────────────────────────

describe("C3 — lista PHYSICAL: caso canónico 0,908 → 1,000", () => {
  const PRICE_LIST = basePriceList({
    commercialRoundingMetalDomain: "PHYSICAL",
    commercialPhysicalRoundingConfig: {
      byMetalParentId: { "oro-fino": { mode: "INTEGER", direction: "NEAREST" } },
    },
  });

  it("genera snapshot physical con preGrams 0.908, postGrams 1.000, delta +0.092", () => {
    const r = applyPriceList(PRICE_LIST, baseCost() as any);
    expect(r.metalHechuraDetail?.physical).not.toBeNull();
    const entry = r.metalHechuraDetail!.physical!.metals[0]!;
    expect(entry.metalParentId).toBe("oro-fino");
    expect(entry.preGrams).toBe(0.908);
    expect(entry.postGrams).toBe(1.000);
    expect(entry.deltaGrams).toBeCloseTo(0.092, 4);
    expect(entry.metalPricePerGram).toBe(ORO_PRICE_SALE);
    // 0,092 × 100.000 = 9.200
    expect(entry.monetaryEquivalent).toBe(9200);
    expect(entry.source).toBe("COMMERCIAL_PHYSICAL_ROUNDING");
    expect(entry.fallback).toBeNull();
    expect(r.metalHechuraDetail!.physical!.metalMonetaryEquivalent).toBe(9200);
  });

  it("metalSale aumenta exactamente por el equivalente monetario (90.800 + 9.200 = 100.000)", () => {
    const r = applyPriceList(PRICE_LIST, baseCost() as any);
    expect(r.metalHechuraDetail?.metalSale).toBe(100000);
    expect(r.metalHechuraDetail?.metalSalePreRounding).toBe(90800);
    expect(r.metalHechuraDetail?.metalSaleRoundingDelta).toBe(9200);
  });

  it("precio final (metal + hechura) refleja el aumento: 100.000 + 15.000 = 115.000", () => {
    const r = applyPriceList(PRICE_LIST, baseCost() as any);
    expect(r.value?.toNumber()).toBe(115000);
  });
});

// ──────────────────────────────────────────────────────────────────────────
// (3) Lista PHYSICAL — 1,526 → 2,000
// ──────────────────────────────────────────────────────────────────────────

describe("C3 — lista PHYSICAL: caso canónico 1,526 → 2,000", () => {
  it("Oro Fino 1,526 g INTEGER NEAREST → 2,000 g (Δ +0,474, equivalente +47.400)", () => {
    const cost = baseCost({
      metalCost:           D(1.526 * ORO_PRICE_BASE),       // 76.300
      value:               D(1.526 * ORO_PRICE_BASE + 15000),
      totalGrams:          D(1.526),
      metalGramsWithMerma: D(1.526),
      metalsByParent: [{
        metalParentId:     "oro-fino",
        metalParentName:   "Oro Fino",
        gramsPure:         1.526,
        metalPricePerGram: ORO_PRICE_SALE,
      }],
    });
    const r = applyPriceList(
      basePriceList({
        commercialRoundingMetalDomain: "PHYSICAL",
        commercialPhysicalRoundingConfig: {
          byMetalParentId: { "oro-fino": { mode: "INTEGER", direction: "NEAREST" } },
        },
      }),
      cost as any,
    );
    const entry = r.metalHechuraDetail!.physical!.metals[0]!;
    expect(entry.preGrams).toBe(1.526);
    expect(entry.postGrams).toBe(2.000);
    expect(entry.deltaGrams).toBeCloseTo(0.474, 4);
    expect(entry.monetaryEquivalent).toBe(47400);
    // metalSale: 1.526 × 50.000 × 2 = 152.600 + 47.400 = 200.000
    expect(r.metalHechuraDetail?.metalSale).toBe(200000);
  });
});

// ──────────────────────────────────────────────────────────────────────────
// (5) Hechura sigue redondeando MONETARIAMENTE — incluso con metal PHYSICAL
// ──────────────────────────────────────────────────────────────────────────

describe("C3 — caso 5: hechura sigue monetaria (regla canónica)", () => {
  it("metal PHYSICAL + hechura HUNDRED NEAREST: la hechura redondea en pesos", () => {
    const cost = baseCost({
      hechuraCost: D(14987.5),                    // ⇒ con margen 0 ⇒ hechuraSale = 14987.5
      value:       D(45400 + 14987.5),
    });
    const r = applyPriceList(
      basePriceList({
        commercialRoundingMetalDomain: "PHYSICAL",
        commercialPhysicalRoundingConfig: {
          byMetalParentId: { "oro-fino": { mode: "INTEGER", direction: "NEAREST" } },
        },
        roundingModeHechura:      "HUNDRED",
        roundingDirectionHechura: "NEAREST",
      }),
      cost as any,
    );
    // Hechura: 14987.5 → 15000 (HUNDRED NEAREST).
    expect(r.metalHechuraDetail?.hechuraSale).toBe(15000);
    expect(r.metalHechuraDetail?.hechuraSalePreRounding).toBeCloseTo(14987.5, 2);
    expect(r.metalHechuraDetail?.hechuraSaleRoundingDelta).toBeCloseTo(12.5, 2);
    // Metal sigue subiendo a 100.000 por el equivalente físico.
    expect(r.metalHechuraDetail?.metalSale).toBe(100000);
    // Snapshot physical solo para METAL (no hechura).
    expect(r.metalHechuraDetail!.physical!.metals).toHaveLength(1);
    expect(r.metalHechuraDetail!.physical!.metals[0]!.metalParentId).toBe("oro-fino");
  });
});

// ──────────────────────────────────────────────────────────────────────────
// (6) Snapshot shape canónico — todos los campos del contrato
// ──────────────────────────────────────────────────────────────────────────

describe("C3 — caso 6: snapshot physical con shape canónico", () => {
  it("metals[i] tiene metalParentId, metalParentName, preGrams, postGrams, deltaGrams, metalPricePerGram, monetaryEquivalent, mode, direction, source, fallback", () => {
    const r = applyPriceList(
      basePriceList({
        commercialRoundingMetalDomain: "PHYSICAL",
        commercialPhysicalRoundingConfig: {
          byMetalParentId: { "oro-fino": { mode: "INTEGER", direction: "NEAREST" } },
        },
      }),
      baseCost() as any,
    );
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
    expect(r.metalHechuraDetail!.physical!.metalMonetaryEquivalent).toBe(9200);
    expect(r.metalHechuraDetail!.physical!.fallback).toBeNull();
  });
});

// ──────────────────────────────────────────────────────────────────────────
// (7) Múltiples metales padre en la misma línea
// ──────────────────────────────────────────────────────────────────────────

describe("C3 — caso 7: múltiples metales padre", () => {
  it("Oro Fino + Plata en la misma línea — cada uno redondea con su config", () => {
    // Costo: oro 0,908 g × 50.000 + plata 5 g × 200 = 45.400 + 1.000 = 46.400.
    // marginMetal=100% ⇒ metalSale = 92.800.
    // Después redondeo PHYSICAL:
    //   - Oro Fino 0,908 → 1,000 (Δ +0,092 × 100.000 = +9.200)
    //   - Plata 5 → 5 (HALF NEAREST sobre 5 = 5, Δ = 0)
    const cost = baseCost({
      metalCost:           D(46400),
      value:               D(46400 + 15000),
      totalGrams:          D(0.908 + 5),
      metalGramsWithMerma: D(0.908 + 5),
      metalsByParent: [
        { metalParentId: "oro-fino", metalParentName: "Oro Fino", gramsPure: 0.908, metalPricePerGram: 100000 },
        { metalParentId: "plata",    metalParentName: "Plata",    gramsPure: 5.000, metalPricePerGram: 400 },
      ],
    });
    const r = applyPriceList(
      basePriceList({
        commercialRoundingMetalDomain: "PHYSICAL",
        commercialPhysicalRoundingConfig: {
          byMetalParentId: {
            "oro-fino": { mode: "INTEGER", direction: "NEAREST" },
            "plata":    { mode: "HALF",    direction: "NEAREST" },
          },
        },
      }),
      cost as any,
    );
    expect(r.metalHechuraDetail!.physical!.metals).toHaveLength(2);
    const byId = Object.fromEntries(
      r.metalHechuraDetail!.physical!.metals.map((m) => [m.metalParentId, m]),
    );
    expect(byId["oro-fino"]!.postGrams).toBe(1.000);
    expect(byId["oro-fino"]!.monetaryEquivalent).toBe(9200);
    expect(byId["plata"]!.postGrams).toBe(5.000);
    expect(byId["plata"]!.monetaryEquivalent).toBe(0);
    expect(r.metalHechuraDetail!.physical!.metalMonetaryEquivalent).toBe(9200);
    // metalSale: 92.800 + 9.200 = 102.000
    expect(r.metalHechuraDetail?.metalSale).toBe(102000);
  });
});

// ──────────────────────────────────────────────────────────────────────────
// (8) Sin metales — fallback limpio (cae a MONETARY)
// ──────────────────────────────────────────────────────────────────────────

describe("C3 — caso 8: sin metalsByParent → fallback limpio", () => {
  it("PHYSICAL + metalsByParent=null → physical=null, comportamiento MONETARY (sin romper)", () => {
    const r = applyPriceList(
      basePriceList({
        commercialRoundingMetalDomain: "PHYSICAL",
        commercialPhysicalRoundingConfig: {
          byMetalParentId: { "oro-fino": { mode: "INTEGER", direction: "NEAREST" } },
        },
      }),
      baseCost({ metalsByParent: null }) as any,
    );
    expect(r.metalHechuraDetail?.physical).toBeNull();
    // El path MONETARY actúa con la config de roundingMode existente
    // (INTEGER NEAREST sobre 90.800 = 90.800, no se mueve).
    expect(r.metalHechuraDetail?.metalSale).toBe(90800);
  });

  it("PHYSICAL + metalsByParent=[] → physical=null", () => {
    const r = applyPriceList(
      basePriceList({
        commercialRoundingMetalDomain: "PHYSICAL",
        commercialPhysicalRoundingConfig: {
          byMetalParentId: { "oro-fino": { mode: "INTEGER", direction: "NEAREST" } },
        },
      }),
      baseCost({ metalsByParent: [] }) as any,
    );
    expect(r.metalHechuraDetail?.physical).toBeNull();
  });

  it("PHYSICAL + config vacía (NO_CONFIG) → metals[] poblado pero todos con fallback NO_CONFIG", () => {
    const r = applyPriceList(
      basePriceList({
        commercialRoundingMetalDomain: "PHYSICAL",
        commercialPhysicalRoundingConfig: null,    // domain PHYSICAL pero sin config
      }),
      baseCost() as any,
    );
    expect(r.metalHechuraDetail?.physical).not.toBeNull();
    const entry = r.metalHechuraDetail!.physical!.metals[0]!;
    expect(entry.fallback).toBe("NO_CONFIG");
    expect(entry.postGrams).toBe(entry.preGrams);
    expect(entry.deltaGrams).toBe(0);
    expect(entry.monetaryEquivalent).toBe(0);
    // metalSale no se mueve (delta 0).
    expect(r.metalHechuraDetail?.metalSale).toBe(90800);
  });
});
