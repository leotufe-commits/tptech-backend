// src/lib/pricing-engine/__tests__/metal-hechura.test.ts
// Tests para applyPriceList en modo METAL_HECHURA

import { describe, it, expect } from "vitest";
import { applyPriceList } from "../pricing-engine.pricelist.js";
import { Prisma } from "@prisma/client";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makePriceList(overrides: Record<string, any> = {}) {
  return {
    id:               "pl-1",
    name:             "Lista Test",
    mode:             "METAL_HECHURA",
    marginTotal:      null,
    marginMetal:      "20",
    marginHechura:    "30",
    costPerGram:      null,
    surcharge:        null,
    minimumPrice:     null,
    roundingTarget:   "NONE",
    roundingMode:     "NONE",
    roundingDirection:"NEAREST",
    validFrom:        null,
    validTo:          null,
    isActive:         true,
    ...overrides,
  };
}

function D(v: number | string) {
  return new Prisma.Decimal(String(v));
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("applyPriceList — METAL_HECHURA", () => {

  it("calcula metalSale y hechuraSale con los márgenes correctos", () => {
    const pl   = makePriceList({ marginMetal: "20", marginHechura: "30" });
    const cost = { value: D(1300), metalCost: D(1000), hechuraCost: D(300) };

    const result = applyPriceList(pl as any, cost);

    // metalSale   = 1000 * 1.20 = 1200
    // hechuraSale = 300  * 1.30 = 390
    // total       = 1590
    expect(result.value?.toNumber()).toBeCloseTo(1590, 2);
    expect(result.partial).toBe(false);
    expect(result.metalHechuraDetail).not.toBeNull();
    expect(result.metalHechuraDetail!.metalCost).toBeCloseTo(1000, 4);
    expect(result.metalHechuraDetail!.metalSale).toBeCloseTo(1200, 4);
    expect(result.metalHechuraDetail!.metalMarginPct).toBe(20);
    expect(result.metalHechuraDetail!.hechuraCost).toBeCloseTo(300, 4);
    expect(result.metalHechuraDetail!.hechuraSale).toBeCloseTo(390, 4);
    expect(result.metalHechuraDetail!.hechuraMarginPct).toBe(30);
  });

  it("funciona cuando metalCost=0 (artículo sin metal)", () => {
    const pl   = makePriceList({ marginMetal: "20", marginHechura: "40" });
    const cost = { value: D(500), metalCost: D(0), hechuraCost: D(500) };

    const result = applyPriceList(pl as any, cost);

    // metalSale   = 0   * 1.20 = 0
    // hechuraSale = 500 * 1.40 = 700
    expect(result.value?.toNumber()).toBeCloseTo(700, 2);
    expect(result.partial).toBe(false);
    expect(result.metalHechuraDetail!.metalSale).toBeCloseTo(0, 4);
    expect(result.metalHechuraDetail!.hechuraSale).toBeCloseTo(700, 4);
  });

  it("funciona cuando hechuraCost=0 (artículo solo metal)", () => {
    const pl   = makePriceList({ marginMetal: "25", marginHechura: "30" });
    const cost = { value: D(800), metalCost: D(800), hechuraCost: D(0) };

    const result = applyPriceList(pl as any, cost);

    // metalSale   = 800 * 1.25 = 1000
    // hechuraSale = 0   * 1.30 = 0
    expect(result.value?.toNumber()).toBeCloseTo(1000, 2);
    expect(result.metalHechuraDetail!.metalSale).toBeCloseTo(1000, 4);
    expect(result.metalHechuraDetail!.hechuraSale).toBeCloseTo(0, 4);
  });

  it("cae a modo parcial cuando no hay desglose (solo value)", () => {
    const pl   = makePriceList({ marginMetal: "20", marginHechura: "30" });
    const cost = { value: D(1000), metalCost: null, hechuraCost: null };

    const result = applyPriceList(pl as any, cost);

    // Fallback: usa marginHechura sobre el costo total → 1000 * 1.30 = 1300
    expect(result.partial).toBe(true);
    expect(result.value?.toNumber()).toBeCloseTo(1300, 2);
    // Sin desglose disponible
    expect(result.metalHechuraDetail).toBeUndefined();
  });

  it("devuelve null cuando no hay costo disponible", () => {
    const pl   = makePriceList({ marginMetal: "20", marginHechura: "30" });
    const cost = { value: null, metalCost: null, hechuraCost: null };

    const result = applyPriceList(pl as any, cost);

    expect(result.value).toBeNull();
    expect(result.partial).toBe(true);
  });

});
