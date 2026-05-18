// src/lib/__tests__/g4-9a-composition-arrays.test.ts
// =============================================================================
// FASE F1.3 G4.x #9-A — composition.metals[] / composition.hechuras[].
//
// Cubre TODAS las validaciones del usuario:
//   1. Artículo con 2 METAL → composition.metals.length === 2
//   2. Artículo con 2 HECHURA → composition.hechuras.length === 2
//   3. Mix metal+hechura+product+service → ningún componente perdido
//   4. Alias legacy: metal === metals[0] (estructural) y hechura === hechuras[0]
//   5. Snapshots viejos sin metals/hechuras → arrays SIEMPRE definidos []
//   6. Cero cambio numérico — totales/precio final no se alteran
//   7. fetchMetalVariantInfoMap batch + failure-safe
// =============================================================================

import { describe, it, expect, vi, beforeEach } from "vitest";

const mockPrisma = vi.hoisted(() => ({
  metalVariant: { findUnique: vi.fn(), findMany: vi.fn() },
  article:      { findMany:   vi.fn() },
}));
vi.mock("../prisma.js", () => ({ prisma: mockPrisma }));

import {
  buildComposition,
  extractCompositionMetals,
  extractCompositionHechuras,
  fetchMetalVariantInfoMap,
} from "../pricing-composition.js";

beforeEach(() => {
  vi.clearAllMocks();
  mockPrisma.metalVariant.findMany.mockResolvedValue([]);
});

// ── Helpers ──────────────────────────────────────────────────────────────────

// Fixtures sintéticos — `value: number` y `meta` literales son aceptados por
// los extractores en runtime (parsean strings/numbers indistintamente). Para
// satisfacer el chequeo de tipos `PricingStep` (que requiere `Decimal`), el
// helper devuelve `any` — el cast NO afecta a runtime ni al test, solo
// silencia el chequeo estricto del build.
function makeStep(key: string, value: number, meta: Record<string, unknown> = {}, label = "step"): any {
  return { key, label, status: "ok" as const, value, meta };
}

function makeResult(steps: any[]): any {
  return {
    steps,
    taxBreakdown: [],
    costOverrideContext: undefined,
  };
}

// `MetalVariantInfo` requiere `variantName` (Fase 2.4). Los tests de Fase
// 1.3 no validan ese campo — lo emitimos como null para satisfacer el tipo.
const noMvi = { purity: null, purityLabel: null, metalName: null, variantName: null };

// =============================================================================
// 1. extractCompositionMetals — múltiples METAL
// =============================================================================

describe("F1.3 #9-A — extractCompositionMetals", () => {
  it("baseline correct: artículo con 2 cost lines METAL → 2 items", () => {
    const steps = [
      makeStep("COST_LINES_METAL", 600, {
        costLineId: "cl-m1", variantId: "mv-1", qty: "1.30", merma: 5,
        quotePrice: "400.00",
      }, "Línea de metal"),
      makeStep("COST_LINES_METAL", 400, {
        costLineId: "cl-m2", variantId: "mv-2", qty: "2.00", merma: 0,
        quotePrice: "200.00",
      }, "Línea de metal"),
    ];
    const map = new Map([
      ["mv-1", { purity: 0.75, purityLabel: "18k", metalName: "Oro", variantName: null }],
      ["mv-2", { purity: 0.925, purityLabel: "22k", metalName: "Plata", variantName: null }],
    ]);
    const items = extractCompositionMetals(steps, map);
    expect(items).toHaveLength(2);
    expect(items[0]).toEqual({
      costLineId:      "cl-m1",
      metalVariantId:  "mv-1",
      metalName:       "Oro",
      // Fase 2.4 — variantName propagado desde MetalVariantInfo del map.
      // Este fixture no setea variantName en el map → null (fallback al
      // "Oro 18k" derivado en frontend).
      variantName:     null,
      purity:          0.75,
      purityLabel:     "18k",
      appliedGrams:    1.30,
      appliedMermaPct: 5,
      lineCost:        600,
      // F1.5 #A++ — sin metalSaleFactor (caller no lo pasó) → lineSale null.
      lineSale:        null,
      // Fase 2.3 — quotePrice propagado desde step.meta (base por gramo).
      quotePrice:      400,
      // FASE F2 — el step de este fixture no setea meta.mermaSource → null.
      mermaSource:     null,
      // FASE F3 — appliedGrams (1.30) × quotePrice (400) = 520.
      lineCostBase:    520,
    });
    expect(items[1].metalVariantId).toBe("mv-2");
    expect(items[1].metalName).toBe("Plata");
    expect(items[1].lineCost).toBe(400);
  });

  it("baseline correct: sin steps METAL → array vacío (nunca undefined)", () => {
    const items = extractCompositionMetals([], undefined);
    expect(items).toEqual([]);
  });

  it("baseline correct: steps METAL con status missing → ignorados", () => {
    const steps = [
      makeStep("COST_LINES_METAL", 600, { variantId: "mv-1" }),
      { key: "COST_LINES_METAL", status: "missing", value: null, label: "x", meta: {} },
    ];
    expect(extractCompositionMetals(steps, undefined)).toHaveLength(1);
  });

  it("baseline correct: sin metalVariantInfoMap → metalName/purity null pero item presente", () => {
    const steps = [
      makeStep("COST_LINES_METAL", 600, { costLineId: "cl-m1", variantId: "mv-x", qty: "1", merma: 0 }),
    ];
    const items = extractCompositionMetals(steps, undefined);
    expect(items).toHaveLength(1);
    expect(items[0].metalName).toBeNull();
    expect(items[0].purity).toBeNull();
    expect(items[0].metalVariantId).toBe("mv-x");
  });
});

// =============================================================================
// 2. extractCompositionHechuras — múltiples HECHURA
// =============================================================================

describe("F1.3 #9-A — extractCompositionHechuras", () => {
  it("baseline correct: artículo con 2 cost lines HECHURA → 2 items", () => {
    const steps = [
      makeStep("COST_LINES_HECHURA", 200, {
        costLineId: "cl-h1", qty: "1", unitValue: "200", lineLabel: "Mano de obra",
      }, "Mano de obra"),
      makeStep("COST_LINES_HECHURA", 150, {
        costLineId: "cl-h2", qty: "1", unitValue: "150", lineLabel: "Pulido",
      }, "Pulido"),
    ];
    const items = extractCompositionHechuras(steps);
    expect(items).toHaveLength(2);
    expect(items[0]).toEqual({
      costLineId:    "cl-h1",
      appliedAmount: 200,
      lineCost:      200,
      // F1.5 #A+ — sin hechuraSaleFactor (caller no lo pasó) → null.
      lineSale:      null,
      lineLabel:     "Mano de obra",
      // Fase 2.3.1 — `unitValue` propagado desde meta.unitValue. El step
      // del fixture trae unitValue:"200", así que llega como 200 (BASE
      // pre-ajuste; sin ajuste configurado coincide con appliedAmount).
      unitValue:     200,
      // `unitValueBase = unitValue × rate`. Sin conversión → rate=1 → 200.
      unitValueBase: 200,
      // Paridad con PRODUCT/SERVICE — `quantity` propagado desde meta.qty.
      // El fixture trae qty:"1".
      quantity:      1,
      // Fase 2.2 — 4 campos lineAdj* propagados desde step.meta.
      // En este fixture no hay ajuste configurado → quedan null.
      lineAdjKind:   null,
      lineAdjType:   null,
      lineAdjValue:  null,
      lineAdjAmount: null,
    });
    expect(items[1].costLineId).toBe("cl-h2");
    expect(items[1].lineLabel).toBe("Pulido");
  });

  it("baseline correct: sin steps HECHURA → array vacío", () => {
    expect(extractCompositionHechuras([])).toEqual([]);
  });

  it("propaga `quantity` desde meta.qty (qty > 1, ej. mano de obra desglosada por horas)", () => {
    const steps = [
      makeStep("COST_LINES_HECHURA", 227.28, {
        costLineId: "cl-h1", qty: "3", unitValue: "75.76", lineLabel: "Mano de obra",
      }, "Mano de obra"),
    ];
    const items = extractCompositionHechuras(steps);
    expect(items[0].quantity).toBe(3);
    expect(items[0].unitValue).toBe(75.76);
    expect(items[0].lineCost).toBe(227.28);
  });

  it("propaga `quantityUnit` desde meta.quantityUnit (selección del operador)", () => {
    const steps = [
      makeStep("COST_LINES_HECHURA", 200, {
        costLineId: "cl-h1", qty: "3", unitValue: "75.76",
        quantityUnit: "hr",       // ← operador eligió "horas"
        lineLabel: "Mano de obra",
      }, "Mano de obra"),
    ];
    const items = extractCompositionHechuras(steps);
    expect(items[0].quantityUnit).toBe("hr");
  });

  it("backward compat: snapshot sin meta.quantityUnit → quantityUnit omitido", () => {
    const steps = [
      makeStep("COST_LINES_HECHURA", 200, {
        costLineId: "cl-h1", qty: "1", unitValue: "200", lineLabel: "Mano de obra",
        // sin quantityUnit en meta
      }, "Mano de obra"),
    ];
    const items = extractCompositionHechuras(steps);
    expect(items[0]).not.toHaveProperty("quantityUnit");
  });

  it("propaga `unitValueBase = unitValue × rate` cuando hay conversión", () => {
    const steps = [
      makeStep("COST_LINES_HECHURA", 101_323.20, {
        costLineId: "cl-h1", qty: "3", unitValue: "75.76",
        fromCurrencyId: "cur-usd",
        currencyCode:   "USD",
        currencySymbol: "US$",
        rate:           "446.00",   // unitValue × rate = 75.76 × 446 = 33_788.96
        lineLabel: "Mano de obra",
      }, "Mano de obra"),
    ];
    const items = extractCompositionHechuras(steps);
    // unitValueBase debe ser unitValue (75.76) × rate (446) = 33788.96.
    expect(items[0].unitValueBase).toBeCloseTo(75.76 * 446, 2);
    // `unitValue` se mantiene en moneda original (sin convertir).
    expect(items[0].unitValue).toBe(75.76);
  });

  it("propaga `unitValueBase` cuando NO hay conversión (rate=1 → coincide con unitValue)", () => {
    const steps = [
      makeStep("COST_LINES_HECHURA", 200, {
        costLineId: "cl-base", qty: "1", unitValue: "200", lineLabel: "Mano de obra",
        // sin conversionMeta — el cost line está en moneda base.
      }, "Mano de obra"),
    ];
    const items = extractCompositionHechuras(steps);
    expect(items[0].unitValueBase).toBe(200);
  });

  it("propaga `currencyCode/Symbol` + `currencyId` cuando el motor registró conversión (meta.fromCurrencyId)", () => {
    const steps = [
      makeStep("COST_LINES_HECHURA", 227.28, {
        costLineId: "cl-h1", qty: "3", unitValue: "75.76",
        // El motor inyecta esto vía spread de conversionMeta cuando el cost
        // line está en moneda != base.
        fromCurrencyId: "cur-usd",
        currencyCode:   "USD",
        currencySymbol: "US$",
        rate:           "1332.5",
        lineLabel: "Mano de obra",
      }, "Mano de obra"),
    ];
    const items = extractCompositionHechuras(steps);
    expect(items[0].currencyId).toBe("cur-usd");
    expect(items[0].currencyCode).toBe("USD");
    expect(items[0].currencySymbol).toBe("US$");
  });

  it("snapshot sin conversión (cost line en moneda base) → currency* no se emiten", () => {
    const steps = [
      makeStep("COST_LINES_HECHURA", 200, {
        costLineId: "cl-base", qty: "1", unitValue: "200", lineLabel: "Mano de obra",
        // sin conversionMeta — el cost line está en moneda base.
      }, "Mano de obra"),
    ];
    const items = extractCompositionHechuras(steps);
    expect(items[0]).not.toHaveProperty("currencyCode");
    expect(items[0]).not.toHaveProperty("currencySymbol");
    expect(items[0]).not.toHaveProperty("currencyId");
  });

  it("backward compat: snapshot legacy sin meta.qty → quantity omitido (no se emite)", () => {
    const steps = [
      makeStep("COST_LINES_HECHURA", 200, {
        costLineId: "cl-legacy", unitValue: "200", lineLabel: "Mano de obra",
        // sin `qty` en meta
      }, "Mano de obra"),
    ];
    const items = extractCompositionHechuras(steps);
    expect(items[0]).not.toHaveProperty("quantity");
    expect(items[0].lineCost).toBe(200);
  });
});

// =============================================================================
// 3. buildComposition — alias legacy + arrays + mix completo
// =============================================================================

describe("F1.3 #9-A — buildComposition arrays + alias legacy", () => {
  it("baseline correct: 2 metals → metal === metals[0] (alias legacy estructural)", () => {
    const result = makeResult([
      makeStep("COST_LINES_METAL", 600, { costLineId: "cl-m1", variantId: "mv-1", qty: "1.30", merma: 5 }),
      makeStep("COST_LINES_METAL", 400, { costLineId: "cl-m2", variantId: "mv-2", qty: "2.00", merma: 0 }),
    ]);
    const map = new Map([
      ["mv-1", { purity: 0.75, purityLabel: "18k", metalName: "Oro", variantName: null }],
      ["mv-2", { purity: 0.925, purityLabel: "22k", metalName: "Plata", variantName: null }],
    ]);
    const comp = buildComposition(result, noMvi, undefined, map);
    expect(comp.metals).toHaveLength(2);
    // INVARIANTE: metal alias refleja al primer item.
    expect(comp.metal).not.toBeNull();
    expect(comp.metal!.metalName).toBe("Oro");
    expect(comp.metal!.purityLabel).toBe("18k");
    expect(comp.metal!.appliedGrams).toBe(1.30);
    // El segundo metal sigue presente en metals[1].
    expect(comp.metals[1].metalName).toBe("Plata");
  });

  it("baseline correct: 2 hechuras → hechura === hechuras[0] (alias legacy)", () => {
    const result = makeResult([
      makeStep("COST_LINES_HECHURA", 200, { costLineId: "cl-h1", lineLabel: "Mano de obra" }),
      makeStep("COST_LINES_HECHURA", 150, { costLineId: "cl-h2", lineLabel: "Pulido" }),
    ]);
    const comp = buildComposition(result, noMvi);
    expect(comp.hechuras).toHaveLength(2);
    expect(comp.hechura).not.toBeNull();
    expect(comp.hechura!.appliedAmount).toBe(200);
    expect(comp.hechuras[1].lineLabel).toBe("Pulido");
  });

  it("baseline correct: mix completo (2 metal + 2 hechura + 1 product + 1 service) → ninguno perdido", () => {
    const result = makeResult([
      makeStep("COST_LINES_METAL",   600, { costLineId: "cl-m1", variantId: "mv-1", qty: "1", merma: 0 }),
      makeStep("COST_LINES_METAL",   400, { costLineId: "cl-m2", variantId: "mv-2", qty: "2", merma: 0 }),
      makeStep("COST_LINES_HECHURA", 200, { costLineId: "cl-h1", lineLabel: "MO" }),
      makeStep("COST_LINES_HECHURA", 100, { costLineId: "cl-h2", lineLabel: "PUL" }),
      makeStep("COST_LINES_PRODUCT",  50, { costLineId: "cl-p1", catalogItemId: "art-P", lineCode: "ZAF", qty: "1", unitValue: "50" }),
      makeStep("COST_LINES_SERVICE",  80, { costLineId: "cl-s1", catalogItemId: "art-S", lineCode: "ENG", qty: "1", unitValue: "80" }),
    ]);
    const comp = buildComposition(result, noMvi);
    expect(comp.metals).toHaveLength(2);
    expect(comp.hechuras).toHaveLength(2);
    expect(comp.products).toHaveLength(1);
    expect(comp.services).toHaveLength(1);
  });

  it("baseline correct: sin cost lines → metals/hechuras/products/services SIEMPRE [] (nunca undefined)", () => {
    const result = makeResult([]);
    const comp = buildComposition(result, noMvi);
    expect(comp.metals).toEqual([]);
    expect(comp.hechuras).toEqual([]);
    expect(comp.products).toEqual([]);
    expect(comp.services).toEqual([]);
    // Defensive: las claves existen, no son undefined.
    expect("metals"   in comp).toBe(true);
    expect("hechuras" in comp).toBe(true);
  });

  it("baseline correct: sin cost lines pero costOverrideContext.grams → metal alias se popula igual (back-compat)", () => {
    const result = {
      steps: [],
      taxBreakdown: [],
      costOverrideContext: {
        grams: { original: 1.5, applied: 2.0, manual: true },
      },
    } as any;
    const comp = buildComposition(result, noMvi);
    // metals[] vacío (no hay step COST_LINES_METAL).
    expect(comp.metals).toEqual([]);
    // Pero el alias legacy se popula desde el ctx.
    expect(comp.metal).not.toBeNull();
    expect(comp.metal!.appliedGrams).toBe(2.0);
    expect(comp.metal!.gramsManual).toBe(true);
  });
});

// =============================================================================
// 4. fetchMetalVariantInfoMap — batch query
// =============================================================================

describe("F1.3 #9-A — fetchMetalVariantInfoMap (batch + failure-safe)", () => {
  it("baseline correct: 3 ids únicos → 1 query Prisma con dedupe", async () => {
    mockPrisma.metalVariant.findMany.mockResolvedValue([
      { id: "mv-1", purity: { toString: () => "0.75" }, name: "Oro 18k", metal: { name: "Oro" } },
      { id: "mv-2", purity: { toString: () => "0.925" }, name: "Plata 925", metal: { name: "Plata" } },
      { id: "mv-3", purity: null, name: "Acero", metal: { name: "Acero" } },
    ]);
    // Pasamos ids con duplicados — el helper deduplica internamente.
    const map = await fetchMetalVariantInfoMap(["mv-1", "mv-2", "mv-1", "mv-3", null, undefined, ""]);
    expect(mockPrisma.metalVariant.findMany).toHaveBeenCalledTimes(1);
    expect(map.size).toBe(3);
    expect(map.get("mv-1")?.metalName).toBe("Oro");
    expect(map.get("mv-1")?.purityLabel).toBe("18k");
    expect(map.get("mv-2")?.purityLabel).toBe("22k");  // 0.925 × 24 ≈ 22
    expect(map.get("mv-3")?.purity).toBeNull();
    expect(map.get("mv-3")?.purityLabel).toBe("Acero");  // fallback al name
  });

  it("baseline correct: ids vacío → 0 queries", async () => {
    const map = await fetchMetalVariantInfoMap([]);
    expect(mockPrisma.metalVariant.findMany).not.toHaveBeenCalled();
    expect(map.size).toBe(0);
  });

  it("baseline correct: Prisma throw → Map vacío + warn (failure-safe)", async () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    mockPrisma.metalVariant.findMany.mockRejectedValue(new Error("DB error"));
    const map = await fetchMetalVariantInfoMap(["mv-1"]);
    expect(map.size).toBe(0);
    expect(warnSpy).toHaveBeenCalledTimes(1);
    expect(warnSpy.mock.calls[0]?.[0]).toMatch(/metalVariant batch lookup falló/i);
    warnSpy.mockRestore();
  });
});

// =============================================================================
// 5. Cero cambio numérico — invariante crítico
// =============================================================================

describe("F1.3 #9-A — cero cambio numérico", () => {
  it("baseline correct: arrays nuevos NO tocan totales — solo display estructural", () => {
    // Builder de composition NO lee/modifica unitPrice / discountAmount /
    // taxAmount / totalWithTax. Esos campos viven en SalePriceResult fuera
    // de composition. Test simbólico: si pasamos un result con campos
    // arbitrarios, la composition los ignora.
    const result = makeResult([
      makeStep("COST_LINES_METAL", 600, { variantId: "mv-1", qty: "1", merma: 0 }),
    ]);
    const comp = buildComposition(result, noMvi);
    // composition NO tiene unitPrice/totalWithTax/etc. — son del result.
    expect((comp as any).unitPrice).toBeUndefined();
    expect((comp as any).totalWithTax).toBeUndefined();
    // Lo único que cambió: structural (arrays + alias).
    expect(comp.metals).toHaveLength(1);
  });
});
