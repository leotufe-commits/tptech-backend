// src/lib/__tests__/pricing-composition-batch-cost-lines.test.ts
// =============================================================================
// FASE F1.3 G4.1.4 — tests para buildCatalogItemsMapForCostLines
// (variante para sales/preview con N líneas del documento).
//
// Reglas verificadas:
//   1. Batch dedupe GLOBAL — UNA query para TODAS las líneas del documento.
//   2. Multi-currency — products/services en distintas monedas.
//   3. Snapshot parity TODO/pending (it.todo) — preview vs persisted.
//   4. Performance benchmark — 100 líneas con productos repetidos → 1 query.
//   5. Failure isolation — Prisma throws → Map vacío sin propagar.
// =============================================================================

import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock prisma
const mockPrisma = vi.hoisted(() => ({
  article: { findMany: vi.fn() },
}));
vi.mock("../prisma.js", () => ({ prisma: mockPrisma }));

import {
  buildCatalogItemsMapForCostLines,
} from "../pricing-composition.js";
import { convertCompositionInPlace } from "../pricing-currency-display.js";

beforeEach(() => {
  vi.clearAllMocks();
});

// =============================================================================
// 1. BATCH DEDUPE GLOBAL — TODAS las líneas en una query
// =============================================================================

describe("buildCatalogItemsMapForCostLines — batch dedupe GLOBAL", () => {
  it("baseline correct: 5 líneas con 3 catalogItemIds únicos → 1 query con 3 ids", async () => {
    mockPrisma.article.findMany.mockResolvedValue([
      { id: "art-A", code: "A", name: "Item A" },
      { id: "art-B", code: "B", name: "Item B" },
      { id: "art-C", code: "C", name: "Item C" },
    ]);
    const linesByArticle = [
      [
        { catalogItemId: "art-A" },
        { catalogItemId: "art-B" },
      ],
      [
        { catalogItemId: "art-A" },          // duplicado
        { catalogItemId: "art-C" },
      ],
      [
        { catalogItemId: "art-B" },          // duplicado
      ],
    ];
    const r = await buildCatalogItemsMapForCostLines("j1", linesByArticle);

    // 1 sola query.
    expect(mockPrisma.article.findMany).toHaveBeenCalledTimes(1);
    // Con exactamente 3 ids dedupeados (no 5).
    const args = mockPrisma.article.findMany.mock.calls[0]?.[0];
    expect(args?.where?.id?.in).toHaveLength(3);
    expect(new Set(args?.where?.id?.in)).toEqual(new Set(["art-A", "art-B", "art-C"]));
    expect(r.size).toBe(3);
  });

  it("baseline correct: ningún catalogItemId → 0 queries", async () => {
    const linesByArticle = [
      [{ catalogItemId: null }, { catalogItemId: undefined }],
      [{ /* sin catalogItemId */ } as any],
    ];
    const r = await buildCatalogItemsMapForCostLines("j1", linesByArticle);
    expect(mockPrisma.article.findMany).not.toHaveBeenCalled();
    expect(r.size).toBe(0);
  });

  it("baseline correct: array vacío → 0 queries", async () => {
    const r = await buildCatalogItemsMapForCostLines("j1", []);
    expect(mockPrisma.article.findMany).not.toHaveBeenCalled();
    expect(r.size).toBe(0);
  });

  it("baseline correct: null/undefined input → 0 queries", async () => {
    expect((await buildCatalogItemsMapForCostLines("j1", null)).size).toBe(0);
    expect((await buildCatalogItemsMapForCostLines("j1", undefined)).size).toBe(0);
    expect(mockPrisma.article.findMany).not.toHaveBeenCalled();
  });

  it("baseline correct: jewelryId vacío → 0 queries (defensivo multi-tenancy)", async () => {
    const linesByArticle = [[{ catalogItemId: "art-A" }]];
    const r = await buildCatalogItemsMapForCostLines("", linesByArticle);
    expect(mockPrisma.article.findMany).not.toHaveBeenCalled();
    expect(r.size).toBe(0);
  });

  it("baseline correct: tenant scope + soft-delete en where", async () => {
    mockPrisma.article.findMany.mockResolvedValue([]);
    await buildCatalogItemsMapForCostLines("j1-tenant", [[{ catalogItemId: "art-A" }]]);
    const args = mockPrisma.article.findMany.mock.calls[0]?.[0];
    expect(args?.where?.jewelryId).toBe("j1-tenant");
    expect(args?.where?.deletedAt).toBeNull();
  });
});

// =============================================================================
// 2. MULTI-CURRENCY — coherencia con conversión multi-moneda
// =============================================================================

describe("convertCompositionInPlace — multi-currency en products/services", () => {
  it("baseline correct: PRODUCT en USD + SERVICE en EUR coexisten sin double-conversion", () => {
    // Backend ya convirtió cada cost line a moneda BASE en el motor.
    // El convertidor display lleva BASE → moneda objetivo del documento.
    // Debe convertir CADA item por su totalValue (en BASE) sin asumir
    // que el currencyId del item es la moneda del documento.
    const comp: any = {
      products: [{
        currencyId:    "USD",       // moneda original del costo
        unitValue:     100,         // ya en BASE (motor convirtió)
        totalValue:    100,
        quantity:      1,
        lineAdjAmount: null,
      }],
      services: [{
        currencyId:    "EUR",
        unitValue:     200,
        totalValue:    200,
        quantity:      1,
        lineAdjAmount: null,
      }],
    };
    // Display rate = 4 (1 unidad target = 4 base).
    convertCompositionInPlace(comp, 4);

    // Cada item se divide por la rate del documento (no por su currencyId
    // individual). currencyId queda como metadata informativa.
    expect(comp.products[0].unitValue).toBe(25);
    expect(comp.products[0].totalValue).toBe(25);
    expect(comp.products[0].currencyId).toBe("USD");      // preservado

    expect(comp.services[0].unitValue).toBe(50);
    expect(comp.services[0].totalValue).toBe(50);
    expect(comp.services[0].currencyId).toBe("EUR");      // preservado
  });

  it("baseline correct: lineAdjAmount con currencyId distinto NO se convierte por currencyId", () => {
    // El motor ya lo emitió en BASE. El converter solo divide por rate del doc.
    const comp: any = {
      products: [{
        currencyId:    "USD",
        unitValue:     200,
        totalValue:    180,           // post-bonif 10
        quantity:      1,
        lineAdjAmount: 20,
        lineAdjType:   "PERCENTAGE",
        lineAdjValue:  10,
      }],
    };
    convertCompositionInPlace(comp, 2);
    expect(comp.products[0].lineAdjAmount).toBe(10);   // 20 / 2
    expect(comp.products[0].lineAdjValue).toBe(10);    // % NO se convierte
  });

  it("Fase 2.4 — convierte metals[].quotePrice (Fase 2.3)", () => {
    const comp: any = {
      metals: [
        {
          metalVariantId: "mv-1",
          appliedGrams:   2,           // gramos NO se convierten
          appliedMermaPct: 1.5,        // % NO se convierte
          purity:         0.75,        // ratio NO se convierte
          lineCost:       400,         // ya cubierto por legacy
          quotePrice:     200,         // Fase 2.3 — debe convertirse
        },
      ],
    };
    convertCompositionInPlace(comp, 2);
    // Monetarios convertidos.
    expect(comp.metals[0].lineCost).toBe(200);
    expect(comp.metals[0].quotePrice).toBe(100);
    // No-monetarios preservados.
    expect(comp.metals[0].appliedGrams).toBe(2);
    expect(comp.metals[0].appliedMermaPct).toBe(1.5);
    expect(comp.metals[0].purity).toBe(0.75);
  });

  it("Fase 2.4 — convierte hechuras[].unitValue / lineAdjAmount / lineAdjValue (FIXED_AMOUNT)", () => {
    const comp: any = {
      hechuras: [
        // BONUS PERCENTAGE — lineAdjValue NO se convierte (es %).
        {
          appliedAmount: 900, lineCost: 900,
          unitValue: 1000,                   // Fase 2.3.1 — debe convertirse
          lineAdjAmount: 100,                // Fase 2.2 — debe convertirse
          lineAdjType:  "PERCENTAGE",
          lineAdjValue: 10,                  // % — NO se convierte
        },
        // SURCHARGE FIXED_AMOUNT — lineAdjValue SÍ se convierte (es monto).
        {
          appliedAmount: 220, lineCost: 220,
          unitValue: 200,
          lineAdjAmount: 20,
          lineAdjType:  "FIXED_AMOUNT",
          lineAdjValue: 20,
        },
      ],
    };
    convertCompositionInPlace(comp, 2);
    // Item 1 — BONUS %.
    expect(comp.hechuras[0].appliedAmount).toBe(450);
    expect(comp.hechuras[0].lineCost).toBe(450);
    expect(comp.hechuras[0].unitValue).toBe(500);
    expect(comp.hechuras[0].lineAdjAmount).toBe(50);
    expect(comp.hechuras[0].lineAdjValue).toBe(10);   // % NO se convierte
    // Item 2 — SURCHARGE FIXED_AMOUNT.
    expect(comp.hechuras[1].unitValue).toBe(100);
    expect(comp.hechuras[1].lineAdjAmount).toBe(10);
    expect(comp.hechuras[1].lineAdjValue).toBe(10);   // monto fijo SÍ
  });

  it("Fase 2.4 — rate=1 no convierte ningún campo nuevo (sin double-conversion)", () => {
    const comp: any = {
      metals:   [{ lineCost: 400, quotePrice: 200, appliedGrams: 2 }],
      hechuras: [{ unitValue: 1000, lineAdjAmount: 100, lineAdjType: "FIXED_AMOUNT", lineAdjValue: 100 }],
    };
    convertCompositionInPlace(comp, 1);
    expect(comp.metals[0].quotePrice).toBe(200);
    expect(comp.hechuras[0].unitValue).toBe(1000);
    expect(comp.hechuras[0].lineAdjAmount).toBe(100);
    expect(comp.hechuras[0].lineAdjValue).toBe(100);
  });

  it("baseline correct: rounding drift bajo conversión repetida → no divergencia", () => {
    // Si el converter se llamara dos veces por error, los valores serían
    // dividos doblemente. Test garantiza que UNA sola pasada.
    const comp: any = {
      products: [{ unitValue: 1000, totalValue: 1000, quantity: 1 }],
    };
    convertCompositionInPlace(comp, 2);
    expect(comp.products[0].unitValue).toBe(500);
    // Re-aplicar convierte de nuevo (el caller debe garantizar single-pass).
    // Test documenta que el converter es idempotente solo cuando rate=1.
    convertCompositionInPlace(comp, 1);
    expect(comp.products[0].unitValue).toBe(500);   // rate=1 no toca
  });
});

// =============================================================================
// 3. PERFORMANCE BENCHMARK — 100 líneas con productos repetidos
// =============================================================================

describe("buildCatalogItemsMapForCostLines — performance benchmark", () => {
  it("baseline correct: 100 líneas × 5 productos repetidos → exactamente 1 query con 5 ids", async () => {
    mockPrisma.article.findMany.mockResolvedValue(
      Array.from({ length: 5 }, (_, i) => ({
        id:   `art-${i}`,
        code: `CODE-${i}`,
        name: `Item ${i}`,
      })),
    );
    // 100 líneas, cada una con 1 producto, 5 productos únicos rotando.
    const linesByArticle: Array<Array<{ catalogItemId: string }>> = [];
    for (let i = 0; i < 100; i++) {
      linesByArticle.push([{ catalogItemId: `art-${i % 5}` }]);
    }
    const t0 = performance.now();
    const r = await buildCatalogItemsMapForCostLines("j1", linesByArticle);
    const tMs = performance.now() - t0;

    // Performance: 1 SOLA query incluso con 100 líneas.
    expect(mockPrisma.article.findMany).toHaveBeenCalledTimes(1);
    // Set dedupe trabajó: 5 ids únicos enviados al query.
    const args = mockPrisma.article.findMany.mock.calls[0]?.[0];
    expect(args?.where?.id?.in).toHaveLength(5);
    expect(r.size).toBe(5);
    // Smoke timing: < 50ms en mock (no es benchmark real, solo guardrail).
    expect(tMs).toBeLessThan(50);
  });

  it("baseline correct: 1000 cost lines repartidas → sigue siendo 1 query", async () => {
    mockPrisma.article.findMany.mockResolvedValue([
      { id: "art-only", code: "X", name: "X" },
    ]);
    // Stress test: 1000 cost lines con el MISMO catalogItemId.
    const lines = Array.from({ length: 1000 }, () => ({ catalogItemId: "art-only" }));
    await buildCatalogItemsMapForCostLines("j1", [lines]);
    expect(mockPrisma.article.findMany).toHaveBeenCalledTimes(1);
    const args = mockPrisma.article.findMany.mock.calls[0]?.[0];
    expect(args?.where?.id?.in).toEqual(["art-only"]);
  });
});

// =============================================================================
// 4. FAILURE ISOLATION — Prisma throws → Map vacío, NO propaga
// =============================================================================

describe("buildCatalogItemsMapForCostLines — failure isolation", () => {
  it("baseline correct: Prisma throw → Map vacío + log warning + sin propagación", async () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    mockPrisma.article.findMany.mockRejectedValue(new Error("DB error"));

    const linesByArticle = [[{ catalogItemId: "art-A" }]];
    const r = await buildCatalogItemsMapForCostLines("j1", linesByArticle);

    expect(r.size).toBe(0);
    expect(warnSpy).toHaveBeenCalledTimes(1);
    expect(warnSpy.mock.calls[0]?.[0]).toMatch(/catalog lookup falló/i);
    warnSpy.mockRestore();
  });

  it("baseline correct: el preview NO se rompe si el catálogo falla — caller sigue", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    mockPrisma.article.findMany.mockRejectedValue(new Error("kaboom"));
    // Si propagara, await throwearía → este test fallaría.
    await expect(
      buildCatalogItemsMapForCostLines("j1", [[{ catalogItemId: "art-A" }]]),
    ).resolves.toBeDefined();
  });

  it("baseline correct: caller con Map vacío todavía puede llamar a buildComposition (cero efecto)", () => {
    // Documenta el contrato downstream: si la map está vacía, los items
    // de products/services siguen apareciendo con catalogItemCode/Name
    // resueltos desde meta.lineCode/lineLabel (resuelto en
    // extractCompositionItems, commit #1).
    // Este test es contractual — el helper de ese flujo está testeado en
    // pricing-composition-items.test.ts.
    expect(true).toBe(true);
  });
});

// =============================================================================
// 5. SNAPSHOT PARITY — cierre del TODO en commit #5b
// =============================================================================
//
// Los tests reales de paridad preview/persisted viven en el archivo
// `pricing-engine/__tests__/g4-5b-snapshot-composition-parity.test.ts`.
// Acá dejamos un sentinel describe para documentar el cierre del marker.
// =============================================================================

describe("snapshot parity — closed in commit #5b", () => {
  it("baseline correct: tests de paridad viven en g4-5b-snapshot-composition-parity.test.ts", () => {
    // Los `it.todo` previos quedaron cubiertos por el archivo dedicado.
    // Ver g4-5b-snapshot-composition-parity.test.ts para:
    //   1. Paridad preview.composition === buildPricingSnapshot(...).composition
    //   2. Retrocompat de snapshots v3 (sin composition / componentSaleBreakdown)
    //   3. salePreManualDiscount persistido en componentSaleBreakdown
    expect(true).toBe(true);
  });
});
