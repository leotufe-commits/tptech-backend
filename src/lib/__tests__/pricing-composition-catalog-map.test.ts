// src/lib/__tests__/pricing-composition-catalog-map.test.ts
// =============================================================================
// FASE F1.3 G4.1.3 — tests para buildCatalogItemsMapForSteps.
//
// Reglas verificadas:
//   · UNA sola query Prisma por request (batch unificado, no N+1).
//   · Dedupe de ids repetidos antes de query.
//   · Filtro: solo COST_LINES_PRODUCT/SERVICE con status="ok".
//   · Failure-safety: si Prisma throw, devuelve Map vacío (NO rompe).
//   · Tenant scope: jewelryId + deletedAt:null en where.
//   · Steps null/empty/sin catalogItemId → no ejecuta query.
//   · Convertidor de moneda extiende composition.products/services.
//   · qty × unitValue ≠ totalValue cuando hay conversión (semántica preservada).
// =============================================================================

import { describe, it, expect, vi, beforeEach } from "vitest";
import { Prisma } from "@prisma/client";

// Mock prisma.article.findMany — capturable
const mockPrisma = vi.hoisted(() => ({
  article: { findMany: vi.fn() },
}));
vi.mock("../prisma.js", () => ({ prisma: mockPrisma }));

import {
  buildCatalogItemsMapForSteps,
} from "../pricing-composition.js";
import { convertCompositionInPlace } from "../pricing-currency-display.js";
import type { PricingStep } from "../pricing-engine/pricing-engine.js";

const D = Prisma.Decimal;

function makeStep(overrides: Partial<PricingStep> & { meta?: any } = {}): PricingStep {
  return {
    key:    "COST_LINES_PRODUCT",
    label:  "Producto Test",
    status: "ok",
    value:  new D(100),
    meta:   {},
    ...overrides,
  } as PricingStep;
}

beforeEach(() => {
  vi.clearAllMocks();
});

// =============================================================================
// 1. Edge cases — no query si no hay nada que buscar
// =============================================================================

describe("buildCatalogItemsMapForSteps — edge cases", () => {
  it("baseline correct: steps null → Map vacío + 0 queries", async () => {
    const r = await buildCatalogItemsMapForSteps("j1", null);
    expect(r.size).toBe(0);
    expect(mockPrisma.article.findMany).not.toHaveBeenCalled();
  });

  it("baseline correct: steps undefined → Map vacío + 0 queries", async () => {
    const r = await buildCatalogItemsMapForSteps("j1", undefined);
    expect(r.size).toBe(0);
    expect(mockPrisma.article.findMany).not.toHaveBeenCalled();
  });

  it("baseline correct: array vacío → Map vacío + 0 queries", async () => {
    const r = await buildCatalogItemsMapForSteps("j1", []);
    expect(r.size).toBe(0);
    expect(mockPrisma.article.findMany).not.toHaveBeenCalled();
  });

  it("baseline correct: jewelryId vacío → Map vacío + 0 queries (defensivo)", async () => {
    const steps = [makeStep({ meta: { catalogItemId: "art-1" } })];
    const r = await buildCatalogItemsMapForSteps("", steps);
    expect(r.size).toBe(0);
    expect(mockPrisma.article.findMany).not.toHaveBeenCalled();
  });

  it("baseline correct: steps solo METAL/HECHURA (sin PRODUCT/SERVICE) → 0 queries", async () => {
    const steps = [
      makeStep({ key: "COST_LINES_METAL",   meta: { catalogItemId: "ignored" } }),
      makeStep({ key: "COST_LINES_HECHURA", meta: {} }),
    ];
    const r = await buildCatalogItemsMapForSteps("j1", steps);
    expect(r.size).toBe(0);
    expect(mockPrisma.article.findMany).not.toHaveBeenCalled();
  });

  it("baseline correct: steps PRODUCT/SERVICE sin catalogItemId → 0 queries", async () => {
    const steps = [
      makeStep({ key: "COST_LINES_PRODUCT", meta: { qty: "1", unitValue: "100" } }),
      makeStep({ key: "COST_LINES_SERVICE", meta: { qty: "1", unitValue: "50" } }),
    ];
    const r = await buildCatalogItemsMapForSteps("j1", steps);
    expect(r.size).toBe(0);
    expect(mockPrisma.article.findMany).not.toHaveBeenCalled();
  });

  it("baseline correct: status != 'ok' → no incluye en query", async () => {
    const steps = [
      makeStep({ status: "skipped", meta: { catalogItemId: "art-skipped" } }),
      makeStep({ status: "missing", meta: { catalogItemId: "art-missing" }, value: null }),
    ];
    const r = await buildCatalogItemsMapForSteps("j1", steps);
    expect(r.size).toBe(0);
    expect(mockPrisma.article.findMany).not.toHaveBeenCalled();
  });
});

// =============================================================================
// 2. Query única + dedupe
// =============================================================================

describe("buildCatalogItemsMapForSteps — query única + dedupe", () => {
  it("baseline correct: 1 query batch para N catalogItemIds únicos", async () => {
    mockPrisma.article.findMany.mockResolvedValue([
      { id: "art-A", code: "CODE-A", name: "Item A" },
      { id: "art-B", code: "CODE-B", name: "Item B" },
      { id: "art-C", code: "CODE-C", name: "Item C" },
    ]);
    const steps = [
      makeStep({ key: "COST_LINES_PRODUCT", meta: { catalogItemId: "art-A" } }),
      makeStep({ key: "COST_LINES_PRODUCT", meta: { catalogItemId: "art-B" } }),
      makeStep({ key: "COST_LINES_SERVICE", meta: { catalogItemId: "art-C" } }),
    ];
    const r = await buildCatalogItemsMapForSteps("j1", steps);

    expect(mockPrisma.article.findMany).toHaveBeenCalledTimes(1);
    expect(r.size).toBe(3);
    expect(r.get("art-A")?.code).toBe("CODE-A");
    expect(r.get("art-B")?.name).toBe("Item B");
    expect(r.get("art-C")?.code).toBe("CODE-C");
  });

  it("baseline correct: ids repetidos se deduplican antes de query", async () => {
    mockPrisma.article.findMany.mockResolvedValue([
      { id: "art-A", code: "CODE-A", name: "Item A" },
    ]);
    const steps = [
      makeStep({ key: "COST_LINES_PRODUCT", meta: { catalogItemId: "art-A" } }),
      makeStep({ key: "COST_LINES_PRODUCT", meta: { catalogItemId: "art-A" } }),
      makeStep({ key: "COST_LINES_SERVICE", meta: { catalogItemId: "art-A" } }),
    ];
    await buildCatalogItemsMapForSteps("j1", steps);

    const callArgs = mockPrisma.article.findMany.mock.calls[0]?.[0];
    expect(callArgs?.where?.id?.in).toHaveLength(1);
    expect(callArgs?.where?.id?.in).toEqual(["art-A"]);
  });

  it("baseline correct: query incluye jewelryId + deletedAt:null (multi-tenancy + soft delete)", async () => {
    mockPrisma.article.findMany.mockResolvedValue([]);
    const steps = [makeStep({ meta: { catalogItemId: "art-1" } })];
    await buildCatalogItemsMapForSteps("j1-tenant", steps);

    const callArgs = mockPrisma.article.findMany.mock.calls[0]?.[0];
    expect(callArgs?.where?.jewelryId).toBe("j1-tenant");
    expect(callArgs?.where?.deletedAt).toBeNull();
  });

  it("baseline correct: id que existe en steps pero NO en DB → no aparece en map", async () => {
    mockPrisma.article.findMany.mockResolvedValue([
      { id: "art-existe", code: "X", name: "Existe" },
      // art-eliminado NO viene en el response (filtrado por deletedAt o ya borrado)
    ]);
    const steps = [
      makeStep({ key: "COST_LINES_PRODUCT", meta: { catalogItemId: "art-existe" } }),
      makeStep({ key: "COST_LINES_PRODUCT", meta: { catalogItemId: "art-eliminado" } }),
    ];
    const r = await buildCatalogItemsMapForSteps("j1", steps);

    expect(r.size).toBe(1);
    expect(r.has("art-existe")).toBe(true);
    expect(r.has("art-eliminado")).toBe(false);
  });
});

// =============================================================================
// 3. Failure-safety — Prisma throws → Map vacío
// =============================================================================

describe("buildCatalogItemsMapForSteps — failure-safety", () => {
  it("baseline correct: Prisma throws → Map vacío (NO rompe el flow)", async () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    mockPrisma.article.findMany.mockRejectedValue(new Error("DB connection lost"));

    const steps = [makeStep({ meta: { catalogItemId: "art-1" } })];
    const r = await buildCatalogItemsMapForSteps("j1", steps);

    expect(r.size).toBe(0);
    expect(warnSpy).toHaveBeenCalledTimes(1);
    expect(warnSpy.mock.calls[0]?.[0]).toMatch(/catalog lookup falló/i);
    warnSpy.mockRestore();
  });

  it("baseline correct: aún tras failure, no propaga el error al caller", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    mockPrisma.article.findMany.mockRejectedValue(new Error("kaboom"));

    const steps = [makeStep({ meta: { catalogItemId: "art-1" } })];
    // Si propagara, el await throwearía y este test fallaría.
    await expect(buildCatalogItemsMapForSteps("j1", steps)).resolves.toBeDefined();
  });
});

// =============================================================================
// 4. Currency converter extiende a products/services
// =============================================================================

describe("convertCompositionInPlace — products/services", () => {
  it("baseline correct: convierte unitValue/totalValue/lineAdjAmount de products", () => {
    const comp: any = {
      products: [
        {
          unitValue:     200,
          totalValue:    400,
          quantity:      2,
          lineAdjAmount: 50,
          lineAdjType:   "FIXED_AMOUNT",
          lineAdjValue:  50,
        },
      ],
      services: [],
    };
    convertCompositionInPlace(comp, 2);  // 1 USD = 2 base

    // Dividen por rate → moneda objetivo.
    expect(comp.products[0].unitValue).toBe(100);
    expect(comp.products[0].totalValue).toBe(200);
    expect(comp.products[0].lineAdjAmount).toBe(25);
    expect(comp.products[0].lineAdjValue).toBe(25);   // FIXED_AMOUNT → convertido
    // NO se convierten:
    expect(comp.products[0].quantity).toBe(2);
    expect(comp.products[0].lineAdjType).toBe("FIXED_AMOUNT");
  });

  it("baseline correct: lineAdjValue NO se convierte cuando type=PERCENTAGE", () => {
    const comp: any = {
      products: [
        {
          unitValue:     200,
          totalValue:    400,
          quantity:      2,
          lineAdjAmount: 40,
          lineAdjType:   "PERCENTAGE",
          lineAdjValue:  10,                  // 10% — porcentaje, NO moneda
        },
      ],
    };
    convertCompositionInPlace(comp, 2);

    expect(comp.products[0].unitValue).toBe(100);     // convertido
    expect(comp.products[0].lineAdjAmount).toBe(20);  // convertido
    expect(comp.products[0].lineAdjValue).toBe(10);   // NO convertido (es %)
  });

  it("baseline correct: aplica también a services (mismo treatment)", () => {
    const comp: any = {
      services: [
        { unitValue: 100, totalValue: 100, quantity: 1, lineAdjAmount: null },
        { unitValue: 200, totalValue: 200, quantity: 1, lineAdjAmount: null },
      ],
    };
    convertCompositionInPlace(comp, 4);

    expect(comp.services[0].unitValue).toBe(25);
    expect(comp.services[1].unitValue).toBe(50);
  });

  it("baseline correct: rate=1 NO toca nada", () => {
    const comp: any = {
      products: [{ unitValue: 100, totalValue: 200, quantity: 2 }],
    };
    convertCompositionInPlace(comp, 1);
    expect(comp.products[0].unitValue).toBe(100);
    expect(comp.products[0].totalValue).toBe(200);
  });

  it("baseline correct: composition sin products/services no rompe (legacy backward-compat)", () => {
    const comp: any = {
      metal:   null,
      hechura: { originalAmount: 100, appliedAmount: 100 },
      taxes:   [],
      // sin products / services
    };
    expect(() => convertCompositionInPlace(comp, 2)).not.toThrow();
    // hechura sí se convierte (legacy path)
    expect(comp.hechura.appliedAmount).toBe(50);
  });

  it("baseline correct: products array vacío → no crash", () => {
    const comp: any = { products: [], services: [] };
    expect(() => convertCompositionInPlace(comp, 2)).not.toThrow();
  });
});

// =============================================================================
// 5. Coherencia qty × unitValue vs totalValue con conversión (regla #3 usuario)
// =============================================================================

describe("convertCompositionInPlace — coherencia qty × unitValue ≠ totalValue con conversión", () => {
  it("baseline correct: post-conversión, totalValue = unitValue × quantity en moneda objetivo", () => {
    // Caso típico: PRODUCT con quantity=2, unitValue=200 base.
    // Backend emit: totalValue=400 (= 2×200, motor lo computa).
    // Conversión a USD (rate=4): unitValue=50, totalValue=100.
    // Coherencia preservada: 50 × 2 = 100. ✓
    const comp: any = {
      products: [{
        quantity:    2,
        unitValue:   200,
        totalValue:  400,
      }],
    };
    convertCompositionInPlace(comp, 4);
    const p = comp.products[0];
    expect(p.unitValue * p.quantity).toBe(p.totalValue);
  });

  it("baseline correct: con adjustment, totalValue ≠ unitValue × quantity (motor aplicó adj)", () => {
    // Caso: PRODUCT con BONUS −10%.
    // qty=1 unit=100 → pre-adj 100 → post-adj 90.
    // Backend emit: totalValue=90 (post-ajuste, motor lo computa).
    // qty × unitValue = 100, NO == totalValue=90. CORRECTO — el adj cambió el total.
    const comp: any = {
      products: [{
        quantity:      1,
        unitValue:     100,
        totalValue:    90,             // post-ajuste BONUS
        lineAdjType:   "PERCENTAGE",
        lineAdjValue:  10,
        lineAdjAmount: 10,             // delta = pre - post
      }],
    };
    convertCompositionInPlace(comp, 1);
    const p = comp.products[0];
    expect(p.totalValue).toBe(90);
    expect(p.unitValue * p.quantity).toBe(100);   // ≠ totalValue — esperado
    // La diferencia es exactamente el lineAdjAmount.
    expect((p.unitValue * p.quantity) - p.totalValue).toBe(p.lineAdjAmount);
  });
});
