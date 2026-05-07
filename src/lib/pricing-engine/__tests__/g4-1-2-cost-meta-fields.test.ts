// src/lib/pricing-engine/__tests__/g4-1-2-cost-meta-fields.test.ts
// =============================================================================
// FASE F1.3 G4.1.2 — verifica los 4 campos nuevos en step.meta del motor cost:
//   · costLineId       — estable, persistente, snapshot-safe (de ArticleCostLine.id)
//   · catalogItemId    — solo PRODUCT/SERVICE
//   · affectsStock     — solo si está definido (semánticamente sensible)
//   · lineAdjAmount    — monto absoluto del ajuste, computado por motor
//
// Reglas verificadas:
//   · Cuando line.id viene → step.meta.costLineId presente.
//   · Cuando line.catalogItemId viene → step.meta.catalogItemId presente.
//   · Cuando line.affectsStock=true/false → emite. Cuando undefined → NO emite.
//   · lineAdjAmount = preAdjValue - postAdjValue (positivo = BONUS, neg = SURCHARGE).
//   · Sin adjustment → no emite lineAdjAmount.
//   · El motor NO recalcula valores comerciales — solo agrega meta.
// =============================================================================

import { describe, it, expect, vi, beforeEach } from "vitest";
import { Prisma } from "@prisma/client";

// Mock Prisma — no necesitamos DB real para PRODUCT/SERVICE/HECHURA
const mockPrisma = vi.hoisted(() => ({
  currency:     { findFirst: vi.fn(), findUnique: vi.fn() },
  metalQuote:   { findFirst: vi.fn(), findMany:   vi.fn() },
  metalVariant: { findFirst: vi.fn(), findMany:   vi.fn() },
  jewelry:      { findUnique: vi.fn() },
  $transaction: vi.fn(),
}));
vi.mock("../../prisma.js", () => ({ prisma: mockPrisma }));

import { calculateCostFromLines } from "../pricing-engine.cost.js";

const D = Prisma.Decimal;

beforeEach(() => {
  vi.clearAllMocks();
  // Currency base
  mockPrisma.currency.findFirst.mockResolvedValue({ id: "ARS-base" });
});

// =============================================================================
// 1. costLineId — estable y snapshot-safe
// =============================================================================

describe("G4.1.2 — costLineId en step.meta", () => {
  it("baseline correct: line.id se propaga a step.meta.costLineId", async () => {
    const lines = [
      {
        id:        "cl-product-001",
        type:      "PRODUCT",
        label:     "Cadenita",
        quantity:  1,
        unitValue: 100,
      },
    ];
    const r = await calculateCostFromLines("j1", lines as any);
    const productStep = r.steps.find((s: any) => s.key === "COST_LINES_PRODUCT");
    expect(productStep).toBeDefined();
    expect((productStep as any)?.meta?.costLineId).toBe("cl-product-001");
  });

  it("baseline correct: 3 líneas con ids distintos → 3 costLineId distintos", async () => {
    const lines = [
      { id: "cl-A", type: "PRODUCT", quantity: 1, unitValue: 100 },
      { id: "cl-B", type: "PRODUCT", quantity: 1, unitValue: 200 },
      { id: "cl-C", type: "SERVICE", quantity: 1, unitValue: 50 },
    ];
    const r = await calculateCostFromLines("j1", lines as any);
    const ids = r.steps
      .filter((s: any) => s.key.startsWith("COST_LINES_"))
      .map((s: any) => s.meta?.costLineId)
      .filter(Boolean);
    expect(ids).toEqual(["cl-A", "cl-B", "cl-C"]);
  });

  it("baseline correct: sin id (línea sintética/extraCostLines de combo), no emite costLineId", async () => {
    const lines = [
      // Sin `id` — caso combo / extraCostLines
      { type: "PRODUCT", quantity: 1, unitValue: 100 },
    ];
    const r = await calculateCostFromLines("j1", lines as any);
    const productStep = r.steps.find((s: any) => s.key === "COST_LINES_PRODUCT");
    expect(productStep).toBeDefined();
    expect((productStep as any)?.meta?.costLineId).toBeUndefined();
  });
});

// =============================================================================
// 2. catalogItemId — solo si viene
// =============================================================================

describe("G4.1.2 — catalogItemId en step.meta", () => {
  it("baseline correct: line.catalogItemId se propaga a step.meta", async () => {
    const lines = [
      {
        id:            "cl-1",
        type:          "PRODUCT",
        catalogItemId: "art-zafiro-01",
        quantity:      1,
        unitValue:     200,
      },
    ];
    const r = await calculateCostFromLines("j1", lines as any);
    const productStep = r.steps.find((s: any) => s.key === "COST_LINES_PRODUCT");
    expect((productStep as any)?.meta?.catalogItemId).toBe("art-zafiro-01");
  });

  it("baseline correct: sin catalogItemId, no emite el campo", async () => {
    const lines = [
      { id: "cl-1", type: "PRODUCT", quantity: 1, unitValue: 100 },
    ];
    const r = await calculateCostFromLines("j1", lines as any);
    const productStep = r.steps.find((s: any) => s.key === "COST_LINES_PRODUCT");
    expect((productStep as any)?.meta?.catalogItemId).toBeUndefined();
  });
});

// =============================================================================
// 3. affectsStock — semánticamente sensible (undefined ≠ false)
// =============================================================================

describe("G4.1.2 — affectsStock en step.meta", () => {
  it("baseline correct: affectsStock=true se emite tal cual", async () => {
    const lines = [
      {
        id:           "cl-1",
        type:         "PRODUCT",
        affectsStock: true,
        quantity:     1,
        unitValue:    100,
      },
    ];
    const r = await calculateCostFromLines("j1", lines as any);
    const productStep = r.steps.find((s: any) => s.key === "COST_LINES_PRODUCT");
    expect((productStep as any)?.meta?.affectsStock).toBe(true);
  });

  it("baseline correct: affectsStock=false se emite tal cual (valor explícito conocido)", async () => {
    const lines = [
      {
        id:           "cl-1",
        type:         "PRODUCT",
        affectsStock: false,
        quantity:     1,
        unitValue:    100,
      },
    ];
    const r = await calculateCostFromLines("j1", lines as any);
    const productStep = r.steps.find((s: any) => s.key === "COST_LINES_PRODUCT");
    expect((productStep as any)?.meta?.affectsStock).toBe(false);
  });

  it("baseline correct: affectsStock undefined → NO emite (semánticamente sensible)", async () => {
    const lines = [
      // Sin `affectsStock` — desconocido. NO debe asumir false.
      { id: "cl-1", type: "PRODUCT", quantity: 1, unitValue: 100 },
    ];
    const r = await calculateCostFromLines("j1", lines as any);
    const productStep = r.steps.find((s: any) => s.key === "COST_LINES_PRODUCT");
    // El campo simplemente no está en el meta — el frontend lo trata como null.
    expect("affectsStock" in ((productStep as any)?.meta ?? {})).toBe(false);
  });
});

// =============================================================================
// 4. lineAdjAmount — monto absoluto del ajuste, computado por motor
// =============================================================================

describe("G4.1.2 — lineAdjAmount computado por motor", () => {
  it("baseline correct: BONUS PERCENTAGE 10% sobre 100 → lineAdjAmount=10 (positivo = reducción)", async () => {
    const lines = [
      {
        id:           "cl-1",
        type:         "PRODUCT",
        quantity:     1,
        unitValue:    100,
        lineAdjKind:  "BONUS",
        lineAdjType:  "PERCENTAGE",
        lineAdjValue: 10,
      },
    ];
    const r = await calculateCostFromLines("j1", lines as any);
    const productStep = r.steps.find((s: any) => s.key === "COST_LINES_PRODUCT");
    // Pre-ajuste: 1 × 100 = 100. Post-ajuste BONUS 10%: 90. Delta: 10.
    expect((productStep as any)?.meta?.lineAdjAmount).toBe("10");
    // Verificación cruzada: step.value debe ser el post-ajuste.
    expect(Number((productStep as any)?.value)).toBe(90);
  });

  it("baseline correct: SURCHARGE PERCENTAGE 15% sobre 200 → lineAdjAmount=-30 (negativo = aumento)", async () => {
    const lines = [
      {
        id:           "cl-1",
        type:         "SERVICE",
        quantity:     1,
        unitValue:    200,
        lineAdjKind:  "SURCHARGE",
        lineAdjType:  "PERCENTAGE",
        lineAdjValue: 15,
      },
    ];
    const r = await calculateCostFromLines("j1", lines as any);
    const serviceStep = r.steps.find((s: any) => s.key === "COST_LINES_SERVICE");
    // Pre: 200. Post SURCHARGE 15%: 230. Delta: 200 - 230 = -30 (negativo).
    expect((serviceStep as any)?.meta?.lineAdjAmount).toBe("-30");
    expect(Number((serviceStep as any)?.value)).toBe(230);
  });

  it("baseline correct: BONUS FIXED_AMOUNT 25 → lineAdjAmount=25", async () => {
    const lines = [
      {
        id:           "cl-1",
        type:         "PRODUCT",
        quantity:     2,
        unitValue:    50,
        lineAdjKind:  "BONUS",
        lineAdjType:  "FIXED_AMOUNT",
        lineAdjValue: 25,
      },
    ];
    const r = await calculateCostFromLines("j1", lines as any);
    const productStep = r.steps.find((s: any) => s.key === "COST_LINES_PRODUCT");
    // Pre: 2 × 50 = 100. Post BONUS −25: 75. Delta: 25.
    expect((productStep as any)?.meta?.lineAdjAmount).toBe("25");
    expect(Number((productStep as any)?.value)).toBe(75);
  });

  it("baseline correct: sin adjustment, no emite lineAdjAmount", async () => {
    const lines = [
      { id: "cl-1", type: "PRODUCT", quantity: 1, unitValue: 100 },
    ];
    const r = await calculateCostFromLines("j1", lines as any);
    const productStep = r.steps.find((s: any) => s.key === "COST_LINES_PRODUCT");
    expect("lineAdjAmount" in ((productStep as any)?.meta ?? {})).toBe(false);
  });

  it("baseline correct: ajuste con lineAdjValue=0 (no-op real) sigue emitiendo lineAdjAmount=0", async () => {
    // Edge case: el operador puede setear adj kind/type pero value=0 (visualmente
    // como "Bonif. 0%"). El motor lo procesa y la diferencia queda en 0.
    const lines = [
      {
        id:           "cl-1",
        type:         "PRODUCT",
        quantity:     1,
        unitValue:    100,
        lineAdjKind:  "BONUS",
        lineAdjType:  "PERCENTAGE",
        lineAdjValue: 0,
      },
    ];
    const r = await calculateCostFromLines("j1", lines as any);
    const productStep = r.steps.find((s: any) => s.key === "COST_LINES_PRODUCT");
    expect((productStep as any)?.meta?.lineAdjAmount).toBe("0");
  });
});

// =============================================================================
// 5. Cero impacto en valores numéricos del motor
// =============================================================================

describe("G4.1.2 — cero impacto numérico (regresión)", () => {
  it("baseline correct: step.value sigue siendo qty × unit POST-ajuste (sin cambio)", async () => {
    const lines = [
      {
        id:           "cl-1",
        type:         "PRODUCT",
        quantity:     3,
        unitValue:    50,
        lineAdjKind:  "BONUS",
        lineAdjType:  "PERCENTAGE",
        lineAdjValue: 20,
      },
    ];
    const r = await calculateCostFromLines("j1", lines as any);
    const productStep = r.steps.find((s: any) => s.key === "COST_LINES_PRODUCT");
    // 3 × 50 = 150 base. BONUS 20% = 30. Post: 120.
    expect(Number((productStep as any)?.value)).toBe(120);
    expect(Number(r.value ?? 0)).toBe(120);
    expect(Number(r.hechuraCost ?? 0)).toBe(120);  // PRODUCT bucketea en hechuraTotal (motor interno)
    expect(Number(r.metalCost ?? 0)).toBe(0);
  });

  it("baseline correct: meta.qty/unitValue/lineAdjKind preservados (G4.1.1 baseline)", async () => {
    const lines = [
      {
        id:           "cl-1",
        type:         "PRODUCT",
        label:        "Test",
        quantity:     2,
        unitValue:    50,
        lineAdjKind:  "BONUS",
        lineAdjType:  "PERCENTAGE",
        lineAdjValue: 10,
      },
    ];
    const r = await calculateCostFromLines("j1", lines as any);
    const productStep = r.steps.find((s: any) => s.key === "COST_LINES_PRODUCT");
    const meta = (productStep as any)?.meta;
    // Campos viejos siguen ahí (cero regresión).
    expect(meta?.qty).toBe("2");
    expect(meta?.unitValue).toBe("50");
    expect(meta?.lineLabel).toBe("Test");
    expect(meta?.lineAdjKind).toBe("BONUS");
    expect(meta?.lineAdjType).toBe("PERCENTAGE");
    expect(meta?.lineAdjValue).toBe(10);
    // Campos nuevos también.
    expect(meta?.costLineId).toBe("cl-1");
    expect(meta?.lineAdjAmount).toBe("10");  // = (2×50) × 10% = 10
  });
});

// =============================================================================
// 6. extractCompositionItems consume correctamente los nuevos campos
// =============================================================================

describe("G4.1.2 — integración con extractCompositionItems (G4.1.1)", async () => {
  it("baseline correct: ciclo completo motor → buildComposition pasa los 4 campos al item", async () => {
    const { extractCompositionItems } = await import("../../pricing-composition.js");
    const lines = [
      {
        id:            "cl-99",
        type:          "PRODUCT",
        label:         "Zafiro",
        catalogItemId: "art-zaf-01",
        affectsStock:  true,
        quantity:      1,
        unitValue:     200,
        lineAdjKind:   "BONUS",
        lineAdjType:   "PERCENTAGE",
        lineAdjValue:  5,
      },
    ];
    const r = await calculateCostFromLines("j1", lines as any);
    const items = extractCompositionItems(r.steps as any, "COST_LINES_PRODUCT");
    expect(items).toHaveLength(1);
    expect(items[0].costLineId).toBe("cl-99");
    expect(items[0].catalogItemId).toBe("art-zaf-01");
    expect(items[0].affectsStock).toBe(true);
    expect(items[0].lineAdjKind).toBe("BONUS");
    expect(items[0].lineAdjType).toBe("PERCENTAGE");
    expect(items[0].lineAdjValue).toBe(5);
    expect(items[0].lineAdjAmount).toBe(10);  // (1×200) × 5% = 10
    expect(items[0].totalValue).toBe(190);    // 200 - 10 = 190
  });
});
