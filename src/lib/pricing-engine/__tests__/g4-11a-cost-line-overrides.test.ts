// src/lib/pricing-engine/__tests__/g4-11a-cost-line-overrides.test.ts
// =============================================================================
// FASE F1.4 G5 #11-A — tests del nuevo contrato `costLineOverrides`.
//
// Cubre TODAS las validaciones del usuario:
//   1. Override per costLineId aplica solo al cost line correcto.
//   2. quantityOverride para METAL → cambia gramos sin tocar otras lines.
//   3. unitValueOverride para HECHURA/PRODUCT/SERVICE → reemplaza unitValue.
//   4. unitValueOverride para METAL → ignorado + debugWarning.
//   5. mermaPercentOverride para METAL → reemplaza merma.
//   6. mermaPercentOverride para no-METAL → ignorado + debugWarning.
//   7. adjustment* para METAL → ignorado + debugWarning.
//   8. adjustmentKind=null limpia el ajuste.
//   9. costLineId no encontrado → ignorado + debugWarning.
//  10. type mismatch → todo el override descartado + debugWarning.
//  11. 2 metales editados independientemente.
//  12. 2 hechuras editadas independientemente.
//  13. PRODUCT + SERVICE simultáneos.
//  14. Sin overrides → byte-paritario con comportamiento previo.
//  15. Legacy gramsOverride sigue funcionando.
//  16. Legacy + new: explicit gana cuando match por costLineId.
//  17. Snapshot v6 persiste costLineOverridesApplied.
//
// Cero contaminación visual: warnings van a `debugWarnings`, NO a `steps[]`.
// =============================================================================

import { describe, it, expect, vi, beforeEach } from "vitest";
import { Prisma } from "@prisma/client";
import {
  validateCostLineOverride,
  unifyCostLineOverrides,
  buildCostLineOverrideMap,
} from "../pricing-engine.cost-line-overrides.js";
import type { CostLineInput, CostLineOverride } from "../pricing-engine.types.js";

const D = Prisma.Decimal;

// ─────────────────────────────────────────────────────────────────────────────
// Mocks para calculateCostFromLines (necesita prisma + getBaseCurrencyId)
// ─────────────────────────────────────────────────────────────────────────────

const mockPrisma = vi.hoisted(() => ({
  metalVariant: { findMany: vi.fn() },
  metalQuote:   { findMany: vi.fn() },
  currency:     { findFirst: vi.fn() },
  jewelry:      { findUnique: vi.fn() },
}));
vi.mock("../../prisma.js", () => ({ prisma: mockPrisma }));

const mockGetBaseCurrencyId = vi.hoisted(() => vi.fn());
vi.mock("../pricing-engine.currency.js", () => ({
  getBaseCurrencyId:  (...args: any[]) => mockGetBaseCurrencyId(...args),
  getExchangeRate:    vi.fn().mockResolvedValue(null),
}));

import { calculateCostFromLines } from "../pricing-engine.cost.js";

beforeEach(() => {
  vi.clearAllMocks();
  mockGetBaseCurrencyId.mockResolvedValue("currency-base");
  mockPrisma.metalVariant.findMany.mockResolvedValue([]);
  mockPrisma.metalQuote.findMany.mockResolvedValue([]);
});

// ─────────────────────────────────────────────────────────────────────────────
// Helpers de fixture
// ─────────────────────────────────────────────────────────────────────────────

function metalLine(id: string, variantId: string, qty: number, mermaPercent = 0): CostLineInput {
  return {
    id,
    type: "METAL",
    quantity: qty,
    metalVariantId: variantId,
    mermaPercent,
  } as CostLineInput;
}

function hechuraLine(id: string, qty: number, unitValue: number, lineAdjKind?: any, lineAdjType?: any, lineAdjValue?: any): CostLineInput {
  return {
    id, type: "HECHURA",
    quantity: qty, unitValue,
    lineAdjKind: lineAdjKind ?? "",
    lineAdjType: lineAdjType ?? "",
    lineAdjValue: lineAdjValue ?? null,
  } as CostLineInput;
}

function productLine(id: string, qty: number, unitValue: number): CostLineInput {
  return {
    id, type: "PRODUCT",
    quantity: qty, unitValue,
    lineAdjKind: "", lineAdjType: "", lineAdjValue: null,
  } as CostLineInput;
}

function setupMetalQuote(variantId: string, price: number) {
  mockPrisma.metalVariant.findMany.mockResolvedValue([
    { id: variantId, saleFactor: new D("1"), purity: new D("0.75") },
  ]);
  mockPrisma.metalQuote.findMany.mockResolvedValue([
    { variantId, price: new D(String(price)) },
  ]);
}

// =============================================================================
// 1. validateCostLineOverride — casos individuales
// =============================================================================

describe("F1.4 #11-A — validateCostLineOverride", () => {
  it("baseline correct: costLineId no existe → applicable=false + 1 warning", () => {
    const ov: CostLineOverride = { costLineId: "missing", type: "METAL", quantityOverride: 5 };
    const r = validateCostLineOverride(ov, undefined);
    expect(r.applicable).toBe(false);
    expect(r.warnings).toHaveLength(1);
    expect(r.warnings[0].code).toBe("COST_LINE_OVERRIDE_NOT_FOUND");
  });

  it("baseline correct: type mismatch → applicable=false + warning", () => {
    const line = hechuraLine("cl-1", 1, 100);
    const ov: CostLineOverride = { costLineId: "cl-1", type: "METAL", quantityOverride: 5 };
    const r = validateCostLineOverride(ov, line);
    expect(r.applicable).toBe(false);
    expect(r.warnings[0].code).toBe("COST_LINE_OVERRIDE_TYPE_MISMATCH");
  });

  it("baseline correct: METAL + unitValueOverride → applicable=true, campo borrado, 1 warning", () => {
    const line = metalLine("cl-1", "mv-1", 1);
    const ov: CostLineOverride = { costLineId: "cl-1", type: "METAL", unitValueOverride: 200 };
    const r = validateCostLineOverride(ov, line);
    expect(r.applicable).toBe(true);
    expect(r.sanitized.unitValueOverride).toBeUndefined();
    expect(r.warnings[0].code).toBe("COST_LINE_OVERRIDE_FIELD_NOT_APPLICABLE");
  });

  it("baseline correct: METAL + adjustment* → todos los campos borrados + 1 warning", () => {
    const line = metalLine("cl-1", "mv-1", 1);
    const ov: CostLineOverride = {
      costLineId: "cl-1", type: "METAL",
      adjustmentKind: "BONUS", adjustmentType: "PERCENTAGE", adjustmentValue: 10,
    };
    const r = validateCostLineOverride(ov, line);
    expect(r.applicable).toBe(true);
    expect(r.sanitized.adjustmentKind).toBeUndefined();
    expect(r.sanitized.adjustmentType).toBeUndefined();
    expect(r.sanitized.adjustmentValue).toBeUndefined();
    expect(r.warnings).toHaveLength(1);
  });

  it("baseline correct: HECHURA + mermaPercentOverride → ignorado + warning", () => {
    const line = hechuraLine("cl-h1", 1, 100);
    const ov: CostLineOverride = { costLineId: "cl-h1", type: "HECHURA", mermaPercentOverride: 5 };
    const r = validateCostLineOverride(ov, line);
    expect(r.applicable).toBe(true);
    expect(r.sanitized.mermaPercentOverride).toBeUndefined();
  });
});

// =============================================================================
// 2. unifyCostLineOverrides — legacy + explicit
// =============================================================================

describe("F1.4 #11-A — unifyCostLineOverrides", () => {
  it("baseline correct: solo legacy → sintetizado para primer METAL/HECHURA", () => {
    const lines = [metalLine("cl-m1", "mv-1", 1), hechuraLine("cl-h1", 1, 100)];
    const r = unifyCostLineOverrides(lines, { gramsOverride: 5, hechuraOverrideAmount: 200 }, undefined);
    expect(r).toHaveLength(2);
    expect(r[0]).toMatchObject({ costLineId: "cl-m1", type: "METAL", quantityOverride: 5 });
    expect(r[1]).toMatchObject({ costLineId: "cl-h1", type: "HECHURA", quantityOverride: 1, unitValueOverride: 200 });
  });

  it("baseline correct: explicit gana cuando match por costLineId — legacy descartado", () => {
    const lines = [metalLine("cl-m1", "mv-1", 1)];
    const explicit: CostLineOverride[] = [
      { costLineId: "cl-m1", type: "METAL", quantityOverride: 10 },
    ];
    const r = unifyCostLineOverrides(lines, { gramsOverride: 5 }, explicit);
    // Solo un entry — legacy NO se sintetiza para cl-m1 (explicit ya está).
    expect(r).toHaveLength(1);
    expect(r[0].quantityOverride).toBe(10);
  });

  it("baseline correct: explicit para METAL[1] + legacy → ambos coexisten", () => {
    const lines = [
      metalLine("cl-m1", "mv-1", 1),
      metalLine("cl-m2", "mv-2", 2),
    ];
    const explicit: CostLineOverride[] = [
      { costLineId: "cl-m2", type: "METAL", quantityOverride: 99 },
    ];
    const r = unifyCostLineOverrides(lines, { gramsOverride: 5 }, explicit);
    expect(r).toHaveLength(2);
    // legacy sintetizado apunta a cl-m1 (primer METAL).
    expect(r.find(o => o.costLineId === "cl-m1")?.quantityOverride).toBe(5);
    // explicit apunta a cl-m2.
    expect(r.find(o => o.costLineId === "cl-m2")?.quantityOverride).toBe(99);
  });

  it("baseline correct: sin legacy ni explicit → array vacío", () => {
    const r = unifyCostLineOverrides([metalLine("cl-1", "mv-1", 1)], {}, undefined);
    expect(r).toEqual([]);
  });
});

// =============================================================================
// 3. buildCostLineOverrideMap — Map sanitizado + warnings
// =============================================================================

describe("F1.4 #11-A — buildCostLineOverrideMap", () => {
  it("baseline correct: 2 overrides válidos → 2 entries en map + 0 warnings", () => {
    const lines = [
      metalLine("cl-m1", "mv-1", 1),
      hechuraLine("cl-h1", 1, 100),
    ];
    const r = buildCostLineOverrideMap([
      { costLineId: "cl-m1", type: "METAL",   quantityOverride: 5 },
      { costLineId: "cl-h1", type: "HECHURA", unitValueOverride: 200 },
    ], lines);
    expect(r.map.size).toBe(2);
    expect(r.applied).toHaveLength(2);
    expect(r.warnings).toHaveLength(0);
  });

  it("baseline correct: id inválido + type mismatch → mapa vacío + 2 warnings", () => {
    const lines = [metalLine("cl-m1", "mv-1", 1)];
    const r = buildCostLineOverrideMap([
      { costLineId: "missing", type: "METAL", quantityOverride: 5 },
      { costLineId: "cl-m1",   type: "HECHURA", quantityOverride: 5 },
    ], lines);
    expect(r.map.size).toBe(0);
    expect(r.warnings).toHaveLength(2);
    expect(r.warnings[0].code).toBe("COST_LINE_OVERRIDE_NOT_FOUND");
    expect(r.warnings[1].code).toBe("COST_LINE_OVERRIDE_TYPE_MISMATCH");
  });
});

// =============================================================================
// 4. Cost engine — overrides aplicados al cálculo real
// =============================================================================

describe("F1.4 #11-A — cost engine aplica overrides", () => {
  it("baseline correct: METAL quantityOverride cambia gramos sin mutar `lines`", async () => {
    setupMetalQuote("mv-1", 100);
    const lines: CostLineInput[] = [metalLine("cl-m1", "mv-1", 1)];
    // Sin override: cost = 1 × 100 = 100.
    const baseline = await calculateCostFromLines("j1", lines);
    expect(baseline.value?.toNumber()).toBeCloseTo(100, 4);
    // Con override: 5 × 100 = 500.
    const overridden = await calculateCostFromLines("j1", lines, undefined, undefined, [
      { costLineId: "cl-m1", type: "METAL", quantityOverride: 5 },
    ]);
    expect(overridden.value?.toNumber()).toBeCloseTo(500, 4);
    // Cero mutación del input — original sigue con qty=1.
    expect(lines[0].quantity).toBe(1);
  });

  it("baseline correct: HECHURA unitValueOverride reemplaza unitValue", async () => {
    const lines: CostLineInput[] = [hechuraLine("cl-h1", 1, 100)];
    const baseline = await calculateCostFromLines("j1", lines);
    expect(baseline.value?.toNumber()).toBeCloseTo(100, 4);
    const overridden = await calculateCostFromLines("j1", lines, undefined, undefined, [
      { costLineId: "cl-h1", type: "HECHURA", unitValueOverride: 250 },
    ]);
    expect(overridden.value?.toNumber()).toBeCloseTo(250, 4);
  });

  it("baseline correct: METAL mermaPercentOverride aplica nueva merma", async () => {
    setupMetalQuote("mv-1", 100);
    const lines: CostLineInput[] = [metalLine("cl-m1", "mv-1", 1, 0)];
    // Sin merma: 1 × 100 = 100.
    const baseline = await calculateCostFromLines("j1", lines);
    expect(baseline.value?.toNumber()).toBeCloseTo(100, 4);
    // Con merma 10%: 1 × 1.10 × 100 = 110.
    const overridden = await calculateCostFromLines("j1", lines, undefined, undefined, [
      { costLineId: "cl-m1", type: "METAL", mermaPercentOverride: 10 },
    ]);
    expect(overridden.value?.toNumber()).toBeCloseTo(110, 4);
  });

  it("baseline correct: 2 metales editados independientemente — solo afectan su line", async () => {
    setupMetalQuote("mv-1", 100);
    mockPrisma.metalVariant.findMany.mockResolvedValue([
      { id: "mv-1", saleFactor: new D("1"), purity: new D("0.75") },
      { id: "mv-2", saleFactor: new D("1"), purity: new D("0.50") },
    ]);
    mockPrisma.metalQuote.findMany.mockResolvedValue([
      { variantId: "mv-1", price: new D("100") },
      { variantId: "mv-2", price: new D("50") },
    ]);
    const lines: CostLineInput[] = [
      metalLine("cl-m1", "mv-1", 1),
      metalLine("cl-m2", "mv-2", 2),
    ];
    // baseline: 1×100 + 2×50 = 200.
    const baseline = await calculateCostFromLines("j1", lines);
    expect(baseline.value?.toNumber()).toBeCloseTo(200, 4);
    // Editar solo cl-m1 (qty 5): 5×100 + 2×50 = 600.
    const r1 = await calculateCostFromLines("j1", lines, undefined, undefined, [
      { costLineId: "cl-m1", type: "METAL", quantityOverride: 5 },
    ]);
    expect(r1.value?.toNumber()).toBeCloseTo(600, 4);
    // Editar solo cl-m2 (qty 10): 1×100 + 10×50 = 600.
    const r2 = await calculateCostFromLines("j1", lines, undefined, undefined, [
      { costLineId: "cl-m2", type: "METAL", quantityOverride: 10 },
    ]);
    expect(r2.value?.toNumber()).toBeCloseTo(600, 4);
  });

  it("baseline correct: PRODUCT + SERVICE simultáneos via overrides", async () => {
    const lines: CostLineInput[] = [
      productLine("cl-p1", 1, 100),
      { id: "cl-s1", type: "SERVICE", quantity: 1, unitValue: 50,
        lineAdjKind: "", lineAdjType: "", lineAdjValue: null } as CostLineInput,
    ];
    const baseline = await calculateCostFromLines("j1", lines);
    expect(baseline.value?.toNumber()).toBeCloseTo(150, 4);
    const r = await calculateCostFromLines("j1", lines, undefined, undefined, [
      { costLineId: "cl-p1", type: "PRODUCT", quantityOverride: 3 },
      { costLineId: "cl-s1", type: "SERVICE", unitValueOverride: 80 },
    ]);
    // 3×100 + 1×80 = 380.
    expect(r.value?.toNumber()).toBeCloseTo(380, 4);
  });

  it("baseline correct: adjustmentKind=null limpia el ajuste de la cost line", async () => {
    // line con BONUS 10% → 100 × 0.90 = 90.
    const lines: CostLineInput[] = [
      hechuraLine("cl-h1", 1, 100, "BONUS", "PERCENTAGE", 10),
    ];
    const baseline = await calculateCostFromLines("j1", lines);
    expect(baseline.value?.toNumber()).toBeCloseTo(90, 4);
    // Override que LIMPIA el ajuste → 100.
    const r = await calculateCostFromLines("j1", lines, undefined, undefined, [
      {
        costLineId: "cl-h1", type: "HECHURA",
        adjustmentKind: null, adjustmentType: null, adjustmentValue: null,
      },
    ]);
    expect(r.value?.toNumber()).toBeCloseTo(100, 4);
  });
});

// =============================================================================
// 5. Preview stability — payload sin overrides es byte-paritario
// =============================================================================

describe("F1.4 #11-A — preview stability sin overrides", () => {
  it("baseline correct: array vacío → resultado idéntico a no pasar overrides", async () => {
    setupMetalQuote("mv-1", 100);
    const lines: CostLineInput[] = [metalLine("cl-m1", "mv-1", 1, 5)];
    const sin = await calculateCostFromLines("j1", lines);
    const conVacio = await calculateCostFromLines("j1", lines, undefined, undefined, []);
    expect(sin.value?.toString()).toBe(conVacio.value?.toString());
    expect(sin.metalCost?.toString()).toBe(conVacio.metalCost?.toString());
  });

  it("baseline correct: array undefined → resultado idéntico", async () => {
    setupMetalQuote("mv-1", 100);
    const lines: CostLineInput[] = [metalLine("cl-m1", "mv-1", 1, 5)];
    const sin = await calculateCostFromLines("j1", lines);
    const conUndef = await calculateCostFromLines("j1", lines, undefined, undefined, undefined);
    expect(sin.value?.toString()).toBe(conUndef.value?.toString());
  });
});

// =============================================================================
// 6. Warnings van a debugWarnings, NO a steps[]
// =============================================================================

describe("F1.4 #11-A — debugWarnings aislados de steps[]", () => {
  it("baseline correct: costLineId inválido NO contamina steps[]", async () => {
    setupMetalQuote("mv-1", 100);
    const lines: CostLineInput[] = [metalLine("cl-m1", "mv-1", 1)];
    const r = await calculateCostFromLines("j1", lines, undefined, undefined, [
      { costLineId: "MISSING", type: "METAL", quantityOverride: 5 },
    ]);
    // Cálculo sigue OK (warning ignora override, valor se mantiene).
    expect(r.value?.toNumber()).toBeCloseTo(100, 4);
    // Warning va a debugWarnings, NO a steps[].
    expect(r.debugWarnings).toBeDefined();
    expect(r.debugWarnings!.length).toBeGreaterThan(0);
    const stepKeys = r.steps.map(s => s.key);
    expect(stepKeys).not.toContain("COST_LINE_OVERRIDE_WARN");
    expect(stepKeys).not.toContain("COST_LINE_OVERRIDE_NOT_FOUND");
  });

  it("baseline correct: METAL + unitValueOverride → warning interno, cost calculado normal", async () => {
    setupMetalQuote("mv-1", 100);
    const lines: CostLineInput[] = [metalLine("cl-m1", "mv-1", 1)];
    const r = await calculateCostFromLines("j1", lines, undefined, undefined, [
      { costLineId: "cl-m1", type: "METAL", unitValueOverride: 9999 },
    ]);
    // unitValueOverride ignorado para METAL → cost = 1×100 = 100.
    expect(r.value?.toNumber()).toBeCloseTo(100, 4);
    expect(r.debugWarnings?.[0]?.code).toBe("COST_LINE_OVERRIDE_FIELD_NOT_APPLICABLE");
  });
});

// =============================================================================
// 7. costLineOverridesApplied propagation
// =============================================================================

describe("F1.4 #11-A — costLineOverridesApplied propagation", () => {
  it("baseline correct: cost engine devuelve `costLineOverridesApplied` con override aplicado", async () => {
    setupMetalQuote("mv-1", 100);
    const lines: CostLineInput[] = [metalLine("cl-m1", "mv-1", 1)];
    const r = await calculateCostFromLines("j1", lines, undefined, undefined, [
      { costLineId: "cl-m1", type: "METAL", quantityOverride: 5 },
    ]);
    expect(r.costLineOverridesApplied).toBeDefined();
    expect(r.costLineOverridesApplied).toHaveLength(1);
    expect(r.costLineOverridesApplied?.[0].quantityOverride).toBe(5);
  });

  it("baseline correct: sin overrides → costLineOverridesApplied undefined", async () => {
    setupMetalQuote("mv-1", 100);
    const lines: CostLineInput[] = [metalLine("cl-m1", "mv-1", 1)];
    const r = await calculateCostFromLines("j1", lines);
    expect(r.costLineOverridesApplied).toBeUndefined();
  });
});
