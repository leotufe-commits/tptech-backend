// src/lib/pricing-engine/__tests__/entity-merma-priority.test.ts
// =============================================================================
// FASE F2 — Prioridad de resolución de merma (fuente única en cost.ts).
//
// Esperado:
//   1) override manual (`costLineOverrides[].mermaPercentOverride`)
//   2) merma del cliente (`EntityMermaOverride` → `entityMermaMap`)
//   3) merma del catálogo (`ArticleCostLine.mermaPercent`)
//   4) 0
//
// El motor expone `mermaSource` en `step.meta` y en
// `composition.metals[i].mermaSource` para auditoría.
// =============================================================================

import { describe, it, expect, vi, beforeEach } from "vitest";
import { Prisma } from "@prisma/client";

const mockPrisma = vi.hoisted(() => ({
  currency:     { findFirst:  vi.fn() },
  currencyRate: { findFirst:  vi.fn() },
  metalQuote:   { findFirst:  vi.fn(), findMany: vi.fn() },
  metalVariant: { findMany:   vi.fn() },
  jewelry:      { findUnique: vi.fn() },
}));

vi.mock("../../prisma.js", () => ({ prisma: mockPrisma }));

import { calculateCostFromLines } from "../pricing-engine.cost.js";
import { extractCompositionMetals } from "../../pricing-composition.js";

function makeMetalLine(overrides: Record<string, unknown> = {}) {
  return {
    id: "cl-metal-1",
    type: "METAL" as const,
    quantity: "10",
    unitValue: "0",
    currencyId: null,
    mermaPercent: null as string | null,
    metalVariantId: "v1",
    ...overrides,
  };
}

beforeEach(() => {
  mockPrisma.currency.findFirst.mockResolvedValue({ id: "ARS" });
  mockPrisma.metalVariant.findMany.mockResolvedValue([
    { id: "v1", saleFactor: new Prisma.Decimal("1") },
  ]);
  mockPrisma.metalQuote.findMany.mockResolvedValue([
    { variantId: "v1", price: new Prisma.Decimal("100") },
  ]);
});

describe("FASE F2 — prioridad de merma", () => {
  it("(3) sólo catálogo → merma del catálogo y mermaSource='line'", async () => {
    const lines = [makeMetalLine({ mermaPercent: "5" })];
    const res = await calculateCostFromLines("j1", lines as any);
    // 10 × 1.05 × 100 = 1050
    expect(res.value?.toNumber()).toBeCloseTo(1050, 4);

    const metalStep = res.steps.find((s) => s.key === "COST_LINES_METAL")!;
    expect((metalStep.meta as any).merma).toBeCloseTo(5);
    expect((metalStep.meta as any).mermaSource).toBe("line");

    const items = extractCompositionMetals(res.steps);
    expect(items[0].appliedMermaPct).toBeCloseTo(5);
    expect(items[0].mermaSource).toBe("line");
  });

  it("(2) cliente con merma + catálogo → gana cliente, mermaSource='entity'", async () => {
    const lines = [makeMetalLine({ mermaPercent: "5" })];
    const entityMermaMap = new Map<string, number>([["v1", 12]]);
    const res = await calculateCostFromLines("j1", lines as any, undefined, undefined, undefined, entityMermaMap);
    // 10 × 1.12 × 100 = 1120
    expect(res.value?.toNumber()).toBeCloseTo(1120, 4);

    const metalStep = res.steps.find((s) => s.key === "COST_LINES_METAL")!;
    expect((metalStep.meta as any).merma).toBeCloseTo(12);
    expect((metalStep.meta as any).mermaSource).toBe("entity");

    const items = extractCompositionMetals(res.steps);
    expect(items[0].appliedMermaPct).toBeCloseTo(12);
    expect(items[0].mermaSource).toBe("entity");
  });

  it("(1) override manual + cliente + catálogo → gana manual, mermaSource='costLineOverride'", async () => {
    const lines = [makeMetalLine({ mermaPercent: "5" })];
    const entityMermaMap = new Map<string, number>([["v1", 12]]);
    const overrides = [
      { costLineId: "cl-metal-1", type: "METAL" as const, mermaPercentOverride: 7 },
    ];
    const res = await calculateCostFromLines("j1", lines as any, undefined, undefined, overrides, entityMermaMap);
    // 10 × 1.07 × 100 = 1070 — gana el manual aun con cliente
    expect(res.value?.toNumber()).toBeCloseTo(1070, 4);

    const metalStep = res.steps.find((s) => s.key === "COST_LINES_METAL")!;
    expect((metalStep.meta as any).merma).toBeCloseTo(7);
    expect((metalStep.meta as any).mermaSource).toBe("costLineOverride");

    const items = extractCompositionMetals(res.steps);
    expect(items[0].appliedMermaPct).toBeCloseTo(7);
    expect(items[0].mermaSource).toBe("costLineOverride");
  });

  it("(4) sin override, sin cliente, sin catálogo → 0, mermaSource='default'", async () => {
    const lines = [makeMetalLine({ mermaPercent: null })];
    const res = await calculateCostFromLines("j1", lines as any);
    // 10 × 1 × 100 = 1000
    expect(res.value?.toNumber()).toBeCloseTo(1000, 4);

    const metalStep = res.steps.find((s) => s.key === "COST_LINES_METAL")!;
    expect((metalStep.meta as any).merma).toBe(0);
    expect((metalStep.meta as any).mermaSource).toBe("default");
  });

  it("no se aplica la merma dos veces: llamar dos veces a calculateCostFromLines da resultado idéntico", async () => {
    const lines = [makeMetalLine({ mermaPercent: "5" })];
    const entityMermaMap = new Map<string, number>([["v1", 12]]);
    const r1 = await calculateCostFromLines("j1", lines as any, undefined, undefined, undefined, entityMermaMap);
    const r2 = await calculateCostFromLines("j1", lines as any, undefined, undefined, undefined, entityMermaMap);
    expect(r1.value?.toString()).toBe(r2.value?.toString());
  });

  it("override manual con valor 0 también gana sobre el cliente (operador anula merma)", async () => {
    const lines = [makeMetalLine({ mermaPercent: "5" })];
    const entityMermaMap = new Map<string, number>([["v1", 12]]);
    const overrides = [
      { costLineId: "cl-metal-1", type: "METAL" as const, mermaPercentOverride: 0 },
    ];
    const res = await calculateCostFromLines("j1", lines as any, undefined, undefined, overrides, entityMermaMap);
    // 10 × 1 × 100 = 1000
    expect(res.value?.toNumber()).toBeCloseTo(1000, 4);

    const items = extractCompositionMetals(res.steps);
    expect(items[0].appliedMermaPct).toBe(0);
    expect(items[0].mermaSource).toBe("costLineOverride");
  });
});
