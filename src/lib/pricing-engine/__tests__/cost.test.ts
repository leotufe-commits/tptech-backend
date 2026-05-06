// src/lib/pricing-engine/__tests__/cost.test.ts
// Tests unitarios para calculateCostFromLines() — única API de costo.

import { describe, it, expect, vi, beforeEach } from "vitest";
import { Prisma } from "@prisma/client";

// ── Mock Prisma (vi.hoisted garantiza que el objeto esté disponible en la factory)
const mockPrisma = vi.hoisted(() => ({
  currency:     { findFirst:  vi.fn() },
  currencyRate: { findFirst:  vi.fn() },
  metalQuote:   { findFirst:  vi.fn(), findMany: vi.fn() },
  metalVariant: { findMany:   vi.fn() },
  jewelry:      { findUnique: vi.fn() },
}));

vi.mock("../../prisma.js", () => ({ prisma: mockPrisma }));

// Import DESPUÉS del mock
import { calculateCostFromLines, resolveVariantAwareWeight } from "../pricing-engine.cost.js";
import type { ArticleCostInput } from "../pricing-engine.types.js";

// ── Helpers ─────────────────────────────────────────────────────────────────

/** Artículo base — agrupa líneas y ajuste para pasarlos juntos */
function makeArticle(overrides: Partial<ArticleCostInput> = {}): ArticleCostInput {
  return {
    costComposition: [],
    manualAdjustmentKind:  null,
    manualAdjustmentType:  null,
    manualAdjustmentValue: null,
    ...overrides,
  };
}

/** Llama calculateCostFromLines con la estructura de un ArticleCostInput */
function calc(art: ArticleCostInput) {
  return calculateCostFromLines("j1", art.costComposition ?? [], {
    kind:  art.manualAdjustmentKind,
    type:  art.manualAdjustmentType,
    value: art.manualAdjustmentValue,
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// COST_LINES — casos base
// ─────────────────────────────────────────────────────────────────────────────

describe("COST_LINES", () => {
  beforeEach(() => {
    mockPrisma.currency.findFirst.mockResolvedValue({ id: "ARS" });
    mockPrisma.metalVariant.findMany.mockResolvedValue([
      { id: "v1", saleFactor: new Prisma.Decimal("1") },
    ]);
    mockPrisma.metalQuote.findMany.mockResolvedValue([
      { variantId: "v1", price: new Prisma.Decimal("50") },
    ]);
  });

  it("Línea METAL (10g × 50, merma 0%) + línea HECHURA (1 × 200) → 700", async () => {
    const art = makeArticle({
      costComposition: [
        { type: "METAL",   quantity: "10", unitValue: "0",   currencyId: null, mermaPercent: "0", metalVariantId: "v1" },
        { type: "HECHURA", quantity: "1",  unitValue: "200", currencyId: null, mermaPercent: null, metalVariantId: null },
      ],
    });
    const res = await calc(art);
    expect(res.value?.toNumber()).toBeCloseTo(700, 4);
    expect(res.mode).toBe("COST_LINES");
    expect(res.partial).toBe(false);
  });

  it("Línea METAL con merma 10% → 10 × 1.1 × 50 = 550", async () => {
    const art = makeArticle({
      costComposition: [
        { type: "METAL", quantity: "10", unitValue: "0", currencyId: null, mermaPercent: "10", metalVariantId: "v1" },
      ],
    });
    const res = await calc(art);
    expect(res.value?.toNumber()).toBeCloseTo(550, 4);
  });

  it("Línea HECHURA en USD → convierte con tasa", async () => {
    mockPrisma.currencyRate.findFirst.mockResolvedValue({
      rate:     new Prisma.Decimal("1000"),
      currency: { code: "USD", symbol: "U$S" },
    });
    const art = makeArticle({
      costComposition: [
        { type: "HECHURA", quantity: "1", unitValue: "5", currencyId: "USD", mermaPercent: null, metalVariantId: null },
      ],
    });
    const res = await calc(art);
    // 1 × 5 USD × 1000 = 5000 ARS
    expect(res.value?.toNumber()).toBeCloseTo(5000, 2);
  });

  it("Sin cotización metal → value=null (parcial), step missing", async () => {
    mockPrisma.metalQuote.findMany.mockResolvedValue([]);
    const art = makeArticle({
      costComposition: [
        { type: "METAL", quantity: "10", unitValue: "0", currencyId: null, mermaPercent: "0", metalVariantId: "v1" },
      ],
    });
    const res = await calc(art);
    expect(res.mode).toBe("COST_LINES");
    expect(res.partial).toBe(true);
    expect(res.steps.some(s => s.status === "missing")).toBe(true);
  });

  it("Sin moneda base → null", async () => {
    mockPrisma.currency.findFirst.mockResolvedValue(null);
    const art = makeArticle({
      costComposition: [
        { type: "METAL", quantity: "10", unitValue: "0", currencyId: null, mermaPercent: "0", metalVariantId: "v1" },
      ],
    });
    const res = await calc(art);
    expect(res.value).toBeNull();
  });

  it("Steps tienen keys esperadas", async () => {
    const art = makeArticle({
      costComposition: [
        { type: "METAL", quantity: "5", unitValue: "0", currencyId: null, mermaPercent: "0", metalVariantId: "v1" },
      ],
    });
    const res = await calc(art);
    const keys = res.steps.map(s => s.key);
    expect(keys).toContain("COST_LINES_METAL");
    expect(keys).toContain("COST_LINES_FINAL");
  });

  it("costComposition vacío → value=null, partial=true", async () => {
    const res = await calculateCostFromLines("j1", []);
    expect(res.value).toBeNull();
    expect(res.partial).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// resolveVariantAwareWeight
// ─────────────────────────────────────────────────────────────────────────────

describe("resolveVariantAwareWeight — prioridad de overrides", () => {
  it("variant.weightOverride presente → lo usa, ignora article.weight", () => {
    const result = resolveVariantAwareWeight("5", "8");
    expect(result?.toNumber()).toBe(8);
  });

  it("variant.weightOverride null → fallback a article.weight", () => {
    const result = resolveVariantAwareWeight("5", null);
    expect(result?.toNumber()).toBe(5);
  });

  it("variant.weightOverride undefined → fallback a article.weight", () => {
    const result = resolveVariantAwareWeight("5", undefined);
    expect(result?.toNumber()).toBe(5);
  });

  it("variant.weightOverride=0 → valor 0 válido (no hace fallback)", () => {
    const result = resolveVariantAwareWeight("5", 0);
    expect(result?.toNumber()).toBe(0);
  });

  it("ambos null → devuelve null", () => {
    const result = resolveVariantAwareWeight(null, null);
    expect(result).toBeNull();
  });

  it("ambos undefined → devuelve null", () => {
    const result = resolveVariantAwareWeight(undefined, undefined);
    expect(result).toBeNull();
  });

  it("solo article.weight disponible → lo devuelve", () => {
    const result = resolveVariantAwareWeight("12.5");
    expect(result?.toNumber()).toBe(12.5);
  });

  it("article.weight=0 → valor 0 válido", () => {
    const result = resolveVariantAwareWeight(0);
    expect(result?.toNumber()).toBe(0);
  });

  it("acepta Decimal.toString() como input", () => {
    const result = resolveVariantAwareWeight(
      new Prisma.Decimal("7.123").toString(),
      new Prisma.Decimal("9.456").toString()
    );
    expect(result?.toNumber()).toBeCloseTo(9.456, 3);
  });

  it("variant.weightOverride tiene prioridad incluso cuando article.weight es mayor", () => {
    const result = resolveVariantAwareWeight("100", "3");
    expect(result?.toNumber()).toBe(3);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// calculateCostFromLines — API pública canónica para COST_LINES
// ─────────────────────────────────────────────────────────────────────────────

describe("calculateCostFromLines", () => {
  beforeEach(() => {
    mockPrisma.currency.findFirst.mockResolvedValue({ id: "ARS" });
    mockPrisma.metalVariant.findMany.mockResolvedValue([]);
    mockPrisma.metalQuote.findMany.mockResolvedValue([]);
  });

  it("Lista vacía → null + partial + step COST_LINES_EMPTY", async () => {
    const res = await calculateCostFromLines("j1", []);
    expect(res.value).toBeNull();
    expect(res.partial).toBe(true);
    expect(res.mode).toBe("COST_LINES");
    expect(res.steps.some(s => s.key === "COST_LINES_EMPTY")).toBe(true);
  });

  it("Línea HECHURA simple → valor correcto", async () => {
    const res = await calculateCostFromLines("j1", [
      { type: "HECHURA", quantity: "2", unitValue: "300", currencyId: null, mermaPercent: null, metalVariantId: null },
    ]);
    expect(res.value?.toNumber()).toBeCloseTo(600, 4);
    expect(res.mode).toBe("COST_LINES");
    expect(res.partial).toBe(false);
    expect(res.steps.some(s => s.key === "COST_LINES_FINAL")).toBe(true);
  });

  it("Línea HECHURA + ajuste recargo 10% → 600 × 1.1 = 660", async () => {
    const res = await calculateCostFromLines(
      "j1",
      [{ type: "HECHURA", quantity: "2", unitValue: "300", currencyId: null, mermaPercent: null, metalVariantId: null }],
      { kind: "SURCHARGE", type: "PERCENTAGE", value: "10" },
    );
    expect(res.value?.toNumber()).toBeCloseTo(660, 4);
  });

  it("Ajuste bonificación fija → 600 − 50 = 550", async () => {
    const res = await calculateCostFromLines(
      "j1",
      [{ type: "HECHURA", quantity: "2", unitValue: "300", currencyId: null, mermaPercent: null, metalVariantId: null }],
      { kind: "BONUS", type: "FIXED_AMOUNT", value: "50" },
    );
    expect(res.value?.toNumber()).toBeCloseTo(550, 4);
  });

  it("Sin ajuste = sin cambio sobre la suma de líneas", async () => {
    const res = await calculateCostFromLines("j1", [
      { type: "HECHURA", quantity: "1", unitValue: "500", currencyId: null, mermaPercent: null, metalVariantId: null },
    ]);
    expect(res.value?.toNumber()).toBeCloseTo(500, 4);
    const finalStep = res.steps.find(s => s.key === "COST_LINES_FINAL");
    expect(finalStep).toBeDefined();
    expect(finalStep?.meta?.sumLines).toBe("500");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Servicio y tipos no metálicos
// ─────────────────────────────────────────────────────────────────────────────

describe("Servicio con COST_LINES (tipo SERVICE)", () => {
  beforeEach(() => {
    mockPrisma.currency.findFirst.mockResolvedValue({ id: "ARS" });
    mockPrisma.metalVariant.findMany.mockResolvedValue([]);
    mockPrisma.metalQuote.findMany.mockResolvedValue([]);
  });

  it("línea SERVICE → costo correcto sin metal", async () => {
    const art = makeArticle({
      costComposition: [
        { type: "SERVICE", quantity: "1", unitValue: "1500", currencyId: null, mermaPercent: null, metalVariantId: null },
      ],
    });
    const res = await calc(art);
    expect(res.value?.toNumber()).toBeCloseTo(1500, 4);
    expect(res.mode).toBe("COST_LINES");
    expect(res.metalCost?.toNumber()).toBeCloseTo(0, 4);
    expect(res.hechuraCost?.toNumber()).toBeCloseTo(1500, 4);
  });

  it("múltiples líneas: METAL + SERVICE + HECHURA → suma correcta", async () => {
    mockPrisma.metalVariant.findMany.mockResolvedValue([
      { id: "v1", saleFactor: new Prisma.Decimal("1") },
    ]);
    mockPrisma.metalQuote.findMany.mockResolvedValue([
      { variantId: "v1", price: new Prisma.Decimal("100") },
    ]);
    const art = makeArticle({
      costComposition: [
        { type: "METAL",   quantity: "5",  unitValue: "0",   currencyId: null, mermaPercent: "0", metalVariantId: "v1" },   // 500
        { type: "HECHURA", quantity: "1",  unitValue: "200", currencyId: null, mermaPercent: null, metalVariantId: null },    // 200
        { type: "SERVICE", quantity: "2",  unitValue: "50",  currencyId: null, mermaPercent: null, metalVariantId: null },    // 100
      ],
    });
    const res = await calc(art);
    expect(res.value?.toNumber()).toBeCloseTo(800, 4);
    expect(res.metalCost?.toNumber()).toBeCloseTo(500, 4);
    expect(res.hechuraCost?.toNumber()).toBeCloseTo(300, 4);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Ajuste global sobre COST_LINES
// ─────────────────────────────────────────────────────────────────────────────

describe("Ajuste global sobre COST_LINES", () => {
  beforeEach(() => {
    mockPrisma.currency.findFirst.mockResolvedValue({ id: "ARS" });
    mockPrisma.metalVariant.findMany.mockResolvedValue([]);
    mockPrisma.metalQuote.findMany.mockResolvedValue([]);
  });

  it("ajuste SURCHARGE 10% sobre suma de líneas → (suma × 1.1)", async () => {
    const art = makeArticle({
      costComposition: [
        { type: "HECHURA", quantity: "1", unitValue: "1000", currencyId: null, mermaPercent: null, metalVariantId: null },
      ],
      manualAdjustmentKind:  "SURCHARGE",
      manualAdjustmentType:  "PERCENTAGE",
      manualAdjustmentValue: "10",
    });
    const res = await calc(art);
    expect(res.value?.toNumber()).toBeCloseTo(1100, 4);
    expect(res.mode).toBe("COST_LINES");
  });

  it("ajuste BONUS fijo 200 sobre suma → (suma - 200)", async () => {
    const art = makeArticle({
      costComposition: [
        { type: "HECHURA", quantity: "1", unitValue: "1000", currencyId: null, mermaPercent: null, metalVariantId: null },
      ],
      manualAdjustmentKind:  "BONUS",
      manualAdjustmentType:  "FIXED_AMOUNT",
      manualAdjustmentValue: "200",
    });
    const res = await calc(art);
    expect(res.value?.toNumber()).toBeCloseTo(800, 4);
  });

  it("sin ajuste → valor igual a la suma de líneas", async () => {
    const art = makeArticle({
      costComposition: [
        { type: "HECHURA", quantity: "3", unitValue: "400", currencyId: null, mermaPercent: null, metalVariantId: null },
      ],
    });
    const res = await calc(art);
    expect(res.value?.toNumber()).toBeCloseTo(1200, 4);
  });
});
