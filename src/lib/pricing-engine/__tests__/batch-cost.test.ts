// src/lib/pricing-engine/__tests__/batch-cost.test.ts
// Tests de regresión críticos para el pricing engine.
//
// Cubre:
//   1. COST_LINES metal + merma (cotización y cálculo correcto)
//   2. COST_LINES multimoneda (ARS + USD + EUR en el mismo batch)
//   3. saleFactor — evitar bug del double-factor (quote.price / saleFactor)
//   4. Batch vs individual: mismo resultado
//   5. buildBatchCostContext: estructura del contexto
//   6. ctx presente → cero queries adicionales

import { describe, it, expect, vi, beforeEach } from "vitest";
import { Prisma } from "@prisma/client";

// ── Mock Prisma ──────────────────────────────────────────────────────────────
const mockPrisma = vi.hoisted(() => ({
  currency:     { findFirst:  vi.fn(), findMany: vi.fn() },
  currencyRate: { findFirst:  vi.fn(), findMany: vi.fn() },
  metalQuote:   { findFirst:  vi.fn(), findMany: vi.fn() },
  metalVariant: { findMany:   vi.fn() },
  jewelry:      { findUnique: vi.fn() },
}));

vi.mock("../../prisma.js", () => ({ prisma: mockPrisma }));

// Imports DESPUÉS del mock
import { calculateCostFromLines, buildBatchCostContext } from "../pricing-engine.cost.js";
import type { ArticleCostInput } from "../pricing-engine.types.js";

// ── Helpers ──────────────────────────────────────────────────────────────────

const D = Prisma.Decimal;

function makeArticle(overrides: Partial<ArticleCostInput> = {}): ArticleCostInput {
  return {
    costComposition:       [],
    manualAdjustmentKind:  null,
    manualAdjustmentType:  null,
    manualAdjustmentValue: null,
    ...overrides,
  };
}

/** Atajo para llamar calculateCostFromLines con la estructura de un ArticleCostInput */
function calc(art: ArticleCostInput, ctx?: Parameters<typeof calculateCostFromLines>[3]) {
  return calculateCostFromLines(
    "j1",
    art.costComposition ?? [],
    { kind: art.manualAdjustmentKind, type: art.manualAdjustmentType, value: art.manualAdjustmentValue },
    ctx,
  );
}

/** Configura todos los mocks para un contexto batch completo */
function setupBatchMocks(opts: {
  baseCurrencyId?:     string;
  defaultMerma?:       number;
  variants?:           { id: string; saleFactor: string }[];
  quotes?:             { variantId: string; price: string }[];
  rates?:              { currencyId: string; rate: string; code: string; symbol: string }[];
} = {}) {
  const { baseCurrencyId = "ARS", defaultMerma = 0, variants = [], quotes = [], rates = [] } = opts;

  mockPrisma.jewelry.findUnique.mockResolvedValue({ defaultMermaPercent: defaultMerma });
  mockPrisma.currency.findFirst.mockResolvedValue({ id: baseCurrencyId });
  mockPrisma.metalVariant.findMany.mockResolvedValue(
    variants.map(v => ({ id: v.id, saleFactor: new D(v.saleFactor) }))
  );
  mockPrisma.metalQuote.findMany.mockResolvedValue(
    quotes.map(q => ({ variantId: q.variantId, price: new D(q.price) }))
  );
  mockPrisma.currencyRate.findMany.mockResolvedValue(
    rates.map(r => ({ currencyId: r.currencyId, rate: new D(r.rate), currency: { code: r.code, symbol: r.symbol } }))
  );

  if (rates.length > 0) {
    mockPrisma.currencyRate.findFirst.mockImplementation(async (args: any) => {
      const currencyId = args?.where?.currencyId;
      const r = rates.find(rate => rate.currencyId === currencyId);
      return r ? { rate: new D(r.rate), currency: { code: r.code, symbol: r.symbol } } : null;
    });
  }
}

beforeEach(() => {
  vi.clearAllMocks();
});

// ─────────────────────────────────────────────────────────────────────────────
// 1. COST_LINES — metal + merma
// ─────────────────────────────────────────────────────────────────────────────

describe("COST_LINES — metal + merma", () => {
  it("10g × precio=100, merma=10% → costo=1100", async () => {
    setupBatchMocks({
      variants: [{ id: "v1", saleFactor: "1" }],
      quotes:   [{ variantId: "v1", price: "100" }],
    });

    const art = makeArticle({
      costComposition: [{
        type: "METAL", quantity: "10", unitValue: "0",
        currencyId: null, mermaPercent: "10", metalVariantId: "v1",
      }],
    });
    const res = await calc(art);

    // 10g × 1.10 (merma 10%) × 100 = 1100
    expect(res.value?.toNumber()).toBeCloseTo(1100, 4);
    expect(res.mode).toBe("COST_LINES");
    expect(res.metalCost?.toNumber()).toBeCloseTo(1100, 4);
    expect(res.hechuraCost?.toNumber()).toBeCloseTo(0, 4);
  });

  it("metal + hechura FIXED → metalCost y hechuraCost correctos", async () => {
    setupBatchMocks({
      variants: [{ id: "v1", saleFactor: "1" }],
      quotes:   [{ variantId: "v1", price: "50" }],
    });

    const art = makeArticle({
      costComposition: [
        { type: "METAL",   quantity: "10", unitValue: "0",   currencyId: null, mermaPercent: "0",  metalVariantId: "v1" },
        { type: "HECHURA", quantity: "1",  unitValue: "200", currencyId: null, mermaPercent: null, metalVariantId: null },
      ],
    });
    const res = await calc(art);

    expect(res.value?.toNumber()).toBeCloseTo(700, 4);
    expect(res.metalCost?.toNumber()).toBeCloseTo(500, 4);
    expect(res.hechuraCost?.toNumber()).toBeCloseTo(200, 4);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. saleFactor — regresión bug double-factor
// ─────────────────────────────────────────────────────────────────────────────

describe("saleFactor — regresión double-factor", () => {
  it("saleFactor=2 → suggestedPrice = quote.price / 2 (no duplicar factor)", async () => {
    setupBatchMocks({
      variants: [{ id: "v1", saleFactor: "2" }],
      quotes:   [{ variantId: "v1", price: "200" }], // finalSalePrice = 200
    });

    const art = makeArticle({
      costComposition: [{
        type: "METAL", quantity: "10", unitValue: "0",
        currencyId: null, mermaPercent: "0", metalVariantId: "v1",
      }],
    });
    const res = await calc(art);

    // suggestedPrice = 200 / 2 = 100. Costo = 10 × 100 = 1000
    expect(res.value?.toNumber()).toBeCloseTo(1000, 4);
  });

  it("saleFactor=1 → resultado idéntico al anterior (sin cambio)", async () => {
    setupBatchMocks({
      variants: [{ id: "v1", saleFactor: "1" }],
      quotes:   [{ variantId: "v1", price: "100" }],
    });

    const art = makeArticle({
      costComposition: [{
        type: "METAL", quantity: "10", unitValue: "0",
        currencyId: null, mermaPercent: "0", metalVariantId: "v1",
      }],
    });
    const res = await calc(art);

    expect(res.value?.toNumber()).toBeCloseTo(1000, 4);
  });

  it("saleFactor=0 → fallback sin división (usa precio completo)", async () => {
    setupBatchMocks({
      variants: [{ id: "v1", saleFactor: "0" }],
      quotes:   [{ variantId: "v1", price: "100" }],
    });

    const art = makeArticle({
      costComposition: [{
        type: "METAL", quantity: "5", unitValue: "0",
        currencyId: null, mermaPercent: "0", metalVariantId: "v1",
      }],
    });
    const res = await calc(art);

    // saleFactor=0 → usa quote.price directamente (no divide por 0)
    expect(res.value?.toNumber()).toBeCloseTo(500, 4);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. COST_LINES multimoneda
// ─────────────────────────────────────────────────────────────────────────────

describe("COST_LINES multimoneda (ARS + USD + EUR)", () => {
  beforeEach(() => {
    setupBatchMocks({
      baseCurrencyId: "ARS",
      variants: [{ id: "v1", saleFactor: "1" }],
      quotes:   [{ variantId: "v1", price: "1000" }],
      rates: [
        { currencyId: "USD", rate: "1000", code: "USD", symbol: "U$S" },
        { currencyId: "EUR", rate: "1100", code: "EUR", symbol: "€"   },
      ],
    });
  });

  it("hechura en USD: 1 × 5 USD × 1000 = 5000 ARS", async () => {
    const art = makeArticle({
      costComposition: [{
        type: "HECHURA", quantity: "1", unitValue: "5",
        currencyId: "USD", mermaPercent: null, metalVariantId: null,
      }],
    });
    const res = await calc(art);
    expect(res.value?.toNumber()).toBeCloseTo(5000, 2);
  });

  it("hechura en EUR: 1 × 5 EUR × 1100 = 5500 ARS", async () => {
    const art = makeArticle({
      costComposition: [{
        type: "HECHURA", quantity: "1", unitValue: "5",
        currencyId: "EUR", mermaPercent: null, metalVariantId: null,
      }],
    });
    const res = await calc(art);
    expect(res.value?.toNumber()).toBeCloseTo(5500, 2);
  });

  it("metal ARS + hechura USD: totales correctos", async () => {
    // metal: 10g × 1000 ARS = 10000
    // hechura: 1 × 2 USD × 1000 = 2000 ARS
    // total: 12000 ARS
    const art = makeArticle({
      costComposition: [
        { type: "METAL",   quantity: "10", unitValue: "0",  currencyId: null,  mermaPercent: "0", metalVariantId: "v1" },
        { type: "HECHURA", quantity: "1",  unitValue: "2",  currencyId: "USD", mermaPercent: null, metalVariantId: null },
      ],
    });
    const res = await calc(art);
    expect(res.value?.toNumber()).toBeCloseTo(12000, 2);
    expect(res.metalCost?.toNumber()).toBeCloseTo(10000, 2);
    expect(res.hechuraCost?.toNumber()).toBeCloseTo(2000, 2);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 4. Batch vs Individual: mismo resultado (regresión crítica)
// ─────────────────────────────────────────────────────────────────────────────

describe("Batch vs Individual — consistencia COST_LINES", () => {
  it("COST_LINES metal: calculateCostFromLines(ctx) === calculateCostFromLines(sin ctx)", async () => {
    const variants = [{ id: "v1", saleFactor: "1" }];
    const quotes   = [{ variantId: "v1", price: "80" }];

    const art = makeArticle({
      costComposition: [{
        type: "METAL", quantity: "5", unitValue: "0",
        currencyId: null, mermaPercent: "10", metalVariantId: "v1",
      }],
    });

    // 1. Resultado sin ctx (individual)
    setupBatchMocks({ variants, quotes });
    const resIndividual = await calc(art);

    // 2. Resultado con ctx (batch)
    vi.clearAllMocks();
    setupBatchMocks({ variants, quotes });
    const ctx = await buildBatchCostContext("j1", [art]);
    const resBatch = await calc(art, ctx);

    expect(resBatch.value?.toNumber()).toBeCloseTo(resIndividual.value?.toNumber() ?? -1, 4);
    expect(resBatch.mode).toBe(resIndividual.mode);
    expect(resBatch.partial).toBe(resIndividual.partial);
  });

  it("COST_LINES hechura USD: batch === individual", async () => {
    const rates = [{ currencyId: "USD", rate: "900", code: "USD", symbol: "U$S" }];

    const art = makeArticle({
      costComposition: [{
        type: "HECHURA", quantity: "1", unitValue: "10",
        currencyId: "USD", mermaPercent: null, metalVariantId: null,
      }],
    });

    // Individual
    setupBatchMocks({ rates });
    const resIndividual = await calc(art);

    // Batch
    vi.clearAllMocks();
    setupBatchMocks({ rates });
    const ctx = await buildBatchCostContext("j1", [art]);
    const resBatch = await calc(art, ctx);

    // 10 USD × 900 = 9000 ARS
    expect(resIndividual.value?.toNumber()).toBeCloseTo(9000, 2);
    expect(resBatch.value?.toNumber()).toBeCloseTo(9000, 2);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 5. buildBatchCostContext — estructura del contexto
// ─────────────────────────────────────────────────────────────────────────────

describe("buildBatchCostContext — estructura", () => {
  it("construye contexto con baseCurrencyId, metalVariantData y rateMap", async () => {
    setupBatchMocks({
      baseCurrencyId: "ARS",
      defaultMerma:   5,
      variants: [{ id: "v1", saleFactor: "1.5" }],
      quotes:   [{ variantId: "v1", price: "200" }],
      rates:    [{ currencyId: "USD", rate: "1000", code: "USD", symbol: "U$S" }],
    });

    const art = makeArticle({
      costComposition: [
        { type: "METAL",   quantity: "1", unitValue: "0", currencyId: null,  mermaPercent: "0",  metalVariantId: "v1" },
        { type: "HECHURA", quantity: "1", unitValue: "5", currencyId: "USD", mermaPercent: null, metalVariantId: null },
      ],
    });

    const ctx = await buildBatchCostContext("j1", [art]);

    expect(ctx.baseCurrencyId).toBe("ARS");
    expect(Number(ctx.defaultMermaPercent)).toBe(5);
    expect(ctx.metalVariantData.has("v1")).toBe(true);
    expect(ctx.metalVariantData.get("v1")?.saleFactor.toNumber()).toBeCloseTo(1.5, 4);
    expect(ctx.metalVariantData.get("v1")?.price.toNumber()).toBeCloseTo(200, 4);
    expect(ctx.rateMap.has("USD")).toBe(true);
    expect(ctx.rateMap.get("USD")?.rate.toNumber()).toBeCloseTo(1000, 2);
    expect(ctx.rateMap.get("USD")?.code).toBe("USD");
  });

  it("ctx sin variantes ni tasas → mapas vacíos (sin crash)", async () => {
    setupBatchMocks({ baseCurrencyId: "ARS" });
    const art = makeArticle({
      costComposition: [
        { type: "HECHURA", quantity: "1", unitValue: "100", currencyId: null, mermaPercent: null, metalVariantId: null },
      ],
    });

    const ctx = await buildBatchCostContext("j1", [art]);

    expect(ctx.baseCurrencyId).toBe("ARS");
    expect(ctx.metalVariantData.size).toBe(0);
    expect(ctx.rateMap.size).toBe(0);
  });

  it("con ctx → calculateCostFromLines no ejecuta queries adicionales (metalVariant.findMany = 0)", async () => {
    setupBatchMocks({
      variants: [{ id: "v1", saleFactor: "1" }],
      quotes:   [{ variantId: "v1", price: "50" }],
    });

    const art = makeArticle({
      costComposition: [{
        type: "METAL", quantity: "5", unitValue: "0",
        currencyId: null, mermaPercent: "0", metalVariantId: "v1",
      }],
    });

    const ctx = await buildBatchCostContext("j1", [art]);
    vi.clearAllMocks();
    // No setupBatchMocks: el ctx ya contiene todo, no se deben hacer queries
    await calc(art, ctx);
    expect(mockPrisma.metalVariant.findMany).not.toHaveBeenCalled();
    expect(mockPrisma.metalQuote.findMany).not.toHaveBeenCalled();
  });
});
