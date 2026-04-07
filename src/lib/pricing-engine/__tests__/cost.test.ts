// src/lib/pricing-engine/__tests__/cost.test.ts
// Tests unitarios para resolveArticleCost()
// Todos los tests son aislados — mockean Prisma sin tocar la DB real.

import { describe, it, expect, vi, beforeEach } from "vitest";
import { Prisma } from "@prisma/client";

// ── Mock Prisma (vi.hoisted garantiza que el objeto esté disponible en la factory)
const mockPrisma = vi.hoisted(() => ({
  currency:     { findFirst:  vi.fn() },
  currencyRate: { findFirst:  vi.fn() },
  metalQuote:   { findFirst:  vi.fn() },
  jewelry:      { findUnique: vi.fn() },
}));

vi.mock("../../prisma.js", () => ({ prisma: mockPrisma }));

// Import DESPUÉS del mock
import { resolveArticleCost } from "../pricing-engine.cost.js";
import type { ArticleCostInput } from "../pricing-engine.types.js";

// ── Helpers ─────────────────────────────────────────────────────────────────

/** Artículo base con todos los campos en null/defaults */
function makeArticle(overrides: Partial<ArticleCostInput> = {}): ArticleCostInput {
  return {
    costCalculationMode: "MANUAL",
    costPrice:           null,
    manualCurrencyId:    null,
    manualBaseCost:      null,
    manualAdjustmentKind:  null,
    manualAdjustmentType:  null,
    manualAdjustmentValue: null,
    multiplierBase:     null,
    multiplierValue:    null,
    multiplierQuantity: null,
    multiplierCurrencyId: null,
    hechuraPrice:     null,
    hechuraPriceMode: "FIXED",
    mermaPercent:     null,
    compositions:     [],
    costComposition:  [],
    category:         null,
    ...overrides,
  };
}

/** Configura mocks para modo metal: moneda base, jewelry sin merma por defecto, y cotización */
function setupMetalMocks(quotePrice: string, baseCurrencyId = "ARS") {
  mockPrisma.currency.findFirst.mockResolvedValue({ id: baseCurrencyId });
  mockPrisma.jewelry.findUnique.mockResolvedValue({ defaultMermaPercent: null });
  mockPrisma.metalQuote.findFirst.mockResolvedValue({
    price: new Prisma.Decimal(quotePrice),
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// MANUAL
// ─────────────────────────────────────────────────────────────────────────────

describe("MANUAL — costPrice legacy (sin DB)", () => {
  it("Caso 1 — base=1000, sin ajuste → 1000", async () => {
    const art = makeArticle({ costPrice: "1000" });
    const res  = await resolveArticleCost("j1", art);

    expect(res.value?.toNumber()).toBe(1000);
    expect(res.mode).toBe("MANUAL");
    expect(res.partial).toBe(false);
    expect(res.steps.length).toBeGreaterThan(0);
    expect(res.steps.some(s => s.status === "ok")).toBe(true);
  });

  it("Caso 2 — base=500, sin ajuste → 500", async () => {
    const art = makeArticle({ costPrice: "500" });
    const res  = await resolveArticleCost("j1", art);
    expect(res.value?.toNumber()).toBe(500);
  });

  it("Sin costPrice ni manualBaseCost → null + partial", async () => {
    const art = makeArticle({ costCalculationMode: "MANUAL" });
    const res  = await resolveArticleCost("j1", art);

    expect(res.value).toBeNull();
    expect(res.partial).toBe(true);
    expect(res.steps.some(s => s.status === "missing")).toBe(true);
  });
});

describe("MANUAL — manualBaseCost (sin moneda = sin DB)", () => {
  it("Caso 1 — base=1000, sin ajuste → 1000", async () => {
    const art = makeArticle({ manualBaseCost: "1000", manualCurrencyId: null });
    const res  = await resolveArticleCost("j1", art);

    expect(res.value?.toNumber()).toBe(1000);
    expect(res.mode).toBe("MANUAL");
    expect(res.partial).toBe(false);
  });

  it("Caso 2 — base=1000 + recargo 10% → 1100", async () => {
    const art = makeArticle({
      manualBaseCost:       "1000",
      manualCurrencyId:     null,
      manualAdjustmentKind: "SURCHARGE",
      manualAdjustmentType: "PERCENTAGE",
      manualAdjustmentValue: "10",
    });
    const res = await resolveArticleCost("j1", art);
    expect(res.value?.toNumber()).toBeCloseTo(1100, 4);
  });

  it("Caso 3 — base=1000 - 100 fijo → 900", async () => {
    const art = makeArticle({
      manualBaseCost:       "1000",
      manualCurrencyId:     null,
      manualAdjustmentKind: "BONUS",
      manualAdjustmentType: "FIXED",
      manualAdjustmentValue: "100",
    });
    const res = await resolveArticleCost("j1", art);
    expect(res.value?.toNumber()).toBeCloseTo(900, 4);
  });

  it("Recargo porcentual sobre base grande → correcto", async () => {
    const art = makeArticle({
      manualBaseCost:       "2000",
      manualCurrencyId:     null,
      manualAdjustmentKind: "SURCHARGE",
      manualAdjustmentType: "PERCENTAGE",
      manualAdjustmentValue: "25",
    });
    const res = await resolveArticleCost("j1", art);
    expect(res.value?.toNumber()).toBeCloseTo(2500, 4);
  });
});

describe("MANUAL — con conversión de moneda (con DB)", () => {
  beforeEach(() => {
    mockPrisma.currency.findFirst.mockResolvedValue({ id: "ARS" });
    mockPrisma.currencyRate.findFirst.mockResolvedValue({
      rate: new Prisma.Decimal("1000"),
    });
  });

  it("USD 5 × tasa 1000 → 5000 en ARS", async () => {
    const art = makeArticle({
      manualBaseCost:    "5",
      manualCurrencyId:  "USD",
    });
    const res = await resolveArticleCost("j1", art);
    expect(res.value?.toNumber()).toBeCloseTo(5000, 2);
  });

  it("Conversión + recargo 10% → convertido primero, ajuste después", async () => {
    // 5 USD × 1000 = 5000 ARS, luego +10% = 5500
    const art = makeArticle({
      manualBaseCost:       "5",
      manualCurrencyId:     "USD",
      manualAdjustmentKind: "SURCHARGE",
      manualAdjustmentType: "PERCENTAGE",
      manualAdjustmentValue: "10",
    });
    const res = await resolveArticleCost("j1", art);
    expect(res.value?.toNumber()).toBeCloseTo(5500, 2);
  });

  it("Sin tasa de cambio → null + partial", async () => {
    mockPrisma.currencyRate.findFirst.mockResolvedValue(null);
    const art = makeArticle({
      manualBaseCost:   "5",
      manualCurrencyId: "USD",
    });
    const res = await resolveArticleCost("j1", art);
    expect(res.value).toBeNull();
    expect(res.partial).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// MULTIPLIER
// ─────────────────────────────────────────────────────────────────────────────

describe("MULTIPLIER — sin conversión de moneda (sin DB)", () => {
  it("qty=10 × value=5 → 50", async () => {
    const art = makeArticle({
      costCalculationMode: "MULTIPLIER",
      multiplierQuantity:  "10",
      multiplierValue:     "5",
      multiplierCurrencyId: null,
    });
    const res = await resolveArticleCost("j1", art);
    expect(res.value?.toNumber()).toBe(50);
    expect(res.mode).toBe("MULTIPLIER");
  });

  it("qty=2.5 × value=100 → 250", async () => {
    const art = makeArticle({
      costCalculationMode: "MULTIPLIER",
      multiplierQuantity:  "2.5",
      multiplierValue:     "100",
      multiplierCurrencyId: null,
    });
    const res = await resolveArticleCost("j1", art);
    expect(res.value?.toNumber()).toBe(250);
  });

  it("Sin multiplierValue → null + partial", async () => {
    const art = makeArticle({
      costCalculationMode: "MULTIPLIER",
      multiplierQuantity:  "10",
      multiplierValue:     null,
    });
    const res = await resolveArticleCost("j1", art);
    expect(res.value).toBeNull();
    expect(res.partial).toBe(true);
    expect(res.steps.some(s => s.status === "missing")).toBe(true);
  });
});

describe("MULTIPLIER — con conversión de moneda (con DB)", () => {
  beforeEach(() => {
    mockPrisma.currency.findFirst.mockResolvedValue({ id: "ARS" });
    mockPrisma.currencyRate.findFirst.mockResolvedValue({
      rate: new Prisma.Decimal("1000"),
    });
  });

  it("qty=10 × value=5 USD × tasa=1000 → 50000 ARS", async () => {
    const art = makeArticle({
      costCalculationMode:  "MULTIPLIER",
      multiplierQuantity:   "10",
      multiplierValue:      "5",
      multiplierCurrencyId: "USD",
    });
    const res = await resolveArticleCost("j1", art);
    expect(res.value?.toNumber()).toBeCloseTo(50000, 2);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// METAL_MERMA_HECHURA
// ─────────────────────────────────────────────────────────────────────────────

describe("METAL_MERMA_HECHURA", () => {
  beforeEach(() => {
    setupMetalMocks("50");
  });

  it("10g × precio=50 + merma=10% + hechura FIXED=200 → 750", async () => {
    // metal = 10 × 1.1 × 50 = 550
    // hechura = 200
    // total = 750
    const art = makeArticle({
      costCalculationMode: "METAL_MERMA_HECHURA",
      mermaPercent:        "10",
      hechuraPrice:        "200",
      hechuraPriceMode:    "FIXED",
      compositions: [{ variantId: "v1", grams: "10", isBase: true }],
    });
    const res = await resolveArticleCost("j1", art);
    expect(res.value?.toNumber()).toBeCloseTo(750, 4);
    expect(res.mode).toBe("METAL_MERMA_HECHURA");
    expect(res.partial).toBe(false);
  });

  it("FIX 2: hechura PER_GRAM usa gramos CON merma", async () => {
    // metal = 10 × 1.1 × 50 = 550
    // gramsWithMerma = 11
    // hechura = 20 × 11 = 220
    // total = 770
    const art = makeArticle({
      costCalculationMode: "METAL_MERMA_HECHURA",
      mermaPercent:        "10",
      hechuraPrice:        "20",
      hechuraPriceMode:    "PER_GRAM",
      compositions: [{ variantId: "v1", grams: "10", isBase: true }],
    });
    const res = await resolveArticleCost("j1", art);
    expect(res.value?.toNumber()).toBeCloseTo(770, 4);
  });

  it("Sin merma (0%) → gramos base × precio", async () => {
    // metal = 10 × 1.0 × 50 = 500
    // hechura = 100
    // total = 600
    const art = makeArticle({
      costCalculationMode: "METAL_MERMA_HECHURA",
      mermaPercent:        "0",
      hechuraPrice:        "100",
      hechuraPriceMode:    "FIXED",
      compositions: [{ variantId: "v1", grams: "10", isBase: true }],
    });
    const res = await resolveArticleCost("j1", art);
    expect(res.value?.toNumber()).toBeCloseTo(600, 4);
  });

  it("Múltiples composiciones → suma de costos metálicos", async () => {
    // v1: 5g × 50 = 250 | v2: 3g × 50 = 150 | total metal = 400
    mockPrisma.metalQuote.findFirst.mockResolvedValue({
      price: new Prisma.Decimal("50"),
    });
    const art = makeArticle({
      costCalculationMode: "METAL_MERMA_HECHURA",
      mermaPercent:        "0",
      hechuraPrice:        null,
      hechuraPriceMode:    "FIXED",
      compositions: [
        { variantId: "v1", grams: "5",  isBase: true },
        { variantId: "v2", grams: "3",  isBase: false },
      ],
    });
    const res = await resolveArticleCost("j1", art);
    expect(res.value?.toNumber()).toBeCloseTo(400, 4);
  });

  it("Sin cotización de metal → partial=true, value=null para esa composición", async () => {
    mockPrisma.metalQuote.findFirst.mockResolvedValue(null);
    const art = makeArticle({
      costCalculationMode: "METAL_MERMA_HECHURA",
      mermaPercent:        "0",
      compositions: [{ variantId: "v1", grams: "10", isBase: true }],
    });
    const res = await resolveArticleCost("j1", art);
    expect(res.partial).toBe(true);
    expect(res.steps.some(s => s.status === "missing")).toBe(true);
  });

  it("Sin composiciones → missing + partial", async () => {
    const art = makeArticle({
      costCalculationMode: "METAL_MERMA_HECHURA",
      compositions:        [],
    });
    const res = await resolveArticleCost("j1", art);
    expect(res.value).toBeNull();
    expect(res.partial).toBe(true);
  });

  it("Devuelve metalCost y hechuraCost correctos", async () => {
    const art = makeArticle({
      costCalculationMode: "METAL_MERMA_HECHURA",
      mermaPercent:        "0",
      hechuraPrice:        "200",
      hechuraPriceMode:    "FIXED",
      compositions: [{ variantId: "v1", grams: "10", isBase: true }],
    });
    const res = await resolveArticleCost("j1", art);
    // metal = 10 × 50 = 500 | hechura = 200 | total = 700
    expect(res.metalCost?.toNumber()).toBeCloseTo(500, 4);
    expect(res.hechuraCost?.toNumber()).toBeCloseTo(200, 4);
    expect(res.totalGrams?.toNumber()).toBeCloseTo(10, 4);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// COST_LINES
// ─────────────────────────────────────────────────────────────────────────────

describe("COST_LINES", () => {
  beforeEach(() => {
    mockPrisma.currency.findFirst.mockResolvedValue({ id: "ARS" });
    mockPrisma.metalQuote.findFirst.mockResolvedValue({
      price: new Prisma.Decimal("50"),
    });
  });

  it("Línea METAL (10g × 50, merma 0%) + línea HECHURA (1 × 200) → 700", async () => {
    const art = makeArticle({
      costComposition: [
        { type: "METAL",   quantity: "10", unitValue: "0",   currencyId: null, mermaPercent: "0", metalVariantId: "v1" },
        { type: "HECHURA", quantity: "1",  unitValue: "200", currencyId: null, mermaPercent: null, metalVariantId: null },
      ],
    });
    const res = await resolveArticleCost("j1", art);
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
    const res = await resolveArticleCost("j1", art);
    expect(res.value?.toNumber()).toBeCloseTo(550, 4);
  });

  it("Línea HECHURA en USD → convierte con tasa", async () => {
    mockPrisma.currencyRate.findFirst.mockResolvedValue({
      rate: new Prisma.Decimal("1000"),
    });
    const art = makeArticle({
      costComposition: [
        { type: "HECHURA", quantity: "1", unitValue: "5", currencyId: "USD", mermaPercent: null, metalVariantId: null },
      ],
    });
    const res = await resolveArticleCost("j1", art);
    // 1 × 5 USD × 1000 = 5000 ARS
    expect(res.value?.toNumber()).toBeCloseTo(5000, 2);
  });

  it("FIX 1: Sin moneda base + costPrice disponible → fallback a MANUAL", async () => {
    // El fallback COST_LINES→MANUAL se activa cuando modoCostLines devuelve value=null.
    // Eso ocurre cuando getBaseCurrencyId() devuelve null (no hay moneda base).
    mockPrisma.currency.findFirst.mockResolvedValue(null); // sin moneda base
    const art = makeArticle({
      costComposition: [
        { type: "METAL", quantity: "10", unitValue: "0", currencyId: null, mermaPercent: "0", metalVariantId: "v1" },
      ],
      costPrice: "999",  // fallback manual (no necesita DB)
    });
    const res = await resolveArticleCost("j1", art);
    expect(res.value?.toNumber()).toBe(999);
    expect(res.mode).toBe("COST_LINES→MANUAL");
    expect(res.steps.some(s => s.key === "COST_LINES_FALLBACK")).toBe(true);
  });

  it("FIX 1: Sin cotización metal → value=0 (parcial), NO activa fallback (es 0, no null)", async () => {
    // Aclaración: si falta la cotización pero sí hay moneda base,
    // el total es 0 (no null) → COST_LINES devuelve 0 con partial=true, sin fallback.
    const art = makeArticle({
      costComposition: [
        { type: "METAL", quantity: "10", unitValue: "0", currencyId: null, mermaPercent: "0", metalVariantId: "v1" },
      ],
      costPrice: "999",
    });
    mockPrisma.metalQuote.findFirst.mockResolvedValue(null);
    const res = await resolveArticleCost("j1", art);
    expect(res.mode).toBe("COST_LINES");
    expect(res.partial).toBe(true); // cotización faltante → parcial
    expect(res.steps.some(s => s.status === "missing")).toBe(true);
  });

  it("FIX 1: Sin moneda base + sin fallback → null", async () => {
    mockPrisma.currency.findFirst.mockResolvedValue(null);
    const art = makeArticle({
      costComposition: [
        { type: "METAL", quantity: "10", unitValue: "0", currencyId: null, mermaPercent: "0", metalVariantId: "v1" },
      ],
    });
    const res = await resolveArticleCost("j1", art);
    expect(res.value).toBeNull();
  });

  it("Steps tienen keys esperadas", async () => {
    const art = makeArticle({
      costComposition: [
        { type: "METAL", quantity: "5", unitValue: "0", currencyId: null, mermaPercent: "0", metalVariantId: "v1" },
      ],
    });
    const res = await resolveArticleCost("j1", art);
    const keys = res.steps.map(s => s.key);
    expect(keys).toContain("COST_LINES_METAL");
    expect(keys).toContain("COST_LINES_FINAL");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// MODO DESCONOCIDO
// ─────────────────────────────────────────────────────────────────────────────

describe("Modo desconocido", () => {
  it("mode='XYZ' → null sin crash", async () => {
    const art = makeArticle({ costCalculationMode: "XYZ" as any });
    const res  = await resolveArticleCost("j1", art);
    expect(res.value).toBeNull();
    expect(res.steps.some(s => s.key === "UNKNOWN_MODE")).toBe(true);
  });
});
