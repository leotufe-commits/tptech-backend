// src/modules/articles/__tests__/g5-cost-preview-breakdown.test.ts
// =============================================================================
// FASE 1.1 — G5 backend gap. Verifica que `previewCostLines` expone los
// campos extendidos del breakdown de costo: `metalGramsWithMerma` y
// `metalPurity`. El motor ya los computa internamente (CostResult); G5 solo
// los serializa al response para que el frontend (ArticleModal/CostosTab)
// deje de replicar `metal × (1 + merma%)` en cliente (POLICY.md R4.3).
// =============================================================================

import { describe, it, expect, vi, beforeEach } from "vitest";
import { Prisma } from "@prisma/client";

// ── Mock Prisma ──
const mockPrisma = vi.hoisted(() => ({
  article: { findFirst: vi.fn(), findUnique: vi.fn() },
}));
vi.mock("../../../lib/prisma.js", () => ({ prisma: mockPrisma }));

// ── Mock pricing-engine ──
const mockCalculateCostFromLines = vi.hoisted(() => vi.fn());
const mockComputePurchaseTaxes   = vi.hoisted(() => vi.fn());
vi.mock("../../../lib/pricing-engine/pricing-engine.js", () => ({
  resolvePriceList:        vi.fn(),
  applyPriceList:          vi.fn(),
  PL_COMPUTE_SELECT:       {},
  buildBatchCostContext:   vi.fn(),
  calculateCostFromLines:  (...args: any[]) => mockCalculateCostFromLines(...args),
  isPriceListValidNow:     vi.fn(() => false),
  isPromotionValid:        vi.fn(() => false),
  applyTaxesFromMap:       vi.fn(),
  computePurchaseTaxes:    (...args: any[]) => mockComputePurchaseTaxes(...args),
}));

vi.mock("../../../lib/combo.utils.js", () => ({
  normalizeComboFields:             () => ({ commercialMode: "NORMAL", comboAdjustmentKind: "NONE", comboAdjustmentValue: null }),
  validateComboComponentsShape:     vi.fn(),
  validateComboComponentsAgainstDb: vi.fn(),
  computeComboAvailability:         vi.fn(),
}));

import { previewCostLines } from "../articles.service.js";

const D = Prisma.Decimal;

beforeEach(() => {
  vi.clearAllMocks();
  mockPrisma.article.findFirst.mockResolvedValue({ id: "art-1" });
  mockComputePurchaseTaxes.mockResolvedValue({
    costBase:         "1000.0000",
    costTaxAmount:    "0.0000",
    costWithTax:      "1000.0000",
    costTaxBreakdown: [],
  });
});

describe("G5 — previewCostLines expone metalGramsWithMerma y metalPurity", () => {
  it("baseline correct: metalGramsWithMerma se serializa con 4 decimales", async () => {
    mockCalculateCostFromLines.mockResolvedValue({
      value:               new D(1000),
      metalCost:           new D(800),
      hechuraCost:         new D(200),
      totalGrams:          new D(5),
      metalGramsWithMerma: new D(5.5),  // 5g + 10% merma
      metalPurity:         new D(0.75),
      partial:             false,
      mode:                "COST_LINES",
      steps:               [],
    });

    const r = await previewCostLines("art-1", "tenant-1", {
      lines: [{ type: "METAL", quantity: 5, unitValue: 100 }],
    } as any);

    expect(r.cost.metalGramsWithMerma).toBe("5.5000");
  });

  it("baseline correct: metalPurity se serializa con 4 decimales", async () => {
    mockCalculateCostFromLines.mockResolvedValue({
      value:               new D(1000),
      metalCost:           new D(1000),
      hechuraCost:         new D(0),
      totalGrams:          new D(5),
      metalGramsWithMerma: new D(5.5),
      metalPurity:         new D(0.916), // oro 22k
      partial:             false,
      mode:                "COST_LINES",
      steps:               [],
    });

    const r = await previewCostLines("art-1", "tenant-1", {
      lines: [{ type: "METAL", quantity: 5, unitValue: 200 }],
    } as any);

    expect(r.cost.metalPurity).toBe("0.9160");
  });

  it("baseline correct: ambos campos null cuando el motor los devuelve null", async () => {
    mockCalculateCostFromLines.mockResolvedValue({
      value:               new D(500),
      metalCost:           new D(0),
      hechuraCost:         new D(500),
      totalGrams:          new D(0),
      metalGramsWithMerma: null,
      metalPurity:         null,
      partial:             false,
      mode:                "COST_LINES",
      steps:               [],
    });

    const r = await previewCostLines("art-1", "tenant-1", {
      lines: [{ type: "HECHURA", quantity: 1, unitValue: 500 }],
    } as any);

    expect(r.cost.metalGramsWithMerma).toBeNull();
    expect(r.cost.metalPurity).toBeNull();
  });

  it("baseline correct: campos previos siguen presentes (regresión)", async () => {
    mockCalculateCostFromLines.mockResolvedValue({
      value:               new D(1000),
      metalCost:           new D(800),
      hechuraCost:         new D(200),
      totalGrams:          new D(5),
      metalGramsWithMerma: new D(5.5),
      metalPurity:         new D(0.75),
      partial:             false,
      mode:                "COST_LINES",
      steps:               [],
    });

    const r = await previewCostLines("art-1", "tenant-1", {
      lines: [{ type: "METAL", quantity: 5, unitValue: 200 }],
    } as any);

    expect(r.cost.value).toBe("1000.0000");
    expect(r.cost.metalCost).toBe("800.0000");
    expect(r.cost.hechuraCost).toBe("200.0000");
    expect(r.cost.totalGrams).toBe("5.0000");
    expect(r.cost.partial).toBe(false);
    expect(r.cost.mode).toBe("COST_LINES");
    expect(r.purchaseTaxes).toBeDefined();
  });
});
