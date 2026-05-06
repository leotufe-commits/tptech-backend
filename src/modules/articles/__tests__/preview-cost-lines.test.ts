// src/modules/articles/__tests__/preview-cost-lines.test.ts
// =============================================================================
// Tests para previewCostLines — el endpoint debe delegar SIEMPRE en el
// pricing-engine. No debe implementar fórmulas propias de costo ni de
// impuestos en el service.
//
// Estos tests congelan el contrato: si alguien agrega lógica local en la
// función, los tests fallan porque detectan que el motor no se invocó.
// =============================================================================

import { describe, it, expect, vi, beforeEach } from "vitest";
import { Prisma } from "@prisma/client";

// ── Mock Prisma (solo lo que la función necesita para assertArticleOwnership) ──
const mockPrisma = vi.hoisted(() => ({
  article:         { findFirst: vi.fn(), findUnique: vi.fn() },
}));
vi.mock("../../../lib/prisma.js", () => ({ prisma: mockPrisma }));

// ── Mock pricing-engine: capturamos las llamadas para verificar delegación ───
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
  // assertArticleOwnership resuelve OK por defecto
  mockPrisma.article.findFirst.mockResolvedValue({ id: "art-1" });

  // Defaults del motor
  mockCalculateCostFromLines.mockResolvedValue({
    value:       new D("1500"),
    metalCost:   new D("1000"),
    hechuraCost: new D("500"),
    totalGrams:  new D("10"),
    partial:     false,
    mode:        "COST_LINES",
    steps:       [],
  });
  mockComputePurchaseTaxes.mockResolvedValue({
    costBase:         "1500.0000",
    costTaxAmount:    "315.0000",
    costWithTax:      "1815.0000",
    costTaxBreakdown: [
      { taxId: "t-iva", name: "IVA", calculationType: "PERCENTAGE", rate: 21, fixedAmount: null, taxAmount: 315 },
    ],
  });
});

describe("previewCostLines — delega en el pricing-engine", () => {
  it("invoca calculateCostFromLines con las líneas + manualAdjustment", async () => {
    const lines = [
      { type: "METAL" as const, label: "Oro 18K", quantity: 10, unitValue: 100, metalVariantId: "mv-1" },
      { type: "HECHURA" as const, label: "Hechura", quantity: 1, unitValue: 500 },
    ];

    await previewCostLines("art-1", "jw-1", {
      lines,
      manualAdjustment: { kind: "SURCHARGE", type: "PERCENTAGE", value: 10 },
    });

    expect(mockCalculateCostFromLines).toHaveBeenCalledOnce();
    const [jewelryArg, linesArg, adjArg] = mockCalculateCostFromLines.mock.calls[0];
    expect(jewelryArg).toBe("jw-1");
    expect(linesArg).toEqual(lines);
    expect(adjArg).toEqual({ kind: "SURCHARGE", type: "PERCENTAGE", value: 10 });
  });

  it("pasa el costo resuelto por el motor a computePurchaseTaxes", async () => {
    mockCalculateCostFromLines.mockResolvedValueOnce({
      value:       new D("2000"),
      metalCost:   null,
      hechuraCost: null,
      totalGrams:  null,
      partial:     false,
      mode:        "MANUAL",
      steps:       [],
    });

    await previewCostLines("art-1", "jw-1", { lines: [] });

    expect(mockComputePurchaseTaxes).toHaveBeenCalledOnce();
    const [jewelryArg, articleArg, baseArg] = mockComputePurchaseTaxes.mock.calls[0];
    expect(jewelryArg).toBe("jw-1");
    expect(articleArg).toBe("art-1");
    // El base pasado es el mismo Decimal que devolvió el motor
    expect(baseArg?.toString()).toBe("2000");
  });

  it("devuelve el shape { cost, purchaseTaxes } con valores formateados", async () => {
    const result = await previewCostLines("art-1", "jw-1", { lines: [] });

    expect(result.cost.value).toBe("1500.0000");
    expect(result.cost.metalCost).toBe("1000.0000");
    expect(result.cost.hechuraCost).toBe("500.0000");
    expect(result.cost.totalGrams).toBe("10.0000");
    expect(result.cost.partial).toBe(false);
    expect(result.cost.mode).toBe("COST_LINES");

    expect(result.purchaseTaxes.costBase).toBe("1500.0000");
    expect(result.purchaseTaxes.costTaxAmount).toBe("315.0000");
    expect(result.purchaseTaxes.costTaxBreakdown).toHaveLength(1);
    expect(result.purchaseTaxes.costTaxBreakdown[0].taxAmount).toBe(315);
  });

  it("cuando el motor devuelve costo null, pasa null a computePurchaseTaxes", async () => {
    mockCalculateCostFromLines.mockResolvedValueOnce({
      value:       null,
      metalCost:   null,
      hechuraCost: null,
      totalGrams:  null,
      partial:     true,
      mode:        "MANUAL",
      steps:       [],
    });

    const result = await previewCostLines("art-1", "jw-1", { lines: [] });

    expect(mockComputePurchaseTaxes).toHaveBeenCalledWith("jw-1", "art-1", null);
    expect(result.cost.value).toBeNull();
    expect(result.cost.partial).toBe(true);
  });

  it("rechaza líneas con tipo inválido (no llama al motor)", async () => {
    await expect(
      previewCostLines("art-1", "jw-1", {
        // tipo inválido intencional — el guard lo debe rechazar
        lines: [{ type: "FAKE_TYPE" as any, label: "x", quantity: 1, unitValue: 100 }],
      }),
    ).rejects.toThrow(/Tipo de línea inválido/);

    expect(mockCalculateCostFromLines).not.toHaveBeenCalled();
    expect(mockComputePurchaseTaxes).not.toHaveBeenCalled();
  });

  it("rechaza cantidad negativa (no llama al motor)", async () => {
    await expect(
      previewCostLines("art-1", "jw-1", {
        lines: [{ type: "HECHURA", label: "x", quantity: -1, unitValue: 100 }],
      }),
    ).rejects.toThrow(/cantidad no puede ser negativa/i);

    expect(mockCalculateCostFromLines).not.toHaveBeenCalled();
  });

  it("rechaza valor unitario negativo (no llama al motor)", async () => {
    await expect(
      previewCostLines("art-1", "jw-1", {
        lines: [{ type: "HECHURA", label: "x", quantity: 1, unitValue: -1 }],
      }),
    ).rejects.toThrow(/valor unitario no puede ser negativo/i);

    expect(mockCalculateCostFromLines).not.toHaveBeenCalled();
  });
});
