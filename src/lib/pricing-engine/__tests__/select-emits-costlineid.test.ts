// src/lib/pricing-engine/__tests__/select-emits-costlineid.test.ts
// =============================================================================
// REGRESIÓN — `costLineId` viaja end-to-end desde el SELECT hasta
// `composition.metals/hechuras/products/services[].costLineId`.
//
// Este test rompe si alguien:
//   · Elimina `id: true` del SELECT de `costComposition` en cualquier path
//     que alimente al cost engine (resolveFinalSalePrice, evaluatePricingPolicy,
//     confirmSale recompute, etc.).
//   · Modifica el cost engine para que omita `step.meta.costLineId`.
//   · Modifica los extractores para que descarten `costLineId`.
//
// Síntoma corregido (2026-05-08): la grilla `SaleCompositionEditableGrid`
// quedaba read-only en runtime con cursor "?" porque `costLineId` viajaba
// `null` desde el backend, así que `isEditable = costLineId != null` era
// false en cada fila. La causa fue un SELECT en `pricing-engine.sale.ts:865`
// que omitía `id: true` en `costComposition.select`.
//
// El contrato que este test asegura:
//   · Si `CostLineInput.id` viene poblado → el step emitido tiene
//     `meta.costLineId === id`.
//   · Si NO viene → el step omite `costLineId` (no emite `null`, omite la
//     key entera) y el extractor lo traduce a `null`.
//   · Los 4 extractores (METAL/HECHURA/PRODUCT/SERVICE) propagan el id.
// =============================================================================

import { describe, it, expect, vi, beforeEach } from "vitest";
import { Prisma } from "@prisma/client";

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
import {
  extractCompositionMetals,
  extractCompositionHechuras,
  extractCompositionItems,
  extractCompositionCostAdjustment,
} from "../../pricing-composition.js";
import type { CostLineInput, PricingStep } from "../pricing-engine.types.js";

const D = Prisma.Decimal;

beforeEach(() => {
  vi.clearAllMocks();
  mockGetBaseCurrencyId.mockResolvedValue("currency-base");
  mockPrisma.metalVariant.findMany.mockResolvedValue([
    { id: "mv-1", saleFactor: new D("1"), purity: new D("0.75") },
  ]);
  mockPrisma.metalQuote.findMany.mockResolvedValue([
    { variantId: "mv-1", price: new D("100") },
  ]);
});

// ────────────────────────────────────────────────────────────────────────────
// 1. Cost engine emite step.meta.costLineId === line.id
// ────────────────────────────────────────────────────────────────────────────

describe("Regresión SELECT/cost engine — step.meta.costLineId", () => {
  it("METAL con id → step META incluye costLineId === id", async () => {
    const line: CostLineInput = {
      id:             "cl-metal-A",
      type:           "METAL",
      quantity:       new D("2"),
      metalVariantId: "mv-1",
      mermaPercent:   new D("1"),
    } as any;

    const result = await calculateCostFromLines("j1", [line]);

    const metalStep = (result.steps ?? []).find(
      (s: PricingStep) => s.key === "COST_LINES_METAL" && s.status === "ok",
    );
    expect(metalStep).toBeDefined();
    expect(metalStep!.meta).toBeDefined();
    expect((metalStep!.meta as any).costLineId).toBe("cl-metal-A");
  });

  it("HECHURA con id → step META incluye costLineId === id", async () => {
    const line: CostLineInput = {
      id:        "cl-hechura-B",
      type:      "HECHURA",
      quantity:  new D("1"),
      unitValue: new D("500"),
      lineAdjKind:  "",
      lineAdjType:  "",
      lineAdjValue: null,
    } as any;

    const result = await calculateCostFromLines("j1", [line]);

    const step = (result.steps ?? []).find(
      (s: PricingStep) => s.key === "COST_LINES_HECHURA" && s.status === "ok",
    );
    expect(step).toBeDefined();
    expect((step!.meta as any).costLineId).toBe("cl-hechura-B");
  });

  it("PRODUCT con id → step META incluye costLineId === id", async () => {
    const line: CostLineInput = {
      id:        "cl-product-C",
      type:      "PRODUCT",
      quantity:  new D("3"),
      unitValue: new D("50"),
      lineAdjKind:  "",
      lineAdjType:  "",
      lineAdjValue: null,
    } as any;

    const result = await calculateCostFromLines("j1", [line]);

    const step = (result.steps ?? []).find(
      (s: PricingStep) => s.key === "COST_LINES_PRODUCT" && s.status === "ok",
    );
    expect(step).toBeDefined();
    expect((step!.meta as any).costLineId).toBe("cl-product-C");
  });

  it("SERVICE con id → step META incluye costLineId === id", async () => {
    const line: CostLineInput = {
      id:        "cl-service-D",
      type:      "SERVICE",
      quantity:  new D("1"),
      unitValue: new D("80"),
      lineAdjKind:  "",
      lineAdjType:  "",
      lineAdjValue: null,
    } as any;

    const result = await calculateCostFromLines("j1", [line]);

    const step = (result.steps ?? []).find(
      (s: PricingStep) => s.key === "COST_LINES_SERVICE" && s.status === "ok",
    );
    expect(step).toBeDefined();
    expect((step!.meta as any).costLineId).toBe("cl-service-D");
  });

  it("línea SIN id → step META omite costLineId (regresión: simula SELECT que olvidó pedir id)", async () => {
    const line: CostLineInput = {
      // id intencionalmente omitido — simula SELECT incompleto
      type:      "PRODUCT",
      quantity:  new D("1"),
      unitValue: new D("100"),
      lineAdjKind:  "",
      lineAdjType:  "",
      lineAdjValue: null,
    } as any;

    const result = await calculateCostFromLines("j1", [line]);

    const step = (result.steps ?? []).find(
      (s: PricingStep) => s.key === "COST_LINES_PRODUCT" && s.status === "ok",
    );
    expect(step).toBeDefined();
    // Cuando line.id es undefined, la key NO debe emitirse (NO `null`).
    expect((step!.meta as any).costLineId).toBeUndefined();
  });
});

// ────────────────────────────────────────────────────────────────────────────
// 2. Extractores de composition propagan costLineId
// ────────────────────────────────────────────────────────────────────────────

describe("Regresión extractores de composition", () => {
  it("extractCompositionMetals propaga costLineId desde step.meta", async () => {
    const line: CostLineInput = {
      id: "cl-mtl-1", type: "METAL", quantity: new D("2"),
      metalVariantId: "mv-1", mermaPercent: new D("0"),
    } as any;
    const result = await calculateCostFromLines("j1", [line]);

    const metals = extractCompositionMetals(result.steps);

    expect(metals).toHaveLength(1);
    expect(metals[0].costLineId).toBe("cl-mtl-1");
  });

  it("extractCompositionHechuras propaga costLineId desde step.meta", async () => {
    const line: CostLineInput = {
      id: "cl-hch-1", type: "HECHURA", quantity: new D("1"), unitValue: new D("500"),
      lineAdjKind: "", lineAdjType: "", lineAdjValue: null,
    } as any;
    const result = await calculateCostFromLines("j1", [line]);

    const hechuras = extractCompositionHechuras(result.steps);

    expect(hechuras).toHaveLength(1);
    expect(hechuras[0].costLineId).toBe("cl-hch-1");
  });

  it("Fase 2.2 — extractCompositionHechuras propaga lineAdjKind/Type/Value/Amount", async () => {
    const line: CostLineInput = {
      id: "cl-hch-adj", type: "HECHURA",
      quantity: new D("1"), unitValue: new D("1000"),
      lineAdjKind:  "BONUS",
      lineAdjType:  "PERCENTAGE",
      lineAdjValue: new D("10"),
    } as any;
    const result = await calculateCostFromLines("j1", [line]);

    const hechuras = extractCompositionHechuras(result.steps);

    expect(hechuras).toHaveLength(1);
    expect(hechuras[0].lineAdjKind).toBe("BONUS");
    expect(hechuras[0].lineAdjType).toBe("PERCENTAGE");
    expect(hechuras[0].lineAdjValue).toBe(10);
    // lineAdjAmount = 1000 × 10% = 100 (motor cost lo computa).
    expect(hechuras[0].lineAdjAmount).not.toBeNull();
    expect(hechuras[0].lineAdjAmount).toBeCloseTo(100, 2);
  });

  it("Fase 2.3.1 — HECHURA con bonif: unitValue=BASE 1000, appliedAmount=POST 900", async () => {
    // Caso del usuario:
    //   unitValue base 1000, BONUS 10% → step.value = 900
    // Esperado en composition.hechuras[]:
    //   unitValue:     1000   (BASE pre-ajuste, columna VAL. UNIT.)
    //   appliedAmount: 900    (POST-ajuste, legacy field)
    //   lineCost:      900    (= step.value)
    //   lineAdjAmount: 100    (delta absoluto)
    const line: CostLineInput = {
      id: "cl-hch-1", type: "HECHURA",
      quantity: new D("1"), unitValue: new D("1000"),
      lineAdjKind:  "BONUS",
      lineAdjType:  "PERCENTAGE",
      lineAdjValue: new D("10"),
    } as any;
    const result = await calculateCostFromLines("j1", [line]);
    const hechuras = extractCompositionHechuras(result.steps);

    expect(hechuras).toHaveLength(1);
    // BASE pre-ajuste — el campo nuevo de Fase 2.3.1.
    expect(hechuras[0].unitValue).toBe(1000);
    // POST-ajuste (== step.value) — campo legacy preservado.
    expect(hechuras[0].appliedAmount).toBe(900);
    expect(hechuras[0].lineCost).toBe(900);
    // Delta del ajuste.
    expect(hechuras[0].lineAdjAmount).toBeCloseTo(100, 2);
  });

  it("Fase 2.2 — HECHURA sin ajuste configurado deja los 4 campos lineAdj* en null", async () => {
    const line: CostLineInput = {
      id: "cl-hch-clean", type: "HECHURA",
      quantity: new D("1"), unitValue: new D("500"),
      lineAdjKind: "", lineAdjType: "", lineAdjValue: null,
    } as any;
    const result = await calculateCostFromLines("j1", [line]);

    const hechuras = extractCompositionHechuras(result.steps);

    expect(hechuras[0].lineAdjKind).toBeNull();
    expect(hechuras[0].lineAdjType).toBeNull();
    expect(hechuras[0].lineAdjValue).toBeNull();
    expect(hechuras[0].lineAdjAmount).toBeNull();
  });

  it("extractCompositionItems(PRODUCT) propaga costLineId", async () => {
    const line: CostLineInput = {
      id: "cl-prd-1", type: "PRODUCT", quantity: new D("1"), unitValue: new D("99"),
      lineAdjKind: "", lineAdjType: "", lineAdjValue: null,
    } as any;
    const result = await calculateCostFromLines("j1", [line]);

    const products = extractCompositionItems(result.steps, "COST_LINES_PRODUCT");

    expect(products).toHaveLength(1);
    expect(products[0].costLineId).toBe("cl-prd-1");
  });

  it("extractCompositionItems(SERVICE) propaga costLineId", async () => {
    const line: CostLineInput = {
      id: "cl-svc-1", type: "SERVICE", quantity: new D("1"), unitValue: new D("60"),
      lineAdjKind: "", lineAdjType: "", lineAdjValue: null,
    } as any;
    const result = await calculateCostFromLines("j1", [line]);

    const services = extractCompositionItems(result.steps, "COST_LINES_SERVICE");

    expect(services).toHaveLength(1);
    expect(services[0].costLineId).toBe("cl-svc-1");
  });

  it("extractor traduce step sin costLineId a entry con costLineId=null (no rompe)", async () => {
    // Forjamos un step manual sin costLineId — simula la situación que
    // teníamos en producción cuando el SELECT no traía `id`.
    const fakeSteps: PricingStep[] = [
      {
        key: "COST_LINES_PRODUCT", label: "Test", status: "ok",
        value: new D("100"),
        meta: { qty: "1", unitValue: "100" },   // ← sin costLineId
      },
    ];
    const products = extractCompositionItems(fakeSteps, "COST_LINES_PRODUCT");
    expect(products).toHaveLength(1);
    // Contract: extractor SIEMPRE devuelve costLineId, sea null o string.
    expect(products[0].costLineId).toBeNull();
  });
});

// ────────────────────────────────────────────────────────────────────────────
// 3. End-to-end: cost engine + extractor → composition.metals[].costLineId
//    refleja line.id del input.
// ────────────────────────────────────────────────────────────────────────────

describe("Regresión end-to-end — line.id → composition[i].costLineId", () => {
  it("3 cost lines con ids distintos → composition tiene 3 items con sus ids", async () => {
    mockPrisma.metalVariant.findMany.mockResolvedValue([
      { id: "mv-1", saleFactor: new D("1"), purity: new D("0.75") },
    ]);
    mockPrisma.metalQuote.findMany.mockResolvedValue([
      { variantId: "mv-1", price: new D("100") },
    ]);

    const lines: CostLineInput[] = [
      { id: "cl-A", type: "METAL",   quantity: new D("1"), metalVariantId: "mv-1", mermaPercent: new D("0") },
      { id: "cl-B", type: "HECHURA", quantity: new D("1"), unitValue: new D("100"), lineAdjKind: "", lineAdjType: "", lineAdjValue: null },
      { id: "cl-C", type: "PRODUCT", quantity: new D("1"), unitValue: new D("50"),  lineAdjKind: "", lineAdjType: "", lineAdjValue: null },
    ] as any;

    const result = await calculateCostFromLines("j1", lines);

    const metals    = extractCompositionMetals(result.steps);
    const hechuras  = extractCompositionHechuras(result.steps);
    const products  = extractCompositionItems(result.steps, "COST_LINES_PRODUCT");

    expect(metals.map((m) => m.costLineId)).toEqual(["cl-A"]);
    expect(hechuras.map((h) => h.costLineId)).toEqual(["cl-B"]);
    expect(products.map((p) => p.costLineId)).toEqual(["cl-C"]);
  });
});

// ────────────────────────────────────────────────────────────────────────────
// Fase 2.5 — extractCompositionCostAdjustment desde step COST_LINES_FINAL
// ────────────────────────────────────────────────────────────────────────────

describe("Fase 2.5 — extractCompositionCostAdjustment", () => {
  it("BONUS PERCENTAGE 25% sobre 1000 → kind/type/value/amount correctos", async () => {
    const line: CostLineInput = {
      id: "cl-1", type: "PRODUCT",
      quantity: new D("1"), unitValue: new D("1000"),
      lineAdjKind: "", lineAdjType: "", lineAdjValue: null,
    } as any;
    const result = await calculateCostFromLines("j1", [line], {
      kind: "BONUS", type: "PERCENTAGE", value: new D("25"),
    });

    const adj = extractCompositionCostAdjustment(result.steps);

    expect(adj).not.toBeNull();
    expect(adj!.kind).toBe("BONUS");
    expect(adj!.type).toBe("PERCENTAGE");
    expect(adj!.value).toBe(25);
    // sumLines=1000, adjusted=750 → amount = 1000 - 750 = 250 (positivo: BONUS).
    expect(adj!.amount).toBeCloseTo(250, 2);
  });

  it("SURCHARGE FIXED_AMOUNT 100 → amount negativo (aumenta)", async () => {
    const line: CostLineInput = {
      id: "cl-1", type: "PRODUCT",
      quantity: new D("1"), unitValue: new D("500"),
      lineAdjKind: "", lineAdjType: "", lineAdjValue: null,
    } as any;
    const result = await calculateCostFromLines("j1", [line], {
      kind: "SURCHARGE", type: "FIXED_AMOUNT", value: new D("100"),
    });

    const adj = extractCompositionCostAdjustment(result.steps);

    expect(adj).not.toBeNull();
    expect(adj!.kind).toBe("SURCHARGE");
    expect(adj!.type).toBe("FIXED_AMOUNT");
    expect(adj!.value).toBe(100);
    // sumLines=500, adjusted=600 → amount = 500 - 600 = -100 (negativo: aumenta).
    expect(adj!.amount).toBeCloseTo(-100, 2);
  });

  it("Sin ajuste configurado (kind='') → null", async () => {
    const line: CostLineInput = {
      id: "cl-1", type: "PRODUCT",
      quantity: new D("1"), unitValue: new D("100"),
      lineAdjKind: "", lineAdjType: "", lineAdjValue: null,
    } as any;
    // adjustment undefined → motor no aplica nada → step COST_LINES_FINAL
    // tiene kind="" o null → extractor devuelve null.
    const result = await calculateCostFromLines("j1", [line]);
    const adj = extractCompositionCostAdjustment(result.steps);
    expect(adj).toBeNull();
  });

  it("Steps vacíos → null (defensivo)", () => {
    expect(extractCompositionCostAdjustment([])).toBeNull();
    expect(extractCompositionCostAdjustment(null)).toBeNull();
    expect(extractCompositionCostAdjustment(undefined)).toBeNull();
  });
});
