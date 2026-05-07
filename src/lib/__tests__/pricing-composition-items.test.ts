// src/lib/__tests__/pricing-composition-items.test.ts
// =============================================================================
// FASE F1.3 G4.1.1 — tests para extractCompositionItems.
//
// Verifica que el helper extrae correctamente bloques PRODUCT/SERVICE desde
// los steps[] que ya emite el motor cost (pricing-engine.cost.ts:279-294),
// con cero recálculo monetario (POLICY R4.5).
//
// Cubre:
//   · Filtra correctamente por key (COST_LINES_PRODUCT vs SERVICE)
//   · status="ok" required (skipped/error → ignorados)
//   · Mapeo de meta.qty / unitValue / step.value sin transformación
//   · Catalog map opcional (con/sin)
//   · Fallback a lineLabel cuando no hay catalog
//   · Ajuste per-línea (BONUS/SURCHARGE)
//   · Campos no expuestos hoy (costLineId, catalogItemId, affectsStock,
//     lineAdjAmount) → null por compatibilidad
//   · Steps null/empty/array vacío → []
// =============================================================================

import { describe, it, expect } from "vitest";
import { Prisma } from "@prisma/client";
import { extractCompositionItems } from "../pricing-composition.js";
import type { PricingStep } from "../pricing-engine/pricing-engine.js";

const D = Prisma.Decimal;

// ─────────────────────────────────────────────────────────────────────────────
// Helpers — armar steps[] mock con shape realista del motor
// ─────────────────────────────────────────────────────────────────────────────

function makeStep(overrides: Partial<PricingStep> & { meta?: any } = {}): PricingStep {
  return {
    key:    "COST_LINES_PRODUCT",
    label:  "Producto Test",
    status: "ok",
    value:  new D(0),
    ...overrides,
  } as PricingStep;
}

// =============================================================================
// 1. Filtrado básico por key + status
// =============================================================================

describe("extractCompositionItems — filtrado", () => {
  it("baseline correct: filtra por key COST_LINES_PRODUCT", () => {
    const steps = [
      makeStep({ key: "COST_LINES_PRODUCT", value: new D(100) }),
      makeStep({ key: "COST_LINES_SERVICE", value: new D(50) }),
      makeStep({ key: "COST_LINES_METAL",   value: new D(800) }),
    ];
    const r = extractCompositionItems(steps, "COST_LINES_PRODUCT");
    expect(r).toHaveLength(1);
    expect(r[0].totalValue).toBe(100);
  });

  it("baseline correct: filtra por key COST_LINES_SERVICE", () => {
    const steps = [
      makeStep({ key: "COST_LINES_PRODUCT", value: new D(100) }),
      makeStep({ key: "COST_LINES_SERVICE", value: new D(50) }),
    ];
    const r = extractCompositionItems(steps, "COST_LINES_SERVICE");
    expect(r).toHaveLength(1);
    expect(r[0].totalValue).toBe(50);
  });

  it("baseline correct: ignora steps con status != 'ok'", () => {
    const steps = [
      makeStep({ status: "ok",      value: new D(100) }),
      makeStep({ status: "skipped", value: new D(200) }),
      makeStep({ status: "missing", value: null }),
      makeStep({ status: "partial", value: new D(50) }),
    ];
    const r = extractCompositionItems(steps, "COST_LINES_PRODUCT");
    expect(r).toHaveLength(1);
    expect(r[0].totalValue).toBe(100);
  });
});

// =============================================================================
// 2. Edge cases: steps null / vacío / array no válido
// =============================================================================

describe("extractCompositionItems — edge cases entrada", () => {
  it("baseline correct: null devuelve []", () => {
    expect(extractCompositionItems(null, "COST_LINES_PRODUCT")).toEqual([]);
  });

  it("baseline correct: undefined devuelve []", () => {
    expect(extractCompositionItems(undefined, "COST_LINES_PRODUCT")).toEqual([]);
  });

  it("baseline correct: array vacío devuelve []", () => {
    expect(extractCompositionItems([], "COST_LINES_PRODUCT")).toEqual([]);
  });

  it("baseline correct: array sin steps del key target devuelve []", () => {
    const steps = [makeStep({ key: "COST_LINES_METAL", value: new D(100) })];
    expect(extractCompositionItems(steps, "COST_LINES_PRODUCT")).toEqual([]);
  });
});

// =============================================================================
// 3. Mapeo de campos básicos (qty, unitValue, totalValue)
// =============================================================================

describe("extractCompositionItems — mapeo de valores numéricos", () => {
  it("baseline correct: qty/unitValue/totalValue passthrough sin transformación", () => {
    const steps = [makeStep({
      value: new D(150),
      meta: {
        qty:       "3",
        unitValue: "50",
      },
    })];
    const [item] = extractCompositionItems(steps, "COST_LINES_PRODUCT");
    expect(item.quantity).toBe(3);
    expect(item.unitValue).toBe(50);
    expect(item.totalValue).toBe(150);
  });

  it("baseline correct: meta.qty ausente → 0", () => {
    const steps = [makeStep({
      value: new D(100),
      meta:  { unitValue: "100" },
    })];
    const [item] = extractCompositionItems(steps, "COST_LINES_PRODUCT");
    expect(item.quantity).toBe(0);
    expect(item.unitValue).toBe(100);
    expect(item.totalValue).toBe(100);
  });

  it("baseline correct: step.value es la fuente de verdad para totalValue (no qty × unit)", () => {
    // Caso real: motor aplicó ajuste BONUS −10% → step.value (90) ≠ qty × unit (100)
    const steps = [makeStep({
      value: new D(90),  // post ajuste
      meta: {
        qty:          "1",
        unitValue:    "100",
        lineAdjKind:  "BONUS",
        lineAdjType:  "PERCENTAGE",
        lineAdjValue: "10",
      },
    })];
    const [item] = extractCompositionItems(steps, "COST_LINES_PRODUCT");
    expect(item.totalValue).toBe(90);  // backend value, NO recalculo
    expect(item.quantity).toBe(1);
    expect(item.unitValue).toBe(100);
  });
});

// =============================================================================
// 4. Catalog map (con / sin) — resolución de code/name
// =============================================================================

describe("extractCompositionItems — catalog map opcional", () => {
  it("baseline correct: sin catalog map, usa lineCode + lineLabel del meta", () => {
    const steps = [makeStep({
      value: new D(100),
      label: "Step label fallback",
      meta:  {
        qty:       "1",
        unitValue: "100",
        lineCode:  "PROD-01",
        lineLabel: "Producto interno",
      },
    })];
    const [item] = extractCompositionItems(steps, "COST_LINES_PRODUCT");
    expect(item.catalogItemCode).toBe("PROD-01");
    expect(item.catalogItemName).toBe("Producto interno");
  });

  it("baseline correct: sin lineLabel, cae a step.label como fallback", () => {
    const steps = [makeStep({
      value: new D(100),
      label: "Step label fallback",
      meta:  { qty: "1", unitValue: "100" },
    })];
    const [item] = extractCompositionItems(steps, "COST_LINES_PRODUCT");
    expect(item.catalogItemName).toBe("Step label fallback");
  });

  it("baseline correct: con catalog map, prefiere catalog code/name sobre meta", () => {
    const catalog = new Map([
      ["art-1", { code: "CATALOG-CODE", name: "Catalog Name Resolved" }],
    ]);
    const steps = [makeStep({
      value: new D(100),
      meta:  {
        qty:           "1",
        unitValue:     "100",
        catalogItemId: "art-1",
        lineCode:      "META-CODE",       // catalog gana
        lineLabel:     "Meta Label",      // catalog gana
      },
    })];
    const [item] = extractCompositionItems(steps, "COST_LINES_PRODUCT", catalog);
    expect(item.catalogItemId).toBe("art-1");
    expect(item.catalogItemCode).toBe("CATALOG-CODE");
    expect(item.catalogItemName).toBe("Catalog Name Resolved");
  });

  it("baseline correct: catalog map sin entrada para el id, cae a meta", () => {
    const catalog = new Map([
      ["other-id", { code: "X", name: "Y" }],
    ]);
    const steps = [makeStep({
      value: new D(100),
      meta:  {
        qty:           "1",
        unitValue:     "100",
        catalogItemId: "art-1",
        lineCode:      "FALLBACK",
        lineLabel:     "Fallback Label",
      },
    })];
    const [item] = extractCompositionItems(steps, "COST_LINES_PRODUCT", catalog);
    expect(item.catalogItemCode).toBe("FALLBACK");
    expect(item.catalogItemName).toBe("Fallback Label");
  });
});

// =============================================================================
// 5. Ajuste per-línea (BONUS / SURCHARGE)
// =============================================================================

describe("extractCompositionItems — ajuste per-línea", () => {
  it("baseline correct: BONUS PERCENTAGE 10%", () => {
    const steps = [makeStep({
      value: new D(90),
      meta:  {
        qty:          "1",
        unitValue:    "100",
        lineAdjKind:  "BONUS",
        lineAdjType:  "PERCENTAGE",
        lineAdjValue: "10",
      },
    })];
    const [item] = extractCompositionItems(steps, "COST_LINES_PRODUCT");
    expect(item.lineAdjKind).toBe("BONUS");
    expect(item.lineAdjType).toBe("PERCENTAGE");
    expect(item.lineAdjValue).toBe(10);
    // lineAdjAmount no expuesto hoy → null
    expect(item.lineAdjAmount).toBeNull();
  });

  it("baseline correct: SURCHARGE FIXED_AMOUNT", () => {
    const steps = [makeStep({
      value: new D(150),
      meta:  {
        qty:          "1",
        unitValue:    "100",
        lineAdjKind:  "SURCHARGE",
        lineAdjType:  "FIXED_AMOUNT",
        lineAdjValue: "50",
      },
    })];
    const [item] = extractCompositionItems(steps, "COST_LINES_PRODUCT");
    expect(item.lineAdjKind).toBe("SURCHARGE");
    expect(item.lineAdjType).toBe("FIXED_AMOUNT");
    expect(item.lineAdjValue).toBe(50);
  });

  it("baseline correct: sin ajuste, kind/type/value/amount son null", () => {
    const steps = [makeStep({
      value: new D(100),
      meta:  { qty: "1", unitValue: "100" },
    })];
    const [item] = extractCompositionItems(steps, "COST_LINES_PRODUCT");
    expect(item.lineAdjKind).toBeNull();
    expect(item.lineAdjType).toBeNull();
    expect(item.lineAdjValue).toBeNull();
    expect(item.lineAdjAmount).toBeNull();
  });

  it("baseline correct: kind/type inválidos → null (defensivo)", () => {
    const steps = [makeStep({
      value: new D(100),
      meta:  {
        qty:          "1",
        unitValue:    "100",
        lineAdjKind:  "OTHER_INVALID",     // no es BONUS/SURCHARGE
        lineAdjType:  "WEIRD_TYPE",
        lineAdjValue: "5",
      },
    })];
    const [item] = extractCompositionItems(steps, "COST_LINES_PRODUCT");
    expect(item.lineAdjKind).toBeNull();
    expect(item.lineAdjType).toBeNull();
  });
});

// =============================================================================
// 6. Campos no expuestos hoy → null por compatibilidad (G4.1.2 los emitirá)
// =============================================================================

describe("extractCompositionItems — campos no expuestos hoy en meta", () => {
  it("baseline correct: costLineId / catalogItemId / affectsStock null cuando no vienen", () => {
    const steps = [makeStep({
      value: new D(100),
      meta:  { qty: "1", unitValue: "100" },
    })];
    const [item] = extractCompositionItems(steps, "COST_LINES_PRODUCT");
    expect(item.costLineId).toBeNull();
    expect(item.catalogItemId).toBeNull();
    expect(item.affectsStock).toBeNull();
  });

  it("baseline correct: cuando G4.1.2 los emita, se passthroughean", () => {
    // Forward-compat — simula meta extendida
    const steps = [makeStep({
      value: new D(100),
      meta:  {
        qty:           "1",
        unitValue:     "100",
        costLineId:    "cl-123",
        catalogItemId: "art-456",
        affectsStock:  true,
      },
    })];
    const [item] = extractCompositionItems(steps, "COST_LINES_PRODUCT");
    expect(item.costLineId).toBe("cl-123");
    expect(item.catalogItemId).toBe("art-456");
    expect(item.affectsStock).toBe(true);
  });
});

// =============================================================================
// 7. Múltiples items en el mismo array
// =============================================================================

describe("extractCompositionItems — múltiples items", () => {
  it("baseline correct: 3 PRODUCTs en steps → array con 3 items", () => {
    const steps = [
      makeStep({ key: "COST_LINES_PRODUCT", value: new D(100), meta: { qty: "1", unitValue: "100", lineLabel: "P1" } }),
      makeStep({ key: "COST_LINES_PRODUCT", value: new D(200), meta: { qty: "2", unitValue: "100", lineLabel: "P2" } }),
      makeStep({ key: "COST_LINES_PRODUCT", value: new D(50),  meta: { qty: "1", unitValue: "50",  lineLabel: "P3" } }),
    ];
    const r = extractCompositionItems(steps, "COST_LINES_PRODUCT");
    expect(r).toHaveLength(3);
    expect(r[0].catalogItemName).toBe("P1");
    expect(r[1].catalogItemName).toBe("P2");
    expect(r[2].catalogItemName).toBe("P3");
    // Suma honesta — el caller puede agregarlos sin recalcular individualmente
    expect(r.reduce((s, i) => s + i.totalValue, 0)).toBe(350);
  });

  it("baseline correct: orden preservado del array de steps", () => {
    const steps = [
      makeStep({ value: new D(1), meta: { lineLabel: "Z" } }),
      makeStep({ value: new D(2), meta: { lineLabel: "A" } }),
      makeStep({ value: new D(3), meta: { lineLabel: "M" } }),
    ];
    const r = extractCompositionItems(steps, "COST_LINES_PRODUCT");
    expect(r.map(i => i.catalogItemName)).toEqual(["Z", "A", "M"]);
  });
});
