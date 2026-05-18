// src/lib/pricing-engine/__tests__/tax-override-zero-priority.test.ts
// =============================================================================
// Caso real: MISMO artículo en dos líneas de la Factura.
//   · Línea A: sin override → impuesto heredado (IVA 21%).
//   · Línea B: override manual de impuesto = 0 ("Sin impuesto").
//
// El motor (`computeLineTaxes`) DEBE resolver cada línea por separado:
//   · override {value:0} → tax 0, con PRIORIDAD sobre el impuesto heredado
//     (NO fallback al IVA del artículo). No debe siquiera consultar los
//     taxIds heredados.
//   · sin override + taxIds heredados → IVA 21% normal.
//
// Así, dos líneas del mismo artículo producen taxAmount distinto. Si esto
// falla, el bug "ambas líneas muestran el mismo total c/ imp." es del motor.
// =============================================================================

import { describe, it, expect, vi, beforeEach } from "vitest";
import { Prisma } from "@prisma/client";

const mockPrisma = vi.hoisted(() => ({
  tax: { findMany: vi.fn() },
}));
vi.mock("../../prisma.js", () => ({ prisma: mockPrisma }));

import { computeLineTaxes } from "../pricing-engine.sale.js";

const D = Prisma.Decimal;
const finalPrice = new D("2246830.59");
const basePrice  = new D("2246830.59");
const JID = "j1";
const INHERITED_TAX_IDS = ["iva-21"];

beforeEach(() => {
  vi.clearAllMocks();
  // IVA 21% heredado del artículo (lo que usa la línea SIN override).
  mockPrisma.tax.findMany.mockResolvedValue([
    {
      id: "iva-21", name: "IVA", code: "IVA", taxType: "VAT",
      calculationType: "PERCENTAGE", applyOn: "TOTAL",
      rate: new D("21"), fixedAmount: null, validFrom: null, validTo: null,
    },
  ]);
});

describe("computeLineTaxes — override 0 gana sobre impuesto heredado", () => {
  it("LÍNEA B (override {PERCENT,0}) → tax 0 y NO consulta el impuesto heredado", async () => {
    const { taxBreakdown, taxAmount } = await computeLineTaxes(
      JID, INHERITED_TAX_IDS, finalPrice, basePrice, null, null, null, null,
      { mode: "PERCENT", value: 0, appliesTo: "TOTAL" },
    );

    expect(taxAmount.toNumber()).toBe(0);
    expect(taxBreakdown).toHaveLength(1);
    expect(taxBreakdown[0].taxAmount).toBe(0);
    expect(taxBreakdown[0].code).toBe("MANUAL_OVERRIDE");
    // Prioridad real: NO se cae al IVA heredado del artículo.
    expect(mockPrisma.tax.findMany).not.toHaveBeenCalled();
  });

  it("LÍNEA A (sin override) → IVA 21% heredado", async () => {
    const { taxBreakdown, taxAmount } = await computeLineTaxes(
      JID, INHERITED_TAX_IDS, finalPrice, basePrice, null, null, null, null,
      null,
    );

    // 21% de 2.246.830,59 = 471.834,4239
    expect(taxAmount.toNumber()).toBeCloseTo(471834.42, 1);
    expect(taxBreakdown).toHaveLength(1);
    expect(taxBreakdown[0].taxAmount).toBeCloseTo(471834.42, 1);
    expect(mockPrisma.tax.findMany).toHaveBeenCalledTimes(1);
  });

  it("dos líneas mismo artículo → taxAmount distinto (A gravada, B 0)", async () => {
    const a = await computeLineTaxes(
      JID, INHERITED_TAX_IDS, finalPrice, basePrice, null, null, null, null, null,
    );
    const b = await computeLineTaxes(
      JID, INHERITED_TAX_IDS, finalPrice, basePrice, null, null, null, null,
      { mode: "PERCENT", value: 0, appliesTo: "TOTAL" },
    );

    expect(a.taxAmount.toNumber()).toBeGreaterThan(0);
    expect(b.taxAmount.toNumber()).toBe(0);
    expect(a.taxAmount.toNumber()).not.toBe(b.taxAmount.toNumber());
  });

  it("override {AMOUNT,0} también limpia (no fallback)", async () => {
    const { taxAmount } = await computeLineTaxes(
      JID, INHERITED_TAX_IDS, finalPrice, basePrice, null, null, null, null,
      { mode: "AMOUNT", value: 0, appliesTo: "TOTAL" },
    );
    expect(taxAmount.toNumber()).toBe(0);
    expect(mockPrisma.tax.findMany).not.toHaveBeenCalled();
  });
});
