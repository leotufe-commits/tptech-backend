// src/lib/pricing-engine/__tests__/tax-applies-to-override.test.ts
// =============================================================================
// Contrato: override de SOLO la base ("Aplica a") del impuesto HEREDADO,
// INDEPENDIENTE del valor. `computeLineTaxes(..., lineApplyOnOverride)`:
//   · sin override de valor → recalcula el impuesto configurado sobre la
//     base elegida (TOTAL / METAL / HECHURA), por encima del applyOn config.
//   · con override de VALOR (manualOverride) → el de valor gana; la base
//     manual se ignora (precedencia del contrato).
//   · determinístico: mismos inputs+base → mismo resultado (paridad
//     preview↔confirm, que llaman a esta MISMA función con la MISMA base).
// =============================================================================

import { describe, it, expect, vi, beforeEach } from "vitest";
import { Prisma } from "@prisma/client";

const mockPrisma = vi.hoisted(() => ({ tax: { findMany: vi.fn() } }));
vi.mock("../../prisma.js", () => ({ prisma: mockPrisma }));

import { computeLineTaxes } from "../pricing-engine.sale.js";

const D = Prisma.Decimal;
const fp = new D("1000");      // precio final (base TOTAL)
const bp = new D("1000");
const mh = { metalSale: 400, hechuraSale: 600 }; // base METAL / HECHURA
const JID = "j1";
const IVA = ["iva-21"];

beforeEach(() => {
  vi.clearAllMocks();
  mockPrisma.tax.findMany.mockResolvedValue([{
    id: "iva-21", name: "IVA", code: "IVA", taxType: "VAT",
    calculationType: "PERCENTAGE", applyOn: "TOTAL",
    rate: new D("21"), fixedAmount: null, validFrom: null, validTo: null,
  }]);
});

describe("computeLineTaxes — lineApplyOnOverride (base sin tocar valor)", () => {
  it("sin override: IVA 21% sobre TOTAL (1000) = 210", async () => {
    const { taxAmount, taxBreakdown } = await computeLineTaxes(
      JID, IVA, fp, bp, mh, null, null, null, null, null,
    );
    expect(taxAmount.toNumber()).toBeCloseTo(210, 4);
    expect(taxBreakdown[0].applyOn).toBe("TOTAL");
  });

  it("override base HECHURA: IVA 21% sobre 600 = 126 (valor heredado intacto)", async () => {
    const { taxAmount, taxBreakdown } = await computeLineTaxes(
      JID, IVA, fp, bp, mh, null, null, null, null, "HECHURA",
    );
    expect(taxAmount.toNumber()).toBeCloseTo(126, 4);
    expect(taxBreakdown[0].applyOn).toBe("HECHURA");
    expect(taxBreakdown[0].rate).toBe(21); // la tasa NO cambió
  });

  it("override base METAL: IVA 21% sobre 400 = 84", async () => {
    const { taxAmount } = await computeLineTaxes(
      JID, IVA, fp, bp, mh, null, null, null, null, "METAL",
    );
    expect(taxAmount.toNumber()).toBeCloseTo(84, 4);
  });

  it("gana sobre el override GLOBAL de entidad (precedencia máxima del operador)", async () => {
    const { taxBreakdown } = await computeLineTaxes(
      JID, IVA, fp, bp, mh, null,
      /* entityApplyOnOverride */ "METAL",
      null, null,
      /* lineApplyOnOverride */ "HECHURA",
    );
    expect(taxBreakdown[0].applyOn).toBe("HECHURA");
  });

  it("si hay override de VALOR, la base manual se ignora (precedencia del contrato)", async () => {
    const { taxAmount, taxBreakdown } = await computeLineTaxes(
      JID, IVA, fp, bp, mh, null, null, null,
      { mode: "PERCENT", value: 10, appliesTo: "TOTAL" }, // override de valor
      "HECHURA",                                          // base manual (ignorada)
    );
    expect(taxBreakdown[0].code).toBe("MANUAL_OVERRIDE");
    expect(taxAmount.toNumber()).toBeCloseTo(100, 4); // 10% de 1000 (TOTAL)
  });

  it("paridad: mismos inputs + misma base → mismo resultado (preview↔confirm)", async () => {
    const a = await computeLineTaxes(JID, IVA, fp, bp, mh, null, null, null, null, "HECHURA");
    const b = await computeLineTaxes(JID, IVA, fp, bp, mh, null, null, null, null, "HECHURA");
    expect(a.taxAmount.toNumber()).toBe(b.taxAmount.toNumber());
  });
});

describe("computeLineTaxes — bases fiscales completas (SUBTOTAL_* y METAL_Y_HECHURA)", () => {
  const fpAfter  = new D("1000"); // finalPrice (post-descuento)
  const bpBefore = new D("1200"); // basePrice (pre-descuento)

  it("SUBTOTAL_AFTER_DISCOUNT → base = finalPrice (1000) → 21% = 210", async () => {
    const { taxAmount, taxBreakdown } = await computeLineTaxes(
      JID, IVA, fpAfter, bpBefore, mh, null, null, null, null, "SUBTOTAL_AFTER_DISCOUNT",
    );
    expect(taxAmount.toNumber()).toBeCloseTo(210, 4);
    expect(taxBreakdown[0].applyOn).toBe("SUBTOTAL_AFTER_DISCOUNT");
  });

  it("SUBTOTAL_BEFORE_DISCOUNT → base = basePrice (1200) → 21% = 252", async () => {
    const { taxAmount } = await computeLineTaxes(
      JID, IVA, fpAfter, bpBefore, mh, null, null, null, null, "SUBTOTAL_BEFORE_DISCOUNT",
    );
    expect(taxAmount.toNumber()).toBeCloseTo(252, 4);
  });

  it("METAL_Y_HECHURA → artículo completo (= finalPrice) → 21% de 1000 = 210", async () => {
    const { taxAmount } = await computeLineTaxes(
      JID, IVA, fpAfter, bpBefore, mh, null, null, null, null, "METAL_Y_HECHURA",
    );
    expect(taxAmount.toNumber()).toBeCloseTo(210, 4);
  });

  it("las 6 bases producen resultados consistentes y distinguibles", async () => {
    const call = (b: string) =>
      computeLineTaxes(JID, IVA, fpAfter, bpBefore, mh, null, null, null, null, b);
    const total   = (await call("TOTAL")).taxAmount.toNumber();
    const metal   = (await call("METAL")).taxAmount.toNumber();
    const hechura = (await call("HECHURA")).taxAmount.toNumber();
    const before  = (await call("SUBTOTAL_BEFORE_DISCOUNT")).taxAmount.toNumber();
    expect(total).toBeCloseTo(210, 0);   // 21% × 1000
    expect(metal).toBeCloseTo(84, 0);    // 21% × 400
    expect(hechura).toBeCloseTo(126, 0); // 21% × 600
    expect(before).toBeCloseTo(252, 0);  // 21% × 1200
    expect(new Set([total, metal, hechura, before]).size).toBe(4);
  });
});
