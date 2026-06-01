// src/lib/pricing-engine/__tests__/discount-tax-net-base.test.ts
// =============================================================================
// BUG REAL (Factura): con bonificación/descuento + impuesto por base parcial,
// el impuesto se calculaba sobre el componente BRUTO. Debe calcularse sobre la
// base NETA luego del descuento que afectó esa misma base.
//
// `resolveTaxComponentBase` (pura, determinística) es la única fuente que usan
// preview y confirm para alimentar `computeLineTaxes` con la base por
// componente → garantiza la matriz y la paridad preview↔confirm.
//
// Números EXACTOS del caso reportado:
//   metalSale bruto   = 226.875
//   hechuraSale bruto =  15.000
//   total bruto       = 241.875
//   bonificación 10%
// =============================================================================

import { describe, it, expect, vi, beforeEach } from "vitest";
import { Prisma } from "@prisma/client";

const mockPrisma = vi.hoisted(() => ({ tax: { findMany: vi.fn() } }));
vi.mock("../../prisma.js", () => ({ prisma: mockPrisma }));

import { resolveTaxComponentBase, computeLineTaxes } from "../pricing-engine.sale.js";

const D = Prisma.Decimal;
const JID = "j1";
const TAX10 = ["tax-10"];

const M_GROSS = 226875;
const H_GROSS = 15000;
const GROSS   = M_GROSS + H_GROSS; // 241875

const adj = (amount: number) => [{ amount }];
const none: { amount: number }[] = [];

beforeEach(() => {
  vi.clearAllMocks();
  mockPrisma.tax.findMany.mockResolvedValue([{
    id: "tax-10", name: "IMP", code: "IMP", taxType: "OTHER",
    calculationType: "PERCENTAGE", applyOn: "TOTAL",
    rate: new D("10"), fixedAmount: null, validFrom: null, validTo: null,
  }]);
});

// Helper: base bruta del componente.
const GROSS_MHB = { metalSale: M_GROSS, hechuraSale: H_GROSS };

describe("resolveTaxComponentBase — matriz descuento/base imponible", () => {
  it("1. Bonif METAL 10% → metal NETO; hechura intacta", () => {
    const fp = GROSS - M_GROSS * 0.1; // 219187.5
    const b = resolveTaxComponentBase(GROSS_MHB, adj(M_GROSS * 0.1), none, fp)!;
    expect(b.metalSale).toBeCloseTo(204187.5, 4); // 226875 − 22687.5
    expect(b.hechuraSale).toBeCloseTo(15000, 4);
  });

  it("2. Bonif HECHURA 10% → hechura NETA; metal intacto", () => {
    const fp = GROSS - H_GROSS * 0.1; // 240375
    const b = resolveTaxComponentBase(GROSS_MHB, none, adj(H_GROSS * 0.1), fp)!;
    expect(b.hechuraSale).toBeCloseTo(13500, 4); // 15000 − 1500
    expect(b.metalSale).toBeCloseTo(226875, 4);
  });

  it("3. Bonif METAL + Impuesto HECHURA → hechura BRUTA (descuento no tocó hechura)", () => {
    const fp = GROSS - M_GROSS * 0.1;
    const b = resolveTaxComponentBase(GROSS_MHB, adj(M_GROSS * 0.1), none, fp)!;
    expect(b.hechuraSale).toBeCloseTo(15000, 4);
  });

  it("4. Bonif HECHURA + Impuesto METAL → metal BRUTO (descuento no tocó metal)", () => {
    const fp = GROSS - H_GROSS * 0.1;
    const b = resolveTaxComponentBase(GROSS_MHB, none, adj(H_GROSS * 0.1), fp)!;
    expect(b.metalSale).toBeCloseTo(226875, 4);
  });

  it("6. Bonif TOTAL 10% (no trackeada por componente) → prorrateo por participación bruta", () => {
    const fp = GROSS - GROSS * 0.1; // 217687.5
    const b = resolveTaxComponentBase(GROSS_MHB, none, none, fp)!;
    // 10% prorrateado: metal − 10% metal, hechura − 10% hechura.
    expect(b.metalSale).toBeCloseTo(204187.5, 4);
    expect(b.hechuraSale).toBeCloseTo(13500, 4);
  });

  it("sin breakdown → null (no cambia comportamiento previo)", () => {
    expect(resolveTaxComponentBase(null, none, none, 0)).toBeNull();
  });
});

describe("end-to-end computeLineTaxes con base NETA (impuesto 10%)", () => {
  it("Caso 1 — Bonif METAL 10% + Impuesto METAL 10% = 20.418,75 (no 22.687,50)", async () => {
    const fp = new D(String(GROSS - M_GROSS * 0.1));
    const mhb = resolveTaxComponentBase(GROSS_MHB, adj(M_GROSS * 0.1), none, fp.toNumber());
    const { taxAmount } = await computeLineTaxes(JID, TAX10, fp, fp, mhb, null, null, null, null, "METAL");
    expect(taxAmount.toNumber()).toBeCloseTo(20418.75, 4);
  });

  it("Caso 2 — Bonif HECHURA 10% + Impuesto HECHURA 10% = 1.350 (no 1.500)", async () => {
    const fp = new D(String(GROSS - H_GROSS * 0.1));
    const mhb = resolveTaxComponentBase(GROSS_MHB, none, adj(H_GROSS * 0.1), fp.toNumber());
    const { taxAmount } = await computeLineTaxes(JID, TAX10, fp, fp, mhb, null, null, null, null, "HECHURA");
    expect(taxAmount.toNumber()).toBeCloseTo(1350, 4);
  });

  it("Caso 3 — Bonif METAL + Impuesto HECHURA = 1.500 (hechura bruta)", async () => {
    const fp = new D(String(GROSS - M_GROSS * 0.1));
    const mhb = resolveTaxComponentBase(GROSS_MHB, adj(M_GROSS * 0.1), none, fp.toNumber());
    const { taxAmount } = await computeLineTaxes(JID, TAX10, fp, fp, mhb, null, null, null, null, "HECHURA");
    expect(taxAmount.toNumber()).toBeCloseTo(1500, 4);
  });

  it("Caso 4 — Bonif HECHURA + Impuesto METAL = 22.687,50 (metal bruto)", async () => {
    const fp = new D(String(GROSS - H_GROSS * 0.1));
    const mhb = resolveTaxComponentBase(GROSS_MHB, none, adj(H_GROSS * 0.1), fp.toNumber());
    const { taxAmount } = await computeLineTaxes(JID, TAX10, fp, fp, mhb, null, null, null, null, "METAL");
    expect(taxAmount.toNumber()).toBeCloseTo(22687.5, 4);
  });

  it("Caso 5 — Bonif TOTAL 10% + Impuesto TOTAL 10% = 21.768,75 (total neto)", async () => {
    const fp = new D(String(GROSS - GROSS * 0.1)); // 217687.5
    const mhb = resolveTaxComponentBase(GROSS_MHB, none, none, fp.toNumber());
    const { taxAmount } = await computeLineTaxes(JID, TAX10, fp, fp, mhb, null, null, null, null, "TOTAL");
    expect(taxAmount.toNumber()).toBeCloseTo(21768.75, 4); // 10% × 217687.5
  });

  it("Caso 6 — Bonif TOTAL 10% + Impuesto METAL 10% = 20.418,75 (prorrateo)", async () => {
    const fp = new D(String(GROSS - GROSS * 0.1));
    const mhb = resolveTaxComponentBase(GROSS_MHB, none, none, fp.toNumber());
    const { taxAmount } = await computeLineTaxes(JID, TAX10, fp, fp, mhb, null, null, null, null, "METAL");
    expect(taxAmount.toNumber()).toBeCloseTo(20418.75, 4); // 10% × 204187.5
  });

  it("CASO REAL reportado (lista Unificada) — Bonif 10% Solo hechura + Imp 10% Solo hechura", async () => {
    // metalSale 381.562,50 · hechuraSale 18.500 · total 400.062,50
    const M = 381562.5;
    const H = 18500;
    const TOTAL = M + H; // 400062.5
    const disc = H * 0.1; // 1850 (bonificación sobre hechura)
    const fp = TOTAL - disc; // 398212.5 (finalPrice neto)

    const mhb = resolveTaxComponentBase(
      { metalSale: M, hechuraSale: H }, none, adj(disc), fp,
    )!;
    expect(mhb.hechuraSale).toBeCloseTo(16650, 4); // base imponible NETA
    expect(mhb.metalSale).toBeCloseTo(381562.5, 4);

    const fpD = new D(String(fp));
    const { taxAmount } = await computeLineTaxes(
      JID, TAX10, fpD, fpD, mhb, null, null, null, null, "HECHURA",
    );
    expect(taxAmount.toNumber()).toBeCloseTo(1665, 4); // NO 1850

    // Criterio de aceptación visual: total línea.
    const discountAmount = disc;             // 1850
    const total = TOTAL - discountAmount + taxAmount.toNumber();
    expect(discountAmount).toBeCloseTo(1850, 4);
    expect(total).toBeCloseTo(399877.5, 4);
  });

  it("paridad preview↔confirm: misma base NETA → mismo impuesto (determinístico)", async () => {
    const fp = new D(String(GROSS - M_GROSS * 0.1));
    const mhb = resolveTaxComponentBase(GROSS_MHB, adj(M_GROSS * 0.1), none, fp.toNumber());
    const a = await computeLineTaxes(JID, TAX10, fp, fp, mhb, null, null, null, null, "METAL");
    const b = await computeLineTaxes(JID, TAX10, fp, fp, mhb, null, null, null, null, "METAL");
    expect(a.taxAmount.toNumber()).toBe(b.taxAmount.toNumber());
    expect(a.taxAmount.toNumber()).toBeCloseTo(20418.75, 4);
  });
});
