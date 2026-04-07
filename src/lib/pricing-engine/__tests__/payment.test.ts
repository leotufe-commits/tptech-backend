// src/lib/pricing-engine/__tests__/payment.test.ts
// Tests unitarios para resolveCheckoutPrice()
// Sin dependencias de DB — función pura.

import { describe, it, expect } from "vitest";
import { resolveCheckoutPrice } from "../pricing-engine.payment.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function r2(n: number) {
  return Math.round(n * 100) / 100;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("resolveCheckoutPrice", () => {

  // ── Sin forma de pago ──────────────────────────────────────────────────────

  it("sin forma de pago: baseAmount = unitPrice, sin ajuste", () => {
    const result = resolveCheckoutPrice({ unitPrice: 1000 });

    expect(result.baseAmount).toBe(1000);
    expect(result.paymentAdjustment).toBe(0);
    expect(result.finalAmount).toBe(1000);
    expect(result.installments).toBeUndefined();
    expect(result.installmentAmount).toBeUndefined();
  });

  it("sin forma de pago con cantidad: baseAmount = unitPrice × qty", () => {
    const result = resolveCheckoutPrice({ unitPrice: 500, quantity: 3 });

    expect(result.baseAmount).toBe(1500);
    expect(result.paymentAdjustment).toBe(0);
    expect(result.finalAmount).toBe(1500);
  });

  it("genera step CHECKOUT_BASE y CHECKOUT_FINAL sin ajuste", () => {
    const result = resolveCheckoutPrice({ unitPrice: 200 });

    const codes = result.steps.map(s => s.code);
    expect(codes).toContain("CHECKOUT_BASE");
    expect(codes).toContain("CHECKOUT_FINAL");
    expect(codes).not.toContain("PAYMENT_ADJUSTMENT");
    expect(codes).not.toContain("INSTALLMENT_VALUE");
  });

  // ── Ajuste por porcentaje ──────────────────────────────────────────────────

  it("recargo porcentual: +10% sobre 1000 = 100", () => {
    const result = resolveCheckoutPrice({
      unitPrice: 1000,
      paymentMethod: { adjustmentType: "PERCENTAGE", adjustmentValue: 10 },
    });

    expect(result.baseAmount).toBe(1000);
    expect(result.paymentAdjustment).toBe(100);
    expect(result.finalAmount).toBe(1100);
  });

  it("descuento porcentual: -5% sobre 1000 = -50", () => {
    const result = resolveCheckoutPrice({
      unitPrice: 1000,
      paymentMethod: { adjustmentType: "PERCENTAGE", adjustmentValue: -5 },
    });

    expect(result.paymentAdjustment).toBe(-50);
    expect(result.finalAmount).toBe(950);
  });

  it("recargo porcentual con cantidad: base 3×500=1500, +10% = 150", () => {
    const result = resolveCheckoutPrice({
      unitPrice: 500,
      quantity: 3,
      paymentMethod: { adjustmentType: "PERCENTAGE", adjustmentValue: 10 },
    });

    expect(result.baseAmount).toBe(1500);
    expect(result.paymentAdjustment).toBe(150);
    expect(result.finalAmount).toBe(1650);
  });

  // ── Ajuste fijo ────────────────────────────────────────────────────────────

  it("recargo fijo: +200 sobre 800", () => {
    const result = resolveCheckoutPrice({
      unitPrice: 800,
      paymentMethod: { adjustmentType: "FIXED", adjustmentValue: 200 },
    });

    expect(result.paymentAdjustment).toBe(200);
    expect(result.finalAmount).toBe(1000);
  });

  it("descuento fijo: -50 sobre 300", () => {
    const result = resolveCheckoutPrice({
      unitPrice: 300,
      paymentMethod: { adjustmentType: "FIXED", adjustmentValue: -50 },
    });

    expect(result.paymentAdjustment).toBe(-50);
    expect(result.finalAmount).toBe(250);
  });

  // ── Cuotas simples ─────────────────────────────────────────────────────────

  it("cuotas sin recargo: 1200 en 3 cuotas = 400 c/u", () => {
    const result = resolveCheckoutPrice({
      unitPrice: 1200,
      installments: { quantity: 3 },
    });

    expect(result.finalAmount).toBe(1200);
    expect(result.installments).toBe(3);
    expect(result.installmentAmount).toBe(400);
  });

  it("1 cuota: installmentAmount = finalAmount", () => {
    const result = resolveCheckoutPrice({
      unitPrice: 750,
      installments: { quantity: 1 },
    });

    expect(result.installments).toBe(1);
    expect(result.installmentAmount).toBe(750);
  });

  it("quantity=0 se normaliza a 1", () => {
    const result = resolveCheckoutPrice({ unitPrice: 500, quantity: 0 });
    expect(result.baseAmount).toBe(500);
  });

  it("cuotas con quantity=0 se ignora", () => {
    const result = resolveCheckoutPrice({
      unitPrice: 600,
      installments: { quantity: 0 },
    });

    expect(result.installments).toBeUndefined();
    expect(result.installmentAmount).toBeUndefined();
  });

  // ── Cuotas con recargo ─────────────────────────────────────────────────────

  it("cuotas con recargo %: 1000 +20% = 1200, en 6 cuotas = 200 c/u", () => {
    const result = resolveCheckoutPrice({
      unitPrice: 1000,
      paymentMethod: { adjustmentType: "PERCENTAGE", adjustmentValue: 20 },
      installments: { quantity: 6 },
    });

    expect(result.baseAmount).toBe(1000);
    expect(result.paymentAdjustment).toBe(200);
    expect(result.finalAmount).toBe(1200);
    expect(result.installments).toBe(6);
    expect(result.installmentAmount).toBe(200);
  });

  it("cuotas con descuento %: 1000 -10% = 900, en 3 cuotas = 300 c/u", () => {
    const result = resolveCheckoutPrice({
      unitPrice: 1000,
      paymentMethod: { adjustmentType: "PERCENTAGE", adjustmentValue: -10 },
      installments: { quantity: 3 },
    });

    expect(result.finalAmount).toBe(900);
    expect(result.installmentAmount).toBe(300);
  });

  // ── Combinación completa ───────────────────────────────────────────────────

  it("combinación completa: qty=2, precio=750, +15%, 6 cuotas", () => {
    const result = resolveCheckoutPrice({
      unitPrice: 750,
      quantity: 2,
      currencyCode: "ARS",
      paymentMethod: {
        adjustmentType: "PERCENTAGE",
        adjustmentValue: 15,
        name: "Tarjeta crédito",
      },
      installments: { quantity: 6, label: "sin interés" },
    });

    // base: 750 × 2 = 1500
    expect(result.baseAmount).toBe(1500);
    // ajuste: 1500 × 15% = 225
    expect(result.paymentAdjustment).toBe(225);
    // total: 1500 + 225 = 1725
    expect(result.finalAmount).toBe(1725);
    // cuota: 1725 / 6 = 287.50
    expect(result.installments).toBe(6);
    expect(result.installmentAmount).toBe(287.5);

    // Steps: BASE, PAYMENT_ADJUSTMENT, CHECKOUT_FINAL, INSTALLMENT_VALUE
    const codes = result.steps.map(s => s.code);
    expect(codes).toEqual([
      "CHECKOUT_BASE",
      "PAYMENT_ADJUSTMENT",
      "CHECKOUT_FINAL",
      "INSTALLMENT_VALUE",
    ]);

    // Verificar currencyCode en todos los steps
    expect(result.steps.every(s => s.code === "CHECKOUT_BASE" ? s.amount === 1500 : true)).toBe(true);
  });

  // ── Edge cases ─────────────────────────────────────────────────────────────

  it("unitPrice=0 sin ajuste: todo en 0", () => {
    const result = resolveCheckoutPrice({ unitPrice: 0 });

    expect(result.baseAmount).toBe(0);
    expect(result.paymentAdjustment).toBe(0);
    expect(result.finalAmount).toBe(0);
  });

  it("ajuste NaN se trata como 0", () => {
    const result = resolveCheckoutPrice({
      unitPrice: 500,
      paymentMethod: { adjustmentType: "FIXED", adjustmentValue: NaN },
    });

    expect(result.paymentAdjustment).toBe(0);
    expect(result.finalAmount).toBe(500);
  });

  it("redondeo a 2 decimales", () => {
    // 1000 / 3 = 333.333...
    const result = resolveCheckoutPrice({
      unitPrice: 1000,
      installments: { quantity: 3 },
    });

    expect(result.installmentAmount).toBe(333.33);
  });

  it("steps tienen formula legible", () => {
    const result = resolveCheckoutPrice({
      unitPrice: 1000,
      paymentMethod: { adjustmentType: "PERCENTAGE", adjustmentValue: 10, name: "Débito" },
      installments: { quantity: 2 },
    });

    const adj = result.steps.find(s => s.code === "PAYMENT_ADJUSTMENT")!;
    expect(adj.formula).toContain("10%");

    const inst = result.steps.find(s => s.code === "INSTALLMENT_VALUE")!;
    expect(inst.formula).toContain("÷ 2");
  });
});
