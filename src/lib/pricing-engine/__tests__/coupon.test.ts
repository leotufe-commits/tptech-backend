import { describe, it, expect } from "vitest";
import { applyCouponAdjustment } from "../pricing-engine.coupon.js";

const PERCENT_10: import("../pricing-engine.coupon.js").CouponInput = {
  id: "c1", code: "DESC10", name: "10% off",
  discountType: "PERCENTAGE", discountValue: 10,
};

const FIXED_200: import("../pricing-engine.coupon.js").CouponInput = {
  id: "c2", code: "CUPON200", name: "$200 off",
  discountType: "FIXED_AMOUNT", discountValue: 200,
};

describe("applyCouponAdjustment", () => {
  it("sin cupón → devuelve precio sin modificar", () => {
    const r = applyCouponAdjustment(1000, null);
    expect(r.discountAmount).toBe(0);
    expect(r.finalAmount).toBe(1000);
    expect(r.applied).toBe(false);
  });

  it("PERCENTAGE 10% → descuento correcto", () => {
    const r = applyCouponAdjustment(1000, PERCENT_10);
    expect(r.discountAmount).toBe(100);
    expect(r.finalAmount).toBe(900);
    expect(r.applied).toBe(true);
    expect(r.couponCode).toBe("DESC10");
  });

  it("FIXED_AMOUNT 200 → descuento correcto", () => {
    const r = applyCouponAdjustment(1000, FIXED_200);
    expect(r.discountAmount).toBe(200);
    expect(r.finalAmount).toBe(800);
    expect(r.applied).toBe(true);
  });

  it("FIXED_AMOUNT mayor que precio → precio no negativo", () => {
    const bigFixed = { ...FIXED_200, discountValue: 5000 };
    const r = applyCouponAdjustment(100, bigFixed);
    expect(r.discountAmount).toBe(100);
    expect(r.finalAmount).toBe(0);
  });

  it("PERCENTAGE 100% → precio queda en 0", () => {
    const all = { ...PERCENT_10, discountValue: 100 };
    const r = applyCouponAdjustment(500, all);
    expect(r.discountAmount).toBe(500);
    expect(r.finalAmount).toBe(0);
  });

  it("PERCENTAGE >100% → acotado a 100%", () => {
    const over = { ...PERCENT_10, discountValue: 150 };
    const r = applyCouponAdjustment(1000, over);
    expect(r.discountAmount).toBe(1000);
    expect(r.finalAmount).toBe(0);
  });

  it("canal + cupón — composición en orden correcto", () => {
    // Canal +30% sobre 1000 → 1300
    const afterChannel = 1300;
    // Cupón 10% sobre 1300 → -130
    const r = applyCouponAdjustment(afterChannel, PERCENT_10);
    expect(r.baseAmount).toBe(1300);
    expect(r.discountAmount).toBe(130);
    expect(r.finalAmount).toBe(1170);
  });

  it("base null → baseAmount 0, descuento 0", () => {
    const r = applyCouponAdjustment(null, PERCENT_10);
    expect(r.baseAmount).toBe(0);
    expect(r.discountAmount).toBe(0);
    expect(r.finalAmount).toBe(0);
  });

  it("redondea a 2 decimales", () => {
    const c = { ...PERCENT_10, discountValue: 33.333 };
    const r = applyCouponAdjustment(100, c);
    expect(r.discountAmount).toBe(33.33);
    expect(r.finalAmount).toBe(66.67);
  });
});
