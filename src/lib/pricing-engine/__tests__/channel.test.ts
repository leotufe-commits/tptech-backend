import { describe, it, expect } from "vitest";
import { applySalesChannelAdjustment } from "../pricing-engine.channel.js";

const ML = { id: "ch1", name: "Mercado Libre", adjustmentType: "PERCENTAGE" as const, adjustmentValue: 30 };
const MAYORISTA = { id: "ch2", name: "Mayorista", adjustmentType: "PERCENTAGE" as const, adjustmentValue: -10 };
const FIJO = { id: "ch3", name: "Canal Fijo", adjustmentType: "FIXED" as const, adjustmentValue: 500 };

describe("applySalesChannelAdjustment", () => {
  it("sin canal → devuelve precio sin modificar", () => {
    const r = applySalesChannelAdjustment(1000, null);
    expect(r.channelAmount).toBe(0);
    expect(r.finalAmount).toBe(1000);
    expect(r.baseAmount).toBe(1000);
  });

  it("PERCENTAGE positivo (+30%) — caso Mercado Libre", () => {
    const r = applySalesChannelAdjustment(1000, ML);
    expect(r.channelAmount).toBe(300);
    expect(r.finalAmount).toBe(1300);
    expect(r.channelName).toBe("Mercado Libre");
  });

  it("PERCENTAGE negativo (-10%) — descuento mayorista", () => {
    const r = applySalesChannelAdjustment(1000, MAYORISTA);
    expect(r.channelAmount).toBe(-100);
    expect(r.finalAmount).toBe(900);
  });

  it("FIXED positivo — monto fijo absoluto", () => {
    const r = applySalesChannelAdjustment(1000, FIJO);
    expect(r.channelAmount).toBe(500);
    expect(r.finalAmount).toBe(1500);
  });

  it("FIXED sobre baseAmount null → devuelve cero", () => {
    const r = applySalesChannelAdjustment(null, FIJO);
    expect(r.baseAmount).toBe(0);
    expect(r.channelAmount).toBe(500);
    expect(r.finalAmount).toBe(500);
  });

  it("canal + pago: canal primero, pago sobre resultado", () => {
    // Simula el orden: lista(1000) → canal +30% → pago +10%
    const afterChannel = applySalesChannelAdjustment(1000, ML);
    expect(afterChannel.finalAmount).toBe(1300);
    // Pago aplica sobre 1300 (lo hace resolveCheckoutPrice externamente)
    const paymentAdj = Math.round(1300 * 0.10 * 100) / 100;
    expect(paymentAdj).toBe(130);
    expect(afterChannel.finalAmount + paymentAdj).toBe(1430);
  });

  it("redondea a 2 decimales", () => {
    const ch = { id: "x", name: "X", adjustmentType: "PERCENTAGE" as const, adjustmentValue: 33.333 };
    const r = applySalesChannelAdjustment(100, ch);
    expect(r.channelAmount).toBe(33.33);
    expect(r.finalAmount).toBe(133.33);
  });
});
