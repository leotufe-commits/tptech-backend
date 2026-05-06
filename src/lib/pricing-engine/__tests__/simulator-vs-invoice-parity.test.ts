// src/lib/pricing-engine/__tests__/simulator-vs-invoice-parity.test.ts
// ============================================================================
// Tests de paridad numérica simulador ↔ factura.
//
// Tanto el endpoint del Simulador (`articles.controller.getPricingPreview`)
// como el de Factura (`sales.service.previewSale`) calculan sus totales con
// `computeSaleDocumentTotals` desde la fase de unificación. La única
// diferencia documentada es que el Simulador NUNCA aplica redondeo a nivel
// comprobante (pasa `documentRounding: null`) — la Factura sí lo aplica
// cuando la política `Jewelry.documentRoundingEnabled` está activa.
//
// Estos tests fijan el contrato: dada la misma línea sintética + el mismo
// contexto comercial, los outputs de ambos flujos deben coincidir. Cuando
// hay política doc activa, la diferencia debe vivir SOLO en `total` y
// `roundingAdjustment`; el resto (taxAmount, taxableBase, etc.) queda
// invariante.
//
// Capa pura: sin DB, sin mocks. Las diferencias por modo de lista
// (MARGIN_TOTAL / COST_PER_GRAM / METAL_HECHURA) son irrelevantes acá: el
// motor de doc-totals solo recibe valores ya resueltos por el motor de
// línea, así que se modelan como distintas combinaciones de
// `basePrice/unitPrice/lineTotal/lineTaxAmount`.
// ============================================================================

import { describe, it, expect } from "vitest";
import {
  computeSaleDocumentTotals,
  type ChannelAdjustmentInput,
  type CouponInput,
  type DocumentRoundingInput,
  type SaleDocumentTotalsLineInput,
  type SaleDocumentTotals,
} from "../pricing-engine.js";

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

type ParityContext = {
  channel?:                 ChannelAdjustmentInput | null;
  coupon?:                  CouponInput            | null;
  paymentAdjustmentAmount?: number;
  shippingAmount?:          number;
  globalDiscountAmount?:    number;
  /** Política doc del tenant. Solo la usa la factura. */
  documentRounding?:        DocumentRoundingInput  | null;
};

/** Simulador: SIEMPRE pasa `documentRounding: null` — regla absoluta. */
function runSimulator(
  line: SaleDocumentTotalsLineInput,
  ctx: ParityContext = {},
): SaleDocumentTotals {
  return computeSaleDocumentTotals({
    lines:                   [line],
    channel:                 ctx.channel ?? null,
    coupon:                  ctx.coupon  ?? null,
    paymentAdjustmentAmount: ctx.paymentAdjustmentAmount ?? 0,
    shippingAmount:          ctx.shippingAmount          ?? 0,
    globalDiscountAmount:    ctx.globalDiscountAmount    ?? 0,
    roundingAdjustment:      0,
    documentRounding:        null,
  });
}

/** Factura: respeta la política doc del tenant. */
function runInvoice(
  line: SaleDocumentTotalsLineInput,
  ctx: ParityContext = {},
): SaleDocumentTotals {
  return computeSaleDocumentTotals({
    lines:                   [line],
    channel:                 ctx.channel ?? null,
    coupon:                  ctx.coupon  ?? null,
    paymentAdjustmentAmount: ctx.paymentAdjustmentAmount ?? 0,
    shippingAmount:          ctx.shippingAmount          ?? 0,
    globalDiscountAmount:    ctx.globalDiscountAmount    ?? 0,
    roundingAdjustment:      0,
    documentRounding:        ctx.documentRounding ?? null,
  });
}

const line = (over: Partial<SaleDocumentTotalsLineInput> = {}): SaleDocumentTotalsLineInput => ({
  quantity:      1,
  basePrice:     1000,
  unitPrice:     1000,
  lineTotal:     1000,
  lineTaxAmount: 0,
  ...over,
});

/** Igualdad estricta en TODOS los campos numéricos del documento. */
function expectFullParity(sim: SaleDocumentTotals, inv: SaleDocumentTotals) {
  expect(sim.subtotalBeforeDiscounts   ).toBeCloseTo(inv.subtotalBeforeDiscounts,    2);
  expect(sim.lineDiscountAmount        ).toBeCloseTo(inv.lineDiscountAmount,         2);
  expect(sim.subtotalAfterLineDiscounts).toBeCloseTo(inv.subtotalAfterLineDiscounts, 2);
  expect(sim.channelAdjustmentAmount   ).toBeCloseTo(inv.channelAdjustmentAmount,    2);
  expect(sim.couponDiscountAmount      ).toBeCloseTo(inv.couponDiscountAmount,       2);
  expect(sim.paymentAdjustmentAmount   ).toBeCloseTo(inv.paymentAdjustmentAmount,    2);
  expect(sim.shippingAmount            ).toBeCloseTo(inv.shippingAmount,             2);
  expect(sim.globalDiscountAmount      ).toBeCloseTo(inv.globalDiscountAmount,       2);
  expect(sim.taxableBase               ).toBeCloseTo(inv.taxableBase,                2);
  expect(sim.taxAmount                 ).toBeCloseTo(inv.taxAmount,                  2);
  expect(sim.totalBeforeTax            ).toBeCloseTo(inv.totalBeforeTax,             2);
  expect(sim.totalWithTax              ).toBeCloseTo(inv.totalWithTax,               2);
  expect(sim.roundingAdjustment        ).toBeCloseTo(inv.roundingAdjustment,         2);
  expect(sim.total                     ).toBeCloseTo(inv.total,                      2);
}

/** Cuando hay política doc activa: TODO debe coincidir EXCEPTO `total` y
 *  `roundingAdjustment`. Útil para fijar el contrato "el doc-rounding solo
 *  afecta el total final". */
function expectInvariantsExceptDocRounding(
  sim: SaleDocumentTotals,
  inv: SaleDocumentTotals,
) {
  expect(sim.subtotalBeforeDiscounts   ).toBeCloseTo(inv.subtotalBeforeDiscounts,    2);
  expect(sim.lineDiscountAmount        ).toBeCloseTo(inv.lineDiscountAmount,         2);
  expect(sim.subtotalAfterLineDiscounts).toBeCloseTo(inv.subtotalAfterLineDiscounts, 2);
  expect(sim.channelAdjustmentAmount   ).toBeCloseTo(inv.channelAdjustmentAmount,    2);
  expect(sim.couponDiscountAmount      ).toBeCloseTo(inv.couponDiscountAmount,       2);
  expect(sim.paymentAdjustmentAmount   ).toBeCloseTo(inv.paymentAdjustmentAmount,    2);
  expect(sim.shippingAmount            ).toBeCloseTo(inv.shippingAmount,             2);
  expect(sim.globalDiscountAmount      ).toBeCloseTo(inv.globalDiscountAmount,       2);
  expect(sim.taxableBase               ).toBeCloseTo(inv.taxableBase,                2);
  expect(sim.taxAmount                 ).toBeCloseTo(inv.taxAmount,                  2);
  expect(sim.totalBeforeTax            ).toBeCloseTo(inv.totalBeforeTax,             2);
  expect(sim.totalWithTax              ).toBeCloseTo(inv.totalWithTax,               2);
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Sin redondeo de lista, sin política doc
//
// El motor de línea produce el `unitPrice` y el `lineTotal` (el simulador y
// la factura los usan tal cual). Como ambos pasan los mismos inputs a
// `computeSaleDocumentTotals`, la igualdad debe ser total para cualquier
// modo de lista.
// ─────────────────────────────────────────────────────────────────────────────

describe("Paridad — sin redondeo de lista, sin política doc", () => {
  it("MARGIN_TOTAL: línea con descuento por cantidad → igualdad total", () => {
    // Lista MARGIN_TOTAL al 100% margen, qty 2, qty discount 20%.
    // basePrice = 1000 (post lista), unitPrice = 800 (post qty discount).
    // lineTotal = 1600 (qty × unitPrice). taxAmount unitario = 168 (21%).
    // lineTaxAmount = 336.
    const l = line({
      quantity:      2,
      basePrice:     1000,
      unitPrice:     800,
      lineTotal:     1600,
      lineTaxAmount: 336,
    });
    expectFullParity(runSimulator(l), runInvoice(l));
  });

  it("COST_PER_GRAM: línea con qty alta → igualdad total", () => {
    // Lista COST_PER_GRAM. unitPrice = 250, qty 5, sin descuento.
    const l = line({
      quantity:      5,
      basePrice:     250,
      unitPrice:     250,
      lineTotal:     1250,
      lineTaxAmount: 262.5,
    });
    expectFullParity(runSimulator(l), runInvoice(l));
  });

  it("METAL_HECHURA: línea con promoción → igualdad total", () => {
    // Lista METAL_HECHURA con margen distinto por componente. La diferencia
    // entre componentes la absorbió el motor de línea en `unitPrice`. A
    // nivel doc-totals no hay distinción.
    const l = line({
      quantity:      1,
      basePrice:     5000,
      unitPrice:     4500,           // post promoción 10%
      lineTotal:     4500,
      lineTaxAmount: 945,            // 21% sobre 4500
    });
    expectFullParity(runSimulator(l), runInvoice(l));
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. Con redondeo por lista
//
// Los modos applyOn = PRICE | NET | TOTAL son una decisión del motor de
// línea — al llegar a `computeSaleDocumentTotals`, la línea ya viene con el
// `lineTotal` post-redondeo. La paridad simulador↔factura es trivial siempre
// que ambos consuman el MISMO `lineTotal`. Estos tests fijan ese contrato.
// ─────────────────────────────────────────────────────────────────────────────

describe("Paridad — con redondeo por lista", () => {
  it("applyOn=PRICE (redondeo absorbido en unitPrice)", () => {
    // Motor redondeó `basePrice` al entero antes de descuentos.
    // basePrice 1000 → unitPrice 1000 (sin descuento), lineTotal 2000.
    const l = line({
      quantity:      2,
      basePrice:     1000,
      unitPrice:     1000,
      lineTotal:     2000,
      lineTaxAmount: 420,
    });
    expectFullParity(runSimulator(l), runInvoice(l));
  });

  it("applyOn=NET (redondeo absorbido en lineTotal post-descuentos)", () => {
    // Motor redondeó el neto post-descuentos. basePrice 1000, unitPrice
    // calculado post-descuento con redondeo aplicado: lineTotal = 1599
    // (en vez de 1598.40 sin redondear).
    const l = line({
      quantity:      2,
      basePrice:     1000,
      unitPrice:     799.5,          // post-redondeo NET
      lineTotal:     1599,
      lineTaxAmount: 335.79,
    });
    expectFullParity(runSimulator(l), runInvoice(l));
  });

  it("applyOn=TOTAL (redondeo absorbido en lineTotalWithTax)", () => {
    // Motor redondeó el total con impuestos al entero: lineTotalWithTax =
    // 1936. lineTaxAmount = 336, lineTotal = 1600 (= 1936 − 336).
    const l = line({
      quantity:      2,
      basePrice:     1000,
      unitPrice:     800,
      lineTotal:     1600,
      lineTaxAmount: 336,
    });
    expectFullParity(runSimulator(l), runInvoice(l));
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. Con política doc ON
//
// El simulador NUNCA aplica `documentRounding` (regla absoluta).
// La factura SÍ lo aplica. La diferencia debe vivir SOLO en `total` y
// `roundingAdjustment`. Todo lo demás (taxAmount, taxableBase, subtotal*,
// channel/coupon/payment/shipping) queda invariante.
// ─────────────────────────────────────────────────────────────────────────────

describe("Paridad — política doc ON: diferencia solo en total final", () => {
  it("TEN / NEAREST: total redondeado al múltiplo de 10 más cercano", () => {
    const l = line({ lineTotal: 1573.45, lineTaxAmount: 0 });
    const sim = runSimulator(l);
    const inv = runInvoice(l, { documentRounding: { mode: "TEN", direction: "NEAREST" } });

    // Invariantes
    expectInvariantsExceptDocRounding(sim, inv);

    // Simulador: total tal cual (sin redondeo doc).
    expect(sim.total).toBeCloseTo(1573.45, 2);
    expect(sim.roundingAdjustment).toBe(0);

    // Factura: total redondeado, roundingAdjustment con el delta.
    expect(inv.total).toBe(1570);
    expect(inv.roundingAdjustment).toBeCloseTo(-3.45, 2);

    // El delta no excede medio paso (5 para TEN/NEAREST).
    expect(Math.abs(inv.total - sim.total)).toBeLessThanOrEqual(5);
  });

  it("TEN / UP: total siempre subido al múltiplo de 10 superior", () => {
    const l = line({ lineTotal: 1573.45, lineTaxAmount: 0 });
    const sim = runSimulator(l);
    const inv = runInvoice(l, { documentRounding: { mode: "TEN", direction: "UP" } });

    expectInvariantsExceptDocRounding(sim, inv);

    expect(sim.total).toBeCloseTo(1573.45, 2);
    expect(sim.roundingAdjustment).toBe(0);

    expect(inv.total).toBe(1580);
    expect(inv.roundingAdjustment).toBeCloseTo(6.55, 2);

    // UP nunca baja el total.
    expect(inv.total).toBeGreaterThanOrEqual(sim.total);
    // El delta no excede un paso completo (10 para TEN/UP).
    expect(inv.total - sim.total).toBeLessThanOrEqual(10);
  });

  it("TEN / DOWN: total siempre bajado al múltiplo de 10 inferior", () => {
    const l = line({ lineTotal: 1573.45, lineTaxAmount: 0 });
    const sim = runSimulator(l);
    const inv = runInvoice(l, { documentRounding: { mode: "TEN", direction: "DOWN" } });

    expectInvariantsExceptDocRounding(sim, inv);

    expect(sim.total).toBeCloseTo(1573.45, 2);
    expect(sim.roundingAdjustment).toBe(0);

    expect(inv.total).toBe(1570);
    expect(inv.roundingAdjustment).toBeCloseTo(-3.45, 2);

    // DOWN nunca sube el total.
    expect(inv.total).toBeLessThanOrEqual(sim.total);
    expect(sim.total - inv.total).toBeLessThanOrEqual(10);
  });

  it("Política activa pero total ya es múltiplo de 10 → delta=0, paridad total", () => {
    // Edge case: si el total preliminar coincide con la granularidad, la
    // política no introduce diferencia. Simulador y factura quedan idénticos.
    const l = line({ lineTotal: 1500, lineTaxAmount: 0 });
    const sim = runSimulator(l);
    const inv = runInvoice(l, { documentRounding: { mode: "TEN", direction: "NEAREST" } });
    expectFullParity(sim, inv);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 4. Combinaciones: canal + cupón + impuestos + pago + envío
// ─────────────────────────────────────────────────────────────────────────────

describe("Paridad — combinaciones canal/cupón/impuestos/pago/envío", () => {
  const channel: ChannelAdjustmentInput = {
    id: "ch-1", name: "Tienda online", adjustmentType: "PERCENTAGE", adjustmentValue: 5,
  };
  const coupon: CouponInput = {
    id: "cp-1", code: "VERANO10", name: "Cupón verano",
    discountType: "FIXED_AMOUNT", discountValue: 100,
  };

  it("Combo completo sin política doc → paridad total en TODOS los campos", () => {
    const l = line({
      quantity:      2,
      basePrice:     1000,
      unitPrice:     800,
      lineTotal:     1600,
      lineTaxAmount: 336,
    });
    const ctx: ParityContext = {
      channel,
      coupon,
      paymentAdjustmentAmount: 25,    // recargo por cuotas (per-doc)
      shippingAmount:          150,
      globalDiscountAmount:    50,
    };
    expectFullParity(runSimulator(l, ctx), runInvoice(l, ctx));
  });

  it("Combo completo + política doc ON → diferencia solo en `total` y `roundingAdjustment`", () => {
    const l = line({
      quantity:      2,
      basePrice:     1000,
      unitPrice:     800,
      lineTotal:     1600,
      lineTaxAmount: 336,
    });
    // Sim: sin política. Inv: con política TEN / NEAREST.
    const baseCtx: ParityContext = {
      channel,
      coupon,
      paymentAdjustmentAmount: 25,
      shippingAmount:          150,
      globalDiscountAmount:    50,
    };
    const sim = runSimulator(l, baseCtx);
    const inv = runInvoice(l, {
      ...baseCtx,
      documentRounding: { mode: "TEN", direction: "NEAREST" },
    });

    // Invariantes (impuestos, base, subtotales, canal, cupón, pago, envío)
    expectInvariantsExceptDocRounding(sim, inv);

    // Diferencia esperada solo en `total` y `roundingAdjustment`.
    // Sim: total libre. Inv: total redondeado a TEN.
    expect(sim.roundingAdjustment).toBe(0);
    expect(inv.total % 10).toBe(0);
    expect(Math.abs(inv.total - sim.total)).toBeLessThanOrEqual(5); // NEAREST
    // El delta de la factura cubre exactamente la diferencia.
    expect(inv.total - sim.total).toBeCloseTo(inv.roundingAdjustment, 2);
  });

  it("Combo completo + política doc UP → factura sube, simulador queda libre", () => {
    const l = line({
      quantity:      2,
      basePrice:     1000,
      unitPrice:     800,
      lineTotal:     1600,
      lineTaxAmount: 336,
    });
    const baseCtx: ParityContext = {
      channel,
      coupon,
      paymentAdjustmentAmount: 25,
      shippingAmount:          150,
      globalDiscountAmount:    50,
    };
    const sim = runSimulator(l, baseCtx);
    const inv = runInvoice(l, {
      ...baseCtx,
      documentRounding: { mode: "TEN", direction: "UP" },
    });

    expectInvariantsExceptDocRounding(sim, inv);
    expect(inv.total).toBeGreaterThanOrEqual(sim.total);
    expect(inv.total % 10).toBe(0);
  });

  it("Combo sin envío ni pago, con cupón fijo y canal de descuento (negativo)", () => {
    // Canal con FIXED negativo (descuento). Verifica que la paridad se
    // mantiene cuando el canal RESTA en lugar de sumar.
    const l = line({
      quantity:      3,
      basePrice:     500,
      unitPrice:     500,
      lineTotal:     1500,
      lineTaxAmount: 315,
    });
    const negChannel: ChannelAdjustmentInput = {
      id: "ch-2", name: "Mayorista",
      adjustmentType: "FIXED", adjustmentValue: -200,
    };
    const ctx: ParityContext = { channel: negChannel, coupon };
    expectFullParity(runSimulator(l, ctx), runInvoice(l, ctx));
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 5. Regresiones específicas
// ─────────────────────────────────────────────────────────────────────────────

describe("Paridad — regresiones específicas", () => {
  it("qty grande no introduce drift (sin redondeos acumulados)", () => {
    // Una qty alta podría exponer cualquier drift de redondeo per-unit en
    // alguna pantalla. Validamos que ambos llegan al mismo total.
    const l = line({
      quantity:      99,
      basePrice:     123.45,
      unitPrice:     123.45,
      lineTotal:     12221.55,        // round2(99 * 123.45)
      lineTaxAmount: 2566.53,         // round2(99 * 25.92)
    });
    expectFullParity(runSimulator(l), runInvoice(l));
  });

  it("Total negativo absorbido a 0: simulador y factura clampean igual", () => {
    // Un descuento global mayor al subtotal → total preliminar negativo →
    // ambos lo clampean a 0. La política doc encima no rompe el clamp.
    const l = line({ lineTotal: 100, lineTaxAmount: 0 });
    const ctx: ParityContext = { globalDiscountAmount: 9999 };
    const sim = runSimulator(l, ctx);
    const inv = runInvoice(l, {
      ...ctx,
      documentRounding: { mode: "TEN", direction: "NEAREST" },
    });
    expect(sim.total).toBe(0);
    expect(inv.total).toBe(0);
  });

  it("HUNDRED / NEAREST: paso grande, paridad invariantes mantenida", () => {
    const l = line({ lineTotal: 1549, lineTaxAmount: 325.29 });
    const sim = runSimulator(l);
    const inv = runInvoice(l, { documentRounding: { mode: "HUNDRED", direction: "NEAREST" } });
    expectInvariantsExceptDocRounding(sim, inv);
    expect(inv.total % 100).toBe(0);
    // NEAREST con paso 100 → diferencia ≤ 50.
    expect(Math.abs(inv.total - sim.total)).toBeLessThanOrEqual(50);
  });
});
