// src/lib/pricing-engine/__tests__/document-totals.test.ts
//
// Tests Fase 3 — computeSaleDocumentTotals es la fuente única de verdad de
// los totales del documento de venta. Capa pura: sin DB, sin engine de líneas.

import { describe, it, expect } from "vitest";
import {
  computeSaleDocumentTotals,
  type ChannelAdjustmentInput,
  type CouponInput,
  type SaleDocumentTotalsLineInput,
  type DocumentRoundingInput,
} from "../pricing-engine.js";

function line(overrides: Partial<SaleDocumentTotalsLineInput> = {}): SaleDocumentTotalsLineInput {
  return {
    quantity:      1,
    basePrice:     1000,
    unitPrice:     1000,
    lineTotal:     1000,
    lineTaxAmount: 0,
    ...overrides,
  };
}

describe("computeSaleDocumentTotals — agregados básicos", () => {
  it("suma lineTotal y lineTaxAmount sin ajustes", () => {
    const out = computeSaleDocumentTotals({
      lines: [
        line({ quantity: 2, basePrice: 500, unitPrice: 500, lineTotal: 1000, lineTaxAmount: 210 }),
        line({ quantity: 1, basePrice: 300, unitPrice: 300, lineTotal: 300,  lineTaxAmount: 63  }),
      ],
      channel: null,
      coupon:  null,
    });
    expect(out.subtotalBeforeDiscounts).toBe(1300);
    expect(out.lineDiscountAmount).toBe(0);
    expect(out.subtotalAfterLineDiscounts).toBe(1300);
    expect(out.taxAmount).toBe(273);
    expect(out.totalBeforeTax).toBe(1300);
    expect(out.total).toBe(1573);
  });

  it("calcula lineDiscountAmount = (basePrice − unitPrice) × qty", () => {
    const out = computeSaleDocumentTotals({
      lines: [line({ quantity: 2, basePrice: 1000, unitPrice: 800, lineTotal: 1600 })],
      channel: null, coupon: null,
    });
    expect(out.subtotalBeforeDiscounts).toBe(2000);
    expect(out.lineDiscountAmount).toBe(400);
    expect(out.subtotalAfterLineDiscounts).toBe(1600);
  });

  it("retorna trace con TODOS los pasos canónicos", () => {
    const out = computeSaleDocumentTotals({ lines: [line()], channel: null, coupon: null });
    const stepKeys = out.sourceTrace.map(s => s.step);
    expect(stepKeys).toEqual([
      // Orden canónico post-fix: PAYMENT se mueve después de TAX porque
      // se aplica sobre el total con impuestos (alineado con articles).
      "SUBTOTAL_BEFORE_DISCOUNTS",
      "LINE_DISCOUNTS",
      "SUBTOTAL_AFTER_LINE_DISCOUNTS",
      "CHANNEL",
      "COUPON",
      "GLOBAL_DISCOUNT",
      "TAXABLE_BASE",
      "SHIPPING",
      "TAX",
      "PAYMENT",
      "ROUNDING",
      "TOTAL",
    ]);
  });
});

describe("computeSaleDocumentTotals — orden de aplicación: canal → cupón → pago/global → impuestos → redondeo", () => {
  it("aplica canal sobre subtotalAfterLineDiscounts", () => {
    const channel: ChannelAdjustmentInput = {
      id: "ch-1", name: "Online", adjustmentType: "PERCENTAGE", adjustmentValue: 10,
    };
    const out = computeSaleDocumentTotals({
      lines: [line({ lineTotal: 1000 })],
      channel, coupon: null,
    });
    expect(out.channelAdjustmentAmount).toBe(100);
    expect(out.taxableBase).toBe(1100);
    expect(out.total).toBe(1100);
  });

  it("aplica cupón DESPUÉS del canal", () => {
    const channel: ChannelAdjustmentInput = {
      id: "ch-1", name: "Online", adjustmentType: "PERCENTAGE", adjustmentValue: 10,
    };
    // 10% de descuento = 110 (sobre 1100, no sobre 1000)
    const coupon: CouponInput = {
      id: "cp-1", code: "ABC", name: "10off", discountType: "PERCENTAGE", discountValue: 10,
    };
    const out = computeSaleDocumentTotals({
      lines: [line({ lineTotal: 1000 })],
      channel, coupon,
    });
    expect(out.channelAdjustmentAmount).toBe(100);
    expect(out.couponDiscountAmount).toBe(110);
    expect(out.taxableBase).toBe(990);
    expect(out.total).toBe(990);
  });

  it("payment + globalDiscount + shipping + rounding aplican en el orden correcto", () => {
    const out = computeSaleDocumentTotals({
      lines: [line({ lineTotal: 1000, lineTaxAmount: 100 })],
      channel: null, coupon: null,
      paymentAdjustmentAmount: 50,
      globalDiscountAmount:    20,
      shippingAmount:          80,
      roundingAdjustment:      -0.5,
    });
    // Orden alineado con articles/pricing-preview:
    //   taxableBase = subtotal + canal − cupón − globalDisc  (SIN payment)
    //              = 1000 + 0 − 0 − 20 = 980
    expect(out.taxableBase).toBe(980);
    // totalBeforeTax = taxableBase + shipping = 980 + 80 = 1060
    expect(out.totalBeforeTax).toBe(1060);
    // totalWithTax = totalBeforeTax + tax = 1060 + 100 = 1160
    expect(out.totalWithTax).toBe(1160);
    // total = totalWithTax + payment + rounding = 1160 + 50 − 0.5 = 1209.5
    expect(out.total).toBeCloseTo(1209.5, 2);
  });

  it("total nunca es negativo", () => {
    const out = computeSaleDocumentTotals({
      lines:   [line({ lineTotal: 100 })],
      channel: null,
      coupon:  null,
      globalDiscountAmount: 9999,
    });
    expect(out.total).toBe(0);
  });

  it("legacyCouponOnlyDiscount = couponDiscountAmount (compat con Sale.discountAmount)", () => {
    const coupon: CouponInput = {
      id: "cp-1", code: "ABC", name: "Off", discountType: "FIXED_AMOUNT", discountValue: 150,
    };
    const out = computeSaleDocumentTotals({
      lines: [line({ lineTotal: 1000 })],
      channel: null, coupon,
    });
    expect(out.couponDiscountAmount).toBe(150);
    expect(out.legacyCouponOnlyDiscount).toBe(150);
  });
});

describe("computeSaleDocumentTotals — escenario combinado", () => {
  it("promoción por línea + cupón + canal + impuestos: total no diverge", () => {
    // Línea 1: lista 1000, promo 20% → unitPrice 800, qty 2 → lineTotal 1600
    // Línea 2: lista 500,  sin promo → unitPrice 500, qty 1 → lineTotal 500
    // Subtotal post-line: 2100. Discount per-line: 400.
    // Canal +5% → +105 → 2205
    // Cupón fijo 200 → 2005
    // Imp: linea1 lineTaxAmount=160 (= 0.10 * 1600), linea2 = 50
    // taxableBase = 2005, totalBeforeTax = 2005, totalWithTax = 2005 + 210 = 2215
    const channel: ChannelAdjustmentInput = {
      id: "ch", name: "Tienda", adjustmentType: "PERCENTAGE", adjustmentValue: 5,
    };
    const coupon: CouponInput = {
      id: "cp", code: "X", name: "fijo200", discountType: "FIXED_AMOUNT", discountValue: 200,
    };
    const out = computeSaleDocumentTotals({
      lines: [
        line({ quantity: 2, basePrice: 1000, unitPrice: 800, lineTotal: 1600, lineTaxAmount: 160 }),
        line({ quantity: 1, basePrice: 500,  unitPrice: 500, lineTotal: 500,  lineTaxAmount: 50  }),
      ],
      channel, coupon,
    });
    expect(out.subtotalBeforeDiscounts).toBe(2500);
    expect(out.lineDiscountAmount).toBe(400);
    expect(out.subtotalAfterLineDiscounts).toBe(2100);
    expect(out.channelAdjustmentAmount).toBe(105);
    expect(out.couponDiscountAmount).toBe(200);
    expect(out.taxableBase).toBe(2005);
    expect(out.taxAmount).toBe(210);
    expect(out.total).toBe(2215);
  });

  it("redondeo de centavos al sumar muchas líneas", () => {
    // 3 líneas que suman justo en frontera de centavo
    const out = computeSaleDocumentTotals({
      lines: [
        line({ basePrice: 333.33, unitPrice: 333.33, lineTotal: 333.33, lineTaxAmount: 33.33 }),
        line({ basePrice: 333.33, unitPrice: 333.33, lineTotal: 333.33, lineTaxAmount: 33.33 }),
        line({ basePrice: 333.34, unitPrice: 333.34, lineTotal: 333.34, lineTaxAmount: 33.34 }),
      ],
      channel: null, coupon: null,
    });
    expect(out.subtotalAfterLineDiscounts).toBe(1000);
    expect(out.taxAmount).toBe(100);
    expect(out.total).toBe(1100);
  });
});

describe("computeSaleDocumentTotals — line discount agregado nunca negativo", () => {
  it("si por error unitPrice > basePrice, lineDiscountAmount queda en 0 (no negativo)", () => {
    const out = computeSaleDocumentTotals({
      lines: [line({ basePrice: 100, unitPrice: 120, lineTotal: 120 })],
      channel: null, coupon: null,
    });
    expect(out.lineDiscountAmount).toBe(0);
  });
});

describe("computeSaleDocumentTotals — Fase 6: expone channelResult y couponResult", () => {
  it("devuelve un ChannelAdjustmentResult con datos del canal aplicado", () => {
    const channel: ChannelAdjustmentInput = {
      id: "ch-1", name: "Online", adjustmentType: "PERCENTAGE", adjustmentValue: 10,
    };
    const out = computeSaleDocumentTotals({
      lines: [line({ lineTotal: 1000 })],
      channel, coupon: null,
    });
    expect(out.channelResult).toBeDefined();
    expect(out.channelResult.channelId).toBe("ch-1");
    expect(out.channelResult.channelName).toBe("Online");
    expect(out.channelResult.channelAmount).toBe(100);
    expect(out.channelResult.finalAmount).toBe(1100);
  });

  it("devuelve un CouponAdjustmentResult con applied=true cuando hay cupón válido", () => {
    const coupon: CouponInput = {
      id: "cp-7", code: "X", name: "off", discountType: "FIXED_AMOUNT", discountValue: 50,
    };
    const out = computeSaleDocumentTotals({
      lines: [line({ lineTotal: 1000 })],
      channel: null, coupon,
    });
    expect(out.couponResult).toBeDefined();
    expect(out.couponResult.couponId).toBe("cp-7");
    expect(out.couponResult.couponCode).toBe("X");
    expect(out.couponResult.discountAmount).toBe(50);
    expect(out.couponResult.applied).toBe(true);
  });

  it("CouponAdjustmentResult con applied=false cuando no hay cupón", () => {
    const out = computeSaleDocumentTotals({
      lines: [line({ lineTotal: 1000 })],
      channel: null, coupon: null,
    });
    expect(out.couponResult.applied).toBe(false);
    expect(out.couponResult.discountAmount).toBe(0);
  });
});

// ============================================================================
// Redondeo a nivel comprobante (modo UNIFIED)
//
// Reglas TPTech:
//   - Redondea SOLO el `total` final del documento.
//   - Se aplica al final, después de impuestos / pago / envío / redondeo previo.
//   - NO modifica líneas, NO modifica `taxAmount`, NO modifica `taxableBase`.
//   - NO se prorratea.
//   - Cuando `documentRounding` está activo, `roundingAdjustment` se sobrescribe
//     con el delta real (postRounding − preRounding).
//   - `documentRoundingApplied` queda `null` cuando la política está apagada o
//     el delta es 0 (mode === "NONE").
// ============================================================================

describe("computeSaleDocumentTotals — redondeo por comprobante UNIFIED", () => {
  it("documentRounding=null → comportamiento legacy idéntico (regresión)", () => {
    const out = computeSaleDocumentTotals({
      lines: [line({ lineTotal: 1573.45, lineTaxAmount: 0 })],
      channel: null, coupon: null,
      documentRounding: null,
    });
    expect(out.total).toBe(1573.45);
    expect(out.roundingAdjustment).toBe(0);
    expect(out.documentRoundingApplied).toBeNull();
  });

  it("mode=NONE → política inerte, total sin tocar", () => {
    const out = computeSaleDocumentTotals({
      lines: [line({ lineTotal: 1573.45 })],
      channel: null, coupon: null,
      documentRounding: { mode: "NONE", direction: "NEAREST" },
    });
    expect(out.total).toBe(1573.45);
    expect(out.roundingAdjustment).toBe(0);
    expect(out.documentRoundingApplied).toBeNull();
  });

  it("INTEGER NEAREST: 1573.45 → 1573 (delta −0.45)", () => {
    const out = computeSaleDocumentTotals({
      lines: [line({ lineTotal: 1573.45 })],
      channel: null, coupon: null,
      documentRounding: { mode: "INTEGER", direction: "NEAREST" },
    });
    expect(out.total).toBe(1573);
    expect(out.roundingAdjustment).toBe(-0.45);
    expect(out.documentRoundingApplied).toMatchObject({
      source:       "TENANT_POLICY",
      applyOn:      "DOC_TOTAL",
      mode:         "INTEGER",
      direction:    "NEAREST",
      preRounding:  1573.45,
      postRounding: 1573,
    });
  });

  it("INTEGER UP: 1573.45 → 1574 (delta +0.55)", () => {
    const out = computeSaleDocumentTotals({
      lines: [line({ lineTotal: 1573.45 })],
      channel: null, coupon: null,
      documentRounding: { mode: "INTEGER", direction: "UP" },
    });
    expect(out.total).toBe(1574);
    expect(out.roundingAdjustment).toBe(0.55);
  });

  it("INTEGER DOWN: 1573.99 → 1573 (delta −0.99)", () => {
    const out = computeSaleDocumentTotals({
      lines: [line({ lineTotal: 1573.99 })],
      channel: null, coupon: null,
      documentRounding: { mode: "INTEGER", direction: "DOWN" },
    });
    expect(out.total).toBe(1573);
    expect(out.roundingAdjustment).toBe(-0.99);
  });

  it("TEN UP: 1573 → 1580", () => {
    const out = computeSaleDocumentTotals({
      lines: [line({ lineTotal: 1573 })],
      channel: null, coupon: null,
      documentRounding: { mode: "TEN", direction: "UP" },
    });
    expect(out.total).toBe(1580);
    expect(out.roundingAdjustment).toBe(7);
  });

  it("HUNDRED NEAREST: 1549 → 1500, 1551 → 1600", () => {
    const a = computeSaleDocumentTotals({
      lines: [line({ lineTotal: 1549 })],
      channel: null, coupon: null,
      documentRounding: { mode: "HUNDRED", direction: "NEAREST" },
    });
    expect(a.total).toBe(1500);
    expect(a.roundingAdjustment).toBe(-49);

    const b = computeSaleDocumentTotals({
      lines: [line({ lineTotal: 1551 })],
      channel: null, coupon: null,
      documentRounding: { mode: "HUNDRED", direction: "NEAREST" },
    });
    expect(b.total).toBe(1600);
    expect(b.roundingAdjustment).toBe(49);
  });

  it("DECIMAL_2 NEAREST: 1573.456 → 1573.46", () => {
    const out = computeSaleDocumentTotals({
      lines: [line({ lineTotal: 1573.456 })],
      channel: null, coupon: null,
      documentRounding: { mode: "DECIMAL_2", direction: "NEAREST" },
    });
    expect(out.total).toBeCloseTo(1573.46, 2);
  });

  it("NO toca taxAmount ni taxableBase", () => {
    const out = computeSaleDocumentTotals({
      lines: [line({ lineTotal: 1000, lineTaxAmount: 210 })],
      channel: null, coupon: null,
      documentRounding: { mode: "INTEGER", direction: "DOWN" },
    });
    expect(out.taxAmount).toBe(210);     // intacto
    expect(out.taxableBase).toBe(1000);  // intacto
    expect(out.totalWithTax).toBe(1210); // intacto (pre redondeo)
    expect(out.total).toBe(1210);        // 1210.00 ya está en INTEGER
    expect(out.roundingAdjustment).toBe(0);
  });

  it("aplica DESPUÉS de pago: total = round(totalWithTax + payment)", () => {
    // totalWithTax = 1100, payment = 50 → preRounding = 1150 → INTEGER UP = 1150
    const out = computeSaleDocumentTotals({
      lines: [line({ lineTotal: 1000, lineTaxAmount: 100 })],
      channel: null, coupon: null,
      paymentAdjustmentAmount: 50.49,
      documentRounding: { mode: "INTEGER", direction: "UP" },
    });
    // 1000 + 100 = 1100 (totalWithTax), + 50.49 = 1150.49 → UP a INTEGER = 1151
    expect(out.totalWithTax).toBe(1100);
    expect(out.total).toBe(1151);
    expect(out.roundingAdjustment).toBeCloseTo(0.51, 2);
  });

  it("total nunca es negativo aun con rounding agresivo", () => {
    const out = computeSaleDocumentTotals({
      lines:   [line({ lineTotal: 5 })],
      channel: null,
      coupon:  null,
      globalDiscountAmount: 100,           // total preliminar = 0 (clamp)
      documentRounding: { mode: "INTEGER", direction: "DOWN" },
    });
    expect(out.total).toBe(0);
  });

  it("escenario combinado: canal + cupón + impuestos + redondeo doc", () => {
    const channel: ChannelAdjustmentInput = {
      id: "ch", name: "Tienda", adjustmentType: "PERCENTAGE", adjustmentValue: 5,
    };
    const coupon: CouponInput = {
      id: "cp", code: "X", name: "fijo50", discountType: "FIXED_AMOUNT", discountValue: 50,
    };
    // Línea: 1000, tax 100. canal +5% → 1050 (sobre 1000), cupón −50 → 1000
    // taxableBase=1000, taxAmount=100, totalWithTax=1100. INTEGER no cambia.
    // Forzamos un caso con decimales: tax 99.99 → totalWithTax = 1099.99
    const out = computeSaleDocumentTotals({
      lines: [line({ lineTotal: 1000, lineTaxAmount: 99.99 })],
      channel, coupon,
      documentRounding: { mode: "INTEGER", direction: "NEAREST" },
    });
    expect(out.taxableBase).toBe(1000);
    expect(out.taxAmount).toBe(99.99);
    expect(out.totalWithTax).toBeCloseTo(1099.99, 2);
    expect(out.total).toBe(1100);
    expect(out.roundingAdjustment).toBeCloseTo(0.01, 2);
    expect(out.documentRoundingApplied?.source).toBe("TENANT_POLICY");
  });

  it("delta=0 cuando el total ya está redondeado al modo: documentRoundingApplied conserva metadatos", () => {
    const out = computeSaleDocumentTotals({
      lines: [line({ lineTotal: 1500 })],
      channel: null, coupon: null,
      documentRounding: { mode: "INTEGER", direction: "NEAREST" },
    });
    expect(out.total).toBe(1500);
    expect(out.roundingAdjustment).toBe(0);
    // `documentRoundingApplied` se popula igualmente (la política se intentó),
    // pero el delta es 0 → null para evitar mostrar redondeo "fantasma".
    expect(out.documentRoundingApplied).toBeNull();
  });

  it("el step ROUNDING del sourceTrace muestra el delta y el modo en `note`", () => {
    const out = computeSaleDocumentTotals({
      lines: [line({ lineTotal: 1573.45 })],
      channel: null, coupon: null,
      documentRounding: { mode: "INTEGER", direction: "NEAREST" },
    });
    const roundingStep = out.sourceTrace.find(s => s.step === "ROUNDING");
    expect(roundingStep).toBeDefined();
    expect(roundingStep?.amount).toBe(-0.45);
    expect(roundingStep?.note).toBe("INTEGER NEAREST");
  });

  it("roundingAdjustment del input se sobrescribe cuando hay política activa", () => {
    // El caller pasó un roundingAdjustment "display" de la lista (PRICE_LIST)
    // pero la política doc está activa → la política manda y reemplaza el valor.
    const out = computeSaleDocumentTotals({
      lines: [line({ lineTotal: 1573.45 })],
      channel: null, coupon: null,
      roundingAdjustment: 0.99,  // valor "fantasma" del caller
      documentRounding: { mode: "INTEGER", direction: "NEAREST" },
    });
    expect(out.roundingAdjustment).toBe(-0.45); // delta real, no 0.99
  });
});

// ============================================================================
// Paridad: con la misma config, preview y confirm dan el mismo `total`.
// `computeSaleDocumentTotals` es la fuente única — si se invoca con los mismos
// inputs, da los mismos outputs en cualquier flujo.
// ============================================================================

describe("computeSaleDocumentTotals — paridad preview vs confirm", () => {
  const docRounding: DocumentRoundingInput = { mode: "INTEGER", direction: "NEAREST" };

  it("mismo input → mismo total en ambos llamados", () => {
    const inputBase = {
      lines: [
        line({ quantity: 2, basePrice: 500, unitPrice: 500, lineTotal: 1000, lineTaxAmount: 105 }),
        line({ quantity: 1, basePrice: 300, unitPrice: 300, lineTotal: 300,  lineTaxAmount: 31.5 }),
      ],
      channel: null,
      coupon:  null,
      paymentAdjustmentAmount: 0,
      shippingAmount:          0,
      globalDiscountAmount:    0,
      roundingAdjustment:      0,
      documentRounding:        docRounding,
    };
    const previewLike = computeSaleDocumentTotals(inputBase);
    const confirmLike = computeSaleDocumentTotals(inputBase);
    expect(previewLike.total).toBe(confirmLike.total);
    expect(previewLike.roundingAdjustment).toBe(confirmLike.roundingAdjustment);
    expect(previewLike.taxAmount).toBe(confirmLike.taxAmount);
  });

  it("activar / desactivar política → diferencia esperada en `total`, sin afectar impuestos", () => {
    const baseInput = {
      lines: [line({ lineTotal: 1573.45, lineTaxAmount: 0 })],
      channel: null,
      coupon:  null,
    };
    const off = computeSaleDocumentTotals({ ...baseInput, documentRounding: null });
    const on  = computeSaleDocumentTotals({ ...baseInput, documentRounding: docRounding });
    expect(off.total).toBe(1573.45);
    expect(on.total).toBe(1573);
    expect(off.taxAmount).toBe(on.taxAmount); // política no toca impuestos
  });
});
