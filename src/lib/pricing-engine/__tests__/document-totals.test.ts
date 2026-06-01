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
    // Etapa 1B — shape discriminado por scope. UNIFIED queda en `applied.unified`.
    expect(out.documentRoundingApplied).toMatchObject({
      source:  "TENANT_POLICY",
      scope:   "UNIFIED",
      applyOn: "DOC_TOTAL",
      totalAdjustment: -0.45,
      unified: {
        applyOn:      "DOC_TOTAL",
        mode:         "INTEGER",
        direction:    "NEAREST",
        preRounding:  1573.45,
        postRounding: 1573,
        adjustment:   -0.45,
      },
    });
    expect(out.documentRoundingApplied?.breakdown).toBeUndefined();
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
    // Etapa 1B — note refleja el helper roundingTraceNote (incluye el scope
    // que efectivamente actuó). UNIFIED puro → "UNIFIED(INTEGER NEAREST)".
    expect(roundingStep?.note).toBe("UNIFIED(INTEGER NEAREST)");
    // Para UNIFIED puro no hay capas BREAKDOWN en el trace.
    const breakdownMetal = out.sourceTrace.find(s => s.step === "ROUNDING_BREAKDOWN_METAL");
    expect(breakdownMetal).toBeUndefined();
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

// ============================================================================
// Etapa 1B — Redondeo por comprobante: scope BREAKDOWN
//
// Reglas:
//   - Aplica sobre los subtotales agregados `metalSaleSubtotal` y
//     `hechuraSaleSubtotal` por separado.
//   - El delta combinado (metal + hechura) se refleja en el `total` final.
//   - Sin datos metal/hechura en las líneas → fallback NO_BREAKDOWN_DATA y
//     no se mueve el total.
//   - NO toca impuestos por línea.
// ============================================================================

describe("computeSaleDocumentTotals — redondeo por comprobante BREAKDOWN", () => {
  const breakdownLine = (metalSale: number, hechuraSale: number, lineTotal = metalSale + hechuraSale) =>
    line({
      quantity:    1,
      basePrice:   lineTotal,
      unitPrice:   lineTotal,
      lineTotal,
      lineTaxAmount: 0,
      metalSale,
      hechuraSale,
    });

  it("redondea metal y hechura por separado, total absorbe el delta combinado", () => {
    const out = computeSaleDocumentTotals({
      lines:   [breakdownLine(1234.45, 567.30)], // total 1801.75
      channel: null,
      coupon:  null,
      documentRounding: {
        scope:     "BREAKDOWN",
        mode:      "NONE",       // unified no actúa
        direction: "NEAREST",
        breakdown: {
          metal:   { mode: "INTEGER", direction: "NEAREST" },
          hechura: { mode: "INTEGER", direction: "NEAREST" },
        },
      },
    });
    // metalSaleSubtotal 1234.45 → INTEGER NEAREST → 1234 (delta −0.45)
    // hechuraSaleSubtotal 567.30 → INTEGER NEAREST → 567 (delta −0.30)
    // combinedDelta = −0.75 → total 1801.75 − 0.75 = 1801.00
    expect(out.total).toBe(1801);
    expect(out.roundingAdjustment).toBeCloseTo(-0.75, 2);
    expect(out.documentRoundingApplied).toMatchObject({
      source:  "TENANT_POLICY",
      scope:   "BREAKDOWN",
      applyOn: "DOC_TOTAL",
    });
    expect(out.documentRoundingApplied?.breakdown).toMatchObject({
      metal:   { applyOn: "DOC_METAL",   adjustment: -0.45 },
      hechura: { applyOn: "DOC_HECHURA", adjustment: -0.30 },
    });
    expect(out.documentRoundingApplied?.unified).toBeUndefined();
  });

  it("fallback NO_BREAKDOWN_DATA cuando no hay subtotales metal/hechura", () => {
    const out = computeSaleDocumentTotals({
      // línea SIN metalSale ni hechuraSale (legacy)
      lines:   [line({ lineTotal: 1573.45 })],
      channel: null,
      coupon:  null,
      documentRounding: {
        scope:     "BREAKDOWN",
        mode:      "NONE",
        direction: "NEAREST",
        breakdown: {
          metal:   { mode: "INTEGER", direction: "NEAREST" },
          hechura: { mode: "INTEGER", direction: "NEAREST" },
        },
      },
    });
    // No hay sobre qué actuar → total intacto, fallback reportado.
    expect(out.total).toBe(1573.45);
    expect(out.roundingAdjustment).toBe(0);
    expect(out.documentRoundingApplied?.fallback).toBe("NO_BREAKDOWN_DATA");
    expect(out.documentRoundingApplied?.breakdown).toBeUndefined();
  });

  it("NO toca taxAmount ni taxableBase aunque el delta sea grande", () => {
    const out = computeSaleDocumentTotals({
      lines:   [breakdownLine(599.99, 400.01, 1000)],
      channel: null,
      coupon:  null,
      documentRounding: {
        scope:     "BREAKDOWN",
        mode:      "NONE",
        direction: "NEAREST",
        breakdown: {
          metal:   { mode: "TEN", direction: "DOWN" },
          hechura: { mode: "TEN", direction: "DOWN" },
        },
      },
    });
    // metal 599.99 → TEN DOWN → 590 (−9.99)
    // hechura 400.01 → TEN DOWN → 400 (−0.01)
    // combinedDelta = −10 → total 1000 − 10 = 990
    expect(out.total).toBe(990);
    expect(out.taxAmount).toBe(0);     // intacto
    expect(out.taxableBase).toBe(1000); // intacto
  });

  it("trace expone capas ROUNDING_BREAKDOWN_METAL y _HECHURA", () => {
    const out = computeSaleDocumentTotals({
      lines:   [breakdownLine(1234.45, 567.30)],
      channel: null,
      coupon:  null,
      documentRounding: {
        scope:     "BREAKDOWN",
        mode:      "NONE",
        direction: "NEAREST",
        breakdown: {
          metal:   { mode: "INTEGER", direction: "NEAREST" },
          hechura: { mode: "INTEGER", direction: "NEAREST" },
        },
      },
    });
    const metalStep   = out.sourceTrace.find(s => s.step === "ROUNDING_BREAKDOWN_METAL");
    const hechuraStep = out.sourceTrace.find(s => s.step === "ROUNDING_BREAKDOWN_HECHURA");
    const unifiedStep = out.sourceTrace.find(s => s.step === "ROUNDING_UNIFIED");
    expect(metalStep?.amount).toBeCloseTo(-0.45, 2);
    expect(hechuraStep?.amount).toBeCloseTo(-0.30, 2);
    expect(unifiedStep).toBeUndefined(); // BREAKDOWN puro, no UNIFIED
  });
});

// ============================================================================
// Etapa 1B — Redondeo por comprobante: scope BOTH (cascada controlada)
//
// Reglas:
//   - Primero aplica BREAKDOWN (si hay datos), luego UNIFIED sobre el total
//     resultante.
//   - Si la capa UNIFIED da delta 0 después del BREAKDOWN, NO se reporta
//     (guard anti-doble-rounding visual / "fantasma").
//   - Si no hay datos para BREAKDOWN, el UNIFIED sigue aplicándose
//     normalmente y queda fallback NO_BREAKDOWN_DATA en el snapshot.
// ============================================================================

describe("computeSaleDocumentTotals — redondeo por comprobante BOTH", () => {
  const blLine = (metalSale: number, hechuraSale: number) =>
    line({
      quantity:    1,
      basePrice:   metalSale + hechuraSale,
      unitPrice:   metalSale + hechuraSale,
      lineTotal:   metalSale + hechuraSale,
      lineTaxAmount: 0,
      metalSale,
      hechuraSale,
    });

  it("cascada: BREAKDOWN primero, UNIFIED después sobre el total ajustado", () => {
    const out = computeSaleDocumentTotals({
      lines:   [blLine(1234.45, 567.30)], // total preliminar 1801.75
      channel: null,
      coupon:  null,
      documentRounding: {
        scope:     "BOTH",
        mode:      "TEN",        // UNIFIED a la decena
        direction: "NEAREST",
        breakdown: {
          metal:   { mode: "INTEGER", direction: "NEAREST" },
          hechura: { mode: "INTEGER", direction: "NEAREST" },
        },
      },
    });
    // 1) BREAKDOWN: metal 1234.45→1234 (−0.45), hechura 567.30→567 (−0.30).
    //    Total intermedio = 1801.75 − 0.75 = 1801.00
    // 2) UNIFIED: 1801 → TEN NEAREST → 1800 (delta −1)
    // combinedDelta = −0.75 + −1 = −1.75
    expect(out.total).toBe(1800);
    expect(out.roundingAdjustment).toBeCloseTo(-1.75, 2);
    expect(out.documentRoundingApplied).toMatchObject({
      scope: "BOTH",
      breakdown: { combinedAdjustment: -0.75 },
      unified:   { mode: "TEN", direction: "NEAREST", adjustment: -1 },
    });
  });

  it("guard anti-fantasma: UNIFIED delta=0 después de BREAKDOWN → no se reporta", () => {
    const out = computeSaleDocumentTotals({
      lines:   [blLine(1234.45, 567)], // metal 1234.45, hechura 567 (entero exacto)
      channel: null,
      coupon:  null,
      documentRounding: {
        scope:     "BOTH",
        mode:      "INTEGER",   // UNIFIED a entero
        direction: "NEAREST",
        breakdown: {
          metal:   { mode: "INTEGER", direction: "NEAREST" },
          hechura: { mode: "INTEGER", direction: "NEAREST" },
        },
      },
    });
    // BREAKDOWN: metal 1234.45→1234 (−0.45), hechura 567→567 (0).
    // Total tras BREAKDOWN = 1801.45 − 0.45 = 1801.00
    // UNIFIED INTEGER sobre 1801 → 1801 → delta 0 → NO se reporta UNIFIED.
    expect(out.total).toBe(1801);
    expect(out.documentRoundingApplied?.breakdown).toBeDefined();
    expect(out.documentRoundingApplied?.unified).toBeUndefined();
  });

  it("sin datos BREAKDOWN: UNIFIED actúa solo y fallback queda reportado", () => {
    const out = computeSaleDocumentTotals({
      // línea SIN metalSale ni hechuraSale
      lines:   [line({ lineTotal: 1573.45 })],
      channel: null,
      coupon:  null,
      documentRounding: {
        scope:     "BOTH",
        mode:      "INTEGER",
        direction: "NEAREST",
        breakdown: {
          metal:   { mode: "INTEGER", direction: "NEAREST" },
          hechura: { mode: "INTEGER", direction: "NEAREST" },
        },
      },
    });
    // BREAKDOWN no actúa (fallback). UNIFIED INTEGER 1573.45 → 1573 (−0.45).
    expect(out.total).toBe(1573);
    expect(out.documentRoundingApplied).toMatchObject({
      scope:    "BOTH",
      fallback: "NO_BREAKDOWN_DATA",
      unified:  { adjustment: -0.45 },
    });
    expect(out.documentRoundingApplied?.breakdown).toBeUndefined();
  });
});

// ============================================================================
// Etapa 1B — Backward compatibility: callers que pasan { mode, direction }
// sin scope explícito siguen comportándose EXACTAMENTE como UNIFIED legacy.
// ============================================================================

describe("computeSaleDocumentTotals — back-compat sin scope (legacy UNIFIED)", () => {
  it("callers pre Etapa 1B siguen funcionando idénticos", () => {
    const out = computeSaleDocumentTotals({
      lines: [line({ lineTotal: 1573.45 })],
      channel: null, coupon: null,
      // ⚠️ sin `scope`: el motor debe interpretarlo como UNIFIED por default.
      documentRounding: { mode: "INTEGER", direction: "NEAREST" },
    });
    expect(out.total).toBe(1573);
    expect(out.documentRoundingApplied?.scope).toBe("UNIFIED");
    expect(out.documentRoundingApplied?.unified?.adjustment).toBe(-0.45);
    expect(out.documentRoundingApplied?.breakdown).toBeUndefined();
  });
});

// ============================================================================
// Etapa Tax — POLICY §Tax.4 — Scaling fiscal del taxAmount con descuentos doc
//
// Regla oficial: si los descuentos de cabecera (canal, cupón, global) bajan
// la `taxableBase`, el `taxAmount` PERCENTAGE debe escalar proporcionalmente.
// Los FIXED_AMOUNT (lineTaxAmountFixed) NO escalan.
//
// Fórmula:
//   effectiveSaleRatio = max(0, taxableBase) / subtotalAfterLineDiscounts
//   scaledScalable     = scalable × ratio
//   taxAmount          = scaledScalable + fixed
// ============================================================================

describe("computeSaleDocumentTotals — Tax scaling §Tax.4", () => {
  it("sin descuento doc → ratio=1, taxAmount === Σ lineTaxAmount (back-compat)", () => {
    const out = computeSaleDocumentTotals({
      lines:   [line({ lineTotal: 1000, lineTaxAmount: 210 })],
      channel: null,
      coupon:  null,
    });
    expect(out.taxAmount).toBe(210);
    expect(out.taxScaling.effectiveSaleRatio).toBe(1);
    expect(out.taxScaling.scalingApplied).toBe(false);
    expect(out.taxScaling.originalTaxAmount).toBe(210);
    expect(out.taxScaling.scaledTaxAmount).toBe(210);
    expect(out.total).toBe(1210);
  });

  it("globalDiscount 10%: tax escala 10%, total proporcional", () => {
    const out = computeSaleDocumentTotals({
      lines:   [line({ lineTotal: 1000, lineTaxAmount: 210 })],
      channel: null,
      coupon:  null,
      globalDiscountAmount: 100, // 10% de 1000
    });
    // taxableBase = 900, ratio = 0.9, scaled tax = 189.
    expect(out.taxableBase).toBe(900);
    expect(out.taxScaling.effectiveSaleRatio).toBeCloseTo(0.9, 4);
    expect(out.taxScaling.scalingApplied).toBe(true);
    expect(out.taxAmount).toBeCloseTo(189, 2);
    expect(out.total).toBeCloseTo(1089, 2);
  });

  it("globalDiscount 50%: tax escala a la mitad", () => {
    const out = computeSaleDocumentTotals({
      lines:   [line({ lineTotal: 1000, lineTaxAmount: 210 })],
      channel: null,
      coupon:  null,
      globalDiscountAmount: 500,
    });
    expect(out.taxableBase).toBe(500);
    expect(out.taxScaling.effectiveSaleRatio).toBe(0.5);
    expect(out.taxAmount).toBe(105);
    expect(out.total).toBe(605);
  });

  it("globalDiscount 100% (CASO CRÍTICO): tax = 0, total = 0, NO hay IVA fantasma", () => {
    const out = computeSaleDocumentTotals({
      lines:   [line({ lineTotal: 1000, lineTaxAmount: 210 })],
      channel: null,
      coupon:  null,
      globalDiscountAmount: 1000,
    });
    expect(out.taxableBase).toBe(0);
    expect(out.taxScaling.effectiveSaleRatio).toBe(0);
    expect(out.taxScaling.originalTaxAmount).toBe(210);
    expect(out.taxAmount).toBe(0);           // ← antes era 210 (IVA fantasma)
    expect(out.total).toBe(0);                // ← antes era 210 (total inflado)
  });

  it("globalDiscount > subtotal: clamp a 0, sin negativos", () => {
    const out = computeSaleDocumentTotals({
      lines:   [line({ lineTotal: 1000, lineTaxAmount: 210 })],
      channel: null,
      coupon:  null,
      globalDiscountAmount: 1500, // mayor al subtotal
    });
    expect(out.taxableBase).toBe(-500);    // taxableBase puede ser negativo informativamente
    expect(out.taxScaling.effectiveSaleRatio).toBe(0); // pero el ratio clampa a 0
    expect(out.taxAmount).toBe(0);
    expect(out.total).toBe(0);
  });

  it("cupón + canal + global simultáneos: todos contribuyen al scaling", () => {
    // Subtotal 1000, IVA 210. Canal +10% (=+100), cupón -50, global -200.
    // taxableBase = 1000 + 100 - 50 - 200 = 850.
    // Pero el denominador del ratio es subtotalAfterLineDiscounts=1000.
    // ratio = 850/1000 = 0.85, scaled tax = 178.5.
    const out = computeSaleDocumentTotals({
      lines:   [line({ lineTotal: 1000, lineTaxAmount: 210 })],
      channel: { id: "ch", name: "X", adjustmentType: "PERCENTAGE", adjustmentValue: 10 },
      coupon:  { id: "cp", code: "C", name: "X", discountType: "FIXED_AMOUNT", discountValue: 50 },
      globalDiscountAmount: 200,
    });
    expect(out.taxableBase).toBe(850);
    expect(out.taxScaling.effectiveSaleRatio).toBeCloseTo(0.85, 4);
    expect(out.taxAmount).toBeCloseTo(178.5, 2);
  });

  it("cliente exento (lineTaxAmount=0): scaling es no-op, total correcto", () => {
    const out = computeSaleDocumentTotals({
      lines:   [line({ lineTotal: 1000, lineTaxAmount: 0 })],
      channel: null,
      coupon:  null,
      globalDiscountAmount: 500,
    });
    expect(out.taxAmount).toBe(0);
    expect(out.total).toBe(500);
    // El ratio se calcula igual, pero al no haber tax que escalar, no hay efecto.
    expect(out.taxScaling.effectiveSaleRatio).toBe(0.5);
    expect(out.taxScaling.originalTaxAmount).toBe(0);
  });

  it("FIXED_AMOUNT tax + globalDiscount 100%: el fijo NO escala (POLICY §Tax.3)", () => {
    // Línea: 1000, sin IVA porcentual. Percepción fija $100 (lineTaxAmountFixed = 100).
    // Global 100% → ratio 0. Pero el fijo sobrevive.
    const out = computeSaleDocumentTotals({
      lines:   [line({
        lineTotal:          1000,
        lineTaxAmount:      100,
        lineTaxAmountFixed: 100,
      })],
      channel: null,
      coupon:  null,
      globalDiscountAmount: 1000,
    });
    expect(out.taxableBase).toBe(0);
    expect(out.taxScaling.scalableTaxAmount).toBe(0);
    expect(out.taxScaling.fixedTaxAmount).toBe(100);
    expect(out.taxAmount).toBe(100);    // ← solo el fijo sobrevive
    expect(out.total).toBe(100);
  });

  it("PERCENTAGE_PLUS_FIXED (IVA 21% + sellado $50) + global 100%: solo sobrevive el fijo", () => {
    // Línea 1000. IVA 21% = 210. Sellado fijo $50. lineTaxAmount=260, fixed=50.
    // Global 100% → ratio 0. IVA escala a 0. Sellado se preserva.
    const out = computeSaleDocumentTotals({
      lines:   [line({
        lineTotal:          1000,
        lineTaxAmount:      260,
        lineTaxAmountFixed: 50,
      })],
      channel: null,
      coupon:  null,
      globalDiscountAmount: 1000,
    });
    expect(out.taxScaling.scalableTaxAmount).toBe(210);
    expect(out.taxScaling.fixedTaxAmount).toBe(50);
    expect(out.taxAmount).toBe(50);
    expect(out.total).toBe(50);
  });

  it("lineTaxAmountFixed > lineTaxAmount: clamp defensivo (no infla nada)", () => {
    const out = computeSaleDocumentTotals({
      lines:   [line({
        lineTotal:          1000,
        lineTaxAmount:      100,
        lineTaxAmountFixed: 500,    // bug del caller — fixed mayor que el total
      })],
      channel: null,
      coupon:  null,
    });
    // Clamp: fixed se reduce al lineTaxAmount. Sin descuento doc, ratio=1,
    // taxAmount === lineTaxAmount original.
    expect(out.taxScaling.fixedTaxAmount).toBe(100);
    expect(out.taxScaling.scalableTaxAmount).toBe(0);
    expect(out.taxAmount).toBe(100);
  });

  it("subtotalAfterLineDiscounts=0 (todas las líneas en 0): no rompe, todo en 0", () => {
    const out = computeSaleDocumentTotals({
      lines:   [line({ lineTotal: 0, lineTaxAmount: 0 })],
      channel: null,
      coupon:  null,
    });
    expect(out.taxableBase).toBe(0);
    expect(out.taxScaling.effectiveSaleRatio).toBe(0);
    expect(out.taxAmount).toBe(0);
    expect(out.total).toBe(0);
  });
});

// ============================================================================
// Etapa Tax + Etapa 1B — Interacción entre scaling fiscal y rounding
// ============================================================================

describe("computeSaleDocumentTotals — Tax scaling × rounding Etapa 1B", () => {
  it("BREAKDOWN rounding + globalDiscount 50%: tax escala primero, rounding después sobre el nuevo total", () => {
    const out = computeSaleDocumentTotals({
      lines:   [{
        quantity:    1,
        basePrice:   1000,
        unitPrice:   1000,
        lineTotal:   1000,
        lineTaxAmount: 210,
        metalSale:   600,
        hechuraSale: 400,
      }],
      channel: null,
      coupon:  null,
      globalDiscountAmount: 500,    // 50%
      documentRounding: {
        scope:     "BREAKDOWN",
        mode:      "NONE",
        direction: "NEAREST",
        breakdown: {
          metal:   { mode: "INTEGER", direction: "NEAREST" },
          hechura: { mode: "INTEGER", direction: "NEAREST" },
        },
      },
    });
    // tax escala: 210 × 0.5 = 105
    expect(out.taxAmount).toBe(105);
    // metalSaleSubtotal=600 (entero), hechuraSaleSubtotal=400 (entero) → BREAKDOWN delta=0
    // Total: taxableBase=500 + tax=105 = 605. Rounding no agrega.
    expect(out.total).toBe(605);
  });

  it("BOTH rounding + globalDiscount 100%: tax=0, BREAKDOWN actúa pero UNIFIED sobre 0 es no-op", () => {
    const out = computeSaleDocumentTotals({
      lines:   [{
        quantity:    1,
        basePrice:   1000,
        unitPrice:   1000,
        lineTotal:   1000,
        lineTaxAmount: 210,
        metalSale:   600,
        hechuraSale: 400,
      }],
      channel: null,
      coupon:  null,
      globalDiscountAmount: 1000,
      documentRounding: {
        scope:     "BOTH",
        mode:      "INTEGER",
        direction: "NEAREST",
        breakdown: {
          metal:   { mode: "INTEGER", direction: "NEAREST" },
          hechura: { mode: "INTEGER", direction: "NEAREST" },
        },
      },
    });
    expect(out.taxableBase).toBe(0);
    expect(out.taxAmount).toBe(0);
    // BREAKDOWN actúa sobre metal/hechura (que son enteros redondeados, delta 0).
    // Pero el delta afecta el total via combinedDelta=0; total final 0.
    expect(out.total).toBe(0);
  });
});

// ============================================================================
// Etapa Tax — Paridad determinística
// ============================================================================

describe("computeSaleDocumentTotals — Tax scaling determinismo (paridad preview↔confirm)", () => {
  it("mismo input → mismo output 100% determinístico", () => {
    const input = {
      lines: [
        line({ quantity: 2, basePrice: 500, unitPrice: 500, lineTotal: 1000, lineTaxAmount: 210, lineTaxAmountFixed: 30 }),
        line({ quantity: 1, basePrice: 300, unitPrice: 300, lineTotal: 300,  lineTaxAmount: 63 }),
      ],
      channel: null,
      coupon:  null,
      globalDiscountAmount: 130,
    };
    const a = computeSaleDocumentTotals(input);
    const b = computeSaleDocumentTotals(input);
    expect(a.taxAmount).toBe(b.taxAmount);
    expect(a.total).toBe(b.total);
    expect(a.taxScaling).toEqual(b.taxScaling);
  });

  it("taxScaling se popula siempre, scalingApplied refleja si actuó", () => {
    const sin = computeSaleDocumentTotals({ lines: [line({ lineTaxAmount: 100 })], channel: null, coupon: null });
    const con = computeSaleDocumentTotals({ lines: [line({ lineTaxAmount: 100 })], channel: null, coupon: null, globalDiscountAmount: 200 });
    expect(sin.taxScaling.scalingApplied).toBe(false);
    expect(con.taxScaling.scalingApplied).toBe(true);
  });
});

// ============================================================================
// BUG FIX 2026-05-28 — Rounding deferred de lista debe afectar
// `documentTotals.total` cuando se pasa como `input.roundingAdjustment`.
//
// Antes del fix: el caller (`previewSale` / `confirmSale`) pasaba
// `roundingAdjustment: 0` al motor y el delta del rounding deferred quedaba
// solo como display, sin reflejarse en `total`. Resultado visible:
// `total = 473.473,97` pero el operador esperaba `473.500` (con +26,03 de
// rounding ya aplicado).
//
// Después del fix: el caller pre-calcula
// `Σ appliedRounding.unitAdjustment × qty` desde los snapshots de línea y
// lo pasa al motor. El motor (línea 766-769) suma este valor al `total`
// final.
//
// Estos tests aseguran el invariante a nivel motor.
// ============================================================================

describe("computeSaleDocumentTotals — Rounding deferred de lista en input.roundingAdjustment", () => {
  it("total INCLUYE el delta cuando input.roundingAdjustment != 0 (sin política comprobante)", () => {
    const out = computeSaleDocumentTotals({
      lines:   [line({ lineTotal: 473473.97, lineTaxAmount: 0 })],
      channel: null,
      coupon:  null,
      // Caller pasa el delta del rounding deferred de lista (no hay política
      // de comprobante activa → este valor SÍ se usa).
      roundingAdjustment: 26.03,
    });
    expect(out.total).toBeCloseTo(473500, 2);              // ← post-rounding
    expect(out.roundingAdjustment).toBeCloseTo(26.03, 2);
  });

  it("total NO duplica cuando hay política comprobante activa (suprime el input)", () => {
    const out = computeSaleDocumentTotals({
      lines:   [line({ lineTotal: 473473.97 })],
      channel: null,
      coupon:  null,
      // Caller pasa el delta pero la política comprobante está activa.
      roundingAdjustment: 26.03,
      documentRounding:   { mode: "INTEGER", direction: "NEAREST" },
    });
    // El motor descarta el input.roundingAdjustment (línea 730-733 de
    // document.ts) y aplica solo el rounding del comprobante. Sin doble.
    expect(out.total).toBe(473474); // INTEGER NEAREST de 473473.97
    expect(out.roundingAdjustment).toBeCloseTo(0.03, 2);  // delta del comprobante
  });

  it("delta NEGATIVO también se aplica (rounding DOWN absorbió valor)", () => {
    // Caso: lista redondea hacia abajo, el delta es negativo.
    const out = computeSaleDocumentTotals({
      lines:   [line({ lineTotal: 473500, lineTaxAmount: 0 })],
      channel: null,
      coupon:  null,
      roundingAdjustment: -26.03,
    });
    expect(out.total).toBeCloseTo(473473.97, 2);
  });

  it("total = subtotal + ajustes + impuestos + rounding deferred (invariante)", () => {
    // Composición completa para validar el orden inmutable del pipeline.
    const out = computeSaleDocumentTotals({
      lines:   [line({ lineTotal: 1000, lineTaxAmount: 210 })],
      channel: { id: "ch", name: "X", adjustmentType: "PERCENTAGE", adjustmentValue: 10 },
      coupon:  null,
      shippingAmount:       200,
      roundingAdjustment:   -100,  // delta del rounding deferred
    });
    // subtotal=1000, canal=+100, taxableBase=1100, tax=210 (sin scaling porque
    // ratio=1), totalBeforeTax=1100+200=1300, totalWithTax=1300+210=1510,
    // total=1510 + 0(payment) + (-100)(rounding) = 1410.
    expect(out.total).toBe(1410);
  });

  it("PARIDAD VISUAL: Σ lineTotalWithTax === documentTotals.total cuando hay rounding deferred TOTAL", () => {
    // Simulamos el invariante que ahora se cumple en sales.service.ts:
    //   · `lineTotalWithTax` per-línea = lineTotal + lineTax + delta TOTAL
    //   · `documentTotals.total`       = Σ lineTotal + Σ lineTax + Σ delta TOTAL
    // → Σ lineTotalWithTax === documentTotals.total (sin envío/payment).
    const lineTotal      = 473047.45;
    const lineTaxAmount  = 426.52;
    const unitAdjustment = 26.03;            // postRounding − preRounding (per unit)
    const qty            = 1;
    // Lo que el caller pasa al motor (suma de delta × qty por línea).
    const docDelta = unitAdjustment * qty;

    const out = computeSaleDocumentTotals({
      lines:   [line({ lineTotal, lineTaxAmount })],
      channel: null,
      coupon:  null,
      roundingAdjustment: docDelta,
    });

    // Frontend muestra (per línea): lineTotal + lineTaxAmount + delta TOTAL.
    const lineTotalWithTaxVisualPerLine = lineTotal + lineTaxAmount + (unitAdjustment * qty);
    // Σ debería coincidir con el total del documento.
    expect(out.total).toBeCloseTo(lineTotalWithTaxVisualPerLine, 2);
    expect(out.total).toBeCloseTo(473500, 0);    // 473.047,45 + 426,52 + 26,03 = 473.500,00
  });
});


