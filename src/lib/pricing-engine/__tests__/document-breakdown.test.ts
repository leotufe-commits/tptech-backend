// src/lib/pricing-engine/__tests__/document-breakdown.test.ts
// ============================================================================
// FASE 2 — agregados Metal/Hechura a nivel documento.
//
// `computeSaleDocumentTotals` ahora suma los `metalCost / hechuraCost /
// metalSale / hechuraSale` que cada línea provee y reporta:
//   - `metalCostSubtotal`
//   - `hechuraCostSubtotal`
//   - `metalSaleSubtotal`
//   - `hechuraSaleSubtotal`
//   - `breakdownEstimated`  (true si alguna línea trae `*Estimated=true`)
//
// Estos campos NO afectan ningún total existente — son agregados informativos
// para futuras pantallas de balance / reportes. La suite valida:
//   1. Sumas correctas por documento (single + multi-línea + combos).
//   2. `breakdownEstimated` aggrega correctamente.
//   3. Compatibilidad: si ninguna línea trae datos → todos en 0.
//   4. Combinación con redondeo doc, canal, cupón → agregados intactos.
// ============================================================================

import { describe, it, expect } from "vitest";
import {
  computeSaleDocumentTotals,
  type ChannelAdjustmentInput,
  type CouponInput,
  type SaleDocumentTotalsLineInput,
} from "../pricing-engine.js";

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

const line = (over: Partial<SaleDocumentTotalsLineInput> = {}): SaleDocumentTotalsLineInput => ({
  quantity:      1,
  basePrice:     1000,
  unitPrice:     1000,
  lineTotal:     1000,
  lineTaxAmount: 0,
  ...over,
});

// ─────────────────────────────────────────────────────────────────────────────
// 1. Compatibilidad — sin breakdown en las líneas, todo queda en 0
// ─────────────────────────────────────────────────────────────────────────────

describe("computeSaleDocumentTotals — agregados Metal/Hechura ausentes", () => {
  it("sin metalCost/hechuraCost en ninguna línea → subtotales=0, estimated=false", () => {
    const out = computeSaleDocumentTotals({
      lines: [line(), line({ lineTotal: 500 })],
      channel: null, coupon: null,
    });
    expect(out.metalCostSubtotal).toBe(0);
    expect(out.hechuraCostSubtotal).toBe(0);
    expect(out.metalSaleSubtotal).toBe(0);
    expect(out.hechuraSaleSubtotal).toBe(0);
    expect(out.breakdownEstimated).toBe(false);
    // Totales clásicos intactos
    expect(out.subtotalAfterLineDiscounts).toBe(1500);
    expect(out.total).toBe(1500);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. Suma simple — una línea con breakdown completo
// ─────────────────────────────────────────────────────────────────────────────

describe("computeSaleDocumentTotals — breakdown agregado: línea única", () => {
  it("METAL_HECHURA exacto (estimated=false): subtotales coinciden", () => {
    const out = computeSaleDocumentTotals({
      lines: [line({
        quantity:    2,
        basePrice:   1000,
        unitPrice:   1000,
        lineTotal:   2000,
        // per-línea = per-unit × qty
        metalCost:            1000,    // 500 × 2
        hechuraCost:          400,     // 200 × 2
        metalSale:            1300,    // 650 × 2
        hechuraSale:          700,     // 350 × 2
        metalSaleEstimated:   false,
        hechuraSaleEstimated: false,
      })],
      channel: null, coupon: null,
    });
    expect(out.metalCostSubtotal).toBe(1000);
    expect(out.hechuraCostSubtotal).toBe(400);
    expect(out.metalSaleSubtotal).toBe(1300);
    expect(out.hechuraSaleSubtotal).toBe(700);
    expect(out.breakdownEstimated).toBe(false);
  });

  it("PROPORTIONAL_COST (estimated=true): flag se propaga al doc", () => {
    const out = computeSaleDocumentTotals({
      lines: [line({
        quantity:    1,
        basePrice:   1700,
        unitPrice:   1700,
        lineTotal:   1700,
        metalCost:   700,
        hechuraCost: 300,
        metalSale:   1190,    // 700 × 1.7
        hechuraSale: 510,     // 300 × 1.7
        metalSaleEstimated:   true,
        hechuraSaleEstimated: true,
      })],
      channel: null, coupon: null,
    });
    expect(out.metalSaleSubtotal).toBe(1190);
    expect(out.hechuraSaleSubtotal).toBe(510);
    expect(out.breakdownEstimated).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. Multi-línea — suma correcta y mezcla de fuentes
// ─────────────────────────────────────────────────────────────────────────────

describe("computeSaleDocumentTotals — multi-línea", () => {
  it("3 líneas: sumas exactas", () => {
    const out = computeSaleDocumentTotals({
      lines: [
        line({ lineTotal: 1000, metalCost: 500, hechuraCost: 200, metalSale: 650, hechuraSale: 350 }),
        line({ lineTotal: 800,  metalCost: 400, hechuraCost: 100, metalSale: 600, hechuraSale: 200 }),
        line({ lineTotal: 500,  metalCost: 0,   hechuraCost: 300, metalSale: 0,   hechuraSale: 500 }),
      ],
      channel: null, coupon: null,
    });
    expect(out.metalCostSubtotal).toBe(900);
    expect(out.hechuraCostSubtotal).toBe(600);
    expect(out.metalSaleSubtotal).toBe(1250);
    expect(out.hechuraSaleSubtotal).toBe(1050);
    // Sin estimated explícito → false
    expect(out.breakdownEstimated).toBe(false);
  });

  it("breakdownEstimated=true cuando UNA línea lo declara", () => {
    const out = computeSaleDocumentTotals({
      lines: [
        line({ lineTotal: 1000, metalCost: 500, hechuraCost: 100, metalSale: 700, hechuraSale: 300, metalSaleEstimated: false, hechuraSaleEstimated: false }),
        line({ lineTotal: 800,  metalCost: 400, hechuraCost: 200, metalSale: 600, hechuraSale: 200, metalSaleEstimated: true,  hechuraSaleEstimated: false }),
      ],
      channel: null, coupon: null,
    });
    expect(out.breakdownEstimated).toBe(true);
  });

  it("breakdownEstimated=true cuando hechuraSaleEstimated solo lo trae una línea", () => {
    const out = computeSaleDocumentTotals({
      lines: [
        line({ lineTotal: 500, metalCost: 250, hechuraCost: 100, metalSale: 350, hechuraSale: 150, metalSaleEstimated: false, hechuraSaleEstimated: true }),
      ],
      channel: null, coupon: null,
    });
    expect(out.breakdownEstimated).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 4. Combos y servicios
// ─────────────────────────────────────────────────────────────────────────────

describe("computeSaleDocumentTotals — combos y servicios", () => {
  it("Combo (COMBO_COMPONENTS): línea con metal+hechura sumados de componentes", () => {
    const out = computeSaleDocumentTotals({
      lines: [line({
        quantity:    1,
        lineTotal:   1800,
        // Componentes acumulados: 600+0=600 metal, 400+200=600 hechura.
        // Total cost = 1200. basePrice/factor → metalSale=900, hechuraSale=900.
        metalCost:            600,
        hechuraCost:          600,
        metalSale:            900,
        hechuraSale:          900,
        metalSaleEstimated:   true,
        hechuraSaleEstimated: true,
      })],
      channel: null, coupon: null,
    });
    expect(out.metalCostSubtotal).toBe(600);
    expect(out.hechuraCostSubtotal).toBe(600);
    expect(out.metalSaleSubtotal).toBe(900);
    expect(out.hechuraSaleSubtotal).toBe(900);
    expect(out.breakdownEstimated).toBe(true);
  });

  it("Servicio puro (SERVICE_AS_HECHURA): metalCost=0, todo a hechura", () => {
    const out = computeSaleDocumentTotals({
      lines: [line({
        lineTotal:    1200,
        metalCost:    0,
        hechuraCost:  800,
        metalSale:    0,
        hechuraSale:  1200,
        metalSaleEstimated:   true,
        hechuraSaleEstimated: true,
      })],
      channel: null, coupon: null,
    });
    expect(out.metalCostSubtotal).toBe(0);
    expect(out.hechuraCostSubtotal).toBe(800);
    expect(out.metalSaleSubtotal).toBe(0);
    expect(out.hechuraSaleSubtotal).toBe(1200);
  });

  it("Mezcla servicios + artículos físicos en mismo documento", () => {
    const out = computeSaleDocumentTotals({
      lines: [
        // Artículo metal+hechura
        line({ lineTotal: 1000, metalCost: 500, hechuraCost: 100, metalSale: 700, hechuraSale: 300 }),
        // Servicio puro
        line({ lineTotal: 600,  metalCost: 0,   hechuraCost: 400, metalSale: 0,   hechuraSale: 600 }),
        // Combo (estimado)
        line({ lineTotal: 1200, metalCost: 400, hechuraCost: 400, metalSale: 600, hechuraSale: 600, metalSaleEstimated: true, hechuraSaleEstimated: true }),
      ],
      channel: null, coupon: null,
    });
    expect(out.metalCostSubtotal).toBe(900);
    expect(out.hechuraCostSubtotal).toBe(900);
    expect(out.metalSaleSubtotal).toBe(1300);
    expect(out.hechuraSaleSubtotal).toBe(1500);
    expect(out.breakdownEstimated).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 5. Convivencia con canal / cupón / impuestos / redondeo
// ─────────────────────────────────────────────────────────────────────────────

describe("computeSaleDocumentTotals — agregados intactos ante otros ajustes", () => {
  it("canal + cupón + impuestos + redondeo doc: agregados Metal/Hechura no se alteran", () => {
    const channel: ChannelAdjustmentInput = {
      id: "ch-1", name: "Tienda", adjustmentType: "PERCENTAGE", adjustmentValue: 5,
    };
    const coupon: CouponInput = {
      id: "cp-1", code: "ABC", name: "10off",
      discountType: "FIXED_AMOUNT", discountValue: 100,
    };
    const out = computeSaleDocumentTotals({
      lines: [line({
        quantity:    2,
        basePrice:   1000,
        unitPrice:   800,
        lineTotal:   1600,
        lineTaxAmount: 336,
        metalCost:    1000,
        hechuraCost:  200,
        metalSale:    1300,
        hechuraSale:  300,
      })],
      channel, coupon,
      paymentAdjustmentAmount: 25,
      shippingAmount:          150,
      documentRounding: { mode: "TEN", direction: "NEAREST" },
    });
    // Agregados Metal/Hechura: invariantes ante doc rounding / canal / cupón.
    expect(out.metalCostSubtotal).toBe(1000);
    expect(out.hechuraCostSubtotal).toBe(200);
    expect(out.metalSaleSubtotal).toBe(1300);
    expect(out.hechuraSaleSubtotal).toBe(300);
    // Totales tradicionales siguen funcionando.
    expect(out.taxAmount).toBe(336);
    expect(out.total % 10).toBe(0);  // redondeo TEN aplicado
  });

  it("agregados sobreviven cuando el total se clampa a 0 por descuento global", () => {
    const out = computeSaleDocumentTotals({
      lines: [line({
        lineTotal:    100,
        metalCost:    50,
        hechuraCost:  20,
        metalSale:    70,
        hechuraSale:  30,
      })],
      channel: null, coupon: null,
      globalDiscountAmount: 9999,  // excede el subtotal
    });
    expect(out.total).toBe(0);
    // Los agregados Metal/Hechura no están afectados por descuentos doc-level.
    expect(out.metalCostSubtotal).toBe(50);
    expect(out.hechuraCostSubtotal).toBe(20);
    expect(out.metalSaleSubtotal).toBe(70);
    expect(out.hechuraSaleSubtotal).toBe(30);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 6. Mezcla con líneas sin breakdown
// ─────────────────────────────────────────────────────────────────────────────

describe("computeSaleDocumentTotals — mezcla con/sin breakdown", () => {
  it("línea con breakdown + línea sin breakdown → suma solo la primera", () => {
    const out = computeSaleDocumentTotals({
      lines: [
        line({ lineTotal: 1000, metalCost: 500, hechuraCost: 100, metalSale: 700, hechuraSale: 300 }),
        // Línea legacy sin breakdown — no debe contaminar los agregados.
        line({ lineTotal: 800 }),
      ],
      channel: null, coupon: null,
    });
    expect(out.metalCostSubtotal).toBe(500);
    expect(out.hechuraCostSubtotal).toBe(100);
    expect(out.metalSaleSubtotal).toBe(700);
    expect(out.hechuraSaleSubtotal).toBe(300);
    // Los totales clásicos sí incluyen ambas líneas.
    expect(out.subtotalAfterLineDiscounts).toBe(1800);
  });
});
