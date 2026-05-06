// src/lib/pricing-engine/__tests__/breakdown-parity.test.ts
// ============================================================================
// FASE 4 — Tests de paridad final del breakdown Metal/Hechura.
//
// Tanto el endpoint del Simulador (`articles.controller.getPricingPreview`)
// como el de Factura (`sales.service.previewSale` / `confirmSale`) usan
// `computeSaleDocumentTotals` como fuente única para los totales del
// documento, incluidos los agregados Metal/Hechura introducidos en FASE 2:
//
//   - `documentTotals.metalCostSubtotal`
//   - `documentTotals.hechuraCostSubtotal`
//   - `documentTotals.metalSaleSubtotal`
//   - `documentTotals.hechuraSaleSubtotal`
//   - `documentTotals.breakdownEstimated`
//
// Estos tests fijan el contrato: dada la misma línea sintética + el mismo
// contexto comercial, ambos flujos deben devolver subtotales idénticos. La
// invariante adicional `metalSaleSubtotal + hechuraSaleSubtotal ≈
// subtotalAfterLineDiscounts` se valida en todos los casos donde el
// breakdown viene poblado.
//
// Capa pura: sin DB, sin mocks. Las líneas se construyen como las produciría
// el motor de línea tras `deriveMetalHechuraBreakdown`. Los tests del
// helper viven en `metal-hechura-universal.test.ts`.
// ============================================================================

import { describe, it, expect } from "vitest";
import {
  computeSaleDocumentTotals,
  deriveMetalHechuraBreakdown,
  type ChannelAdjustmentInput,
  type CouponInput,
  type DocumentRoundingInput,
  type SaleDocumentTotals,
  type SaleDocumentTotalsLineInput,
  type DeriveMetalHechuraInput,
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
  /** Política doc del tenant. Solo factura. */
  documentRounding?:        DocumentRoundingInput  | null;
};

/** Simulador: nunca aplica `documentRounding`. */
function runSimulator(
  lines: SaleDocumentTotalsLineInput[],
  ctx: ParityContext = {},
): SaleDocumentTotals {
  return computeSaleDocumentTotals({
    lines,
    channel:                 ctx.channel ?? null,
    coupon:                  ctx.coupon  ?? null,
    paymentAdjustmentAmount: ctx.paymentAdjustmentAmount ?? 0,
    shippingAmount:          ctx.shippingAmount          ?? 0,
    globalDiscountAmount:    ctx.globalDiscountAmount    ?? 0,
    roundingAdjustment:      0,
    documentRounding:        null,
  });
}

/** Factura: respeta `documentRounding` del tenant. */
function runInvoice(
  lines: SaleDocumentTotalsLineInput[],
  ctx: ParityContext = {},
): SaleDocumentTotals {
  return computeSaleDocumentTotals({
    lines,
    channel:                 ctx.channel ?? null,
    coupon:                  ctx.coupon  ?? null,
    paymentAdjustmentAmount: ctx.paymentAdjustmentAmount ?? 0,
    shippingAmount:          ctx.shippingAmount          ?? 0,
    globalDiscountAmount:    ctx.globalDiscountAmount    ?? 0,
    roundingAdjustment:      0,
    documentRounding:        ctx.documentRounding ?? null,
  });
}

/** Construye una línea sintética con su breakdown Metal/Hechura usando el
 *  helper puro `deriveMetalHechuraBreakdown` — exactamente lo que el motor
 *  de línea produce. */
function lineWithBreakdown(args: {
  quantity:    number;
  unitPrice:   number;
  basePrice?:  number;
  taxPerUnit?: number;
  bd:          DeriveMetalHechuraInput;
}): SaleDocumentTotalsLineInput {
  const qty       = args.quantity;
  const unitPrice = args.unitPrice;
  const basePrice = args.basePrice ?? unitPrice;
  const tax       = args.taxPerUnit ?? 0;
  const mhb       = deriveMetalHechuraBreakdown(args.bd);
  const round2    = (n: number) => Math.round(n * 100) / 100;

  const out: SaleDocumentTotalsLineInput = {
    quantity:      qty,
    basePrice,
    unitPrice,
    lineTotal:     round2(unitPrice * qty),
    lineTaxAmount: round2(tax       * qty),
  };
  if (mhb) {
    out.metalCost            = round2(mhb.metalCost   * qty);
    out.hechuraCost          = round2(mhb.hechuraCost * qty);
    out.metalSale            = round2(mhb.metalSale   * qty);
    out.hechuraSale          = round2(mhb.hechuraSale * qty);
    out.metalSaleEstimated   = mhb.metalSaleEstimated   ?? false;
    out.hechuraSaleEstimated = mhb.hechuraSaleEstimated ?? false;
  }
  return out;
}

/** Garantía: `metalSaleSubtotal + hechuraSaleSubtotal ≈ subtotalAfterLineDiscounts`.
 *  Este es el invariante REAL del agregado: el motor garantiza
 *  `metalSale + hechuraSale = unitPrice` por línea (FASE 1), por lo que
 *  Σ(metalSale × qty) + Σ(hechuraSale × qty) = Σ(lineTotal) =
 *  subtotalAfterLineDiscounts. */
function expectBreakdownInvariant(out: SaleDocumentTotals) {
  const m = out.metalSaleSubtotal   ?? 0;
  const h = out.hechuraSaleSubtotal ?? 0;
  // Tolerancia 0.02 para absorber float-precision del round2 aplicado por
  // separado a `metalSale × qty`, `hechuraSale × qty` y `lineTotal`.
  expect(Math.abs((m + h) - out.subtotalAfterLineDiscounts)).toBeLessThanOrEqual(0.02);
}

/** Paridad simulador↔factura en los agregados Metal/Hechura. */
function expectMetalHechuraParity(sim: SaleDocumentTotals, inv: SaleDocumentTotals) {
  expect(sim.metalCostSubtotal   ?? 0).toBeCloseTo(inv.metalCostSubtotal   ?? 0, 2);
  expect(sim.hechuraCostSubtotal ?? 0).toBeCloseTo(inv.hechuraCostSubtotal ?? 0, 2);
  expect(sim.metalSaleSubtotal   ?? 0).toBeCloseTo(inv.metalSaleSubtotal   ?? 0, 2);
  expect(sim.hechuraSaleSubtotal ?? 0).toBeCloseTo(inv.hechuraSaleSubtotal ?? 0, 2);
  expect(sim.breakdownEstimated  ?? false).toBe(inv.breakdownEstimated ?? false);
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. METAL_HECHURA exacto
// ─────────────────────────────────────────────────────────────────────────────

describe("Paridad breakdown — METAL_HECHURA exacto", () => {
  it("metalSaleSubtotal y hechuraSaleSubtotal coinciden + invariante de suma + estimated=false", () => {
    const ln = lineWithBreakdown({
      quantity:  2,
      unitPrice: 1000,        // metalSale + hechuraSale = 1000 (exacto)
      bd: {
        metalCost:      500,
        hechuraCost:    200,
        costTotal:      700,
        basePrice:      1000,
        priceSource:    "PRICE_LIST",
        commercialMode: null,
        exactBreakdown: {
          metalSale:   650,
          hechuraSale: 350,
          metalMarginPct:   30,
          hechuraMarginPct: 75,
        },
      },
    });
    const sim = runSimulator([ln]);
    const inv = runInvoice([ln]);
    expectMetalHechuraParity(sim, inv);
    // En METAL_HECHURA exacto NO hay estimated.
    expect(sim.breakdownEstimated).toBe(false);
    // metalSale × qty = 1300, hechuraSale × qty = 700.
    expect(sim.metalSaleSubtotal).toBe(1300);
    expect(sim.hechuraSaleSubtotal).toBe(700);
    // Invariante: 1300 + 700 = 2000 = subtotalAfterLineDiscounts.
    expectBreakdownInvariant(sim);
    // Cuando NO hay impuestos / canal / cupón, total == subtotal.
    expect(sim.metalSaleSubtotal + sim.hechuraSaleSubtotal).toBeCloseTo(sim.total, 2);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. MARGIN_TOTAL — derivado por proporción (estimated=true)
// ─────────────────────────────────────────────────────────────────────────────

describe("Paridad breakdown — MARGIN_TOTAL (PROPORTIONAL_COST)", () => {
  it("subtotales coinciden simulador↔factura, estimated=true, suma==subtotal", () => {
    const ln = lineWithBreakdown({
      quantity:  3,
      unitPrice: 1700,        // factor 1.7 sobre cost 1000 = 700+300
      bd: {
        metalCost:    700,
        hechuraCost:  300,
        costTotal:    1000,
        basePrice:    1700,
        priceSource:  "PRICE_LIST",
        commercialMode: null,
      },
    });
    const sim = runSimulator([ln]);
    const inv = runInvoice([ln]);
    expectMetalHechuraParity(sim, inv);
    expect(sim.breakdownEstimated).toBe(true);
    // metalSale = 1190 / línea × 3 = 3570; hechuraSale = 510 × 3 = 1530.
    expect(sim.metalSaleSubtotal).toBeCloseTo(3570, 2);
    expect(sim.hechuraSaleSubtotal).toBeCloseTo(1530, 2);
    // Suma = subtotalAfterLineDiscounts.
    expectBreakdownInvariant(sim);
    expect(sim.metalSaleSubtotal + sim.hechuraSaleSubtotal).toBeCloseTo(sim.total, 2);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. COST_PER_GRAM — también PROPORTIONAL_COST
// ─────────────────────────────────────────────────────────────────────────────

describe("Paridad breakdown — COST_PER_GRAM", () => {
  it("misma proporcionalidad que MARGIN_TOTAL", () => {
    const ln = lineWithBreakdown({
      quantity:  5,
      unitPrice: 750,
      bd: {
        metalCost:    400,
        hechuraCost:  100,
        costTotal:    500,
        basePrice:    750,
        priceSource:  "PRICE_LIST",
        commercialMode: null,
      },
    });
    const sim = runSimulator([ln]);
    const inv = runInvoice([ln]);
    expectMetalHechuraParity(sim, inv);
    expect(sim.breakdownEstimated).toBe(true);
    // metalSale = 600 × 5 = 3000; hechuraSale = 150 × 5 = 750.
    expect(sim.metalSaleSubtotal).toBe(3000);
    expect(sim.hechuraSaleSubtotal).toBe(750);
    expectBreakdownInvariant(sim);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 4. MANUAL_OVERRIDE — distintos sub-casos según el costo disponible
// ─────────────────────────────────────────────────────────────────────────────

describe("Paridad breakdown — MANUAL_OVERRIDE", () => {
  it("manual con costo > 0 → PROPORTIONAL_COST, paridad y estimated=true", () => {
    const ln = lineWithBreakdown({
      quantity:  1,
      unitPrice: 1500,
      bd: {
        metalCost:    500,
        hechuraCost:  500,
        costTotal:    1000,
        basePrice:    1500,
        priceSource:  "MANUAL_OVERRIDE",
        commercialMode: null,
      },
    });
    const sim = runSimulator([ln]);
    const inv = runInvoice([ln]);
    expectMetalHechuraParity(sim, inv);
    expect(sim.breakdownEstimated).toBe(true);
    expect(sim.metalSaleSubtotal).toBeCloseTo(750, 2);
    expect(sim.hechuraSaleSubtotal).toBeCloseTo(750, 2);
    expectBreakdownInvariant(sim);
  });

  it("manual SIN costo → MANUAL_AS_HECHURA, todo a hechura", () => {
    const ln = lineWithBreakdown({
      quantity:  2,
      unitPrice: 999.99,
      bd: {
        metalCost:    0,
        hechuraCost:  0,
        costTotal:    0,
        basePrice:    999.99,
        priceSource:  "MANUAL_OVERRIDE",
        commercialMode: null,
      },
    });
    const sim = runSimulator([ln]);
    const inv = runInvoice([ln]);
    expectMetalHechuraParity(sim, inv);
    // Todo a hechura.
    expect(sim.metalSaleSubtotal).toBe(0);
    expect(sim.hechuraSaleSubtotal).toBeCloseTo(1999.98, 2);
    expectBreakdownInvariant(sim);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 5. SERVICE — artículo sin metal
// ─────────────────────────────────────────────────────────────────────────────

describe("Paridad breakdown — SERVICE_AS_HECHURA", () => {
  it("metalCost=0 + hechuraCost>0 → todo a hechura", () => {
    const ln = lineWithBreakdown({
      quantity:  4,
      unitPrice: 900,
      bd: {
        metalCost:    0,
        hechuraCost:  500,
        costTotal:    500,
        basePrice:    900,
        priceSource:  "PRICE_LIST",
        commercialMode: null,
      },
    });
    const sim = runSimulator([ln]);
    const inv = runInvoice([ln]);
    expectMetalHechuraParity(sim, inv);
    expect(sim.metalSaleSubtotal).toBe(0);
    expect(sim.hechuraSaleSubtotal).toBe(3600);  // 900 × 4
    expectBreakdownInvariant(sim);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 6. COMBO_COMMERCIAL — costo acumulado de componentes
// ─────────────────────────────────────────────────────────────────────────────

describe("Paridad breakdown — COMBO_COMPONENTS", () => {
  it("combo con metal+hechura sumados de componentes — paridad y estimated=true", () => {
    const ln = lineWithBreakdown({
      quantity:  1,
      unitPrice: 1800,
      bd: {
        metalCost:      600,
        hechuraCost:    600,
        costTotal:      1200,
        basePrice:      1800,
        priceSource:    "PRICE_LIST",
        commercialMode: "COMBO_COMMERCIAL",
      },
    });
    const sim = runSimulator([ln]);
    const inv = runInvoice([ln]);
    expectMetalHechuraParity(sim, inv);
    expect(sim.breakdownEstimated).toBe(true);
    // factor 1.5 → metalSale 900, hechuraSale 900.
    expect(sim.metalSaleSubtotal).toBeCloseTo(900, 2);
    expect(sim.hechuraSaleSubtotal).toBeCloseTo(900, 2);
    expectBreakdownInvariant(sim);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 7. Multi-línea — mezcla de modos
// ─────────────────────────────────────────────────────────────────────────────

describe("Paridad breakdown — multi-línea", () => {
  it("3 líneas (METAL_HECHURA + MARGIN_TOTAL + SERVICE): subtotales coherentes", () => {
    const lines: SaleDocumentTotalsLineInput[] = [
      // Línea 1: METAL_HECHURA exacto, qty=2.
      lineWithBreakdown({
        quantity: 2, unitPrice: 1000,
        bd: {
          metalCost: 500, hechuraCost: 200, costTotal: 700,
          basePrice: 1000, priceSource: "PRICE_LIST", commercialMode: null,
          exactBreakdown: {
            metalSale: 650, hechuraSale: 350, metalMarginPct: 30, hechuraMarginPct: 75,
          },
        },
      }),
      // Línea 2: MARGIN_TOTAL, qty=1.
      lineWithBreakdown({
        quantity: 1, unitPrice: 1700,
        bd: { metalCost: 700, hechuraCost: 300, costTotal: 1000, basePrice: 1700, priceSource: "PRICE_LIST", commercialMode: null },
      }),
      // Línea 3: SERVICE, qty=3.
      lineWithBreakdown({
        quantity: 3, unitPrice: 600,
        bd: { metalCost: 0, hechuraCost: 200, costTotal: 200, basePrice: 600, priceSource: "PRICE_LIST", commercialMode: null },
      }),
    ];
    const sim = runSimulator(lines);
    const inv = runInvoice(lines);
    expectMetalHechuraParity(sim, inv);
    // Estimated=true porque líneas 2 y 3 son derivadas.
    expect(sim.breakdownEstimated).toBe(true);
    // Σ metalSale: 650×2 + 1190×1 + 0×3 = 1300 + 1190 = 2490
    // Σ hechuraSale: 350×2 + 510×1 + 600×3 = 700 + 510 + 1800 = 3010
    expect(sim.metalSaleSubtotal).toBeCloseTo(2490, 2);
    expect(sim.hechuraSaleSubtotal).toBeCloseTo(3010, 2);
    expectBreakdownInvariant(sim);
  });

  it("multi-línea solo con METAL_HECHURA exacto → estimated=false", () => {
    const lines: SaleDocumentTotalsLineInput[] = [
      lineWithBreakdown({
        quantity: 2, unitPrice: 800,
        bd: {
          metalCost: 400, hechuraCost: 100, costTotal: 500,
          basePrice: 800, priceSource: "PRICE_LIST", commercialMode: null,
          exactBreakdown: {
            metalSale: 600, hechuraSale: 200, metalMarginPct: 50, hechuraMarginPct: 100,
          },
        },
      }),
      lineWithBreakdown({
        quantity: 1, unitPrice: 500,
        bd: {
          metalCost: 200, hechuraCost: 100, costTotal: 300,
          basePrice: 500, priceSource: "PRICE_LIST", commercialMode: null,
          exactBreakdown: {
            metalSale: 350, hechuraSale: 150, metalMarginPct: 75, hechuraMarginPct: 50,
          },
        },
      }),
    ];
    const sim = runSimulator(lines);
    const inv = runInvoice(lines);
    expectMetalHechuraParity(sim, inv);
    expect(sim.breakdownEstimated).toBe(false);
    expectBreakdownInvariant(sim);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 8. Con canal + cupón
// ─────────────────────────────────────────────────────────────────────────────

describe("Paridad breakdown — con canal + cupón", () => {
  it("agregados Metal/Hechura no cambian por canal/cupón (independientes)", () => {
    const channel: ChannelAdjustmentInput = {
      id: "ch-1", name: "Tienda", adjustmentType: "PERCENTAGE", adjustmentValue: 5,
    };
    const coupon: CouponInput = {
      id: "cp-1", code: "VERANO", name: "10off",
      discountType: "FIXED_AMOUNT", discountValue: 100,
    };
    const lines: SaleDocumentTotalsLineInput[] = [
      lineWithBreakdown({
        quantity: 2, unitPrice: 1000,
        bd: { metalCost: 500, hechuraCost: 100, costTotal: 600, basePrice: 1000, priceSource: "PRICE_LIST", commercialMode: null },
      }),
    ];
    const sim = runSimulator(lines, { channel, coupon });
    const inv = runInvoice(lines, { channel, coupon });
    // Subtotales Metal/Hechura idénticos: canal y cupón no los afectan.
    expectMetalHechuraParity(sim, inv);
    // Suma = subtotalAfterLineDiscounts (NO total — canal y cupón se restan después).
    expectBreakdownInvariant(sim);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 9. Con impuestos
// ─────────────────────────────────────────────────────────────────────────────

describe("Paridad breakdown — con impuestos", () => {
  it("impuestos no contaminan los agregados Metal/Hechura", () => {
    const lines: SaleDocumentTotalsLineInput[] = [
      lineWithBreakdown({
        quantity:    2,
        unitPrice:   1000,
        taxPerUnit:  210,         // IVA 21%
        bd: { metalCost: 700, hechuraCost: 300, costTotal: 1000, basePrice: 1000, priceSource: "PRICE_LIST", commercialMode: null },
      }),
    ];
    const sim = runSimulator(lines);
    const inv = runInvoice(lines);
    expectMetalHechuraParity(sim, inv);
    // Σ metalSale × qty = 700 × 2 = 1400.  Σ hechuraSale × qty = 300 × 2 = 600.
    expect(sim.metalSaleSubtotal).toBeCloseTo(1400, 2);
    expect(sim.hechuraSaleSubtotal).toBeCloseTo(600, 2);
    expect(sim.taxAmount).toBe(420);
    // Suma == subtotalAfterLineDiscounts == 2000. NO incluye impuestos.
    expectBreakdownInvariant(sim);
    expect(sim.metalSaleSubtotal + sim.hechuraSaleSubtotal).toBeCloseTo(sim.subtotalAfterLineDiscounts, 2);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 10. Con redondeo (línea y comprobante)
// ─────────────────────────────────────────────────────────────────────────────

describe("Paridad breakdown — con redondeo", () => {
  it("redondeo de lista absorbido en lineTotal: agregados coherentes", () => {
    // El motor de línea redondeó `lineTotal` (applyOn=NET/TOTAL). El
    // breakdown ya viene escalado al `unitPrice` post-redondeo; los
    // agregados quedan exactos.
    const lines: SaleDocumentTotalsLineInput[] = [
      lineWithBreakdown({
        quantity: 2,
        unitPrice: 858,                    // redondeado
        bd: {
          metalCost: 500, hechuraCost: 0, costTotal: 500,
          basePrice: 858, priceSource: "PRICE_LIST", commercialMode: null,
        },
      }),
    ];
    const sim = runSimulator(lines);
    const inv = runInvoice(lines);
    expectMetalHechuraParity(sim, inv);
    // hechuraCost=0 → factor proporcional asigna todo al metal.
    expect(sim.metalSaleSubtotal).toBeCloseTo(1716, 2);  // 858 × 2
    expect(sim.hechuraSaleSubtotal).toBe(0);
    expectBreakdownInvariant(sim);
  });

  it("redondeo por comprobante (TENANT_POLICY) — Metal/Hechura intactos, solo cambia total", () => {
    const lines: SaleDocumentTotalsLineInput[] = [
      lineWithBreakdown({
        quantity: 1, unitPrice: 1573.45,
        bd: {
          metalCost: 700, hechuraCost: 300, costTotal: 1000,
          basePrice: 1573.45, priceSource: "PRICE_LIST", commercialMode: null,
        },
      }),
    ];
    const sim = runSimulator(lines);
    const inv = runInvoice(lines, {
      documentRounding: { mode: "TEN", direction: "NEAREST" },
    });
    // Subtotales Metal/Hechura idénticos en ambos lados — el redondeo
    // a nivel comprobante NO los afecta.
    expectMetalHechuraParity(sim, inv);
    expectBreakdownInvariant(sim);
    expectBreakdownInvariant(inv);
    // El delta vive solo en `total` y `roundingAdjustment`.
    expect(sim.total).toBeCloseTo(1573.45, 2);
    expect(inv.total).toBe(1570);   // redondeado a TEN
    // Pero los agregados Metal/Hechura coinciden centavo a centavo.
    expect(sim.metalSaleSubtotal).toBe(inv.metalSaleSubtotal);
    expect(sim.hechuraSaleSubtotal).toBe(inv.hechuraSaleSubtotal);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 11. Coherencia de `source` y `breakdownEstimated`
//
// El `source` exacto vive en cada línea (no en doc-totals); estos tests
// validan que el helper `deriveMetalHechuraBreakdown` produce el `source`
// correcto por modo y que `breakdownEstimated` se propaga correctamente al
// agregado doc.
// ─────────────────────────────────────────────────────────────────────────────

describe("source y breakdownEstimated por modo", () => {
  const cases: Array<{ name: string; input: DeriveMetalHechuraInput; source: string; estimated: boolean }> = [
    {
      name:  "METAL_HECHURA",
      input: {
        metalCost: 500, hechuraCost: 200, costTotal: 700, basePrice: 1000,
        priceSource: "PRICE_LIST", commercialMode: null,
        exactBreakdown: { metalSale: 650, hechuraSale: 350, metalMarginPct: 30, hechuraMarginPct: 75 },
      },
      source: "METAL_HECHURA", estimated: false,
    },
    {
      name:  "MARGIN_TOTAL → PROPORTIONAL_COST",
      input: { metalCost: 700, hechuraCost: 300, costTotal: 1000, basePrice: 1700, priceSource: "PRICE_LIST", commercialMode: null },
      source: "PROPORTIONAL_COST", estimated: true,
    },
    {
      name:  "COST_PER_GRAM → PROPORTIONAL_COST",
      input: { metalCost: 400, hechuraCost: 100, costTotal: 500, basePrice: 750, priceSource: "PRICE_LIST", commercialMode: null },
      source: "PROPORTIONAL_COST", estimated: true,
    },
    {
      name:  "MANUAL_OVERRIDE con costo → PROPORTIONAL_COST",
      input: { metalCost: 500, hechuraCost: 500, costTotal: 1000, basePrice: 1500, priceSource: "MANUAL_OVERRIDE", commercialMode: null },
      source: "PROPORTIONAL_COST", estimated: true,
    },
    {
      name:  "MANUAL_OVERRIDE sin costo → MANUAL_AS_HECHURA",
      input: { metalCost: 0, hechuraCost: 0, costTotal: 0, basePrice: 1500, priceSource: "MANUAL_OVERRIDE", commercialMode: null },
      source: "MANUAL_AS_HECHURA", estimated: true,
    },
    {
      name:  "Servicio → SERVICE_AS_HECHURA",
      input: { metalCost: 0, hechuraCost: 500, costTotal: 500, basePrice: 900, priceSource: "PRICE_LIST", commercialMode: null },
      source: "SERVICE_AS_HECHURA", estimated: true,
    },
    {
      name:  "Combo → COMBO_COMPONENTS",
      input: { metalCost: 600, hechuraCost: 600, costTotal: 1200, basePrice: 1800, priceSource: "PRICE_LIST", commercialMode: "COMBO_COMMERCIAL" },
      source: "COMBO_COMPONENTS", estimated: true,
    },
  ];

  for (const c of cases) {
    it(`source="${c.source}" para ${c.name}`, () => {
      const r = deriveMetalHechuraBreakdown(c.input);
      expect(r).not.toBeNull();
      expect(r!.source).toBe(c.source);
      expect(r!.metalSaleEstimated).toBe(c.estimated);
      expect(r!.hechuraSaleEstimated).toBe(c.estimated);
    });
  }

  it("breakdownEstimated del documento se propaga: una línea con estimated=true → doc estimated=true", () => {
    const lines: SaleDocumentTotalsLineInput[] = [
      // Línea 1: METAL_HECHURA exacto.
      lineWithBreakdown({
        quantity: 1, unitPrice: 1000,
        bd: {
          metalCost: 500, hechuraCost: 200, costTotal: 700,
          basePrice: 1000, priceSource: "PRICE_LIST", commercialMode: null,
          exactBreakdown: { metalSale: 650, hechuraSale: 350, metalMarginPct: 30, hechuraMarginPct: 75 },
        },
      }),
      // Línea 2: MARGIN_TOTAL → estimated.
      lineWithBreakdown({
        quantity: 1, unitPrice: 1700,
        bd: { metalCost: 700, hechuraCost: 300, costTotal: 1000, basePrice: 1700, priceSource: "PRICE_LIST", commercialMode: null },
      }),
    ];
    const sim = runSimulator(lines);
    const inv = runInvoice(lines);
    expect(sim.breakdownEstimated).toBe(true);
    expect(inv.breakdownEstimated).toBe(true);
    expectMetalHechuraParity(sim, inv);
  });

  it("breakdownEstimated=false cuando TODAS las líneas son METAL_HECHURA exactas", () => {
    const lines: SaleDocumentTotalsLineInput[] = [
      lineWithBreakdown({
        quantity: 2, unitPrice: 1000,
        bd: {
          metalCost: 500, hechuraCost: 200, costTotal: 700,
          basePrice: 1000, priceSource: "PRICE_LIST", commercialMode: null,
          exactBreakdown: { metalSale: 650, hechuraSale: 350, metalMarginPct: 30, hechuraMarginPct: 75 },
        },
      }),
    ];
    const sim = runSimulator(lines);
    expect(sim.breakdownEstimated).toBe(false);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 12. Caso integral — todos los ajustes juntos
// ─────────────────────────────────────────────────────────────────────────────

describe("Paridad breakdown — caso integral", () => {
  it("multi-línea + canal + cupón + impuestos + pago + envío + doc-rounding", () => {
    const channel: ChannelAdjustmentInput = {
      id: "ch", name: "Online", adjustmentType: "PERCENTAGE", adjustmentValue: 5,
    };
    const coupon: CouponInput = {
      id: "cp", code: "X", name: "fijo50",
      discountType: "FIXED_AMOUNT", discountValue: 50,
    };
    const lines: SaleDocumentTotalsLineInput[] = [
      lineWithBreakdown({
        quantity: 2, unitPrice: 1000, taxPerUnit: 100,
        bd: {
          metalCost: 700, hechuraCost: 300, costTotal: 1000,
          basePrice: 1000, priceSource: "PRICE_LIST", commercialMode: null,
        },
      }),
      lineWithBreakdown({
        quantity: 1, unitPrice: 600, taxPerUnit: 60,
        bd: {
          metalCost: 0, hechuraCost: 200, costTotal: 200,
          basePrice: 600, priceSource: "PRICE_LIST", commercialMode: null,
        },
      }),
    ];
    const ctx: ParityContext = {
      channel, coupon,
      paymentAdjustmentAmount: 25,
      shippingAmount:          150,
      globalDiscountAmount:    50,
    };
    const sim = runSimulator(lines, ctx);
    const inv = runInvoice(lines, {
      ...ctx,
      documentRounding: { mode: "TEN", direction: "NEAREST" },
    });

    // Agregados Metal/Hechura: paridad estricta.
    expectMetalHechuraParity(sim, inv);

    // Σ metalSale: 700×2 + 0×1 = 1400.
    // Σ hechuraSale: 300×2 + 600×1 = 1200.
    expect(sim.metalSaleSubtotal).toBeCloseTo(1400, 2);
    expect(sim.hechuraSaleSubtotal).toBeCloseTo(1200, 2);
    // Suma = subtotalAfterLineDiscounts = 2000 + 600 = 2600.
    expectBreakdownInvariant(sim);
    expectBreakdownInvariant(inv);

    // Estimated=true porque ambas líneas son derivadas (PROPORTIONAL_COST y
    // SERVICE_AS_HECHURA).
    expect(sim.breakdownEstimated).toBe(true);
    expect(inv.breakdownEstimated).toBe(true);
  });
});
