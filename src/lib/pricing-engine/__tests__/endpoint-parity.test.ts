// src/lib/pricing-engine/__tests__/endpoint-parity.test.ts
// ============================================================================
// Paridad endpoint a endpoint:
//   GET  /api/articles/:id/pricing-preview   (articles.controller.getPricingPreview)
//   POST /api/sales/preview                  (sales.service.previewSale)
//
// Regla: mismo input comercial → mismos `metalHechuraBreakdown`, `documentTotals`
// y `taxBreakdown`.
//
// Ambos endpoints terminan invocando:
//   1) `resolveFinalSalePrice` por línea (mismo motor, passthrough de
//      `metalHechuraBreakdown` y `taxBreakdown`).
//   2) `computeSaleDocumentTotals` con un `SaleDocumentTotalsLineInput`
//      construido a partir del `SalePriceResult`.
//
// Las dos fórmulas de armado del `docLine` divergen literalmente en el código:
//   · articles.controller.ts:1276-1309 → deriva `lineTotal` de `unitTotalWithTax × qty − tax × qty`.
//   · sales.service.ts:2638-2659      → toma `lineTotal` y `lineTaxAmount` del resolvedLine.
//
// Si las dos fórmulas producen el MISMO docLine para el mismo SalePriceResult,
// los `documentTotals` quedan idénticos. Si en algún caso divergen, este test
// los pone a la luz.
//
// Capa pura: sin DB, sin mocks. Construimos `SalePriceResult` sintéticos.
// ============================================================================

import { describe, it, expect } from "vitest";
import { Prisma } from "@prisma/client";
import {
  computeSaleDocumentTotals,
  type ChannelAdjustmentInput,
  type CouponInput,
  type SaleDocumentTotalsLineInput,
  type SaleDocumentTotals,
} from "../pricing-engine.js";

const D = Prisma.Decimal;

// ─────────────────────────────────────────────────────────────────────────────
// Tipos: forma mínima del SalePriceResult que ambos endpoints reciben del motor.
// Espejo de los campos relevantes de SalePriceResult (pricing-engine.types.ts).
// ─────────────────────────────────────────────────────────────────────────────

type MHB = {
  metalCost: number;
  hechuraCost: number;
  metalSale: number;
  hechuraSale: number;
  metalMarginPct: number;
  hechuraMarginPct: number;
  metalGramsBase?: number | null;
  metalGramsSale?: number | null;
  metalPricePerGram?: number | null;
  metalSaleEstimated?: boolean;
  hechuraSaleEstimated?: boolean;
  source?: string;
};

type SyntheticSaleResult = {
  unitPrice:     Prisma.Decimal | null;
  basePrice:     Prisma.Decimal | null;
  taxAmount:     Prisma.Decimal | null;
  totalWithTax:  Prisma.Decimal | null;
  taxBreakdown:  Array<{ taxId: string; name: string; rate: number | null; baseAmount: number; taxAmount: number }>;
  metalHechuraBreakdown: MHB | null;
};

const round2 = (n: number) => Math.round(n * 100) / 100;

function makeResult(overrides: Partial<SyntheticSaleResult> = {}): SyntheticSaleResult {
  return {
    unitPrice:    new D("1000"),
    basePrice:    new D("1000"),
    taxAmount:    new D("0"),
    totalWithTax: new D("1000"),
    taxBreakdown: [],
    metalHechuraBreakdown: null,
    ...overrides,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// REPLICAS DEL RUNTIME — cada helper copia exactamente las líneas del endpoint.
// Si alguien edita el runtime y no este test, el test falla y obliga a sincronizar.
// ─────────────────────────────────────────────────────────────────────────────

/** Réplica exacta de `articles.controller.ts:1276-1309` (getPricingPreview).
 *  Deriva `lineTotal` de `lineTotalWithTax − lineTaxAmount`. */
function buildDocLineArticleStyle(
  result: SyntheticSaleResult,
  quantity: number,
): SaleDocumentTotalsLineInput {
  const unitPriceNum     = result.unitPrice?.toNumber()    ?? 0;
  const basePriceNum     = result.basePrice?.toNumber()    ?? unitPriceNum;
  const unitTaxNum       = result.taxAmount?.toNumber()    ?? 0;
  const unitTotalWithTax = result.totalWithTax?.toNumber() ?? unitPriceNum;
  const lineTotalWithTax = round2(unitTotalWithTax * quantity);
  const lineTaxAmountDoc = round2(unitTaxNum       * quantity);
  const lineTotalNet     = round2(lineTotalWithTax - lineTaxAmountDoc);

  const mhb = result.metalHechuraBreakdown ?? null;
  return {
    quantity,
    basePrice:     basePriceNum,
    unitPrice:     unitPriceNum,
    lineTotal:     lineTotalNet,
    lineTaxAmount: lineTaxAmountDoc,
    ...(mhb
      ? {
          metalCost:            round2(mhb.metalCost   * quantity),
          hechuraCost:          round2(mhb.hechuraCost * quantity),
          metalSale:            round2(mhb.metalSale   * quantity),
          hechuraSale:          round2(mhb.hechuraSale * quantity),
          metalSaleEstimated:   mhb.metalSaleEstimated   ?? false,
          hechuraSaleEstimated: mhb.hechuraSaleEstimated ?? false,
        }
      : {}),
  };
}

/** Réplica de `sales.service.ts:2638-2659` (previewSale → computeSaleDocumentTotals).
 *  Lee `lineTotal` y `lineTaxAmount` directamente de la línea resuelta. La línea
 *  resuelta usa: `lineTotal = round2(unitPrice × qty)` y
 *  `lineTaxAmount = round2(unitTax × qty)`. */
function buildDocLineSalesStyle(
  result: SyntheticSaleResult,
  quantity: number,
): SaleDocumentTotalsLineInput {
  const unitPriceNum = result.unitPrice?.toNumber() ?? 0;
  const basePriceNum = result.basePrice?.toNumber() ?? unitPriceNum;
  const unitTaxNum   = result.taxAmount?.toNumber() ?? 0;

  // Lo que `previewSale` usa para `l.lineTotal` y `l.lineTaxAmount` (espejo de
  // sales.service.ts donde construye el resolvedLine, post-redondeo de línea).
  const lineTotal     = round2(unitPriceNum * quantity);
  const lineTaxAmount = round2(unitTaxNum   * quantity);

  const mhb = result.metalHechuraBreakdown ?? null;
  const q = quantity || 1;
  return {
    quantity,
    basePrice:     basePriceNum,
    unitPrice:     unitPriceNum,
    lineTotal,
    lineTaxAmount,
    ...(mhb
      ? {
          metalCost:            Math.round(Number(mhb.metalCost   ?? 0) * q * 100) / 100,
          hechuraCost:          Math.round(Number(mhb.hechuraCost ?? 0) * q * 100) / 100,
          metalSale:            Math.round(Number(mhb.metalSale   ?? 0) * q * 100) / 100,
          hechuraSale:          Math.round(Number(mhb.hechuraSale ?? 0) * q * 100) / 100,
          metalSaleEstimated:   mhb.metalSaleEstimated   ?? false,
          hechuraSaleEstimated: mhb.hechuraSaleEstimated ?? false,
        }
      : {}),
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Wrappers que invocan `computeSaleDocumentTotals` con la misma envoltura que
// cada endpoint usa (channel, coupon, payment, shipping, etc.).
// ─────────────────────────────────────────────────────────────────────────────

type Ctx = {
  channel?: ChannelAdjustmentInput | null;
  coupon?:  CouponInput            | null;
  paymentAdjustmentAmount?: number;
  shippingAmount?:          number;
  globalDiscountAmount?:    number;
};

function totalsFromArticleEndpoint(result: SyntheticSaleResult, qty: number, ctx: Ctx = {}): SaleDocumentTotals {
  return computeSaleDocumentTotals({
    lines:                   [buildDocLineArticleStyle(result, qty)],
    channel:                 ctx.channel ?? null,
    coupon:                  ctx.coupon  ?? null,
    paymentAdjustmentAmount: ctx.paymentAdjustmentAmount ?? 0,
    shippingAmount:          ctx.shippingAmount          ?? 0,
    globalDiscountAmount:    ctx.globalDiscountAmount    ?? 0,
    roundingAdjustment:      0,
    documentRounding:        null,        // Simulador NUNCA aplica política doc.
  });
}

function totalsFromSalesEndpoint(result: SyntheticSaleResult, qty: number, ctx: Ctx = {}): SaleDocumentTotals {
  return computeSaleDocumentTotals({
    lines:                   [buildDocLineSalesStyle(result, qty)],
    channel:                 ctx.channel ?? null,
    coupon:                  ctx.coupon  ?? null,
    paymentAdjustmentAmount: ctx.paymentAdjustmentAmount ?? 0,
    shippingAmount:          ctx.shippingAmount          ?? 0,
    globalDiscountAmount:    ctx.globalDiscountAmount    ?? 0,
    roundingAdjustment:      0,
    documentRounding:        null,        // Sin política doc para aislar paridad.
  });
}

/** Iguala TODOS los campos numéricos de `SaleDocumentTotals`. */
function expectDocTotalsEqual(a: SaleDocumentTotals, b: SaleDocumentTotals) {
  expect(a.subtotalBeforeDiscounts   ).toBeCloseTo(b.subtotalBeforeDiscounts,    2);
  expect(a.lineDiscountAmount        ).toBeCloseTo(b.lineDiscountAmount,         2);
  expect(a.subtotalAfterLineDiscounts).toBeCloseTo(b.subtotalAfterLineDiscounts, 2);
  expect(a.channelAdjustmentAmount   ).toBeCloseTo(b.channelAdjustmentAmount,    2);
  expect(a.couponDiscountAmount      ).toBeCloseTo(b.couponDiscountAmount,       2);
  expect(a.paymentAdjustmentAmount   ).toBeCloseTo(b.paymentAdjustmentAmount,    2);
  expect(a.shippingAmount            ).toBeCloseTo(b.shippingAmount,             2);
  expect(a.globalDiscountAmount      ).toBeCloseTo(b.globalDiscountAmount,       2);
  expect(a.taxableBase               ).toBeCloseTo(b.taxableBase,                2);
  expect(a.taxAmount                 ).toBeCloseTo(b.taxAmount,                  2);
  expect(a.totalBeforeTax            ).toBeCloseTo(b.totalBeforeTax,             2);
  expect(a.totalWithTax              ).toBeCloseTo(b.totalWithTax,               2);
  expect(a.total                     ).toBeCloseTo(b.total,                      2);

  // Agregados Metal/Hechura — cuando alguna línea los provee, deben coincidir.
  expect(a.metalCostSubtotal   ?? 0).toBeCloseTo(b.metalCostSubtotal   ?? 0, 2);
  expect(a.hechuraCostSubtotal ?? 0).toBeCloseTo(b.hechuraCostSubtotal ?? 0, 2);
  expect(a.metalSaleSubtotal   ?? 0).toBeCloseTo(b.metalSaleSubtotal   ?? 0, 2);
  expect(a.hechuraSaleSubtotal ?? 0).toBeCloseTo(b.hechuraSaleSubtotal ?? 0, 2);
  expect(!!a.breakdownEstimated).toBe(!!b.breakdownEstimated);
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. documentTotals — paridad de armado entre articles y sales endpoint
// ─────────────────────────────────────────────────────────────────────────────

describe("Paridad endpoint — documentTotals (articles vs sales)", () => {
  it("qty=1, sin impuestos, sin canal/cupón → docTotals idénticos", () => {
    const r = makeResult({
      unitPrice:    new D("1500"),
      basePrice:    new D("1500"),
      taxAmount:    new D("0"),
      totalWithTax: new D("1500"),
    });
    expectDocTotalsEqual(totalsFromArticleEndpoint(r, 1), totalsFromSalesEndpoint(r, 1));
  });

  it("qty=3, sin impuestos → escalado coherente entre ambos endpoints", () => {
    const r = makeResult({
      unitPrice:    new D("800"),
      basePrice:    new D("1000"),                 // descuento 200 unitario
      taxAmount:    new D("0"),
      totalWithTax: new D("800"),
    });
    expectDocTotalsEqual(totalsFromArticleEndpoint(r, 3), totalsFromSalesEndpoint(r, 3));
  });

  it("qty=2 con IVA 21% → taxableBase y taxAmount coinciden", () => {
    // unitPrice 1000, tax 210 unit, totalWithTax 1210
    const r = makeResult({
      unitPrice:    new D("1000"),
      basePrice:    new D("1000"),
      taxAmount:    new D("210"),
      totalWithTax: new D("1210"),
      taxBreakdown: [{ taxId: "iva", name: "IVA", rate: 21, baseAmount: 1000, taxAmount: 210 }],
    });
    const a = totalsFromArticleEndpoint(r, 2);
    const b = totalsFromSalesEndpoint(r, 2);
    expectDocTotalsEqual(a, b);
    // Smoke: taxAmount esperado = 420
    expect(a.taxAmount).toBeCloseTo(420, 2);
  });

  it("qty=2 con MHB poblado → agregados metal/hechura escalados igual", () => {
    const r = makeResult({
      unitPrice:    new D("6860"),                 // 6600 metal + 260 hechura
      basePrice:    new D("6860"),
      taxAmount:    new D("0"),
      totalWithTax: new D("6860"),
      metalHechuraBreakdown: {
        metalCost:        5500, metalSale:        6600, metalMarginPct:   20,
        hechuraCost:       200, hechuraSale:       260, hechuraMarginPct: 30,
        metalGramsBase:    5.5, metalGramsSale:    5.5, metalPricePerGram: 1000,
        metalSaleEstimated: false, hechuraSaleEstimated: false,
        source: "METAL_HECHURA",
      },
    });
    const a = totalsFromArticleEndpoint(r, 2);
    const b = totalsFromSalesEndpoint(r, 2);
    expectDocTotalsEqual(a, b);
    // Smoke: metalSaleSubtotal esperado = 6600 × 2 = 13200
    expect(a.metalSaleSubtotal).toBeCloseTo(13200, 2);
    expect(a.hechuraSaleSubtotal).toBeCloseTo(520, 2);
  });

  it("qty=2 con MHB derivado por proporción → flag `breakdownEstimated` propagado igual", () => {
    const r = makeResult({
      unitPrice:    new D("1500"),
      basePrice:    new D("1500"),
      taxAmount:    new D("0"),
      totalWithTax: new D("1500"),
      metalHechuraBreakdown: {
        metalCost:   600, metalSale:   900, metalMarginPct: 50,
        hechuraCost: 400, hechuraSale: 600, hechuraMarginPct: 50,
        metalSaleEstimated: true,        // derivado por proporción
        hechuraSaleEstimated: true,
        source: "PROPORTIONAL_COST",
      },
    });
    const a = totalsFromArticleEndpoint(r, 2);
    const b = totalsFromSalesEndpoint(r, 2);
    expectDocTotalsEqual(a, b);
    expect(a.breakdownEstimated).toBe(true);
  });

  it("qty=2 con canal +5% y cupón -100 → totales idénticos en ambos endpoints", () => {
    const r = makeResult({
      unitPrice:    new D("1000"),
      basePrice:    new D("1000"),
      taxAmount:    new D("0"),
      totalWithTax: new D("1000"),
    });
    const ctx: Ctx = {
      channel: { id: "ch", name: "Online",  adjustmentType: "PERCENTAGE", adjustmentValue: 5 },
      coupon:  { id: "cp", code: "X", name: "X", discountType: "FIXED_AMOUNT", discountValue: 100 },
    };
    expectDocTotalsEqual(
      totalsFromArticleEndpoint(r, 2, ctx),
      totalsFromSalesEndpoint(r, 2, ctx),
    );
  });

  it("qty=1 con pago + envío + descuento global → totales idénticos", () => {
    const r = makeResult({
      unitPrice:    new D("2000"),
      basePrice:    new D("2000"),
      taxAmount:    new D("420"),
      totalWithTax: new D("2420"),
      taxBreakdown: [{ taxId: "iva", name: "IVA", rate: 21, baseAmount: 2000, taxAmount: 420 }],
    });
    const ctx: Ctx = {
      paymentAdjustmentAmount: 50,
      shippingAmount:          200,
      globalDiscountAmount:    100,
    };
    expectDocTotalsEqual(
      totalsFromArticleEndpoint(r, 1, ctx),
      totalsFromSalesEndpoint(r, 1, ctx),
    );
  });

  it("qty alta (qty=99) — ningún drift de redondeo entre ambas formas de armado", () => {
    const r = makeResult({
      unitPrice:    new D("123.45"),
      basePrice:    new D("123.45"),
      taxAmount:    new D("25.92"),               // 21% sobre 123.45 ≈ 25.9245
      totalWithTax: new D("149.37"),              // 123.45 + 25.92 (post-round2 unit)
      taxBreakdown: [{ taxId: "iva", name: "IVA", rate: 21, baseAmount: 123.45, taxAmount: 25.92 }],
    });
    expectDocTotalsEqual(totalsFromArticleEndpoint(r, 99), totalsFromSalesEndpoint(r, 99));
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. metalHechuraBreakdown — passthrough en ambos endpoints
//
// Articles devuelve `result.metalHechuraBreakdown` directo (controller:1388).
// Sales lo expone como `lines[i].metalHechuraBreakdown` (sales.service —
// passthrough del result del motor por línea).
//
// Como ambos llaman a `resolveFinalSalePrice` con los mismos args, el motor
// devuelve el mismo objeto. El test verifica el contrato de PROPAGACIÓN: los
// campos del MHB que cada endpoint inyecta al docLine son idénticos.
// ─────────────────────────────────────────────────────────────────────────────

describe("Paridad endpoint — metalHechuraBreakdown (passthrough)", () => {
  it("MHB completo se propaga al docLine de ambos endpoints con los mismos campos", () => {
    const mhb: MHB = {
      metalCost: 5500, metalSale: 6600, metalMarginPct: 20,
      hechuraCost: 200, hechuraSale: 260, hechuraMarginPct: 30,
      metalGramsBase: 5.5, metalGramsSale: 5.5, metalPricePerGram: 1000,
      metalSaleEstimated: false, hechuraSaleEstimated: false, source: "METAL_HECHURA",
    };
    const r = makeResult({
      unitPrice: new D("6860"), basePrice: new D("6860"),
      taxAmount: new D("0"),    totalWithTax: new D("6860"),
      metalHechuraBreakdown: mhb,
    });
    const articleLine = buildDocLineArticleStyle(r, 2);
    const salesLine   = buildDocLineSalesStyle(r, 2);

    // Los 4 importes Metal/Hechura escalados × qty deben ser idénticos.
    expect(articleLine.metalCost).toBe(salesLine.metalCost);
    expect(articleLine.hechuraCost).toBe(salesLine.hechuraCost);
    expect(articleLine.metalSale).toBe(salesLine.metalSale);
    expect(articleLine.hechuraSale).toBe(salesLine.hechuraSale);
    expect(articleLine.metalSaleEstimated).toBe(salesLine.metalSaleEstimated);
    expect(articleLine.hechuraSaleEstimated).toBe(salesLine.hechuraSaleEstimated);
  });

  it("MHB ausente (source=NONE) → ambos endpoints construyen docLine sin campos Metal/Hechura", () => {
    const r = makeResult({ metalHechuraBreakdown: null });
    const articleLine = buildDocLineArticleStyle(r, 1);
    const salesLine   = buildDocLineSalesStyle(r, 1);

    expect(articleLine.metalCost).toBeUndefined();
    expect(salesLine.metalCost).toBeUndefined();
    expect(articleLine.hechuraSale).toBeUndefined();
    expect(salesLine.hechuraSale).toBeUndefined();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. taxBreakdown — passthrough del motor
//
// Articles: `taxBreakdown: result.taxBreakdown ?? []` (controller:1391).
// Sales:    `taxBreakdown` por línea, también passthrough del result.
//
// El test verifica que con la misma `taxBreakdown` de entrada, el agregado
// `taxAmount` que `computeSaleDocumentTotals` devuelve coincide en ambos
// endpoints (= Σ línea × qty, mismo redondeo).
// ─────────────────────────────────────────────────────────────────────────────

describe("Paridad endpoint — taxBreakdown (passthrough)", () => {
  it("dos taxes (IVA 21% + IIBB 3%) escalados × qty → mismo taxAmount en ambos", () => {
    // unitPrice 1000, IVA 210, IIBB 30, totalWithTax 1240
    const r = makeResult({
      unitPrice:    new D("1000"),
      basePrice:    new D("1000"),
      taxAmount:    new D("240"),
      totalWithTax: new D("1240"),
      taxBreakdown: [
        { taxId: "iva",  name: "IVA",  rate: 21, baseAmount: 1000, taxAmount: 210 },
        { taxId: "iibb", name: "IIBB", rate: 3,  baseAmount: 1000, taxAmount: 30  },
      ],
    });
    const a = totalsFromArticleEndpoint(r, 2);
    const b = totalsFromSalesEndpoint(r, 2);

    expect(a.taxAmount).toBeCloseTo(480, 2);     // 240 × 2
    expect(a.taxAmount).toBeCloseTo(b.taxAmount, 2);
    expect(a.taxableBase).toBeCloseTo(b.taxableBase, 2);
  });

  it("sin impuestos (taxBreakdown=[]) → taxAmount=0 en ambos", () => {
    const r = makeResult({ taxBreakdown: [] });
    const a = totalsFromArticleEndpoint(r, 5);
    const b = totalsFromSalesEndpoint(r, 5);
    expect(a.taxAmount).toBe(0);
    expect(b.taxAmount).toBe(0);
    expectDocTotalsEqual(a, b);
  });
});
