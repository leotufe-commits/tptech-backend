// src/lib/pricing-engine/__tests__/commercial-doc-rounding-preview-confirm.test.ts
//
// DEMO + PARIDAD — pipeline end-to-end con la capa comercial PER_DOCUMENT.
//
// 1. Demuestra la traza completa desde applyPriceList → computeSaleDocumentTotals
//    → buildSaleBalanceBreakdown → engineTotal (sin DB).
// 2. Verifica que preview y confirm producen `commercialDocumentRoundingApplied`,
//    `documentRoundingApplied`, `engineTotal` y `balanceBreakdown.monetaryBalance`
//    idénticos byte a byte.
// 3. Verifica la INVARIANTE D-prime:
//      monetaryBalance.amount = totalComercialPostCommercialRounding + shipping
//                               + payment + financialDelta − metalValuation
//
// Borrar cuando termine la auditoría.

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import {
  applyPriceList,
  computeSaleDocumentTotals,
  buildDocumentBalanceBreakdown,
  type SaleDocumentTotalsLineInput,
  type CommercialDocRoundingInput,
} from "../pricing-engine.js";
import {
  runWithTrace,
  __resetPricingTraceModeCache,
} from "../pricing-trace.js";
import { Prisma } from "@prisma/client";

const D = (v: number | string) => new Prisma.Decimal(String(v));
const ORO_PRICE_PER_GRAM = 80000;

// Lista compartida del documento — PER_DOCUMENT (modo simulado).
function sharedList() {
  return {
    id:                       "pl-shared",
    name:                     "Lista PER_DOCUMENT",
    mode:                     "METAL_HECHURA",
    marginTotal:              null,
    marginMetal:              "100",     // 100% margen sobre metal
    marginHechura:            "0",
    costPerGram:              null,
    surcharge:                null,
    minimumPrice:             null,
    roundingTarget:           "METAL",
    roundingMode:             "NONE",
    roundingDirection:        "NEAREST",
    roundingApplyOn:          "PRICE",
    roundingModeHechura:      "HUNDRED",
    roundingDirectionHechura: "NEAREST",
    validFrom:                null,
    validTo:                  null,
    isActive:                 true,
    commercialRoundingMetalDomain:    "PHYSICAL",
    commercialPhysicalRoundingConfig: null,
  } as any;
}

function lineCost(hechuraCost: number, gramsPure: number) {
  return {
    value:               D(hechuraCost + gramsPure * (ORO_PRICE_PER_GRAM / 2)),
    metalCost:           D(gramsPure * (ORO_PRICE_PER_GRAM / 2)),
    hechuraCost:         D(hechuraCost),
    totalGrams:          D(gramsPure),
    metalGramsWithMerma: D(gramsPure),
    metalPurity:         D(1),
    partial:             false,
    mode:                "COST_LINES",
    metalsByParent: [{
      metalParentId:     "OroFino",
      metalParentName:   "Oro Fino",
      gramsPure,
      metalPricePerGram: ORO_PRICE_PER_GRAM,
    }],
  } as any;
}

/**
 * Simula un "pase" del motor (preview o confirm) — son el mismo código.
 * Hace: applyPriceList(PER_DOCUMENT) por línea + computeSaleDocumentTotals
 * + buildDocumentBalanceBreakdown. Devuelve los snapshots clave.
 */
function runPipelinePerDocument(args: {
  hechuraCost: number;
  gramsPure:   number;
  commercialDocumentRounding: CommercialDocRoundingInput;
  shipping:    number;
  payment:     number;
}) {
  // Capa por línea con flags activos (anti-doble).
  const priceResult = applyPriceList(
    sharedList(),
    lineCost(args.hechuraCost, args.gramsPure),
    {
      suppressLineHechuraRounding:       true,
      suppressLineMetalPhysicalRounding: true,
    },
  );

  const mhb = priceResult.metalHechuraDetail!;
  const lineForDocTotals: SaleDocumentTotalsLineInput = {
    quantity:      1,
    basePrice:     priceResult.value!.toNumber(),
    unitPrice:     priceResult.value!.toNumber(),
    lineTotal:     priceResult.value!.toNumber(),
    lineTaxAmount: 0,
    metalCost:     mhb.metalCost,
    hechuraCost:   mhb.hechuraCost,
    metalSale:     mhb.metalSale,
    hechuraSale:   mhb.hechuraSale,
  };

  const totals = computeSaleDocumentTotals({
    lines:                                   [lineForDocTotals],
    channel:                                 null,
    coupon:                                  null,
    shippingAmount:                          args.shipping,
    paymentAdjustmentAmount:                 args.payment,
    commercialDocumentRounding:              args.commercialDocumentRounding,
    metalsByParentForCommercialRounding: [{
      metalParentId:     "OroFino",
      metalParentName:   "Oro Fino",
      gramsPure:         args.gramsPure,
      metalPricePerGram: ORO_PRICE_PER_GRAM,
    }],
    metalValuationSumForCommercialRounding: args.gramsPure * ORO_PRICE_PER_GRAM,
  });

  // Balance breakdown — saldo monetario derivado.
  const balance = buildDocumentBalanceBreakdown(
    {
      currency: { code: "ARS", rate: 1 },
      documentTotal:     totals.total,
      documentTotalBase: totals.total,
      lines: [{
        lineId:   "L1",
        quantity: 1,
        metals: [{
          metalParentId:                  "OroFino",
          metalParentName:                "Oro Fino",
          metalVariantId:                 "",
          metalVariantName:               "Oro Fino",
          appliedGramsPerUnit:            args.gramsPure,
          purity:                         1,
          quotePriceSnapshot:             ORO_PRICE_PER_GRAM,
          metalLineValuationDocCurrency:  args.gramsPure * ORO_PRICE_PER_GRAM,
        }],
      }],
    },
    "BREAKDOWN",
  );

  return { priceResult, totals, balance };
}

describe("Etapa D' — pipeline PER_DOCUMENT end-to-end", () => {
  const prevEnv = process.env.PRICING_TRACE;
  beforeAll(() => {
    process.env.PRICING_TRACE = "console";
    __resetPricingTraceModeCache();
  });
  afterAll(() => {
    process.env.PRICING_TRACE = prevEnv;
    __resetPricingTraceModeCache();
  });

  it("DEMO — factura real con lista PER_DOCUMENT, traza completa applyPriceList → totals → balance → engineTotal", async () => {
    const config: CommercialDocRoundingInput = {
      scope:   "BREAKDOWN",
      metal:   { mode: "NONE",    direction: "NEAREST" },
      hechura: { mode: "HUNDRED", direction: "NEAREST" },
    };

    const { result } = await runWithTrace("DEMO_FACTURA_PER_DOCUMENT", async () => {
      return runPipelinePerDocument({
        hechuraCost: 182091.10,
        gramsPure:   1.2375,
        commercialDocumentRounding: config,
        shipping:    150,
        payment:     25,
      });
    });

    // ── Asserts del flujo end-to-end ────────────────────────────────────
    // applyPriceList con flags suprimidos → metalSale y hechuraSale CRUDAS.
    const mhb = result.priceResult.metalHechuraDetail!;
    expect(mhb.physical).toBeNull();             // metal PHYSICAL no se ejecutó per-line
    expect(mhb.hechuraSale).toBe(182091.10);    // hechura no se redondeó per-line
    expect(mhb.metalSale).toBe(99000);          // 1.2375 × 80000

    // computeSaleDocumentTotals con capa nueva:
    const totals = result.totals;
    const com = totals.commercialDocumentRoundingApplied!;
    expect(com.scope).toBe("BREAKDOWN");
    expect(com.breakdown!.hechura.preRoundingSaldoMonetario).toBe(182091.10);
    expect(com.breakdown!.hechura.postRoundingSaldoMonetario).toBe(182100);
    expect(com.breakdown!.hechura.deltaSaldoMonetario).toBe(8.90);
    expect(totals.totalComercialPreCommercialRounding).toBe(281091.10);
    expect(totals.totalComercialPostCommercialRounding).toBe(281100);
    // total final = totalComercialPostCommercialRounding + shipping + payment + financialDelta
    expect(totals.total).toBe(281275);

    // balanceBreakdown.monetaryBalance.amount
    //   = total - valorización física del metal
    //   = 281275 - (1.2375 × 80000) = 281275 - 99000 = 182275
    expect(result.balance.monetaryBalance.amount).toBe(182275);
    expect(result.balance.monetaryBalance.amountBase).toBe(182275);
  });

  it("PARIDAD preview = confirm — snapshots idénticos byte a byte", () => {
    const config: CommercialDocRoundingInput = {
      scope:   "BREAKDOWN",
      metal:   { mode: "NONE",    direction: "NEAREST" },
      hechura: { mode: "HUNDRED", direction: "NEAREST" },
    };
    const args = {
      hechuraCost: 182091.10,
      gramsPure:   1.2375,
      commercialDocumentRounding: config,
      shipping:    150,
      payment:     25,
    };

    const preview = runPipelinePerDocument(args);
    const confirm = runPipelinePerDocument(args);

    // ── Snapshots clave deben ser idénticos byte a byte ────────────────
    expect(JSON.stringify(preview.totals.commercialDocumentRoundingApplied))
      .toBe(JSON.stringify(confirm.totals.commercialDocumentRoundingApplied));
    expect(JSON.stringify(preview.totals.documentRoundingApplied))
      .toBe(JSON.stringify(confirm.totals.documentRoundingApplied));
    expect(preview.totals.total).toBe(confirm.totals.total);
    expect(preview.totals.totalComercialPreCommercialRounding)
      .toBe(confirm.totals.totalComercialPreCommercialRounding);
    expect(preview.totals.totalComercialPostCommercialRounding)
      .toBe(confirm.totals.totalComercialPostCommercialRounding);
    expect(JSON.stringify(preview.balance.monetaryBalance))
      .toBe(JSON.stringify(confirm.balance.monetaryBalance));
  });
});
