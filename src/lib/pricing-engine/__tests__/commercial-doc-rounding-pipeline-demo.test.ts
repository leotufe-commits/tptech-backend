// src/lib/pricing-engine/__tests__/commercial-doc-rounding-pipeline-demo.test.ts
//
// DEMO TEMPORAL — pipeline real con la capa nueva integrada.
//
// Caso: BREAKDOWN HUNDRED NEAREST sobre saldo monetario.
//   · 1 línea con metal físico + hechura.
//   · taxableBase + tax = totalComercialPreRounding = 281091.10
//   · metalValuationSum = 99000 (1.2375 g × $80000/g — sin redondeo de metal)
//   · hechura: HUNDRED NEAREST → 182091.10 → 182100 (delta +8.90)
//   · post-comercial: shipping + payment + financialRounding
//
// Salida: PRICING_TRACE=console emite las 15 capas + L05B_COMMERCIAL_DOC_ROUNDING.
//
// Borrar cuando termine la auditoría de pipeline.

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import {
  computeSaleDocumentTotals,
  type CommercialDocRoundingInput,
  type DocumentRoundingInput,
} from "../pricing-engine.js";
import {
  runWithTrace,
  __resetPricingTraceModeCache,
} from "../pricing-trace.js";

describe("DEMO — pipeline real con capa comercial PER_DOCUMENT", () => {
  const prevEnv = process.env.PRICING_TRACE;

  beforeAll(() => {
    process.env.PRICING_TRACE = "console";
    __resetPricingTraceModeCache();
  });

  afterAll(() => {
    process.env.PRICING_TRACE = prevEnv;
    __resetPricingTraceModeCache();
  });

  it("BREAKDOWN — saldo 182091.10 → 182100 con hechura HUNDRED NEAREST", async () => {
    // Construyo el caso para que el motor produzca:
    //   subtotalAfterLineDiscounts = 232307.52
    //   taxableBase                = 232307.52 (sin canal/cupón/global)
    //   tax 21%                    = 48784.58
    //   totalComercialPreRounding  = 281092.10  (~= 281091.10 con float drift)
    //   metalValuationSum          = 99000  (1.2375 g × $80000)
    //   saldoMonetarioPre          = 182092.10
    // Para que sea exactamente 182091.10 ajusto los inputs:
    //   metalSale (precio del metal en la línea) = 99000
    //   hechuraSale + lo demás = 281091.10 - 99000 = 182091.10
    // Construyo con basePrice/unitPrice/lineTotal/lineTaxAmount que den la suma exacta.
    //
    // basePrice = 99000 (metal) + 132305 (hechura) = 231305
    // tax = round2(231305 * 21/100) = 48574.05? quiero 49786.10
    // mejor: armo desde el revés:
    //   targetTotalComercial = 281091.10 → taxableBase + tax = 281091.10
    //   sin tax → asumo tax 0 para simplificar el demo (no afecta el contrato comercial)
    // Caso simplificado: tax=0.
    //   lineTotal = 281091.10
    //   metalSale = 99000, hechuraSale = 182091.10

    const commercialDocumentRounding: CommercialDocRoundingInput = {
      scope:   "BREAKDOWN",
      metal:   { mode: "NONE",    direction: "NEAREST" },
      hechura: { mode: "HUNDRED", direction: "NEAREST" },
    };

    // Política financiera del tenant — para mostrar que NO afecta el comercial.
    const documentRounding: DocumentRoundingInput = {
      scope:     "UNIFIED",
      mode:      "INTEGER",
      direction: "NEAREST",
    };

    const { result, trace } = await runWithTrace("DEMO_PIPELINE_COMMERCIAL_PER_DOC", async () => {
      const totals = computeSaleDocumentTotals({
        lines: [{
          quantity:      1,
          basePrice:     281091.10,
          unitPrice:     281091.10,
          lineTotal:     281091.10,
          lineTaxAmount: 0,
          metalCost:     50000,
          metalSale:     99000,
          hechuraCost:   80000,
          hechuraSale:   182091.10,
        }],
        channel:                                null,
        coupon:                                 null,
        shippingAmount:                         150,
        paymentAdjustmentAmount:                25,
        // ── NUEVA capa ──
        commercialDocumentRounding,
        metalValuationSumForCommercialRounding: 99000,
        metalsByParentForCommercialRounding: [
          { metalParentId: "OroFino", metalParentName: "Oro Fino", gramsPure: 1.2375, metalPricePerGram: 80000 },
        ],
        // ── Financiero (intacto) ──
        documentRounding,
      });
      return { totals };
    });

    // ── Asserts del caso ─────────────────────────────────────────────────
    expect(result.totals.taxableBase).toBe(281091.10);
    expect(result.totals.taxAmount).toBe(0);
    expect(result.totals.totalComercialPreCommercialRounding).toBe(281091.10);
    expect(result.totals.commercialDocumentRoundingApplied).not.toBeNull();
    const com = result.totals.commercialDocumentRoundingApplied!;
    expect(com.scope).toBe("BREAKDOWN");
    expect(com.breakdown!.hechura.preRoundingSaldoMonetario).toBe(182091.10);
    expect(com.breakdown!.hechura.postRoundingSaldoMonetario).toBe(182100);
    expect(com.breakdown!.hechura.deltaSaldoMonetario).toBe(8.90);
    expect(com.totalAdjustment).toBe(8.90);

    // totalComercialPost = 281091.10 + 8.90 = 281100
    expect(result.totals.totalComercialPostCommercialRounding).toBe(281100);

    // total final = totalComercialPost + shipping + payment + financialRounding
    //             = 281100 + 150 + 25 + financialRounding
    //             = 281275 + financialRounding (INTEGER NEAREST sobre 281275 = 0)
    //             = 281275
    expect(result.totals.total).toBe(281275);

    // ── Asserts de trazabilidad ──────────────────────────────────────────
    expect(trace).not.toBeNull();
    const expected = [
      "L05B_COMMERCIAL_DOC_ROUNDING",
      "L06_CHANNEL",
      "L07_COUPON",
      "L08_GLOBAL_DISCOUNT",
      "L09_SHIPPING",
      "L10_PAYMENT",
      "L11_TOTAL_BEFORE_FIN_ROUND",
      "L12_FINANCIAL_ROUNDING",
      "L13_ENGINE_TOTAL",
    ];
    const seen = new Set(trace!.document.map((d) => d.layer));
    for (const layer of expected) {
      expect(seen.has(layer), `Falta capa ${layer}`).toBe(true);
    }

    // El financiero NO se cruzó con el comercial: ambos snapshots presentes.
    const l05b = trace!.document.find((d) => d.layer === "L05B_COMMERCIAL_DOC_ROUNDING");
    const l12  = trace!.document.find((d) => d.layer === "L12_FINANCIAL_ROUNDING");
    expect(l05b).toBeDefined();
    expect(l12).toBeDefined();
    expect((l05b!.data as any).applied).toBe(true);
    expect((l05b!.data as any).scope).toBe("BREAKDOWN");
  });
});
