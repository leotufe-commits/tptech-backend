// =============================================================================
// CONTRATO — MIXED por listas REALMENTE APLICADAS ⇒ SIN redondeo comercial documental.
//
// Regla funcional (CLAUDE.md "Redondeo Comercial vs Redondeo Financiero"):
//   · Redondeo COMERCIAL = dominio artículo/lista. En MIXED NO se consolida a
//     nivel comprobante.
//   · Redondeo FINANCIERO = dominio documento/tenant. Aplica aunque haya MIXED.
//
// El contexto comercial se resuelve por INTENCIÓN (override/`priceListId`,
// pre-pricing). Si las listas EFECTIVAMENTE aplicadas por línea difieren, el
// documento es MIXED y `appliedPriceListsAreMixed` lo detecta → el wiring fuerza
// `commercialDocumentRounding = null` ⇒ el motor emite
// `commercialDocumentRoundingApplied = null` (sin COMMERCIAL_DOC_ROUNDING, sin
// appliedAt=DOCUMENT). Same-list ⇒ el redondeo comercial documental SÍ puede existir.
// =============================================================================
import { describe, it, expect } from "vitest";
import { computeSaleDocumentTotals } from "../../../lib/pricing-engine/pricing-engine.js";
import {
  appliedPriceListsAreMixed,
  computeLineAutonomousCommercialMoney,
  consolidateCommercialDocFromPerLine,
} from "../commercial-doc-rounding-wiring.js";
import type { CommercialDocRoundingPartConfig } from "../../../lib/pricing-engine/commercial-document-rounding.js";

const HUNDRED: CommercialDocRoundingPartConfig = { mode: "HUNDRED", direction: "NEAREST" };
const NONE:    CommercialDocRoundingPartConfig = { mode: "NONE",    direction: "NEAREST" };

// Dos líneas (modelo de mixed-list-wiring-integration): Unificada + Desglosada.
const LINE0 = { lineTotal: 1000, lineTaxAmount: 300, lineTotalWithTax: 1300 };
const LINE1 = { lineTotal: 1560, lineTaxAmount: 468, lineTotalWithTax: 2028 };

function docLines() {
  return [
    {
      quantity: 1, basePrice: LINE0.lineTotal, unitPrice: LINE0.lineTotal,
      lineTotal: LINE0.lineTotal, lineTaxAmount: LINE0.lineTaxAmount,
      metalCost: 0, hechuraCost: LINE0.lineTotal, metalSale: 0, hechuraSale: LINE0.lineTotal,
    },
    {
      quantity: 1, basePrice: LINE1.lineTotal, unitPrice: LINE1.lineTotal,
      lineTotal: LINE1.lineTotal, lineTaxAmount: LINE1.lineTaxAmount,
      metalCost: 0, hechuraCost: LINE1.lineTotal, metalSale: 0, hechuraSale: LINE1.lineTotal,
    },
  ] as any;
}

/** Snapshot comercial documental same-list (Σ round línea) — caso NO-mixto. */
function buildPrecomputed() {
  const money = computeLineAutonomousCommercialMoney({
    lineCommercialRoundingMetals: new Map(),
    refValueByParent:             new Map(),
    lineTotalWithTaxByIdx:        new Map([[0, LINE0.lineTotalWithTax], [1, LINE1.lineTotalWithTax]]),
    metalSaleSumByIdx:            new Map([[0, 0], [1, 0]]),
    hechuraCfg:                   NONE,
    hechuraCfgByLineIdx:          new Map([[0, NONE], [1, HUNDRED]]),
    lineCount:                    2,
  });
  return consolidateCommercialDocFromPerLine({
    lineCommercialRoundingMetals: new Map(),
    lineMoney:                    money,
    metalNameById:                new Map(),
    refValueByParent:             new Map(),
    metalCfg:                     NONE,
    hechuraCfg:                   HUNDRED,
    lineCount:                    2,
  });
}

function runEngine(precomputed: any) {
  return computeSaleDocumentTotals({
    lines:                                  docLines(),
    channel:                                null,
    coupon:                                 null,
    paymentAdjustmentAmount:                0,
    shippingAmount:                         0,
    globalDiscountAmount:                   0,
    roundingAdjustment:                     0,
    documentRounding:                       null,
    // En MIXED el wiring fuerza estos dos a null:
    commercialDocumentRounding:             null,
    metalsByParentForCommercialRounding:    [],
    metalValuationSumForCommercialRounding: 0,
    commercialDocumentRoundingPrecomputed:  precomputed,
  } as any);
}

describe("appliedPriceListsAreMixed — detección MIXED por listas aplicadas", () => {
  it("listas distintas → true", () => {
    expect(appliedPriceListsAreMixed(["pl-desglosada", "pl-unificada"])).toBe(true);
  });
  it("misma lista en todas las líneas → false", () => {
    expect(appliedPriceListsAreMixed(["pl-a", "pl-a", "pl-a"])).toBe(false);
  });
  it("una sola línea → false", () => {
    expect(appliedPriceListsAreMixed(["pl-a"])).toBe(false);
  });
  it("ignora null/undefined/'' (no cuentan como lista) → false con una sola real", () => {
    expect(appliedPriceListsAreMixed([null, "pl-a", undefined, ""])).toBe(false);
  });
  it("dos reales + nulls → true", () => {
    expect(appliedPriceListsAreMixed([null, "pl-a", "pl-b"])).toBe(true);
  });
});

describe("Motor documental — MIXED ⇒ commercialDocumentRoundingApplied = null", () => {
  it("MIXED (wiring fuerza commercialDocumentRounding + precomputed = null) → SIN redondeo comercial documental", () => {
    const totals: any = runEngine(null);
    // Sin snapshot comercial documental: ni objeto, ni appliedAt=DOCUMENT, ni delta.
    expect(totals.commercialDocumentRoundingApplied ?? null).toBeNull();
    // El total comercial post = pre (la capa comercial documental no actuó).
    expect(totals.totalComercialPostCommercialRounding)
      .toBe(totals.totalComercialPreCommercialRounding);
  });

  it("same-list (precomputed presente) → el redondeo comercial documental SÍ puede existir", () => {
    const precomputed = buildPrecomputed();
    expect(precomputed).not.toBeNull();
    const totals: any = runEngine(precomputed);
    expect(totals.commercialDocumentRoundingApplied ?? null).not.toBeNull();
  });
});
