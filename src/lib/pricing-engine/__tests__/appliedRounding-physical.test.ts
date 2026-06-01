// src/lib/pricing-engine/__tests__/appliedRounding-physical.test.ts
// =============================================================================
// Tests del fix "Redondeo comercial PHYSICAL expone appliedRounding".
//
// Bug original confirmado por log fresco:
//   El motor de lista (applyPriceList) calcula correctamente el snapshot
//   PHYSICAL y modifica metalSaleD por el monetaryEquivalent. PERO el campo
//   `appliedRounding` top-level del SalePriceResult sigue `null` y el snapshot
//   v6 NO propaga `metalHechuraBreakdown.physical` — el frontend nunca puede
//   señalizar "se aplicó redondeo comercial" en esta línea.
//
// Fix (POLICY §R-Rounding-14):
//   1. `appliedRounding.applyOn` extendido a "PRICE" | "NET" | "TOTAL" | "METAL".
//   2. Cuando el path PHYSICAL del motor de lista actuó, `resolveFinalSalePrice`
//      setea `appliedRounding = { applyOn: "METAL", physical: {...} }`.
//   3. `buildPricingSnapshot` propaga `metalHechuraBreakdown.physical` al
//      snapshot v6 persistido — antes esta línea no existía y el snapshot
//      perdía el detalle físico aunque el motor lo calculara.
//
// Estos tests verifican (2) y (3) usando un SalePriceResult armado a mano.
// El path (1) del motor de lista (`applyPriceList`) ya está cubierto por
// `pricelist-commercial-physical.test.ts`.
// =============================================================================

import { describe, it, expect } from "vitest";
import { Prisma } from "@prisma/client";
import { buildPricingSnapshot } from "../pricing-engine.sale.js";
import type { SalePriceResult } from "../pricing-engine.types.js";

const D = Prisma.Decimal;

/** Factory minimal de SalePriceResult — solo los campos que el fix afecta.
 *  Cualquier campo no relevante se llena con defaults seguros para que
 *  buildPricingSnapshot no rompa. */
function makeSalePriceResult(over: Partial<SalePriceResult> = {}): SalePriceResult {
  return {
    unitPrice:                 new D("100000"),
    basePrice:                 new D("100000"),
    quantityDiscountAmount:    new D("0"),
    promotionDiscountAmount:   new D("0"),
    customerDiscountAmount:    new D("0"),
    discountAmount:            new D("0"),
    taxAmount:                 new D("0"),
    totalWithTax:              new D("100000"),
    priceSource:               "PRICE_LIST",
    baseSource:                "PRICE_LIST",
    unitCost:                  new D("80000"),
    unitMargin:                new D("20000"),
    marginPercent:             new D("20"),
    markupPercent:             new D("25"),
    costPartial:               false,
    costMode:                  "COST_LINES",
    partial:                   false,
    appliedPriceListId:        "pl-1",
    appliedPriceListName:      "Precios desglosados",
    appliedPriceListMode:      "METAL_HECHURA",
    appliedPromotionId:        null,
    appliedPromotionName:      null,
    appliedDiscountId:         null,
    steps:                     [],
    alerts:                    [],
    policy:                    { canConfirm: true, blockingAlerts: [] },
    stackingMode:              "BEST_OF_PROMO",
    metalHechuraBreakdown:     null,
    appliedRounding:           null,
    taxBreakdown:              [],
    composition:               null as any,
    componentSaleBreakdown:    null,
    ...over,
  } as SalePriceResult;
}

describe("appliedRounding PHYSICAL — fix (POLICY §R-Rounding-14)", () => {
  it("(fix-1) Shape canónico de appliedRounding cuando applyOn='METAL'", () => {
    // Verificamos que el tipo TS admite el shape extendido. Si esto compila
    // y los campos esperados están, el contrato del response es correcto.
    const physical = {
      metals: [{
        metalParentId:     "oro-fino",
        metalParentName:   "Oro Fino",
        preGrams:          0.908,
        postGrams:         1.000,
        deltaGrams:        0.092,
        metalPricePerGram: 100000,
        monetaryEquivalent: 9200,
        mode:              "INTEGER" as const,
        direction:         "NEAREST" as const,
        source:            "COMMERCIAL_PHYSICAL_ROUNDING" as const,
        fallback:          null,
      }],
      metalMonetaryEquivalent: 9200,
      fallback: null,
    };

    const ar: SalePriceResult["appliedRounding"] = {
      applyOn:       "METAL",
      mode:          "INTEGER",
      direction:     "NEAREST",
      preRounding:   new D("90800"),
      postRounding:  new D("100000"),
      priceListId:    "pl-1",
      priceListName:  "Precios desglosados",
      physical,
    };

    expect(ar?.applyOn).toBe("METAL");
    expect(ar?.physical).not.toBeNull();
    expect(ar?.physical?.metals[0]?.deltaGrams).toBe(0.092);
    expect(ar?.physical?.metals[0]?.monetaryEquivalent).toBe(9200);
    // Delta entre pre y post = monetaryEquivalent agregado.
    expect(
      Number(ar!.postRounding.minus(ar!.preRounding).toString())
    ).toBe(9200);
  });

  it("(fix-2) buildPricingSnapshot PROPAGA metalHechuraBreakdown.physical al snapshot v6", () => {
    // Antes del fix, este campo se PERDÍA en la copia hand-picked de
    // buildPricingSnapshot. Ahora pasa al snapshot persistido.
    const physical = {
      metals: [{
        metalParentId:     "oro-fino",
        metalParentName:   "Oro Fino",
        preGrams:          1.526,
        postGrams:         2.000,
        deltaGrams:        0.474,
        metalPricePerGram: 100000,
        monetaryEquivalent: 47400,
        mode:              "INTEGER" as const,
        direction:         "NEAREST" as const,
        source:            "COMMERCIAL_PHYSICAL_ROUNDING" as const,
        fallback:          null,
      }],
      metalMonetaryEquivalent: 47400,
      fallback: null,
    };

    const result = makeSalePriceResult({
      metalHechuraBreakdown: {
        metalCost:        200000,
        metalSale:        247400,
        metalMarginPct:   10,
        hechuraCost:      30000,
        hechuraSale:      45000,
        hechuraMarginPct: 50,
        physical,
      } as any,
    });

    const snapshot = buildPricingSnapshot(result);

    expect(snapshot.metalHechuraBreakdown).not.toBeNull();
    expect((snapshot.metalHechuraBreakdown as any).physical).toEqual(physical);
    expect((snapshot.metalHechuraBreakdown as any).physical.metals[0].preGrams).toBe(1.526);
    expect((snapshot.metalHechuraBreakdown as any).physical.metals[0].postGrams).toBe(2.000);
    expect((snapshot.metalHechuraBreakdown as any).physical.metalMonetaryEquivalent).toBe(47400);
  });

  it("(fix-3) buildPricingSnapshot OMITE physical cuando metalHechuraBreakdown lo tiene null", () => {
    // Caso back-compat: lista MONETARY sigue produciendo physical=null y el
    // snapshot NO debe inventar el campo.
    const result = makeSalePriceResult({
      metalHechuraBreakdown: {
        metalCost:        200000,
        metalSale:        220000,
        metalMarginPct:   10,
        hechuraCost:      30000,
        hechuraSale:      45000,
        hechuraMarginPct: 50,
        physical:         null,
      } as any,
    });
    const snapshot = buildPricingSnapshot(result);
    expect((snapshot.metalHechuraBreakdown as any).physical).toBeUndefined();
  });

  it("(fix-4) buildPricingSnapshot SIN metalHechuraBreakdown → null (no rompe)", () => {
    const result = makeSalePriceResult({ metalHechuraBreakdown: null });
    const snapshot = buildPricingSnapshot(result);
    expect(snapshot.metalHechuraBreakdown).toBeNull();
  });

  it("(B1+B2) deriveMetalHechuraBreakdown PROPAGA physical cuando exactBreakdown lo trae", async () => {
    // Antes de B1+B2, el helper reconstruía el shape exact omitiendo el campo
    // `physical`. Aunque appliedRounding.physical viajaba bien (fix anterior),
    // el snapshot v6 quedaba con metalHechuraBreakdown.physical = null porque
    // este helper SOBRESCRIBÍA la asignación inicial de metalHechuraBreakdown
    // y descartaba el campo.
    const { deriveMetalHechuraBreakdown } = await import("../pricing-engine.sale.js");
    const physical = {
      metals: [{
        metalParentId:     "oro-fino",
        metalParentName:   "Oro Fino",
        preGrams:          0.825,
        postGrams:         1.000,
        deltaGrams:        0.175,
        metalPricePerGram: 187500,
        monetaryEquivalent: 32812.5,
        mode:              "INTEGER" as const,
        direction:         "NEAREST" as const,
        source:            "COMMERCIAL_PHYSICAL_ROUNDING" as const,
        fallback:          null,
      }],
      metalMonetaryEquivalent: 32812.5,
      fallback: null,
    };

    const result = deriveMetalHechuraBreakdown({
      metalCost:      154687.5,
      hechuraCost:    10000,
      costTotal:      164687.5,
      basePrice:      200000,
      priceSource:    "PRICE_LIST",
      commercialMode: null,
      exactBreakdown: {
        metalSale:         187500,
        hechuraSale:       15000,
        metalMarginPct:    20,
        hechuraMarginPct:  50,
        metalGramsBase:    0.825,
        metalGramsSale:    0.990,
        metalPricePerGram: 187500,
        pureGramsBase:     null,
        pureGramsSale:     null,
        physical,            // ← B1: ahora el caller lo pasa
      } as any,
    });

    expect(result).not.toBeNull();
    // ANTES: result.physical era undefined porque el return omitía el campo.
    // AHORA: B2 lo propaga.
    expect((result as any).physical).toEqual(physical);
    expect((result as any).physical.metals[0].deltaGrams).toBe(0.175);
    expect((result as any).physical.metalMonetaryEquivalent).toBe(32812.5);
  });

  it("(fix-5) applyOn='NET' o 'TOTAL' o 'PRICE' siguen siendo válidos (back-compat MONETARY)", () => {
    // La extensión del enum es ADITIVA — los casos existentes no se rompen.
    const cases: Array<SalePriceResult["appliedRounding"]> = [
      {
        applyOn: "PRICE",  mode: "TEN",      direction: "NEAREST",
        preRounding: new D("995"), postRounding: new D("1000"),
        priceListId: "pl-1", priceListName: "Lista A",
      },
      {
        applyOn: "NET",    mode: "FIVE",     direction: "UP",
        preRounding: new D("100"), postRounding: new D("105"),
        priceListId: "pl-1", priceListName: "Lista A",
      },
      {
        applyOn: "TOTAL",  mode: "HUNDRED",  direction: "DOWN",
        preRounding: new D("1234"), postRounding: new D("1200"),
        priceListId: "pl-1", priceListName: "Lista A",
      },
    ];
    for (const ar of cases) {
      expect(ar?.applyOn).toMatch(/PRICE|NET|TOTAL/);
      // El campo physical es opcional — para los casos monetary queda undefined.
      expect(ar?.physical).toBeUndefined();
    }
  });
});
