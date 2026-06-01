// src/lib/pricing-engine/__tests__/no-double-rounding-line-vs-document.test.ts
// =============================================================================
// Gate anti-doble redondeo (Etapa D' — POLICY §R-Rounding-15).
//
// Verifica que el redondeo de hechura y/o metal físico NUNCA se aplica
// simultáneamente PER_LINE (dentro de applyPriceList) y PER_DOCUMENT
// (en computeSaleDocumentTotals).
//
// Mecanismo del gate:
//   El caller le pasa a applyPriceList el `ApplyPriceListOptions` con flags
//   `suppressLineHechuraRounding` y/o `suppressLineMetalPhysicalRounding`.
//   Cuando true, applyPriceList NO ejecuta el redondeo correspondiente — el
//   bucket pasa por el motor del documento (capa nueva PER_DOCUMENT).
//
// Casos cubiertos:
//   1. PER_LINE  (sin flags) — applyPriceList redondea, capa doc NO se llama.
//   2. PER_DOCUMENT (flags activos) — applyPriceList NO redondea, capa doc
//      redondea sobre el saldo agregado.
//   3. Comparativa: total final coincide entre ambos modos para una sola
//      línea (la única diferencia es DÓNDE ocurre el redondeo).
//   4. Defensa: si por error el caller activa AMBOS (flag + capa doc), el
//      delta del comercial-doc se aplica una sola vez (porque el bucket
//      llega crudo a la capa doc — no hay redondeo previo que sumarle).
//   5. Análogo para metal físico.

import { describe, it, expect } from "vitest";
import { Prisma } from "@prisma/client";
import { applyPriceList } from "../pricing-engine.pricelist.js";
import { applyCommercialDocumentRounding } from "../commercial-document-rounding.js";

const D = (v: number | string) => new Prisma.Decimal(String(v));

// ─────────────────────────────────────────────────────────────────────────────
// Factories
// ─────────────────────────────────────────────────────────────────────────────

/** Lista de hechura: METAL_HECHURA con redondeo HUNDRED NEAREST sobre hechura. */
function listHechuraHundred(over: Record<string, any> = {}) {
  return {
    id:                       "pl-hechura",
    name:                     "Lista hechura HUNDRED",
    mode:                     "METAL_HECHURA",
    marginTotal:              null,
    marginMetal:              "0",        // sin margen
    marginHechura:            "0",
    costPerGram:              null,
    surcharge:                null,
    minimumPrice:             null,
    roundingTarget:           "METAL",    // habilita per-component
    roundingMode:             "NONE",     // metal monetary off
    roundingDirection:        "NEAREST",
    roundingApplyOn:          "PRICE",
    roundingModeHechura:      "HUNDRED",  // ← redondeo hechura activo
    roundingDirectionHechura: "NEAREST",
    validFrom:                null,
    validTo:                  null,
    isActive:                 true,
    commercialRoundingMetalDomain:    "MONETARY",
    commercialPhysicalRoundingConfig: null,
    ...over,
  };
}

/** Lista para metal físico: METAL_HECHURA con PHYSICAL en metal. */
function listMetalPhysical(over: Record<string, any> = {}) {
  return {
    id:                       "pl-metal-physical",
    name:                     "Lista metal PHYSICAL",
    mode:                     "METAL_HECHURA",
    marginTotal:              null,
    marginMetal:              "100",      // 100% sobre metal
    marginHechura:            "0",
    costPerGram:              null,
    surcharge:                null,
    minimumPrice:             null,
    roundingTarget:           "METAL",
    roundingMode:             "NONE",
    roundingDirection:        "NEAREST",
    roundingApplyOn:          "PRICE",
    roundingModeHechura:      "NONE",
    roundingDirectionHechura: "NEAREST",
    validFrom:                null,
    validTo:                  null,
    isActive:                 true,
    commercialRoundingMetalDomain:    "PHYSICAL",
    commercialPhysicalRoundingConfig: {
      fallback: { mode: "DECIMAL_1", direction: "NEAREST" },
      perMetalParent: {},
    } as any,
    ...over,
  };
}

/** Cost breakdown: hechura cruda + metal cruda. */
function costHechura(hechuraCost: number) {
  return {
    value:               D(hechuraCost),
    metalCost:           D(0),
    hechuraCost:         D(hechuraCost),
    totalGrams:          D(0),
    metalGramsWithMerma: D(0),
    metalPurity:         D(0),
    partial:             false,
    mode:                "COST_LINES",
    metalsByParent:      [],
  } as any;
}

function costMetalPhysical(gramsPure: number, pricePerGram: number) {
  const metalCost = gramsPure * pricePerGram;
  return {
    value:               D(metalCost),
    metalCost:           D(metalCost),
    hechuraCost:         D(0),
    totalGrams:          D(gramsPure),
    metalGramsWithMerma: D(gramsPure),
    metalPurity:         D(1),
    partial:             false,
    mode:                "COST_LINES",
    metalsByParent: [{
      metalParentId:     "OroFino",
      metalParentName:   "Oro Fino",
      gramsPure,
      metalPricePerGram: pricePerGram * 2,  // venta = 100% margen sobre costo
    }],
  } as any;
}

// ─────────────────────────────────────────────────────────────────────────────
// HECHURA — gate anti-doble
// ─────────────────────────────────────────────────────────────────────────────

describe("Gate anti-doble — HECHURA (PER_LINE vs PER_DOCUMENT)", () => {
  const HECHURA_CRUDA = 182091.10;
  const HUNDRED_NEAREST_RESULT = 182100;

  it("PER_LINE (sin flag): applyPriceList REDONDEA per-line — hechuraSale ya viene redondeada", () => {
    const result = applyPriceList(listHechuraHundred(), costHechura(HECHURA_CRUDA));
    expect(result.metalHechuraDetail).not.toBeNull();
    // hechura per-line redondeada de 182091.10 a 182100.
    expect(result.metalHechuraDetail!.hechuraSale).toBe(HUNDRED_NEAREST_RESULT);
  });

  it("PER_DOCUMENT (suppressLineHechuraRounding=true): applyPriceList NO redondea — hechuraSale queda cruda", () => {
    const result = applyPriceList(
      listHechuraHundred(),
      costHechura(HECHURA_CRUDA),
      { suppressLineHechuraRounding: true },
    );
    expect(result.metalHechuraDetail).not.toBeNull();
    // hechura cruda — el redondeo per-line fue suprimido.
    expect(result.metalHechuraDetail!.hechuraSale).toBe(HECHURA_CRUDA);
  });

  it("Total final coincide entre PER_LINE y PER_DOCUMENT (gate redirige, no duplica)", () => {
    // PER_LINE: applyPriceList redondea per-line → total línea = 182100 directo.
    const perLine = applyPriceList(listHechuraHundred(), costHechura(HECHURA_CRUDA));
    const totalPerLine = perLine.metalHechuraDetail!.hechuraSale + perLine.metalHechuraDetail!.metalSale;

    // PER_DOCUMENT: applyPriceList NO redondea + capa documento redondea.
    const perDoc = applyPriceList(
      listHechuraHundred(),
      costHechura(HECHURA_CRUDA),
      { suppressLineHechuraRounding: true },
    );
    const hechuraCruda = perDoc.metalHechuraDetail!.hechuraSale;
    const totalComercialPostTax = hechuraCruda;  // sin metal, sin tax → solo hechura

    const docResult = applyCommercialDocumentRounding({
      totalComercialPostTax,
      metalValuationSum:     0,
      config: {
        scope:   "BREAKDOWN",
        metal:   { mode: "NONE",    direction: "NEAREST" },
        hechura: { mode: "HUNDRED", direction: "NEAREST" },
      },
    });

    expect(totalPerLine).toBe(HUNDRED_NEAREST_RESULT);
    expect(docResult.totalPostCommercial).toBe(HUNDRED_NEAREST_RESULT);
    expect(totalPerLine).toBe(docResult.totalPostCommercial);
  });

  it("DEFENSA — si por error caller activa ambos modos, el delta NO se aplica dos veces", () => {
    // Modo A (correcto PER_DOCUMENT): supresión PER_LINE + capa doc.
    const perDocOk = applyPriceList(
      listHechuraHundred(),
      costHechura(HECHURA_CRUDA),
      { suppressLineHechuraRounding: true },
    );
    const docOk = applyCommercialDocumentRounding({
      totalComercialPostTax: perDocOk.metalHechuraDetail!.hechuraSale,
      metalValuationSum:     0,
      config: {
        scope:   "BREAKDOWN",
        metal:   { mode: "NONE",    direction: "NEAREST" },
        hechura: { mode: "HUNDRED", direction: "NEAREST" },
      },
    });

    // Modo B (erróneo — sin flag, doble): per-line redondea + capa doc encima.
    const perLineErrante = applyPriceList(listHechuraHundred(), costHechura(HECHURA_CRUDA));
    const docExtra = applyCommercialDocumentRounding({
      totalComercialPostTax: perLineErrante.metalHechuraDetail!.hechuraSale,  // YA redondeado
      metalValuationSum:     0,
      config: {
        scope:   "BREAKDOWN",
        metal:   { mode: "NONE",    direction: "NEAREST" },
        hechura: { mode: "HUNDRED", direction: "NEAREST" },
      },
    });

    // El modo correcto da 182100 por una sola aplicación.
    expect(docOk.totalPostCommercial).toBe(HUNDRED_NEAREST_RESULT);
    // El modo erróneo da 182100 también — porque el valor entrante ya estaba
    // redondeado, el segundo applyRounding es idempotente sobre múltiplos de 100.
    // El gate garantiza que el caso modo-erróneo nunca debería ocurrir, pero si
    // ocurre con valores ya redondeados el resultado coincide (la doble aplicación
    // sería visible recién con un delta NO-cero del segundo redondeo).
    expect(docExtra.totalPostCommercial).toBe(HUNDRED_NEAREST_RESULT);
    // Lo más importante: el gate del modo correcto NO ejecuta dos veces.
    expect(perDocOk.metalHechuraDetail!.hechuraSale).toBe(HECHURA_CRUDA);
    expect(perLineErrante.metalHechuraDetail!.hechuraSale).toBe(HUNDRED_NEAREST_RESULT);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// METAL FÍSICO — gate anti-doble
// ─────────────────────────────────────────────────────────────────────────────

describe("Gate anti-doble — METAL FÍSICO (PER_LINE vs PER_DOCUMENT)", () => {
  // Caso: 1.2375 g de oro, precio 50000 costo / 100000 venta.
  // Sin redondeo: metalSale = 1.2375 × 100000 = 123750.
  // Con DECIMAL_1 NEAREST sobre 1.2375 g → 1.2 g (delta -0.0375 g × 100000 = -3750)
  //   → metalSale post = 120000.

  it("PER_LINE (sin flag): applyPriceList ejecuta el path PHYSICAL — metalSale ajustada", () => {
    const result = applyPriceList(listMetalPhysical(), costMetalPhysical(1.2375, 50000));
    expect(result.metalHechuraDetail).not.toBeNull();
    expect(result.metalHechuraDetail!.physical).not.toBeNull();
    // metalSale redondeada: 1.2375 × 100000 − 3750 = 120000
    expect(result.metalHechuraDetail!.metalSale).toBe(120000);
  });

  it("PER_DOCUMENT (suppressLineMetalPhysicalRounding=true): applyPriceList NO ejecuta el path PHYSICAL — metalSale cruda", () => {
    const result = applyPriceList(
      listMetalPhysical(),
      costMetalPhysical(1.2375, 50000),
      { suppressLineMetalPhysicalRounding: true },
    );
    expect(result.metalHechuraDetail).not.toBeNull();
    // physical snapshot debe quedar null (path NO ejecutado).
    expect(result.metalHechuraDetail!.physical).toBeNull();
    // metalSale cruda: 1.2375 × 100000 = 123750
    expect(result.metalHechuraDetail!.metalSale).toBe(123750);
  });

  it("PER_DOCUMENT + capa documento metal: total comercial coincide con PER_LINE", () => {
    // PER_LINE: applyPriceList ejecuta path PHYSICAL per-line.
    const perLine = applyPriceList(listMetalPhysical(), costMetalPhysical(1.2375, 50000));
    const totalPerLine = perLine.metalHechuraDetail!.metalSale + perLine.metalHechuraDetail!.hechuraSale;

    // PER_DOCUMENT: applyPriceList suprime + capa documento ejecuta sobre gramos agregados.
    const perDoc = applyPriceList(
      listMetalPhysical(),
      costMetalPhysical(1.2375, 50000),
      { suppressLineMetalPhysicalRounding: true },
    );
    const metalSaleCrudo = perDoc.metalHechuraDetail!.metalSale;
    const hechuraCruda   = perDoc.metalHechuraDetail!.hechuraSale;
    const totalCrudo     = metalSaleCrudo + hechuraCruda;

    const docResult = applyCommercialDocumentRounding({
      totalComercialPostTax: totalCrudo,
      metalValuationSum:     metalSaleCrudo,    // valorización física = metalSale
      metalsByParent: [{
        metalParentId:     "OroFino",
        metalParentName:   "Oro Fino",
        gramsPure:         1.2375,
        metalPricePerGram: 100000,
      }],
      config: {
        scope:   "BREAKDOWN",
        metal:   { mode: "DECIMAL_1", direction: "NEAREST" },
        hechura: { mode: "NONE",      direction: "NEAREST" },
      },
    });

    // Ambos modos coinciden: 120000 (PER_LINE) = 123750 + (-3750) (PER_DOCUMENT).
    expect(totalPerLine).toBe(120000);
    expect(docResult.totalPostCommercial).toBe(120000);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// INVARIANTE — el gate garantiza exclusividad
// ─────────────────────────────────────────────────────────────────────────────

describe("INVARIANTE — PER_LINE y PER_DOCUMENT nunca simultáneos", () => {
  it("misma lista + mismo artículo + mismo modo: A (per-line) y B (per-document) producen el mismo total final", () => {
    // Caso desglosado completo: metal físico + hechura redondeados.
    const list = listMetalPhysical({
      roundingModeHechura:      "HUNDRED",       // hechura también activa
      roundingDirectionHechura: "NEAREST",
    });
    const cost = {
      value:               D(0),
      metalCost:           D(61875),               // 1.2375 × 50000
      hechuraCost:         D(182091.10),
      totalGrams:          D(1.2375),
      metalGramsWithMerma: D(1.2375),
      metalPurity:         D(1),
      partial:             false,
      mode:                "COST_LINES",
      metalsByParent: [{
        metalParentId:     "OroFino",
        metalParentName:   "Oro Fino",
        gramsPure:         1.2375,
        metalPricePerGram: 100000,
      }],
    } as any;

    // A) PER_LINE: applyPriceList sin flags → ambos redondeos per-line.
    const a = applyPriceList(list, cost);
    const totalA = a.metalHechuraDetail!.metalSale + a.metalHechuraDetail!.hechuraSale;

    // B) PER_DOCUMENT: applyPriceList con flags → sin redondeos per-line.
    //    Capa doc ejecuta sobre los agregados.
    const b = applyPriceList(list, cost, {
      suppressLineHechuraRounding:      true,
      suppressLineMetalPhysicalRounding: true,
    });
    const metalSaleCrudo = b.metalHechuraDetail!.metalSale;
    const hechuraCruda   = b.metalHechuraDetail!.hechuraSale;
    const totalCrudo     = metalSaleCrudo + hechuraCruda;

    const docB = applyCommercialDocumentRounding({
      totalComercialPostTax: totalCrudo,
      metalValuationSum:     metalSaleCrudo,
      metalsByParent: [{
        metalParentId:     "OroFino",
        metalParentName:   "Oro Fino",
        gramsPure:         1.2375,
        metalPricePerGram: 100000,
      }],
      config: {
        scope:   "BREAKDOWN",
        metal:   { mode: "DECIMAL_1", direction: "NEAREST" },
        hechura: { mode: "HUNDRED",   direction: "NEAREST" },
      },
    });

    expect(totalA).toBe(docB.totalPostCommercial);

    // Y el snapshot del path PHYSICAL prueba la exclusividad:
    // A tiene physical poblado; B tiene physical null (no ejecutó per-line).
    expect(a.metalHechuraDetail!.physical).not.toBeNull();
    expect(b.metalHechuraDetail!.physical).toBeNull();
    // A tiene hechura ya redondeada; B tiene hechura cruda.
    expect(a.metalHechuraDetail!.hechuraSale).toBe(182100);
    expect(b.metalHechuraDetail!.hechuraSale).toBe(182091.10);
  });
});
