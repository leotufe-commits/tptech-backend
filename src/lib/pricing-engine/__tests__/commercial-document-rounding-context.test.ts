// src/lib/pricing-engine/__tests__/commercial-document-rounding-context.test.ts
//
// Tests del helper puro `resolveDocCommercialRoundingContext` +
// `buildCommercialDocRoundingFromPriceList` + `assertCommercialDocRoundingConsistency`.

import { describe, it, expect } from "vitest";
import {
  resolveDocCommercialRoundingContext,
  buildCommercialDocRoundingFromPriceList,
  assertCommercialDocRoundingConsistency,
  type PriceListSummaryForContext,
} from "../commercial-document-rounding-context.js";

function listMetalHechuraTargetMetal(
  over: Partial<PriceListSummaryForContext> = {},
): PriceListSummaryForContext {
  return {
    id:                            "pl-1",
    name:                          "Lista Test",
    mode:                          "METAL_HECHURA",
    roundingTarget:                "METAL",
    roundingMode:                  "NONE",
    roundingDirection:             "NEAREST",
    roundingModeHechura:           "HUNDRED",
    roundingDirectionHechura:      "NEAREST",
    commercialRoundingMetalDomain: "PHYSICAL",
    commercialRoundingScope:       "PER_LINE_LEGACY",
    ...over,
  };
}

function listMarginTotal(
  over: Partial<PriceListSummaryForContext> = {},
): PriceListSummaryForContext {
  return {
    id:                            "pl-mt",
    name:                          "Lista MarginTotal",
    mode:                          "MARGIN_TOTAL",
    roundingTarget:                "FINAL_PRICE",
    roundingMode:                  "DECIMAL_1",
    roundingDirection:             "NEAREST",
    roundingModeHechura:           null,
    roundingDirectionHechura:      null,
    commercialRoundingMetalDomain: null,
    commercialRoundingScope:       "PER_LINE_LEGACY",
    ...over,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// resolveDocCommercialRoundingContext
// ─────────────────────────────────────────────────────────────────────────────

describe("resolveDocCommercialRoundingContext — modos", () => {

  it("mixed-list → MIXED_LIST_FALLBACK con fallback NO_SHARED_LIST", () => {
    const r = resolveDocCommercialRoundingContext({
      sharedPriceList:   listMetalHechuraTargetMetal(),
      allLinesShareList: false,
    });
    expect(r.mode).toBe("MIXED_LIST_FALLBACK");
    expect(r.fallback).toBe("NO_SHARED_LIST");
    expect(r.documentActivePriceList).toBeNull();
    expect(r.applyPriceListOptions).toEqual({});
    expect(r.commercialDocumentRounding).toBeNull();
  });

  it("sharedPriceList=null → MIXED_LIST_FALLBACK", () => {
    const r = resolveDocCommercialRoundingContext({
      sharedPriceList:   null,
      allLinesShareList: true,
    });
    expect(r.mode).toBe("MIXED_LIST_FALLBACK");
    expect(r.fallback).toBe("NO_SHARED_LIST");
  });

  it("sin env y sin forceScope → PER_LINE_LEGACY (comportamiento default)", () => {
    const r = resolveDocCommercialRoundingContext({
      sharedPriceList:   listMetalHechuraTargetMetal(),
      allLinesShareList: true,
    });
    expect(r.mode).toBe("PER_LINE_LEGACY");
    expect(r.applyPriceListOptions).toEqual({});
    expect(r.commercialDocumentRounding).toBeNull();
    expect(r.documentActivePriceList).toEqual({ id: "pl-1", name: "Lista Test" });
  });

  it("forceScope=PER_DOCUMENT → PER_DOCUMENT con flags y config", () => {
    const r = resolveDocCommercialRoundingContext({
      sharedPriceList:   listMetalHechuraTargetMetal(),
      allLinesShareList: true,
      forceScope:        "PER_DOCUMENT",
    });
    expect(r.mode).toBe("PER_DOCUMENT");
    expect(r.applyPriceListOptions).toEqual({
      suppressLineHechuraRounding:       true,
      suppressLineMetalPhysicalRounding: true,
    });
    expect(r.commercialDocumentRounding).not.toBeNull();
    expect(r.commercialDocumentRounding!.scope).toBe("BREAKDOWN");
  });

  it("lista con commercialRoundingScope=PER_DOCUMENT → PER_DOCUMENT", () => {
    const r = resolveDocCommercialRoundingContext({
      sharedPriceList:   listMetalHechuraTargetMetal({ commercialRoundingScope: "PER_DOCUMENT" }),
      allLinesShareList: true,
    });
    expect(r.mode).toBe("PER_DOCUMENT");
  });

  it("forceScope=PER_LINE_LEGACY pisa el campo PER_DOCUMENT de la lista", () => {
    const r = resolveDocCommercialRoundingContext({
      sharedPriceList:   listMetalHechuraTargetMetal({ commercialRoundingScope: "PER_DOCUMENT" }),
      allLinesShareList: true,
      forceScope:        "PER_LINE_LEGACY",
    });
    expect(r.mode).toBe("PER_LINE_LEGACY");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// buildCommercialDocRoundingFromPriceList
// ─────────────────────────────────────────────────────────────────────────────

describe("buildCommercialDocRoundingFromPriceList", () => {
  it("METAL_HECHURA + target=METAL + PHYSICAL + hechura HUNDRED → BREAKDOWN", () => {
    const r = buildCommercialDocRoundingFromPriceList(listMetalHechuraTargetMetal({
      roundingMode: "DECIMAL_1",
    }));
    expect(r).toEqual({
      scope:   "BREAKDOWN",
      metal:   { mode: "DECIMAL_1", direction: "NEAREST" },
      hechura: { mode: "HUNDRED",   direction: "NEAREST" },
    });
  });

  it("METAL_HECHURA + target=METAL + MONETARY → metal queda en NONE", () => {
    const r = buildCommercialDocRoundingFromPriceList(listMetalHechuraTargetMetal({
      commercialRoundingMetalDomain: "MONETARY",
      roundingMode:                  "DECIMAL_1",
    }));
    expect(r).not.toBeNull();
    expect(r!.scope).toBe("BREAKDOWN");
    expect((r as any).metal.mode).toBe("NONE");
    expect((r as any).hechura.mode).toBe("HUNDRED");
  });

  it("METAL_HECHURA + target=METAL pero todos los rounding=NONE → null", () => {
    const r = buildCommercialDocRoundingFromPriceList(listMetalHechuraTargetMetal({
      roundingMode:        "NONE",
      roundingModeHechura: "NONE",
    }));
    expect(r).toBeNull();
  });

  it("MARGIN_TOTAL → UNIFIED", () => {
    const r = buildCommercialDocRoundingFromPriceList(listMarginTotal());
    expect(r).toEqual({ scope: "UNIFIED", mode: "DECIMAL_1", direction: "NEAREST" });
  });

  it("MARGIN_TOTAL con roundingMode=NONE → null (capa no actúa)", () => {
    const r = buildCommercialDocRoundingFromPriceList(listMarginTotal({ roundingMode: "NONE" }));
    expect(r).toBeNull();
  });

  it("METAL_HECHURA + target=FINAL_PRICE → trata como UNIFIED", () => {
    const r = buildCommercialDocRoundingFromPriceList(listMetalHechuraTargetMetal({
      roundingTarget: "FINAL_PRICE",
      roundingMode:   "TEN",
    }));
    expect(r).toEqual({ scope: "UNIFIED", mode: "TEN", direction: "NEAREST" });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// assertCommercialDocRoundingConsistency
// ─────────────────────────────────────────────────────────────────────────────

describe("assertCommercialDocRoundingConsistency", () => {
  it("PER_LINE_LEGACY (sin flags, sin capa doc) → OK", () => {
    expect(() => assertCommercialDocRoundingConsistency({
      mode:                       "PER_LINE_LEGACY",
      documentActivePriceList:    { id: "pl-1", name: "Lista" },
      applyPriceListOptions:      {},
      commercialDocumentRounding: null,
      fallback:                   null,
    })).not.toThrow();
  });

  it("PER_DOCUMENT (flags + capa doc) → OK", () => {
    expect(() => assertCommercialDocRoundingConsistency({
      mode:                       "PER_DOCUMENT",
      documentActivePriceList:    { id: "pl-1", name: "Lista" },
      applyPriceListOptions:      { suppressLineHechuraRounding: true, suppressLineMetalPhysicalRounding: true },
      commercialDocumentRounding: { scope: "UNIFIED", mode: "HUNDRED", direction: "NEAREST" },
      fallback:                   null,
    })).not.toThrow();
  });

  it("capa doc activa SIN flags PER_LINE → throw (doble redondeo)", () => {
    expect(() => assertCommercialDocRoundingConsistency({
      mode:                       "PER_DOCUMENT",
      documentActivePriceList:    { id: "pl-1", name: "Lista" },
      applyPriceListOptions:      {},  // ❌ flags apagados
      commercialDocumentRounding: { scope: "UNIFIED", mode: "HUNDRED", direction: "NEAREST" },
      fallback:                   null,
    })).toThrow(/DOBLE redondeo/i);
  });

  it("PER_DOCUMENT con flags pero sin capa doc → OK (lista sin redondeo)", () => {
    expect(() => assertCommercialDocRoundingConsistency({
      mode:                       "PER_DOCUMENT",
      documentActivePriceList:    { id: "pl-1", name: "Lista sin redondeo" },
      applyPriceListOptions:      { suppressLineHechuraRounding: true, suppressLineMetalPhysicalRounding: true },
      commercialDocumentRounding: null,
      fallback:                   null,
    })).not.toThrow();
  });

  it("MIXED_LIST_FALLBACK (sin flags + sin capa doc) → OK", () => {
    expect(() => assertCommercialDocRoundingConsistency({
      mode:                       "MIXED_LIST_FALLBACK",
      documentActivePriceList:    null,
      applyPriceListOptions:      {},
      commercialDocumentRounding: null,
      fallback:                   "NO_SHARED_LIST",
    })).not.toThrow();
  });
});
