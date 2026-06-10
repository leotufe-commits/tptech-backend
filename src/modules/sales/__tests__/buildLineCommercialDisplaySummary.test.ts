// =============================================================================
// FASE 1 — lineCommercialDisplaySummary AUTÓNOMO por línea (display-only).
//
// Garantiza el invariante del dominio ARTÍCULO: el resumen comercial de una
// línea se calcula SOLO con datos de la propia línea (sus metales, su margen
// PRE redondeo, su lista). La función NO recibe ninguna info de otras líneas ni
// del modo del documento → es autónoma por construcción.
// =============================================================================
import { describe, it, expect } from "vitest";
import { buildLineCommercialDisplaySummary } from "../commercial-doc-rounding-wiring.js";
import type { CommercialDocRoundingPartConfig } from "../../../lib/pricing-engine/commercial-document-rounding.js";

const INTEGER: CommercialDocRoundingPartConfig = { mode: "INTEGER", direction: "NEAREST" };
const NONE:    CommercialDocRoundingPartConfig = { mode: "NONE",    direction: "NEAREST" };

const SOURCE = { strategy: "PER_LINE" as const, appliedListMode: "METAL_HECHURA", appliedPriceListId: "pl-desglosada", documentContext: "MIXED_LIST" as const };

// Oro: 2 g × margen 1,2 = 2,4 → INTEGER NEAREST = 2 → Δ −0,4 × 1000 = −400.
const ORO = { metalParentId: "oro", metalParentName: "Oro Fino", appliedGramsPerUnit: 2.0, quotePriceSnapshot: 1000 };
// Plata: 3 g × 1,2 = 3,6 → INTEGER = 4 → Δ +0,4 × 100 = +40.
const PLATA = { metalParentId: "plata", metalParentName: "Plata", appliedGramsPerUnit: 3.0, quotePriceSnapshot: 100 };

describe("buildLineCommercialDisplaySummary — autonomía por línea", () => {
  it("artículo SIMPLE (1 metal): roundingImpact = Δgramos × precio", () => {
    const s = buildLineCommercialDisplaySummary({
      mode: "BREAKDOWN", lineMetals: [ORO], quantity: 1,
      marginFactor: 1.2, metalCfg: INTEGER, hechuraCfg: NONE,
      lineTotalWithTax: 5000, metalSaleSum: 2400, source: SOURCE,
    });
    expect(s.mode).toBe("BREAKDOWN");
    expect(s.metals).not.toBeNull();
    expect(s.metals!.byParent).toHaveLength(1);
    expect(s.metals!.byParent[0].roundingImpact).toBe(-400);
    expect(s.metals!.roundingImpact).toBe(-400);
  });

  it("artículo MULTIMETAL: impacto total = Σ por metal padre (con signo)", () => {
    const s = buildLineCommercialDisplaySummary({
      mode: "BREAKDOWN", lineMetals: [ORO, PLATA], quantity: 1,
      marginFactor: 1.2, metalCfg: INTEGER, hechuraCfg: NONE,
      lineTotalWithTax: 6000, metalSaleSum: 2700, source: SOURCE,
    });
    const byId = Object.fromEntries(s.metals!.byParent.map((p) => [p.metalParentId, p.roundingImpact]));
    expect(byId.oro).toBe(-400);
    expect(byId.plata).toBe(40);
    // Σ por padre = total (−400 + 40 = −360).
    expect(s.metals!.roundingImpact).toBe(-360);
  });

  it("AUTONOMÍA: misma entrada line-local ⇒ misma salida (determinístico)", () => {
    const args = {
      mode: "BREAKDOWN" as const, lineMetals: [ORO, PLATA], quantity: 1,
      marginFactor: 1.2, metalCfg: INTEGER, hechuraCfg: NONE,
      lineTotalWithTax: 6000, metalSaleSum: 2700, source: SOURCE,
    };
    expect(buildLineCommercialDisplaySummary(args)).toEqual(buildLineCommercialDisplaySummary(args));
  });

  it("UNIFIED (o sin metales): sin desglose de metal, total = monetario", () => {
    const s = buildLineCommercialDisplaySummary({
      mode: "UNIFIED", lineMetals: [], quantity: 1,
      marginFactor: 1, metalCfg: NONE, hechuraCfg: NONE,
      lineTotalWithTax: 1300, metalSaleSum: 0, source: { ...SOURCE, strategy: "NONE" },
    });
    expect(s.mode).toBe("UNIFIED");
    expect(s.metals).toBeNull();
    expect(s.monetary.amount).toBe(1300);
    expect(s.totalLineAmount).toBe(1300);
  });
});
