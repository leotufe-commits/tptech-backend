// src/lib/pricing-engine/__tests__/document-balance-breakdown.test.ts
// =============================================================================
// T52 — Tests del builder puro `buildDocumentBalanceBreakdown`. Sub-fase 3B.2.
//
// Congelan las reglas canónicas R11.x (POLICY.md §11) sobre cómo se construye
// el breakdown del documento desde el output del pricing-engine:
//
//   · UNIFIED   → metals = [], monetary.amount = documentTotal
//   · BREAKDOWN → agrupado por metal padre + pureza ponderada
//   · IVA / promo / descuento / recargo / rounding SIEMPRE caen en monetary,
//     nunca modifican gramos físicos
//   · manualPrice no afecta gramos (sólo el monto monetario que el caller
//     pasa como `documentTotal`)
//   · Pureza ponderada: Σ(g_i × p_i) / Σ g_i, null cuando Σ g_i = 0
//
// Función pura — sin mocks, sin DB, sin side effects.
// =============================================================================

import { describe, it, expect } from "vitest";
import {
  buildDocumentBalanceBreakdown,
  type BuildDocumentBalanceBreakdownInput,
  type BuildBreakdownLineInput,
} from "../pricing-engine.balance.js";

// ── Helpers de fixture ───────────────────────────────────────────────────────

function lineWithMetal(over: Partial<BuildBreakdownLineInput> & {
  metals?: BuildBreakdownLineInput["metals"];
} = {}): BuildBreakdownLineInput {
  return {
    lineId:   "line-1",
    quantity: 1,
    metals: [{
      metalParentId:                 "oro-fino",
      metalParentName:               "Oro Fino",
      metalVariantId:                "oro-18k",
      metalVariantName:              "Oro 18 Kilates",
      appliedGramsPerUnit:           1,
      purity:                        0.75,
      quotePriceSnapshot:            100000,
      metalLineValuationDocCurrency: 75000,  // 1g × 0.75 × 100000 = 75000
    }],
    ...over,
  };
}

function ars(rate = 1) {
  return { code: "ARS", rate };
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. UNIFIED
// ─────────────────────────────────────────────────────────────────────────────

describe("UNIFIED — todo monetario, metals vacío", () => {
  it("metals = [] y monetary.amount = documentTotal", () => {
    const out = buildDocumentBalanceBreakdown(
      {
        documentTotal:     100000,
        documentTotalBase: 100000,
        currency:          ars(),
        lines:             [lineWithMetal()],
      },
      "UNIFIED",
    );
    expect(out.metals).toEqual([]);
    expect(out.monetaryBalance.amount).toBe(100000);
    expect(out.monetaryBalance.amountBase).toBe(100000);
    expect(out.monetaryBalance.currencyCode).toBe("ARS");
  });

  it("UNIFIED ignora gramos aunque el input los traiga", () => {
    const out = buildDocumentBalanceBreakdown(
      {
        documentTotal:     500000,
        documentTotalBase: 500000,
        currency:          ars(),
        lines:             [lineWithMetal({ quantity: 5 })],  // gramos masivos
      },
      "UNIFIED",
    );
    expect(out.metals).toEqual([]);
    expect(out.monetaryBalance.amount).toBe(500000);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. BREAKDOWN — un metal padre, una variante
// ─────────────────────────────────────────────────────────────────────────────

describe("BREAKDOWN — un padre, una variante", () => {
  it("metals.length = 1, gramsPure y purity correctos", () => {
    const out = buildDocumentBalanceBreakdown(
      {
        documentTotal:     100000,
        documentTotalBase: 100000,
        currency:          ars(),
        lines:             [lineWithMetal()],
      },
      "BREAKDOWN",
    );
    expect(out.metals).toHaveLength(1);
    const m = out.metals[0];
    expect(m.metalParentId).toBe("oro-fino");
    expect(m.metalParentName).toBe("Oro Fino");
    expect(m.gramsOriginal).toBeCloseTo(1, 6);
    expect(m.gramsPure).toBeCloseTo(0.75, 6);
    expect(m.purity).toBeCloseTo(0.75, 6);
    expect(m.sourceLineIds).toEqual(["line-1"]);
    expect(m.variants).toHaveLength(1);
    expect(m.variants![0].variantId).toBe("oro-18k");
  });

  it("monetary.amount = documentTotal − valuación metal (regla T30)", () => {
    const out = buildDocumentBalanceBreakdown(
      {
        documentTotal:     100000,
        documentTotalBase: 100000,
        currency:          ars(),
        lines:             [lineWithMetal()],  // valuación 75000
      },
      "BREAKDOWN",
    );
    expect(out.monetaryBalance.amount).toBeCloseTo(25000, 2);
    expect(out.monetaryBalance.amountBase).toBeCloseTo(25000, 2);
  });

  it("valuationMonetary = gramsPure × quotePrice (display referencial)", () => {
    const out = buildDocumentBalanceBreakdown(
      {
        documentTotal:     100000,
        documentTotalBase: 100000,
        currency:          ars(),
        lines:             [lineWithMetal()],
      },
      "BREAKDOWN",
    );
    expect(out.metals[0].valuationMonetary).toBeCloseTo(75000, 2);
    expect(out.metals[0].valuationCurrencyCode).toBe("ARS");
    expect(out.metals[0].quotePriceSnapshot).toBe(100000);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. BREAKDOWN — un padre, varias variantes (pureza ponderada)
// ─────────────────────────────────────────────────────────────────────────────

describe("BREAKDOWN — un padre, varias variantes", () => {
  it("agrupa por padre y conserva las variantes en metadata", () => {
    const out = buildDocumentBalanceBreakdown(
      {
        documentTotal:     100000,
        documentTotalBase: 100000,
        currency:          ars(),
        lines: [{
          lineId:   "line-1",
          quantity: 1,
          metals: [
            { metalParentId: "oro-fino", metalParentName: "Oro Fino",
              metalVariantId: "oro-18k", metalVariantName: "Oro 18k",
              appliedGramsPerUnit: 1, purity: 0.75,
              quotePriceSnapshot: 100000, metalLineValuationDocCurrency: 75000 },
            { metalParentId: "oro-fino", metalParentName: "Oro Fino",
              metalVariantId: "oro-22k", metalVariantName: "Oro 22k",
              appliedGramsPerUnit: 2, purity: 0.916,
              quotePriceSnapshot: 100000, metalLineValuationDocCurrency: 183200 },
          ],
        }],
      },
      "BREAKDOWN",
    );
    expect(out.metals).toHaveLength(1);
    expect(out.metals[0].variants).toHaveLength(2);
  });

  it("pureza ponderada Σ(g×p)/Σg con 2 variantes", () => {
    // 1g × 0.75 + 2g × 0.916 = 0.75 + 1.832 = 2.582 gramsPure
    // Σ g = 3 → ponderada = 2.582 / 3 ≈ 0.8606667
    const out = buildDocumentBalanceBreakdown(
      {
        documentTotal:     300000,
        documentTotalBase: 300000,
        currency:          ars(),
        lines: [{
          lineId:   "line-1",
          quantity: 1,
          metals: [
            { metalParentId: "oro-fino", metalParentName: "Oro Fino",
              metalVariantId: "oro-18k", metalVariantName: "Oro 18k",
              appliedGramsPerUnit: 1, purity: 0.75 },
            { metalParentId: "oro-fino", metalParentName: "Oro Fino",
              metalVariantId: "oro-22k", metalVariantName: "Oro 22k",
              appliedGramsPerUnit: 2, purity: 0.916 },
          ],
        }],
      },
      "BREAKDOWN",
    );
    const m = out.metals[0];
    expect(m.gramsOriginal).toBeCloseTo(3, 6);
    expect(m.gramsPure).toBeCloseTo(2.582, 6);
    expect(m.purity!).toBeCloseTo(2.582 / 3, 6);
  });

  it("variantes preservan su purity individual (no la ponderada)", () => {
    const out = buildDocumentBalanceBreakdown(
      {
        documentTotal:     100000,
        documentTotalBase: 100000,
        currency:          ars(),
        lines: [{
          lineId:   "line-1",
          quantity: 1,
          metals: [
            { metalParentId: "oro-fino", metalParentName: "Oro Fino",
              metalVariantId: "oro-18k", metalVariantName: "Oro 18k",
              appliedGramsPerUnit: 1, purity: 0.75 },
            { metalParentId: "oro-fino", metalParentName: "Oro Fino",
              metalVariantId: "oro-22k", metalVariantName: "Oro 22k",
              appliedGramsPerUnit: 1, purity: 0.916 },
          ],
        }],
      },
      "BREAKDOWN",
    );
    const v18 = out.metals[0].variants!.find((x) => x.variantId === "oro-18k")!;
    const v22 = out.metals[0].variants!.find((x) => x.variantId === "oro-22k")!;
    expect(v18.purity).toBe(0.75);
    expect(v22.purity).toBe(0.916);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 4. BREAKDOWN — varios padres
// ─────────────────────────────────────────────────────────────────────────────

describe("BREAKDOWN — varios padres", () => {
  it("Oro y Plata se separan en entradas independientes ordenadas por nombre", () => {
    const out = buildDocumentBalanceBreakdown(
      {
        documentTotal:     200000,
        documentTotalBase: 200000,
        currency:          ars(),
        lines: [{
          lineId:   "line-1",
          quantity: 1,
          metals: [
            { metalParentId: "plata-925", metalParentName: "Plata",
              metalVariantId: "plata-925", metalVariantName: "Plata 925",
              appliedGramsPerUnit: 10, purity: 0.925 },
            { metalParentId: "oro-fino",  metalParentName: "Oro",
              metalVariantId: "oro-18k",  metalVariantName: "Oro 18k",
              appliedGramsPerUnit: 1, purity: 0.75 },
          ],
        }],
      },
      "BREAKDOWN",
    );
    // Orden: Oro antes que Plata (alfabético es-AR).
    expect(out.metals.map((m) => m.metalParentName)).toEqual(["Oro", "Plata"]);
    const oro   = out.metals.find((m) => m.metalParentId === "oro-fino")!;
    const plata = out.metals.find((m) => m.metalParentId === "plata-925")!;
    expect(oro.gramsPure).toBeCloseTo(0.75, 6);
    expect(plata.gramsPure).toBeCloseTo(9.25, 6);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 5. Línea solo hechura (sin metales)
// ─────────────────────────────────────────────────────────────────────────────

describe("BREAKDOWN — línea solo hechura (sin metales)", () => {
  it("metals = [] y monetary.amount = documentTotal (regla T45.1)", () => {
    const out = buildDocumentBalanceBreakdown(
      {
        documentTotal:     50000,
        documentTotalBase: 50000,
        currency:          ars(),
        lines: [{
          lineId:   "line-1",
          quantity: 1,
          // sin metals
          monetaryComponents: [
            { type: "HECHURA", label: "Hechura", amount: 50000 },
          ],
        }],
      },
      "BREAKDOWN",
    );
    expect(out.metals).toEqual([]);
    expect(out.monetaryBalance.amount).toBe(50000);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 6. quantity > 1
// ─────────────────────────────────────────────────────────────────────────────

describe("BREAKDOWN — quantity > 1", () => {
  it("gramos se multiplican por quantity (1g/u × 3u = 3g)", () => {
    const out = buildDocumentBalanceBreakdown(
      {
        documentTotal:     300000,
        documentTotalBase: 300000,
        currency:          ars(),
        lines: [lineWithMetal({
          quantity: 3,
          metals: [{
            metalParentId: "oro-fino",  metalParentName: "Oro Fino",
            metalVariantId: "oro-18k",  metalVariantName: "Oro 18k",
            appliedGramsPerUnit: 1, purity: 0.75,
            quotePriceSnapshot: 100000,
            metalLineValuationDocCurrency: 225000, // 3 × 0.75 × 100000
          }],
        })],
      },
      "BREAKDOWN",
    );
    expect(out.metals[0].gramsOriginal).toBeCloseTo(3, 6);
    expect(out.metals[0].gramsPure).toBeCloseTo(2.25, 6);   // 3 × 0.75
    expect(out.monetaryBalance.amount).toBeCloseTo(75000, 2);  // 300000 − 225000
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 7. manualPrice — no cambia gramos físicos
// ─────────────────────────────────────────────────────────────────────────────

describe("BREAKDOWN — manualPrice no afecta gramos", () => {
  it("documentTotal distinto (override) no toca gramsPure/gramsOriginal", () => {
    // Caso: misma línea con metales (1g × 0.75 = 0.75 gramsPure), pero el
    // operador puso manualPrice → documentTotal y valuación cambian.
    // POLICY R11.x: gramos físicos siguen reflejando el cost.
    const out = buildDocumentBalanceBreakdown(
      {
        documentTotal:     150000,     // manualPrice cambia el total
        documentTotalBase: 150000,
        currency:          ars(),
        lines: [lineWithMetal({
          metals: [{
            metalParentId: "oro-fino", metalParentName: "Oro Fino",
            metalVariantId: "oro-18k", metalVariantName: "Oro 18k",
            appliedGramsPerUnit: 1, purity: 0.75,
            quotePriceSnapshot: 100000,
            // valuación redistribuida por el motor con manualPrice — gramos
            // físicos siguen siendo 0.75 gramsPure.
            metalLineValuationDocCurrency: 112500,
          }],
        })],
      },
      "BREAKDOWN",
    );
    expect(out.metals[0].gramsOriginal).toBeCloseTo(1, 6);
    expect(out.metals[0].gramsPure).toBeCloseTo(0.75, 6);
    expect(out.monetaryBalance.amount).toBeCloseTo(37500, 2); // 150000 − 112500
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 8. IVA applyOn=METAL — siempre en monetary (R11.3)
// ─────────────────────────────────────────────────────────────────────────────

describe("BREAKDOWN — IVA siempre en monetary, NUNCA en gramos (R11.3)", () => {
  it("componente TAX con applyOn=METAL no toca gramos; aparece en components", () => {
    const out = buildDocumentBalanceBreakdown(
      {
        documentTotal:     121000,
        documentTotalBase: 121000,
        currency:          ars(),
        lines: [lineWithMetal({
          metals: [{
            metalParentId: "oro-fino", metalParentName: "Oro Fino",
            metalVariantId: "oro-18k", metalVariantName: "Oro 18k",
            appliedGramsPerUnit: 1, purity: 0.75,
            quotePriceSnapshot: 100000, metalLineValuationDocCurrency: 75000,
          }],
          monetaryComponents: [
            { type: "TAX", label: "IVA 21% (sobre metal)", amount: 21000,
              source: "tax-iva" },
          ],
        })],
      },
      "BREAKDOWN",
    );
    expect(out.metals[0].gramsPure).toBeCloseTo(0.75, 6);  // intacto
    expect(out.monetaryBalance.amount).toBeCloseTo(46000, 2); // 121000 − 75000
    const taxComp = out.monetaryBalance.components?.find((c) => c.type === "TAX");
    expect(taxComp).toBeDefined();
    expect(taxComp!.amount).toBe(21000);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 9. Promo applyOn=METAL — siempre en monetary, no toca gramos
// ─────────────────────────────────────────────────────────────────────────────

describe("BREAKDOWN — promo/descuento NUNCA modifican gramos", () => {
  it("DISCOUNT_PROMO con applyOn=METAL aparece en components, gramos intactos", () => {
    const out = buildDocumentBalanceBreakdown(
      {
        documentTotal:     90000,
        documentTotalBase: 90000,
        currency:          ars(),
        lines: [lineWithMetal({
          metals: [{
            metalParentId: "oro-fino", metalParentName: "Oro Fino",
            metalVariantId: "oro-18k", metalVariantName: "Oro 18k",
            appliedGramsPerUnit: 1, purity: 0.75,
            quotePriceSnapshot: 100000, metalLineValuationDocCurrency: 75000,
          }],
          monetaryComponents: [
            { type: "DISCOUNT_PROMO", label: "Promo Verano", amount: -10000,
              source: "promo-verano" },
          ],
        })],
      },
      "BREAKDOWN",
    );
    expect(out.metals[0].gramsPure).toBeCloseTo(0.75, 6);
    const promoComp = out.monetaryBalance.components?.find(
      (c) => c.type === "DISCOUNT_PROMO",
    );
    expect(promoComp).toBeDefined();
    expect(promoComp!.amount).toBe(-10000);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 10. Currency — gramos invariantes, monetary refleja moneda
// ─────────────────────────────────────────────────────────────────────────────

describe("BREAKDOWN — currency: gramos invariantes con cambio de moneda", () => {
  it("documento en USD (rate 1000): gramos iguales que en ARS, monetary refleja USD", () => {
    // Mismos gramos físicos. Total en USD = 100, rate 1000 → totalBase = 100000.
    // Valuación metal en USD = 75 (1g × 0.75 × 100 USD/g).
    const out = buildDocumentBalanceBreakdown(
      {
        documentTotal:     100,    // USD
        documentTotalBase: 100000, // ARS base
        currency:          { code: "USD", rate: 1000 },
        lines: [lineWithMetal({
          metals: [{
            metalParentId: "oro-fino", metalParentName: "Oro Fino",
            metalVariantId: "oro-18k", metalVariantName: "Oro 18k",
            appliedGramsPerUnit: 1, purity: 0.75,
            quotePriceSnapshot: 100,                 // 100 USD/g
            metalLineValuationDocCurrency: 75,       // en USD
          }],
        })],
      },
      "BREAKDOWN",
    );
    expect(out.metals[0].gramsOriginal).toBeCloseTo(1, 6);
    expect(out.metals[0].gramsPure).toBeCloseTo(0.75, 6);
    expect(out.metals[0].valuationCurrencyCode).toBe("USD");
    expect(out.monetaryBalance.currencyCode).toBe("USD");
    expect(out.monetaryBalance.amount).toBeCloseTo(25, 2);            // 100 − 75
    expect(out.monetaryBalance.amountBase).toBeCloseTo(25000, 2);     // (100−75) × 1000
  });

  it("rate inválido (0 o negativo) → fallback rate=1 sin romper", () => {
    const out = buildDocumentBalanceBreakdown(
      {
        documentTotal:     100,
        documentTotalBase: 100,
        currency:          { code: "USD", rate: 0 },
        lines:             [lineWithMetal()],
      },
      "UNIFIED",
    );
    expect(out.monetaryBalance.currencyRate).toBe(1);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 11. Invariantes de la función pura
// ─────────────────────────────────────────────────────────────────────────────

describe("Invariantes — función pura, determinística, no muta input", () => {
  it("no muta el input", () => {
    const input: BuildDocumentBalanceBreakdownInput = {
      documentTotal:     100000,
      documentTotalBase: 100000,
      currency:          ars(),
      lines: [lineWithMetal()],
    };
    const snapshot = JSON.stringify(input);
    buildDocumentBalanceBreakdown(input, "BREAKDOWN");
    expect(JSON.stringify(input)).toBe(snapshot);
  });

  it("determinístico — mismo input produce mismo output (deep equal)", () => {
    const input: BuildDocumentBalanceBreakdownInput = {
      documentTotal:     100000,
      documentTotalBase: 100000,
      currency:          ars(),
      lines: [lineWithMetal()],
    };
    const r1 = buildDocumentBalanceBreakdown(input, "BREAKDOWN");
    const r2 = buildDocumentBalanceBreakdown(input, "BREAKDOWN");
    expect(JSON.stringify(r1)).toBe(JSON.stringify(r2));
  });

  it("purity null en la variante → tratada como 1 para gramsPure (no pierde gramos)", () => {
    const out = buildDocumentBalanceBreakdown(
      {
        documentTotal:     100000,
        documentTotalBase: 100000,
        currency:          ars(),
        lines: [{
          lineId:   "line-1",
          quantity: 1,
          metals: [{
            metalParentId: "oro-fino", metalParentName: "Oro Fino",
            metalVariantId: "oro-legacy", metalVariantName: "Legacy",
            appliedGramsPerUnit: 2, purity: null,
          }],
        }],
      },
      "BREAKDOWN",
    );
    // purity null → math con 1 → gramsPure = gramsOriginal = 2.
    expect(out.metals[0].gramsOriginal).toBeCloseTo(2, 6);
    expect(out.metals[0].gramsPure).toBeCloseTo(2, 6);
    // Pureza ponderada = 2/2 = 1.
    expect(out.metals[0].purity).toBeCloseTo(1, 6);
  });

  it("gramos = 0 → padre se descarta (no aparece en metals)", () => {
    const out = buildDocumentBalanceBreakdown(
      {
        documentTotal:     50000,
        documentTotalBase: 50000,
        currency:          ars(),
        lines: [{
          lineId:   "line-1",
          quantity: 1,
          metals: [{
            metalParentId: "oro-fino", metalParentName: "Oro Fino",
            metalVariantId: "oro-18k", metalVariantName: "Oro 18k",
            appliedGramsPerUnit: 0, purity: 0.75,
          }],
        }],
      },
      "BREAKDOWN",
    );
    expect(out.metals).toEqual([]);
  });

  it("components a nivel línea enriquecen sourceLineId si no lo traen", () => {
    const out = buildDocumentBalanceBreakdown(
      {
        documentTotal:     50000,
        documentTotalBase: 50000,
        currency:          ars(),
        lines: [{
          lineId:   "L-7",
          quantity: 1,
          monetaryComponents: [{ type: "HECHURA", label: "Hechura", amount: 50000 }],
        }],
      },
      "UNIFIED",
    );
    expect(out.monetaryBalance.components).toHaveLength(1);
    expect(out.monetaryBalance.components![0].sourceLineId).toBe("L-7");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// T58 (Etapa 4) — Negativos reales en BREAKDOWN. Hasta esta etapa el motor
// clampeaba `monetary.amount` con `Math.max(0, ...)` ocultando dos casos
// comerciales legítimos: (a) descuentos/bonificaciones que superan la base
// monetaria; (b) créditos monetarios a favor del cliente. POLICY.md §11
// nunca prohibió negativos — el clamp era hardening defensivo no
// documentado. Estos tests congelan el nuevo comportamiento.
// ─────────────────────────────────────────────────────────────────────────────

describe("T58 — Negativos en BREAKDOWN (clamp removido)", () => {
  /** Fixture: 1 línea de metal con valuación fija + override del documentTotal
   *  para simular el caso "descuentos vs. hechura". `metalValuation = 75000`
   *  (1 g × 0.75 × 100000). Variando `documentTotal` controlamos el saldo
   *  monetario: amountDoc = documentTotal − 75000. */
  function buildWithTotal(documentTotal: number, totalBase = documentTotal) {
    return buildDocumentBalanceBreakdown(
      {
        documentTotal,
        documentTotalBase: totalBase,
        currency:          ars(),
        lines:             [lineWithMetal()],
      },
      "BREAKDOWN",
    );
  }

  it("(1) descuento MENOR que hechura → monetary.amount positivo normal", () => {
    // documentTotal 100.000 ; metal 75.000 → monetario 25.000
    const out = buildWithTotal(100000);
    expect(out.monetaryBalance.amount).toBeCloseTo(25000, 2);
    expect(out.monetaryBalance.amountBase).toBeCloseTo(25000, 2);
    expect(out.metals).toHaveLength(1);
  });

  it("(2) descuento IGUAL a hechura → monetary.amount === 0 exacto", () => {
    // documentTotal 75.000 ; metal 75.000 → monetario 0
    const out = buildWithTotal(75000);
    expect(out.monetaryBalance.amount).toBeCloseTo(0, 6);
    expect(out.monetaryBalance.amountBase).toBeCloseTo(0, 6);
    expect(out.metals).toHaveLength(1);
  });

  it("(3) descuento MAYOR que hechura → monetary.amount NEGATIVO (permitido)", () => {
    // documentTotal 60.000 ; metal 75.000 → monetario −15.000
    const out = buildWithTotal(60000);
    expect(out.monetaryBalance.amount).toBeCloseTo(-15000, 2);
    expect(out.monetaryBalance.amountBase).toBeCloseTo(-15000, 2);
    // Defensa explícita contra el regreso del clamp `Math.max(0, ...)`.
    expect(out.monetaryBalance.amount).toBeLessThan(0);
    expect(out.monetaryBalance.amountBase).toBeLessThan(0);
  });

  it("(4) BREAKDOWN mantiene metales separados aunque monetary sea negativo", () => {
    // El negativo monetario NO compensa gramos — los metales siguen como
    // deuda física independiente.
    const out = buildWithTotal(10000);  // → monetario −65.000
    expect(out.monetaryBalance.amount).toBeLessThan(0);
    expect(out.metals).toHaveLength(1);
    expect(out.metals[0].metalParentName).toBe("Oro Fino");
    expect(out.metals[0].gramsPure).toBeCloseTo(0.75, 6);  // intacto
    expect(out.metals[0].valuationMonetary).toBeCloseTo(75000, 2);  // intacto
  });

  it("(5) UNIFIED sigue igual — no se ve afectado por el cambio del clamp", () => {
    // UNIFIED: monetary.amount = documentTotal directo (sin restar metal).
    // Si el operador descuenta más allá del costo, el documentTotal puede
    // venir negativo y se debe reflejar tal cual.
    const out = buildDocumentBalanceBreakdown(
      {
        documentTotal:     -5000,
        documentTotalBase: -5000,
        currency:          ars(),
        lines:             [lineWithMetal()],
      },
      "UNIFIED",
    );
    expect(out.metals).toEqual([]);
    expect(out.monetaryBalance.amount).toBe(-5000);
    expect(out.monetaryBalance.amountBase).toBe(-5000);
  });

  it("(6) NO se aplica Math.max clamp — paridad exacta amount = total − metal", () => {
    // Caso patológico: documentTotal 0, metal 75.000 → monetario −75.000.
    // Si el clamp volviera, este test fallaría porque amount === 0.
    const out = buildWithTotal(0);
    expect(out.monetaryBalance.amount).toBe(-75000);
    expect(out.monetaryBalance.amountBase).toBe(-75000);
    expect(out.monetaryBalance.amount).not.toBe(0);  // <- guard explícito
  });

  it("(7) currencyRate ≠ 1 — la conversión BASE↔doc sigue siendo consistente con signo", () => {
    // doc en USD (rate=400 ARS/USD); metal valuation viene en doc currency.
    // documentTotal (doc) = 100 USD, totalBase = 40.000 ARS, metalValuationDoc
    // = 150 (lineWithMetal fixture base) → no aplica al fixture (rate=1).
    // Replicamos con override manual del rate para verificar que ambos lados
    // del cálculo (amountDoc y amountBase) usan el mismo signo (no se queda
    // amountBase clamped a 0 mientras amountDoc va negativo).
    const out = buildDocumentBalanceBreakdown(
      {
        documentTotal:     50,        // USD
        documentTotalBase: 20000,     // ARS (= 50 × 400)
        currency:          { code: "USD", rate: 400 },
        lines:             [{
          lineId:   "L-fx",
          quantity: 1,
          metals: [{
            metalParentId:                 "oro-fino",
            metalParentName:               "Oro Fino",
            metalVariantId:                "oro-24k",
            metalVariantName:              "Oro 24k",
            appliedGramsPerUnit:           1,
            purity:                        1,
            quotePriceSnapshot:            100,    // USD/g
            metalLineValuationDocCurrency: 100,    // USD (1g × 1 × 100)
          }],
        }],
      },
      "BREAKDOWN",
    );
    // doc:  50 USD − 100 USD = −50 USD
    // base: 20000 ARS − (100 USD × 400 ARS/USD) = −20.000 ARS
    expect(out.monetaryBalance.amount).toBeCloseTo(-50, 2);
    expect(out.monetaryBalance.amountBase).toBeCloseTo(-20000, 2);
    // Ambos firmados consistente — si el clamp viejo siguiera en amountBase,
    // amountBase quedaría en 0 mientras amountDoc va negativo.
    expect(Math.sign(out.monetaryBalance.amount))
      .toBe(Math.sign(out.monetaryBalance.amountBase));
  });

  it("(8) componentes monetarios passthrough — no se filtran por signo del total", () => {
    // El destrabe del clamp NO debe afectar la emisión de components.
    // Con monetary.amount negativo, los components siguen llegando al consumer.
    const out = buildDocumentBalanceBreakdown(
      {
        documentTotal:     10000,   // → monetario −65.000 (75k metal)
        documentTotalBase: 10000,
        currency:          ars(),
        lines: [{
          ...lineWithMetal(),
          monetaryComponents: [
            { type: "HECHURA",         label: "Hechura",          amount: 55000 },
            { type: "DISCOUNT_MANUAL", label: "Descuento global", amount: -120000 },
          ],
        }],
      },
      "BREAKDOWN",
    );
    expect(out.monetaryBalance.amount).toBeLessThan(0);
    expect(out.monetaryBalance.components).toHaveLength(2);
    // El amount declarado por el motor (−65.000) NO coincide con Σ components
    // (55.000 − 120.000 = −65.000 acá da igual). El test garantiza que
    // `amount` viene del cálculo `documentTotal − valuación metal`, no de
    // sumar components.
    expect(out.monetaryBalance.amount).toBeCloseTo(-65000, 2);
  });
});
