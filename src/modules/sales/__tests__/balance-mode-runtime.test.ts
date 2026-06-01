// src/modules/sales/__tests__/balance-mode-runtime.test.ts
// =============================================================================
// T55 — Tests del runtime de Balance Mode (Fase 3B.5).
//
// Cubren los dos helpers puros que el flujo de venta usa para resolver y
// construir el breakdown del documento:
//
//   1. `resolveSaleBalanceMode`   — prioridad R11.4 + back-compat
//      `CommercialEntity.balanceType` legacy (mapBalanceTypeToMode).
//   2. `buildSaleBalanceBreakdown` — proyecta líneas + totales del documento
//      al input canónico de `buildDocumentBalanceBreakdown`.
//
// Tests funcionales sin DB. NO se ejerce `previewSale`/`confirmSale` enteros
// — esos flujos tienen sus tests de paridad ya existentes
// (`preview-confirm-parity.test.ts`, `confirm-sale-pricing-snapshot.test.ts`).
//
// Reglas críticas validadas:
//   · R11.4 prioridad: documentOverride > entityBalanceMode > legacy
//     balanceType > priceListDefault > tenantDefault > FALLBACK_UNIFIED.
//   · El nuevo `balanceMode` del cliente GANA sobre `balanceType` legacy.
//   · IVA / promo / descuento / manualPrice nunca tocan gramos físicos.
//   · UNIFIED → metals=[], monetary.amount=total.
//   · BREAKDOWN → metals agrupado por padre + valuación; monetary = total −
//     valuación metal.
// =============================================================================

import { describe, it, expect } from "vitest";
import {
  resolveSaleBalanceMode,
  buildSaleBalanceBreakdown,
  buildDocumentMonetaryComponentsFromTotals,
  extractMetalItemsFromSteps,
  type SaleLineForBalance,
} from "../balance-mode-runtime.js";

// ─────────────────────────────────────────────────────────────────────────────
// resolveSaleBalanceMode — prioridad R11.4 + back-compat balanceType
// ─────────────────────────────────────────────────────────────────────────────

describe("resolveSaleBalanceMode — prioridad R11.4", () => {
  it("documentOverride GANA sobre todo el resto (R11.4 nivel 1)", () => {
    const r = resolveSaleBalanceMode({
      documentOverride:        "BREAKDOWN",
      entityBalanceMode:       "UNIFIED",
      entityBalanceTypeLegacy: "UNIFIED",
      priceListDefault:        "UNIFIED",
      tenantDefault:           "UNIFIED",
    });
    expect(r).toEqual({ mode: "BREAKDOWN", source: "DOCUMENT_OVERRIDE" });
  });

  it("entityBalanceMode (nuevo) GANA sobre legacy balanceType", () => {
    // Cliente con `balanceMode = "UNIFIED"` y `balanceType = "BREAKDOWN"`
    // legacy. El campo canónico (`balanceMode`) tiene prioridad — el legacy
    // queda como compatibilidad.
    const r = resolveSaleBalanceMode({
      documentOverride:        null,
      entityBalanceMode:       "UNIFIED",
      entityBalanceTypeLegacy: "BREAKDOWN",
      priceListDefault:        "BREAKDOWN",
      tenantDefault:           "BREAKDOWN",
    });
    expect(r).toEqual({ mode: "UNIFIED", source: "ENTITY_DEFAULT" });
  });

  it("fallback a legacy balanceType cuando balanceMode nuevo es null", () => {
    // Cliente histórico solo tiene `balanceType` legacy.
    const r = resolveSaleBalanceMode({
      documentOverride:        null,
      entityBalanceMode:       null,
      entityBalanceTypeLegacy: "BREAKDOWN",
      priceListDefault:        "UNIFIED",
      tenantDefault:           "UNIFIED",
    });
    expect(r).toEqual({ mode: "BREAKDOWN", source: "ENTITY_DEFAULT" });
  });

  it("priceListDefault gana cuando documento y entity son null", () => {
    const r = resolveSaleBalanceMode({
      documentOverride:        null,
      entityBalanceMode:       null,
      entityBalanceTypeLegacy: null,
      priceListDefault:        "BREAKDOWN",
      tenantDefault:           "UNIFIED",
    });
    expect(r).toEqual({ mode: "BREAKDOWN", source: "PRICELIST_DEFAULT" });
  });

  it("tenantDefault gana cuando los 3 niveles superiores son null", () => {
    const r = resolveSaleBalanceMode({
      tenantDefault: "BREAKDOWN",
    });
    expect(r).toEqual({ mode: "BREAKDOWN", source: "TENANT_DEFAULT" });
  });

  it("FALLBACK_UNIFIED cuando TODOS los niveles son null", () => {
    const r = resolveSaleBalanceMode({});
    expect(r).toEqual({ mode: "UNIFIED", source: "FALLBACK_UNIFIED" });
  });

  it("legacy balanceType con valor inválido → se ignora (cae al siguiente nivel)", () => {
    const r = resolveSaleBalanceMode({
      documentOverride:        null,
      entityBalanceMode:       null,
      entityBalanceTypeLegacy: "GARBAGE_VALUE",
      priceListDefault:        "BREAKDOWN",
      tenantDefault:           "UNIFIED",
    });
    expect(r).toEqual({ mode: "BREAKDOWN", source: "PRICELIST_DEFAULT" });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Default inteligente nivel lista — `PriceList.mode === METAL_HECHURA`
// ─────────────────────────────────────────────────────────────────────────────
// Cuando la lista tiene `balanceMode = null` (legacy / sin override) pero su
// `mode` calcula precios desglosando metal y hechura (`METAL_HECHURA`), el
// nivel "lista" aporta `BREAKDOWN`. Cierra el bug "Patrimonio Metálico muestra
// metalGramsSale en vez de postGrams" — antes, la lista caía a `null` y la
// cadena terminaba en el tenant UNIFIED → balanceBreakdown.metals quedaba
// vacío → frontend usaba el fallback `documentMetals` (gramos lado venta).
// ─────────────────────────────────────────────────────────────────────────────

describe("resolveSaleBalanceMode — default inteligente METAL_HECHURA", () => {
  it("(A) lista METAL_HECHURA sin balanceMode + sin override + sin cliente → BREAKDOWN con source PRICELIST_DEFAULT", () => {
    const r = resolveSaleBalanceMode({
      documentOverride:        null,
      entityBalanceMode:       null,
      entityBalanceTypeLegacy: null,
      priceListDefault:        null,
      priceListMode:           "METAL_HECHURA",
      tenantDefault:           "UNIFIED",
    });
    expect(r).toEqual({ mode: "BREAKDOWN", source: "PRICELIST_DEFAULT" });
  });

  it("(B) lista METAL_HECHURA con balanceMode=UNIFIED explícito → gana UNIFIED (NO se sobreescribe)", () => {
    const r = resolveSaleBalanceMode({
      documentOverride:        null,
      entityBalanceMode:       null,
      entityBalanceTypeLegacy: null,
      priceListDefault:        "UNIFIED",
      priceListMode:           "METAL_HECHURA",
      tenantDefault:           "BREAKDOWN",
    });
    expect(r).toEqual({ mode: "UNIFIED", source: "PRICELIST_DEFAULT" });
  });

  it("(B-bis) lista METAL_HECHURA con balanceMode=BREAKDOWN explícito → gana BREAKDOWN (idempotente)", () => {
    const r = resolveSaleBalanceMode({
      documentOverride:        null,
      entityBalanceMode:       null,
      entityBalanceTypeLegacy: null,
      priceListDefault:        "BREAKDOWN",
      priceListMode:           "METAL_HECHURA",
      tenantDefault:           "UNIFIED",
    });
    expect(r).toEqual({ mode: "BREAKDOWN", source: "PRICELIST_DEFAULT" });
  });

  it("(C) lista MARGIN_TOTAL sin balanceMode → la inferencia NO dispara, cae a tenant", () => {
    const r = resolveSaleBalanceMode({
      documentOverride:        null,
      entityBalanceMode:       null,
      entityBalanceTypeLegacy: null,
      priceListDefault:        null,
      priceListMode:           "MARGIN_TOTAL",
      tenantDefault:           "UNIFIED",
    });
    expect(r).toEqual({ mode: "UNIFIED", source: "TENANT_DEFAULT" });
  });

  it("(C-bis) lista COST_PER_GRAM sin balanceMode → la inferencia NO dispara, cae a tenant", () => {
    const r = resolveSaleBalanceMode({
      documentOverride:        null,
      entityBalanceMode:       null,
      entityBalanceTypeLegacy: null,
      priceListDefault:        null,
      priceListMode:           "COST_PER_GRAM",
      tenantDefault:           "BREAKDOWN",
    });
    expect(r).toEqual({ mode: "BREAKDOWN", source: "TENANT_DEFAULT" });
  });

  it("(D) cliente UNIFIED + lista METAL_HECHURA sin balanceMode → gana cliente UNIFIED por prioridad R11.4", () => {
    const r = resolveSaleBalanceMode({
      documentOverride:        null,
      entityBalanceMode:       "UNIFIED",
      entityBalanceTypeLegacy: null,
      priceListDefault:        null,
      priceListMode:           "METAL_HECHURA",
      tenantDefault:           "UNIFIED",
    });
    expect(r).toEqual({ mode: "UNIFIED", source: "ENTITY_DEFAULT" });
  });

  it("(D-bis) documentOverride BREAKDOWN + lista MARGIN_TOTAL → gana override del documento", () => {
    const r = resolveSaleBalanceMode({
      documentOverride:        "BREAKDOWN",
      entityBalanceMode:       null,
      entityBalanceTypeLegacy: null,
      priceListDefault:        null,
      priceListMode:           "MARGIN_TOTAL",
      tenantDefault:           "UNIFIED",
    });
    expect(r).toEqual({ mode: "BREAKDOWN", source: "DOCUMENT_OVERRIDE" });
  });

  it("(back-compat) caller que NO pasa `priceListMode` → comportamiento idéntico al previo (priceListDefault crudo)", () => {
    const r = resolveSaleBalanceMode({
      documentOverride:        null,
      entityBalanceMode:       null,
      entityBalanceTypeLegacy: null,
      priceListDefault:        null,
      // priceListMode ausente
      tenantDefault:           "UNIFIED",
    });
    expect(r).toEqual({ mode: "UNIFIED", source: "TENANT_DEFAULT" });
  });

  it("(robustez) priceListMode con string desconocido → no dispara la inferencia", () => {
    const r = resolveSaleBalanceMode({
      documentOverride:        null,
      entityBalanceMode:       null,
      entityBalanceTypeLegacy: null,
      priceListDefault:        null,
      priceListMode:           "ALGO_DESCONOCIDO",
      tenantDefault:           "UNIFIED",
    });
    expect(r).toEqual({ mode: "UNIFIED", source: "TENANT_DEFAULT" });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// buildSaleBalanceBreakdown — proyección líneas + totales → breakdown canónico
// ─────────────────────────────────────────────────────────────────────────────

function lineWithMetal(over: Partial<SaleLineForBalance> = {}): SaleLineForBalance {
  return {
    lineId:   "L-1",
    quantity: 1,
    metalItems: [{
      metalId:       "oro-fino",
      variantId:     "oro-18k",
      gramsOriginal: 1,
      purity:        0.75,
      gramsPure:     0.75,
      unitValue:     100000,
    }],
    metalLineValuationDocCurrency: 75000,
    ...over,
  };
}

describe("buildSaleBalanceBreakdown — UNIFIED", () => {
  it("UNIFIED → metals=[], monetary.amount=documentTotal", () => {
    const out = buildSaleBalanceBreakdown({
      mode:              "UNIFIED",
      documentTotal:     100000,
      documentTotalBase: 100000,
      currency:          { code: "ARS", rate: 1 },
      lines:             [lineWithMetal()],
    });
    expect(out.metals).toEqual([]);
    expect(out.monetaryBalance.amount).toBe(100000);
    expect(out.monetaryBalance.currencyCode).toBe("ARS");
  });
});

describe("buildSaleBalanceBreakdown — BREAKDOWN", () => {
  it("agrupa por metal padre con pureza ponderada + gramsPure correcto", () => {
    const out = buildSaleBalanceBreakdown({
      mode:              "BREAKDOWN",
      documentTotal:     100000,
      documentTotalBase: 100000,
      currency:          { code: "ARS", rate: 1 },
      lines:             [lineWithMetal()],
      metalNames:        new Map([["oro-fino", "Oro Fino"]]),
      variantNames:      new Map([["oro-18k", "Oro 18 Kilates"]]),
    });
    expect(out.metals).toHaveLength(1);
    expect(out.metals[0].metalParentName).toBe("Oro Fino");
    expect(out.metals[0].gramsOriginal).toBeCloseTo(1, 6);
    expect(out.metals[0].gramsPure).toBeCloseTo(0.75, 6);
    expect(out.metals[0].purity).toBeCloseTo(0.75, 6);
    // monetary = total − valuación metal
    expect(out.monetaryBalance.amount).toBeCloseTo(25000, 2);
  });

  it("varios padres → entradas separadas", () => {
    const out = buildSaleBalanceBreakdown({
      mode:              "BREAKDOWN",
      documentTotal:     200000,
      documentTotalBase: 200000,
      currency:          { code: "ARS", rate: 1 },
      lines: [{
        lineId:   "L-1",
        quantity: 1,
        metalItems: [
          { metalId: "oro-fino",  variantId: "oro-18k",  gramsOriginal: 1,  purity: 0.75, gramsPure: 0.75, unitValue: 100000 },
          { metalId: "plata-925", variantId: "plata-925", gramsOriginal: 10, purity: 0.925, gramsPure: 9.25, unitValue: 5000 },
        ],
        metalLineValuationDocCurrency: 121250,
      }],
      metalNames: new Map([
        ["oro-fino", "Oro Fino"],
        ["plata-925", "Plata 925"],
      ]),
    });
    expect(out.metals).toHaveLength(2);
    const oro   = out.metals.find((m) => m.metalParentId === "oro-fino")!;
    const plata = out.metals.find((m) => m.metalParentId === "plata-925")!;
    expect(oro.gramsPure).toBeCloseTo(0.75, 6);
    expect(plata.gramsPure).toBeCloseTo(9.25, 6);
  });

  it("línea solo hechura (sin metales) → metals=[]", () => {
    const out = buildSaleBalanceBreakdown({
      mode:              "BREAKDOWN",
      documentTotal:     50000,
      documentTotalBase: 50000,
      currency:          { code: "ARS", rate: 1 },
      lines: [{
        lineId:   "L-1",
        quantity: 1,
        // sin metalItems
      }],
    });
    expect(out.metals).toEqual([]);
    expect(out.monetaryBalance.amount).toBe(50000);
  });

  it("quantity > 1 → gramos × qty correctamente", () => {
    const out = buildSaleBalanceBreakdown({
      mode:              "BREAKDOWN",
      documentTotal:     300000,
      documentTotalBase: 300000,
      currency:          { code: "ARS", rate: 1 },
      lines: [lineWithMetal({
        quantity: 3,
        metalLineValuationDocCurrency: 225000,
      })],
    });
    expect(out.metals[0].gramsOriginal).toBeCloseTo(3, 6);
    expect(out.metals[0].gramsPure).toBeCloseTo(2.25, 6);
    expect(out.monetaryBalance.amount).toBeCloseTo(75000, 2);
  });

  it("metalId vacío en el item → se descarta (sin padre, no se puede agrupar)", () => {
    const out = buildSaleBalanceBreakdown({
      mode:              "BREAKDOWN",
      documentTotal:     50000,
      documentTotalBase: 50000,
      currency:          { code: "ARS", rate: 1 },
      lines: [{
        lineId:   "L-1",
        quantity: 1,
        metalItems: [{
          metalId:       null,    // falta padre
          variantId:     "x",
          gramsOriginal: 5,
          purity:        0.9,
          gramsPure:     4.5,
        }],
      }],
    });
    expect(out.metals).toEqual([]);
  });

  it("metal padre sin nombre cargado → usa metalId como name (fallback)", () => {
    const out = buildSaleBalanceBreakdown({
      mode:              "BREAKDOWN",
      documentTotal:     100000,
      documentTotalBase: 100000,
      currency:          { code: "ARS", rate: 1 },
      lines:             [lineWithMetal()],
      // sin metalNames
    });
    expect(out.metals[0].metalParentName).toBe("oro-fino");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// manualPrice / IVA applyOn=METAL / promo applyOn=METAL — gramos invariantes
// ─────────────────────────────────────────────────────────────────────────────

describe("buildSaleBalanceBreakdown — gramos invariantes (R11.3)", () => {
  it("manualPrice cambia documentTotal pero NO toca gramos físicos", () => {
    // Mismo cost de metal (gramsPure=0.75) pero el operador puso manualPrice
    // → documentTotal sube + el motor redistribuyó metalSale.
    const out = buildSaleBalanceBreakdown({
      mode:              "BREAKDOWN",
      documentTotal:     150000,
      documentTotalBase: 150000,
      currency:          { code: "ARS", rate: 1 },
      lines: [lineWithMetal({
        // gramos físicos siguen siendo 1g × 0.75 = 0.75 gramsPure
        metalLineValuationDocCurrency: 112500, // redistribuido por manualPrice
      })],
    });
    expect(out.metals[0].gramsOriginal).toBeCloseTo(1, 6);
    expect(out.metals[0].gramsPure).toBeCloseTo(0.75, 6);
    expect(out.monetaryBalance.amount).toBeCloseTo(37500, 2);
  });

  it("IVA applyOn=METAL no cambia gramos (R11.3 — IVA SIEMPRE monetario)", () => {
    // El IVA aumenta documentTotal (75000 metal + 21% = 90750 con IVA + cualquier
    // hechura). El motor ya lo absorbió en documentTotal. Los gramos físicos
    // permanecen iguales.
    const out = buildSaleBalanceBreakdown({
      mode:              "BREAKDOWN",
      documentTotal:     121000, // 100k + 21% IVA
      documentTotalBase: 121000,
      currency:          { code: "ARS", rate: 1 },
      lines:             [lineWithMetal()],
    });
    expect(out.metals[0].gramsPure).toBeCloseTo(0.75, 6);
    // monetary absorbe el IVA: 121000 − 75000 = 46000
    expect(out.monetaryBalance.amount).toBeCloseTo(46000, 2);
  });

  it("promo applyOn=METAL no cambia gramos (POLICY.md §11)", () => {
    // Promo de 10% sobre el metal: el motor redujo metalSale a 67500 (en vez
    // de 75000), bajando documentTotal en 7500. Los gramos del COST siguen.
    const out = buildSaleBalanceBreakdown({
      mode:              "BREAKDOWN",
      documentTotal:     92500,
      documentTotalBase: 92500,
      currency:          { code: "ARS", rate: 1 },
      lines: [lineWithMetal({
        metalLineValuationDocCurrency: 67500,
      })],
    });
    expect(out.metals[0].gramsOriginal).toBeCloseTo(1, 6);
    expect(out.metals[0].gramsPure).toBeCloseTo(0.75, 6);
    expect(out.monetaryBalance.amount).toBeCloseTo(25000, 2);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Currency — gramos invariantes ante cambio de moneda
// ─────────────────────────────────────────────────────────────────────────────

describe("buildSaleBalanceBreakdown — currency invariante", () => {
  it("documento en USD: gramos iguales que en ARS, monetary refleja USD", () => {
    const out = buildSaleBalanceBreakdown({
      mode:              "BREAKDOWN",
      documentTotal:     100,     // USD
      documentTotalBase: 100000,  // ARS
      currency:          { code: "USD", rate: 1000 },
      lines: [{
        lineId:   "L-1",
        quantity: 1,
        metalItems: [{
          metalId:       "oro-fino",
          variantId:     "oro-18k",
          gramsOriginal: 1,
          purity:        0.75,
          gramsPure:     0.75,
          unitValue:     100, // USD/g
        }],
        metalLineValuationDocCurrency: 75, // USD
      }],
    });
    expect(out.metals[0].gramsPure).toBeCloseTo(0.75, 6);
    expect(out.monetaryBalance.currencyCode).toBe("USD");
    expect(out.monetaryBalance.amount).toBeCloseTo(25, 2);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Idempotencia / parity preview ↔ confirm
// ─────────────────────────────────────────────────────────────────────────────

describe("buildSaleBalanceBreakdown — parity preview ↔ confirm", () => {
  it("mismo input → mismo output (determinístico)", () => {
    // El uso real: previewSale arma con `costBreakdown.metal.items` por línea;
    // confirmSale arma con `lineResults[].breakdownSnapshot.metal.items` — el
    // mismo shape. Si la proyección es estable, los breakdowns son idénticos.
    const input = {
      mode:              "BREAKDOWN" as const,
      documentTotal:     100000,
      documentTotalBase: 100000,
      currency:          { code: "ARS", rate: 1 },
      lines:             [lineWithMetal()],
      metalNames:        new Map([["oro-fino", "Oro Fino"]]),
    };
    const preview = buildSaleBalanceBreakdown(input);
    const confirm = buildSaleBalanceBreakdown(input);
    expect(JSON.stringify(preview)).toBe(JSON.stringify(confirm));
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// buildDocumentMonetaryComponentsFromTotals — display components doc-level
// ─────────────────────────────────────────────────────────────────────────────

describe("buildDocumentMonetaryComponentsFromTotals", () => {
  it("omite todos los componentes cuando los agregados son 0", () => {
    const out = buildDocumentMonetaryComponentsFromTotals({
      totals: {
        hechuraSaleSubtotal:     0,
        lineDiscountAmount:      0,
        channelAdjustmentAmount: 0,
        couponDiscountAmount:    0,
        globalDiscountAmount:    0,
        paymentAdjustmentAmount: 0,
        shippingAmount:          0,
        taxAmount:                0,
        roundingAdjustment:      0,
      },
    });
    expect(out).toEqual([]);
  });

  it("emite HECHURA positivo y group=HECHURA", () => {
    const out = buildDocumentMonetaryComponentsFromTotals({
      totals: { hechuraSaleSubtotal: 12345 },
    });
    expect(out).toHaveLength(1);
    expect(out[0]).toMatchObject({
      type: "HECHURA", group: "HECHURA", label: "Hechura", amount: 12345,
    });
  });

  it("convierte montos de descuento a NEGATIVO (cupón / global / lineDiscount)", () => {
    const out = buildDocumentMonetaryComponentsFromTotals({
      totals: {
        lineDiscountAmount:    500,
        couponDiscountAmount:  300,
        globalDiscountAmount:  200,
      },
    });
    const byType = Object.fromEntries(out.map((c) => [c.type, c]));
    expect(byType.DISCOUNT_QTY.amount).toBe(-500);
    expect(byType.DISCOUNT_QTY.group).toBe("DISCOUNT");
    expect(byType.COUPON.amount).toBe(-300);
    expect(byType.COUPON.group).toBe("COUPON");
    expect(byType.DISCOUNT_MANUAL.amount).toBe(-200);
    expect(byType.DISCOUNT_MANUAL.group).toBe("DISCOUNT");
  });

  it("preserva signo de channel / payment / rounding (pueden ser + o −)", () => {
    const out = buildDocumentMonetaryComponentsFromTotals({
      totals: {
        channelAdjustmentAmount: -1000, // descuento del canal
        paymentAdjustmentAmount:  +250, // recargo por forma de pago
        roundingAdjustment:       -0.50,
      },
    });
    const byType = Object.fromEntries(out.map((c) => [c.type, c]));
    expect(byType.CHANNEL.amount).toBe(-1000);
    expect(byType.PAYMENT.amount).toBe(250);
    expect(byType.ROUNDING_MONETARY.amount).toBe(-0.50);
    expect(byType.ROUNDING_MONETARY.group).toBe("ROUNDING");
  });

  it("usa labels custom y carga source cuando se pasan IDs", () => {
    const out = buildDocumentMonetaryComponentsFromTotals({
      totals: {
        channelAdjustmentAmount: 100,
        couponDiscountAmount:    50,
      },
      channelLabel:  "Tienda Online",
      channelSource: "chan-001",
      couponLabel:   "VERANO15",
      couponSource:  "coupon-xyz",
    });
    const byType = Object.fromEntries(out.map((c) => [c.type, c]));
    expect(byType.CHANNEL.label).toBe("Tienda Online");
    expect(byType.CHANNEL.source).toBe("chan-001");
    expect(byType.COUPON.label).toBe("VERANO15");
    expect(byType.COUPON.source).toBe("coupon-xyz");
  });

  it("emite TAX / SHIPPING positivos cuando aplican", () => {
    const out = buildDocumentMonetaryComponentsFromTotals({
      totals: {
        taxAmount:      2100,
        shippingAmount:  500,
      },
    });
    const byType = Object.fromEntries(out.map((c) => [c.type, c]));
    expect(byType.TAX.amount).toBe(2100);
    expect(byType.TAX.group).toBe("TAX");
    expect(byType.SHIPPING.amount).toBe(500);
    expect(byType.SHIPPING.group).toBe("SHIPPING");
  });

  it("orden estable de los componentes (mismo input → misma secuencia)", () => {
    const totals = {
      hechuraSaleSubtotal:     1000,
      lineDiscountAmount:      100,
      channelAdjustmentAmount: -50,
      couponDiscountAmount:    25,
      shippingAmount:          200,
      taxAmount:               210,
      roundingAdjustment:      -0.10,
    };
    const a = buildDocumentMonetaryComponentsFromTotals({ totals });
    const b = buildDocumentMonetaryComponentsFromTotals({ totals });
    expect(a.map((c) => c.type)).toEqual(b.map((c) => c.type));
    expect(JSON.stringify(a)).toBe(JSON.stringify(b));
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Integración: documentMonetaryComponents llegan al snapshot del breakdown
// ─────────────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────────────
// extractMetalItemsFromSteps — Opción A fix balance metals.
//
// Estos tests validan el SHAPE REAL que el motor de cost emite en runtime
// (steps `COST_LINES_METAL` post `enrichCostMetalSteps`). Antes de este fix,
// los tests de balance mockeaban manualmente `metalItems` con un shape que
// nunca aparece en producción → falso positivo. Acá usamos el shape de
// steps tal como sale del motor.
// ─────────────────────────────────────────────────────────────────────────────

/** Construye un step `COST_LINES_METAL` con el shape post-enrich (igual al
 *  que emite `pricing-engine.cost.ts` + `enrichCostMetalSteps`). */
function metalStep(over: Partial<{
  metalId: string | null;
  variantId: string | null;
  qty: string;            // raw del motor (Decimal.toString)
  gramsOriginal: number;  // post-enrich
  merma: number;
  purity: number;
  quotePrice: string;     // raw del motor
  status: string;
}> = {}) {
  return {
    key:    "COST_LINES_METAL" as const,
    label:  "Línea de metal",
    status: over.status ?? "ok",
    value:  0,
    meta: {
      variantId:     over.variantId     ?? "var-oro-18k",
      qty:           over.qty           ?? "1",
      merma:         over.merma         ?? 0,
      quotePrice:    over.quotePrice    ?? "100000",
      costLineId:    "cl-1",
      // post-enrichCostMetalSteps:
      metalId:       over.metalId       === null ? null : (over.metalId ?? "oro-fino"),
      variantName:   "Oro 18 Kilates",
      variantSku:    "AU18",
      metalName:     "Oro Fino",
      metalSymbol:   "Au",
      purity:        over.purity        ?? 0.75,
      gramsOriginal: over.gramsOriginal ?? 1,
    },
  };
}

describe("extractMetalItemsFromSteps — shape real del motor de cost", () => {
  it("mapea step COST_LINES_METAL post-enrich al shape SaleLineForBalance.metalItems", () => {
    const out = extractMetalItemsFromSteps([metalStep()]);
    expect(out).toHaveLength(1);
    expect(out[0]).toMatchObject({
      metalId:       "oro-fino",
      variantId:     "var-oro-18k",
      gramsOriginal: 1,
      purity:        0.75,
      unitValue:     100000, // quotePrice parseado
    });
    // gramsPure se omite — el builder lo calcula.
    expect(out[0].gramsPure).toBeUndefined();
  });

  it("ignora steps que NO son COST_LINES_METAL", () => {
    const out = extractMetalItemsFromSteps([
      { key: "COST_LINES_HECHURA", status: "ok", meta: { metalId: "oro-fino" } },
      metalStep({ metalId: "plata-925", variantId: "var-plata" }),
      { key: "COST_LINES_FINAL", status: "ok", meta: {} },
    ]);
    expect(out).toHaveLength(1);
    expect(out[0].metalId).toBe("plata-925");
  });

  it("ignora steps con status != 'ok'", () => {
    const out = extractMetalItemsFromSteps([
      metalStep({ status: "partial" }),
      metalStep({ status: "missing" }),
    ]);
    expect(out).toEqual([]);
  });

  it("descarta steps sin metalId (no se puede agrupar por padre)", () => {
    const out = extractMetalItemsFromSteps([metalStep({ metalId: null })]);
    expect(out).toEqual([]);
  });

  it("descarta steps con gramsOriginal <= 0", () => {
    const out = extractMetalItemsFromSteps([metalStep({ gramsOriginal: 0 })]);
    expect(out).toEqual([]);
  });

  it("fallback: si `gramsOriginal` no está, parsea `qty` (string del Decimal)", () => {
    // Step pre-enrich: solo qty como string, sin gramsOriginal numérico.
    const out = extractMetalItemsFromSteps([
      {
        key:    "COST_LINES_METAL",
        status: "ok",
        meta:   { metalId: "oro-fino", variantId: "v1", qty: "2.5", purity: 0.75, quotePrice: "100" },
      },
    ]);
    expect(out).toHaveLength(1);
    expect(out[0].gramsOriginal).toBe(2.5);
  });

  it("input null / vacío → []", () => {
    expect(extractMetalItemsFromSteps(null)).toEqual([]);
    expect(extractMetalItemsFromSteps(undefined)).toEqual([]);
    expect(extractMetalItemsFromSteps([])).toEqual([]);
  });

  it("varios steps del mismo padre en variantes distintas → todos pasan, el builder los consolida", () => {
    const out = extractMetalItemsFromSteps([
      metalStep({ variantId: "var-oro-18k", purity: 0.75, gramsOriginal: 1 }),
      metalStep({ variantId: "var-oro-14k", purity: 0.583, gramsOriginal: 2 }),
      metalStep({ variantId: "var-oro-24k", purity: 1,     gramsOriginal: 0.5 }),
    ]);
    expect(out).toHaveLength(3);
    expect(out.map((m) => m.variantId)).toEqual([
      "var-oro-18k", "var-oro-14k", "var-oro-24k",
    ]);
    // Todos comparten metalId padre — el builder los acumula.
    expect(out.every((m) => m.metalId === "oro-fino")).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Integración end-to-end con shape real: steps → extract → buildBalance
//
// Esto reemplaza al test "preview ↔ confirm parity" que basaba la paridad
// en mocks de `metalItems` ya construidos (falso positivo). Acá partimos del
// shape STEPS que el motor REALMENTE emite y confirmamos que el flujo arma
// el balance breakdown como espera el frontend.
// ─────────────────────────────────────────────────────────────────────────────

describe("Integración: steps → extractMetalItemsFromSteps → buildSaleBalanceBreakdown", () => {
  it("BREAKDOWN: línea con 1 metal padre + 2 variantes → 1 entrada consolidada", () => {
    const stepsLine1 = [
      metalStep({ variantId: "var-oro-18k", purity: 0.75,  gramsOriginal: 1 }),
      metalStep({ variantId: "var-oro-14k", purity: 0.583, gramsOriginal: 2 }),
    ];
    const metalItems = extractMetalItemsFromSteps(stepsLine1);
    const out = buildSaleBalanceBreakdown({
      mode:              "BREAKDOWN",
      documentTotal:     100000,
      documentTotalBase: 100000,
      currency:          { code: "ARS", rate: 1 },
      lines: [{
        lineId:   "L-1",
        quantity: 1,
        metalItems,
      }],
      metalNames: new Map([["oro-fino", "Oro Fino"]]),
    });
    expect(out.metals).toHaveLength(1);
    expect(out.metals[0].metalParentId).toBe("oro-fino");
    expect(out.metals[0].gramsOriginal).toBeCloseTo(3, 4);
    // gramsPure consolidado: 1×0.75 + 2×0.583 = 1.916
    expect(out.metals[0].gramsPure).toBeCloseTo(0.75 + 1.166, 3);
  });

  it("BREAKDOWN multi-línea: distintos padres → distintas entradas; qty>1 multiplica", () => {
    // Línea 1 — anillo de oro fino qty=1
    const stepsL1 = [metalStep({ variantId: "v18", gramsOriginal: 1, purity: 0.75 })];
    // Línea 2 — anillos de plata qty=3
    const stepsL2 = [metalStep({
      metalId:   "plata-925",
      variantId: "vplata",
      gramsOriginal: 1.32,
      purity: 0.925,
    })];
    const out = buildSaleBalanceBreakdown({
      mode:              "BREAKDOWN",
      documentTotal:     50000,
      documentTotalBase: 50000,
      currency:          { code: "ARS", rate: 1 },
      lines: [
        { lineId: "L-1", quantity: 1, metalItems: extractMetalItemsFromSteps(stepsL1) },
        { lineId: "L-2", quantity: 3, metalItems: extractMetalItemsFromSteps(stepsL2) },
      ],
      metalNames: new Map([
        ["oro-fino",  "Oro Fino"],
        ["plata-925", "Plata"],
      ]),
    });
    expect(out.metals).toHaveLength(2);
    const oro   = out.metals.find((m) => m.metalParentId === "oro-fino")!;
    const plata = out.metals.find((m) => m.metalParentId === "plata-925")!;
    expect(oro.gramsOriginal).toBeCloseTo(1, 4);
    expect(plata.gramsOriginal).toBeCloseTo(1.32 * 3, 4); // qty=3 aplicado
  });

  it("Steps sin metalId → metals = [] (no rompe, no inventa)", () => {
    // Step con variantId pero sin metalId enriquecido (caso edge: variante
    // huérfana o enrich falló). El extractor descarta; el builder no recibe
    // nada → metals queda vacío en lugar de explotar.
    const stepsHuerfanos = [metalStep({ metalId: null })];
    const out = buildSaleBalanceBreakdown({
      mode:              "BREAKDOWN",
      documentTotal:     1000,
      documentTotalBase: 1000,
      currency:          { code: "ARS", rate: 1 },
      lines: [{
        lineId:   "L-1",
        quantity: 1,
        metalItems: extractMetalItemsFromSteps(stepsHuerfanos),
      }],
    });
    expect(out.metals).toEqual([]);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// R11.4 — Escenarios integrales (mapeo directo al pedido del operador)
// ─────────────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────────────
// Consolidado por metal padre — documento con varias líneas, mismo padre
// repetido en variantes/lineas distintas, qty > 1.
// ─────────────────────────────────────────────────────────────────────────────

describe("buildSaleBalanceBreakdown — consolidado multi-línea por metal padre", () => {
  it("3 líneas con Oro Fino (variantes distintas) + 1 línea con Plata → 2 entradas (una por padre)", () => {
    // Documento realista del ejemplo del usuario:
    //   Línea 1: Anillo Oro 18K, qty=1 → 1g de oro fino @ 0.75
    //   Línea 2: Anillo Oro 14K, qty=1 → 2g de oro fino @ 0.583
    //   Línea 3: Collar Oro 18K, qty=1 → 1.2g de oro fino @ 0.75
    //   Línea 4: Aros Plata 925, qty=2 → 1.32g/u × 2 = 2.64g de plata @ 0.925
    // Total esperado:
    //   Oro Fino → 4.20 g originales, 2.766 g puros
    //   Plata     → 2.64 g originales, 2.442 g puros
    const out = buildSaleBalanceBreakdown({
      mode:              "BREAKDOWN",
      documentTotal:     100000,
      documentTotalBase: 100000,
      currency:          { code: "ARS", rate: 1 },
      lines: [
        {
          lineId:   "L-1",
          quantity: 1,
          metalItems: [{
            metalId: "oro-fino", variantId: "oro-18k-a",
            gramsOriginal: 1, purity: 0.75, gramsPure: 0.75, unitValue: 100,
          }],
        },
        {
          lineId:   "L-2",
          quantity: 1,
          metalItems: [{
            metalId: "oro-fino", variantId: "oro-14k",
            gramsOriginal: 2, purity: 0.583, gramsPure: 1.166, unitValue: 100,
          }],
        },
        {
          lineId:   "L-3",
          quantity: 1,
          metalItems: [{
            metalId: "oro-fino", variantId: "oro-18k-b",
            gramsOriginal: 1.2, purity: 0.75, gramsPure: 0.90, unitValue: 100,
          }],
        },
        {
          lineId:   "L-4",
          quantity: 2,  // ← qty > 1: 1.32g/u × 2 = 2.64g
          metalItems: [{
            metalId: "plata-925", variantId: "plata-925",
            gramsOriginal: 1.32, purity: 0.925, gramsPure: 1.221, unitValue: 5,
          }],
        },
      ],
      metalNames: new Map([
        ["oro-fino",  "Oro Fino"],
        ["plata-925", "Plata"],
      ]),
    });
    // Solo DOS entradas — una por metal padre, no por variante/línea.
    expect(out.metals).toHaveLength(2);
    const oro   = out.metals.find((m) => m.metalParentId === "oro-fino");
    const plata = out.metals.find((m) => m.metalParentId === "plata-925");
    // Oro Fino consolidado.
    expect(oro).toBeDefined();
    expect(oro!.gramsOriginal).toBeCloseTo(4.20, 4);
    expect(oro!.gramsPure).toBeCloseTo(0.75 + 1.166 + 0.90, 3);
    // Plata: SE MULTIPLICA POR QTY (1.32 × 2 = 2.64).
    expect(plata).toBeDefined();
    expect(plata!.gramsOriginal).toBeCloseTo(2.64, 4);
    expect(plata!.gramsPure).toBeCloseTo(1.221 * 2, 3);
    // Cada padre lista todas las líneas de origen para auditoría.
    expect(oro!.sourceLineIds).toEqual(expect.arrayContaining(["L-1", "L-2", "L-3"]));
    expect(plata!.sourceLineIds).toEqual(["L-4"]);
  });

  it("mismo padre en variantes distintas dentro de UNA línea → consolida en una entrada (variants[] preserva detalle)", () => {
    // Caso edge: la misma línea trae 2 items metálicos del MISMO padre
    // (ej. artículo bimetálico Oro 18K + Oro 24K).
    const out = buildSaleBalanceBreakdown({
      mode:              "BREAKDOWN",
      documentTotal:     50000,
      documentTotalBase: 50000,
      currency:          { code: "ARS", rate: 1 },
      lines: [{
        lineId:   "L-1",
        quantity: 1,
        metalItems: [
          { metalId: "oro-fino", variantId: "oro-18k", gramsOriginal: 1, purity: 0.75, gramsPure: 0.75, unitValue: 100 },
          { metalId: "oro-fino", variantId: "oro-24k", gramsOriginal: 0.5, purity: 1,    gramsPure: 0.5,  unitValue: 100 },
        ],
      }],
      metalNames: new Map([["oro-fino", "Oro Fino"]]),
    });
    expect(out.metals).toHaveLength(1);
    expect(out.metals[0].metalParentId).toBe("oro-fino");
    expect(out.metals[0].gramsOriginal).toBeCloseTo(1.5, 4);
    expect(out.metals[0].gramsPure).toBeCloseTo(1.25, 4);
    // variants[] preserva el detalle para drill-down futuro.
    expect(out.metals[0].variants).toBeDefined();
    expect(out.metals[0].variants!.length).toBeGreaterThanOrEqual(2);
  });

  it("paridad: el ROUNDING_MONETARY queda en monetary.components — NO en metals", () => {
    // Verifica que el redondeo nunca se cuela al bloque metales (R11.3:
    // gramos físicos invariantes; el redondeo es siempre monetario).
    const components = buildDocumentMonetaryComponentsFromTotals({
      totals: {
        hechuraSaleSubtotal: 1000,
        roundingAdjustment:  -0.05,
      },
    });
    const out = buildSaleBalanceBreakdown({
      mode:              "BREAKDOWN",
      documentTotal:     999.95,
      documentTotalBase: 999.95,
      currency:          { code: "ARS", rate: 1 },
      lines:             [lineWithMetal()],
      metalNames:        new Map([["oro-fino", "Oro Fino"]]),
      documentMonetaryComponents: components,
    });
    expect(out.metals).toHaveLength(1);
    const rounding = out.monetaryBalance.components?.find(
      (c) => c.type === "ROUNDING_MONETARY",
    );
    expect(rounding).toBeDefined();
    expect(rounding!.amount).toBeCloseTo(-0.05, 4);
    // El metal NO incorpora el ajuste de redondeo.
    expect(out.metals[0].gramsPure).toBeCloseTo(0.75, 6);
  });
});

describe("R11.4 — escenarios integrales de resolución", () => {
  it("[override] override manual del documento GANA sobre cliente/lista/tenant", () => {
    const r = resolveSaleBalanceMode({
      documentOverride:        "BREAKDOWN",
      entityBalanceMode:       "UNIFIED",
      entityBalanceTypeLegacy: "UNIFIED",
      priceListDefault:        "UNIFIED",
      tenantDefault:           "UNIFIED",
    });
    expect(r.mode).toBe("BREAKDOWN");
    expect(r.source).toBe("DOCUMENT_OVERRIDE");
  });

  it("[cliente BREAKDOWN] obliga BREAKDOWN sin override del documento", () => {
    const r = resolveSaleBalanceMode({
      documentOverride:  null,
      entityBalanceMode: "BREAKDOWN",
      priceListDefault:  "UNIFIED",
      tenantDefault:     "UNIFIED",
    });
    expect(r.mode).toBe("BREAKDOWN");
    expect(r.source).toBe("ENTITY_DEFAULT");
  });

  it("[cliente UNIFIED] queda UNIFIED → el frontend lo deja ocultable", () => {
    const r = resolveSaleBalanceMode({
      documentOverride:  null,
      entityBalanceMode: "UNIFIED",
      priceListDefault:  "BREAKDOWN",
      tenantDefault:     "BREAKDOWN",
    });
    expect(r.mode).toBe("UNIFIED");
    expect(r.source).toBe("ENTITY_DEFAULT");
  });

  it("[lista BREAKDOWN sin cliente] aplica el default de la lista", () => {
    const r = resolveSaleBalanceMode({
      documentOverride:  null,
      entityBalanceMode: null,
      priceListDefault:  "BREAKDOWN",
      tenantDefault:     "UNIFIED",
    });
    expect(r.mode).toBe("BREAKDOWN");
    expect(r.source).toBe("PRICELIST_DEFAULT");
  });

  it("[tenant default] aplica si cliente/lista no definen modo", () => {
    const r = resolveSaleBalanceMode({
      documentOverride:  null,
      entityBalanceMode: null,
      priceListDefault:  null,
      tenantDefault:     "BREAKDOWN",
    });
    expect(r.mode).toBe("BREAKDOWN");
    expect(r.source).toBe("TENANT_DEFAULT");
  });

  it("[fallback UNIFIED] cuando ningún nivel define modo", () => {
    const r = resolveSaleBalanceMode({});
    expect(r.mode).toBe("UNIFIED");
    expect(r.source).toBe("FALLBACK_UNIFIED");
  });

  it("[back-compat balanceType] cliente histórico solo con balanceType legacy", () => {
    const r = resolveSaleBalanceMode({
      documentOverride:        null,
      entityBalanceMode:       null,           // nuevo campo aún null
      entityBalanceTypeLegacy: "BREAKDOWN",    // solo legacy poblado
      priceListDefault:        "UNIFIED",
      tenantDefault:           "UNIFIED",
    });
    expect(r.mode).toBe("BREAKDOWN");
    expect(r.source).toBe("ENTITY_DEFAULT");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Paridad preview ↔ confirm sobre components[]
// ─────────────────────────────────────────────────────────────────────────────

/* Confirm hoy pasa `paymentAdjustmentAmount=0`, `shippingAmount=0`,
 * `globalDiscountAmount=0` al motor (TODOs documentados en sales.service.ts).
 * Por eso los components que SÍ aparecen en ambos paths son el subset:
 *   HECHURA / DISCOUNT_QTY / CHANNEL / COUPON / TAX / ROUNDING.
 *
 * Este test ejercita el helper que ambos paths usan con los mismos campos
 * "estables" y verifica que los components son byte-a-byte idénticos.
 * PAYMENT / SHIPPING / DISCOUNT_MANUAL quedan FUERA del scope por TODO
 * existente del backend (no introducido por esta fase). */

describe("preview ↔ confirm — paridad de components[] (subset estable)", () => {
  it("mismos campos estables → mismos components (byte-a-byte)", () => {
    const stableTotals = {
      hechuraSaleSubtotal:     5000,
      lineDiscountAmount:      120,
      channelAdjustmentAmount: -300,
      couponDiscountAmount:    150,
      taxAmount:               910,
      roundingAdjustment:      -0.05,
    };
    const meta = {
      channelLabel:  "Tienda Física",
      channelSource: "channel-001",
      couponLabel:   "VERANO15",
      couponSource:  "coupon-abc",
    };
    const previewLike = buildDocumentMonetaryComponentsFromTotals({
      totals: {
        ...stableTotals,
        // Campos NO-paritarios (preview puede tenerlos, confirm hoy 0).
        paymentAdjustmentAmount: 500,
        shippingAmount:           250,
        globalDiscountAmount:     100,
      },
      ...meta,
    });
    const confirmLike = buildDocumentMonetaryComponentsFromTotals({
      totals: {
        ...stableTotals,
        // Como hace confirmSale hoy (TODOs Fase 3/4).
        paymentAdjustmentAmount: 0,
        shippingAmount:          0,
        globalDiscountAmount:    0,
      },
      ...meta,
    });
    // Filtramos a los tipos que ambos paths emiten consistentemente.
    const STABLE_TYPES = new Set([
      "HECHURA",
      "DISCOUNT_QTY",
      "CHANNEL",
      "COUPON",
      "TAX",
      "ROUNDING_MONETARY",
    ]);
    const previewStable = previewLike.filter((c) => STABLE_TYPES.has(c.type));
    const confirmStable = confirmLike.filter((c) => STABLE_TYPES.has(c.type));
    expect(JSON.stringify(previewStable)).toBe(JSON.stringify(confirmStable));
  });

  it("balanceMode y balanceModeSource son idénticos para los mismos inputs", () => {
    // Misma resolución comercial → mismo modo + source en ambos paths.
    const commercial = {
      documentOverride:        null,
      entityBalanceMode:       "BREAKDOWN" as const,
      entityBalanceTypeLegacy: null,
      priceListDefault:        null,
      tenantDefault:           null,
    };
    const previewR = resolveSaleBalanceMode(commercial);
    const confirmR = resolveSaleBalanceMode(commercial);
    expect(previewR).toEqual(confirmR);
    expect(previewR.mode).toBe("BREAKDOWN");
    expect(previewR.source).toBe("ENTITY_DEFAULT");
  });

  it("balanceBreakdown.metals y monetary.amount son idénticos para mismas líneas + total", () => {
    // Idem que el test "parity preview ↔ confirm" existente, pero con
    // documentMonetaryComponents incluidos para asegurar paridad end-to-end.
    const components = buildDocumentMonetaryComponentsFromTotals({
      totals: {
        hechuraSaleSubtotal: 25000,
        taxAmount:            5250,
      },
    });
    const input = {
      mode:              "BREAKDOWN" as const,
      documentTotal:     105250,
      documentTotalBase: 105250,
      currency:          { code: "ARS", rate: 1 },
      lines:             [lineWithMetal()],
      metalNames:        new Map([["oro-fino", "Oro Fino"]]),
      documentMonetaryComponents: components,
    };
    const preview = buildSaleBalanceBreakdown(input);
    const confirm = buildSaleBalanceBreakdown(input);
    expect(JSON.stringify(preview)).toBe(JSON.stringify(confirm));
  });
});

describe("buildSaleBalanceBreakdown — propaga documentMonetaryComponents", () => {
  it("UNIFIED → components[] presentes en monetaryBalance.components", () => {
    const components = buildDocumentMonetaryComponentsFromTotals({
      totals: { hechuraSaleSubtotal: 1000, taxAmount: 210 },
    });
    const out = buildSaleBalanceBreakdown({
      mode:              "UNIFIED",
      documentTotal:     1210,
      documentTotalBase: 1210,
      currency:          { code: "ARS", rate: 1 },
      lines:             [],
      documentMonetaryComponents: components,
    });
    expect(out.monetaryBalance.components).toBeDefined();
    expect(out.monetaryBalance.components).toHaveLength(2);
    expect(out.monetaryBalance.components!.map((c) => c.type).sort())
      .toEqual(["HECHURA", "TAX"]);
  });

  it("BREAKDOWN → components[] presentes y metals agrupados", () => {
    const components = buildDocumentMonetaryComponentsFromTotals({
      totals: { hechuraSaleSubtotal: 25000, taxAmount: 21000 },
    });
    const out = buildSaleBalanceBreakdown({
      mode:              "BREAKDOWN",
      documentTotal:     121000,
      documentTotalBase: 121000,
      currency:          { code: "ARS", rate: 1 },
      lines:             [lineWithMetal()],
      metalNames:        new Map([["oro-fino", "Oro Fino"]]),
      documentMonetaryComponents: components,
    });
    expect(out.metals).toHaveLength(1);
    expect(out.monetaryBalance.components).toHaveLength(2);
  });

  it("components[] omitidos cuando el array es vacío (passthrough)", () => {
    const out = buildSaleBalanceBreakdown({
      mode:              "UNIFIED",
      documentTotal:     1000,
      documentTotalBase: 1000,
      currency:          { code: "ARS", rate: 1 },
      lines:             [],
      documentMonetaryComponents: [],
    });
    expect(out.monetaryBalance.components).toBeUndefined();
  });
});
