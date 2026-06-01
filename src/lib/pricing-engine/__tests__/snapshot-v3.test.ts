// src/lib/pricing-engine/__tests__/snapshot-v3.test.ts
// =============================================================================
// T53 — Tests del Snapshot v3 (Balance Mode) + helper `readBalanceBreakdown`.
// Sub-fase 3B.3.
//
// Congelan el contrato:
//   · buildDocumentPricingSnapshot emite version=3 y popula balanceMode /
//     balanceModeSource / balanceBreakdown.
//   · Defaults seguros para callers que NO pasan balanceMode: UNIFIED
//     implícito con monetary.amount = totals.total.
//   · readBalanceBreakdown(snapshot) tolera v2, v3, parciales, inválidos.
//   · Snapshots históricos v2 NUNCA crean metals → quedan UNIFIED implícito.
//   · La función nunca tira y nunca muta su input.
// =============================================================================

import { describe, it, expect } from "vitest";
import {
  buildDocumentPricingSnapshot,
  DOCUMENT_SNAPSHOT_VERSION,
  type BuildSnapshotInput,
  type DocumentPricingSnapshot,
} from "../pricing-engine.document.js";
import {
  readBalanceBreakdown,
} from "../pricing-engine.balance.js";
import type {
  DocumentBalanceBreakdown,
} from "../pricing-engine.types.js";

// ── Fixture mínimo del snapshot input ────────────────────────────────────────
// Mantiene el shape exigido por `BuildSnapshotInput` con los menores datos
// posibles. Casteamos `as BuildSnapshotInput` para no acoplarnos a campos
// internos de `PricingLineSnapshot` que no son relevantes para este test
// — el builder no calcula nada, solo serializa.
function baseInput(over: Partial<BuildSnapshotInput> = {}): BuildSnapshotInput {
  return {
    currency: {
      id:               "cur-ars",
      currencyCode:     "ARS",
      symbol:           "$",
      currencyRate:     1,
      baseCurrencyCode: "ARS",
    },
    issuer: {
      jewelryId:    "j-1",
      name:         "Joyería Test",
      cuit:         "20-12345678-9",
      ivaCondition: "RI",
    },
    counterparty:     null,
    channel:          null,
    coupon:           null,
    promotion:        null,
    quantityDiscount: null,
    paymentMethod:    null,
    rounding: {
      source: "NONE", appliedOn: "NONE", mode: "NONE",
      direction: "NONE", adjustment: 0,
    },
    taxBreakdown: [],
    totals: {
      subtotal:               100000,
      channelAmount:          0,
      couponAmount:           0,
      quantityDiscountAmount: 0,
      promotionAmount:        0,
      paymentSurcharge:       0,
      discountAmount:         0,
      taxAmount:              0,
      roundingAdjustment:     0,
      total:                  100000,
      totalBase:              100000,
    },
    cost: { totalCost: null, totalMargin: null, marginPercent: null, costPartial: false },
    lines: [],
    ...over,
  } as BuildSnapshotInput;
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. version === 3
// ─────────────────────────────────────────────────────────────────────────────

describe("buildDocumentPricingSnapshot — version y campos v3", () => {
  it("emite version === 3 (Balance Mode)", () => {
    const snap = buildDocumentPricingSnapshot(baseInput());
    expect(snap.version).toBe(3);
    expect(DOCUMENT_SNAPSHOT_VERSION).toBe(3);
  });

  it("snapshot v3 trae balanceMode, balanceModeSource y balanceBreakdown", () => {
    const snap = buildDocumentPricingSnapshot(baseInput());
    expect(snap.balanceMode).toBeDefined();
    expect(snap.balanceModeSource).toBeDefined();
    expect(snap.balanceBreakdown).toBeDefined();
    expect(snap.balanceBreakdown.metals).toEqual([]);
    expect(snap.balanceBreakdown.monetaryBalance).toBeDefined();
  });

  it("default UNIFIED + FALLBACK_UNIFIED cuando el caller no provee Balance Mode", () => {
    const snap = buildDocumentPricingSnapshot(baseInput());
    expect(snap.balanceMode).toBe("UNIFIED");
    expect(snap.balanceModeSource).toBe("FALLBACK_UNIFIED");
  });

  it("monetary.amount default = totals.total cuando no se provee balanceBreakdown", () => {
    const snap = buildDocumentPricingSnapshot(
      baseInput({
        totals: { ...baseInput().totals, total: 250000, totalBase: 250000 },
      }),
    );
    expect(snap.balanceBreakdown.monetaryBalance.amount).toBe(250000);
    expect(snap.balanceBreakdown.monetaryBalance.amountBase).toBe(250000);
    expect(snap.balanceBreakdown.monetaryBalance.currencyCode).toBe("ARS");
    expect(snap.balanceBreakdown.monetaryBalance.currencyRate).toBe(1);
  });

  it("passthrough de balanceMode/Source/Breakdown explícitos", () => {
    const customBreakdown: DocumentBalanceBreakdown = {
      metals: [{
        metalParentId:    "oro-fino",
        metalParentName:  "Oro Fino",
        gramsOriginal:    1,
        purity:           0.75,
        gramsPure:        0.75,
        quotePriceSnapshot:    100000,
        valuationMonetary:     75000,
        valuationCurrencyCode: "ARS",
        sourceLineIds:    ["L-1"],
      }],
      monetaryBalance: {
        amount:       25000,
        currencyCode: "ARS",
        currencyRate: 1,
        amountBase:   25000,
      },
    };
    const snap = buildDocumentPricingSnapshot(
      baseInput({
        balanceMode:       "BREAKDOWN",
        balanceModeSource: "ENTITY_DEFAULT",
        balanceBreakdown:  customBreakdown,
      }),
    );
    expect(snap.balanceMode).toBe("BREAKDOWN");
    expect(snap.balanceModeSource).toBe("ENTITY_DEFAULT");
    expect(snap.balanceBreakdown).toEqual(customBreakdown);
  });

  it("sourceDocument opcional — sólo aparece cuando se provee", () => {
    const snapSin = buildDocumentPricingSnapshot(baseInput());
    expect(snapSin.sourceDocument).toBeUndefined();
    const snapCon = buildDocumentPricingSnapshot(
      baseInput({ sourceDocument: { kind: "SALE", id: "sale-1", number: "0001-00000001" } }),
    );
    expect(snapCon.sourceDocument).toEqual({
      kind: "SALE", id: "sale-1", number: "0001-00000001",
    });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. readBalanceBreakdown — v3 con breakdown nativo
// ─────────────────────────────────────────────────────────────────────────────

describe("readBalanceBreakdown — v3 nativo", () => {
  it("devuelve balanceBreakdown REAL en snapshot v3 + source SNAPSHOT_V3", () => {
    const snap = buildDocumentPricingSnapshot(
      baseInput({
        balanceMode:       "BREAKDOWN",
        balanceModeSource: "TENANT_DEFAULT",
        balanceBreakdown: {
          metals: [{
            metalParentId:    "oro-fino",
            metalParentName:  "Oro Fino",
            gramsOriginal:    2,
            purity:           0.75,
            gramsPure:        1.5,
            quotePriceSnapshot:    100000,
            valuationMonetary:     150000,
            valuationCurrencyCode: "ARS",
            sourceLineIds:    ["L-1"],
          }],
          monetaryBalance: {
            amount: 50000, currencyCode: "ARS", currencyRate: 1, amountBase: 50000,
          },
        },
      }),
    );
    const r = readBalanceBreakdown(snap);
    expect(r.source).toBe("SNAPSHOT_V3");
    expect(r.breakdown.metals).toHaveLength(1);
    expect(r.breakdown.metals[0].gramsPure).toBe(1.5);
    expect(r.breakdown.monetaryBalance.amount).toBe(50000);
  });

  it("v3 UNIFIED mantiene metals=[] y monetary.amount del balanceBreakdown", () => {
    const snap = buildDocumentPricingSnapshot(
      baseInput({
        balanceMode:       "UNIFIED",
        balanceModeSource: "DOCUMENT_OVERRIDE",
        balanceBreakdown: {
          metals: [],
          monetaryBalance: {
            amount: 300000, currencyCode: "USD", currencyRate: 1000, amountBase: 300000000,
          },
        },
      }),
    );
    const r = readBalanceBreakdown(snap);
    expect(r.source).toBe("SNAPSHOT_V3");
    expect(r.breakdown.metals).toEqual([]);
    expect(r.breakdown.monetaryBalance.amount).toBe(300000);
    expect(r.breakdown.monetaryBalance.currencyCode).toBe("USD");
    expect(r.breakdown.monetaryBalance.currencyRate).toBe(1000);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. readBalanceBreakdown — back-compat v2/legacy
// ─────────────────────────────────────────────────────────────────────────────

describe("readBalanceBreakdown — back-compat v2/legacy", () => {
  it("snapshot v2 sin balanceBreakdown → UNIFIED implícito + source LEGACY_UNIFIED", () => {
    // Simulamos el shape v2 histórico SIN los campos de Balance Mode.
    const snapV2 = {
      version: 2,
      currency: { currencyCode: "ARS", currencyRate: 1, baseCurrencyCode: "ARS" },
      totals:   { total: 175000, totalBase: 175000 },
    };
    const r = readBalanceBreakdown(snapV2);
    expect(r.source).toBe("LEGACY_UNIFIED");
    expect(r.breakdown.metals).toEqual([]);
    expect(r.breakdown.monetaryBalance.amount).toBe(175000);
    expect(r.breakdown.monetaryBalance.amountBase).toBe(175000);
    expect(r.breakdown.monetaryBalance.currencyCode).toBe("ARS");
    expect(r.breakdown.monetaryBalance.currencyRate).toBe(1);
  });

  it("snapshot SIN version → tratado como legacy + LEGACY_UNIFIED", () => {
    const snapNoVer = {
      currency: { currencyCode: "ARS", currencyRate: 1 },
      totals:   { total: 90000, totalBase: 90000 },
    };
    const r = readBalanceBreakdown(snapNoVer);
    expect(r.source).toBe("LEGACY_UNIFIED");
    expect(r.breakdown.monetaryBalance.amount).toBe(90000);
  });

  it("v2 con campos parciales (sin totalBase) → totalBase = total (fallback)", () => {
    const snapPartial = {
      version:  2,
      currency: { currencyCode: "ARS", currencyRate: 1 },
      totals:   { total: 60000 },
    };
    const r = readBalanceBreakdown(snapPartial);
    expect(r.source).toBe("LEGACY_UNIFIED");
    expect(r.breakdown.monetaryBalance.amount).toBe(60000);
    expect(r.breakdown.monetaryBalance.amountBase).toBe(60000);
  });

  it("v2 con currency en USD rate 1000 — passthrough de currency", () => {
    const snapUsd = {
      version:  2,
      currency: { currencyCode: "USD", currencyRate: 1000 },
      totals:   { total: 100, totalBase: 100000 },
    };
    const r = readBalanceBreakdown(snapUsd);
    expect(r.source).toBe("LEGACY_UNIFIED");
    expect(r.breakdown.monetaryBalance.amount).toBe(100);
    expect(r.breakdown.monetaryBalance.amountBase).toBe(100000);
    expect(r.breakdown.monetaryBalance.currencyCode).toBe("USD");
    expect(r.breakdown.monetaryBalance.currencyRate).toBe(1000);
  });

  it("v2 NUNCA crea metals: aunque el snapshot tenga metalHechuraBreakdown, se ignora", () => {
    // Históricos pueden traer detalles de metal a nivel línea, pero el helper
    // tolerante NO los reconstruye en balanceBreakdown — quedan UNIFIED.
    const snapV2WithLineMetal = {
      version:  2,
      currency: { currencyCode: "ARS", currencyRate: 1 },
      totals:   { total: 100000, totalBase: 100000 },
      lines: [{
        metalHechuraBreakdown: {
          metalCost: 50000, metalSale: 75000,
          hechuraCost: 10000, hechuraSale: 25000,
          metalGramsBase: 1,
        },
      }],
    };
    const r = readBalanceBreakdown(snapV2WithLineMetal);
    expect(r.source).toBe("LEGACY_UNIFIED");
    expect(r.breakdown.metals).toEqual([]);
    expect(r.breakdown.monetaryBalance.amount).toBe(100000);
  });

  it("v3 con balanceBreakdown inválido (sin monetaryBalance) → fallback LEGACY_UNIFIED", () => {
    const snapBroken = {
      version: 3,
      balanceBreakdown: { metals: [] /* falta monetaryBalance */ },
      currency: { currencyCode: "ARS", currencyRate: 1 },
      totals:   { total: 42, totalBase: 42 },
    };
    const r = readBalanceBreakdown(snapBroken);
    expect(r.source).toBe("LEGACY_UNIFIED");
    expect(r.breakdown.monetaryBalance.amount).toBe(42);
  });

  it("v3 con balanceBreakdown.metals no-array → fallback LEGACY_UNIFIED", () => {
    const snapBroken = {
      version: 3,
      balanceBreakdown: { metals: "oops", monetaryBalance: { amount: 1 } } as any,
      currency: { currencyCode: "ARS", currencyRate: 1 },
      totals:   { total: 7, totalBase: 7 },
    };
    const r = readBalanceBreakdown(snapBroken);
    expect(r.source).toBe("LEGACY_UNIFIED");
    expect(r.breakdown.monetaryBalance.amount).toBe(7);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 4. readBalanceBreakdown — inputs inválidos / edge cases
// ─────────────────────────────────────────────────────────────────────────────

describe("readBalanceBreakdown — inputs inválidos", () => {
  it("null → UNIFIED vacío + source INVALID", () => {
    const r = readBalanceBreakdown(null);
    expect(r.source).toBe("INVALID");
    expect(r.breakdown.metals).toEqual([]);
    expect(r.breakdown.monetaryBalance.amount).toBe(0);
    expect(r.breakdown.monetaryBalance.currencyCode).toBe("");
  });

  it("undefined → UNIFIED vacío + source INVALID", () => {
    const r = readBalanceBreakdown(undefined);
    expect(r.source).toBe("INVALID");
    expect(r.breakdown.metals).toEqual([]);
  });

  it("string / number → UNIFIED vacío + source INVALID", () => {
    expect(readBalanceBreakdown("foo").source).toBe("INVALID");
    expect(readBalanceBreakdown(123).source).toBe("INVALID");
    expect(readBalanceBreakdown(true).source).toBe("INVALID");
  });

  it("objeto vacío {} → LEGACY_UNIFIED con amount=0", () => {
    // No es inválido en el sentido estricto (es un objeto), pero no trae
    // ningún dato útil. Cae a LEGACY_UNIFIED con valores por defecto.
    const r = readBalanceBreakdown({});
    expect(r.source).toBe("LEGACY_UNIFIED");
    expect(r.breakdown.monetaryBalance.amount).toBe(0);
    expect(r.breakdown.monetaryBalance.currencyCode).toBe("");
  });

  it("totals con valores NaN/Infinity → fallback a 0 sin romper", () => {
    const snapWeird = {
      version:  2,
      currency: { currencyCode: "ARS", currencyRate: Number.NaN },
      totals:   { total: Number.NaN, totalBase: Number.POSITIVE_INFINITY },
    };
    const r = readBalanceBreakdown(snapWeird);
    expect(r.source).toBe("LEGACY_UNIFIED");
    expect(r.breakdown.monetaryBalance.amount).toBe(0);
    expect(r.breakdown.monetaryBalance.currencyRate).toBe(1);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 5. Invariantes
// ─────────────────────────────────────────────────────────────────────────────

describe("readBalanceBreakdown — invariantes", () => {
  it("no muta el snapshot original", () => {
    const snap = buildDocumentPricingSnapshot(baseInput());
    const snapshotStr = JSON.stringify(snap);
    readBalanceBreakdown(snap);
    expect(JSON.stringify(snap)).toBe(snapshotStr);
  });

  it("determinístico — mismo input produce mismo output", () => {
    const snap: DocumentPricingSnapshot = buildDocumentPricingSnapshot(
      baseInput({
        balanceMode: "BREAKDOWN",
        balanceBreakdown: {
          metals: [],
          monetaryBalance: {
            amount: 100, currencyCode: "ARS", currencyRate: 1, amountBase: 100,
          },
        },
      }),
    );
    const r1 = readBalanceBreakdown(snap);
    const r2 = readBalanceBreakdown(snap);
    expect(JSON.stringify(r1)).toBe(JSON.stringify(r2));
  });

  it("nunca tira con inputs hostiles", () => {
    const hostiles: unknown[] = [
      null, undefined, 0, "", false, [], {},
      { version: "tres" },
      { version: 3, balanceBreakdown: null },
      { totals: null, currency: null },
    ];
    for (const h of hostiles) {
      expect(() => readBalanceBreakdown(h)).not.toThrow();
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 6. Round-trip: build → read
// ─────────────────────────────────────────────────────────────────────────────

describe("Round-trip build → read", () => {
  it("snapshot recién construido se lee de vuelta sin pérdida (UNIFIED default)", () => {
    const snap = buildDocumentPricingSnapshot(
      baseInput({
        totals: { ...baseInput().totals, total: 99999, totalBase: 99999 },
      }),
    );
    const r = readBalanceBreakdown(snap);
    expect(r.source).toBe("SNAPSHOT_V3");
    expect(r.breakdown.monetaryBalance.amount).toBe(99999);
    expect(r.breakdown.metals).toEqual([]);
  });

  it("snapshot BREAKDOWN se lee exactamente igual", () => {
    const breakdown: DocumentBalanceBreakdown = {
      metals: [
        {
          metalParentId: "oro-fino",  metalParentName: "Oro Fino",
          gramsOriginal: 3,           purity: 0.86,
          gramsPure: 2.58,
          quotePriceSnapshot: 100000, valuationMonetary: 258000,
          valuationCurrencyCode: "ARS",
          sourceLineIds: ["L-1"],
        },
      ],
      monetaryBalance: {
        amount: 42000, currencyCode: "ARS", currencyRate: 1, amountBase: 42000,
      },
    };
    const snap = buildDocumentPricingSnapshot(
      baseInput({
        balanceMode:       "BREAKDOWN",
        balanceModeSource: "ENTITY_DEFAULT",
        balanceBreakdown:  breakdown,
      }),
    );
    const r = readBalanceBreakdown(snap);
    expect(r.source).toBe("SNAPSHOT_V3");
    expect(r.breakdown).toEqual(breakdown);
  });
});
