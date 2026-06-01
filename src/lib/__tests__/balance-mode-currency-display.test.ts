// src/lib/__tests__/balance-mode-currency-display.test.ts
// =============================================================================
// T57 (Fase 3B.7) — Conversión de Balance Mode breakdown BASE → moneda doc.
//
// Reglas testeadas (POLICY.md §11 R11.3 + currency display contract):
//   · monetary.amount → SE CONVIERTE.
//   · monetary.amountBase → NO se toca (definición = BASE).
//   · monetary.currencyRate → NO se toca (snapshot histórico).
//   · monetary.components[].amount → SE CONVIERTE.
//   · metals[].valuationMonetary → SE CONVIERTE.
//   · metals[].quotePriceSnapshot → SE CONVIERTE.
//   · metals[].gramsOriginal / gramsPure / purity → NUNCA se convierten.
//   · rate === 1 → no-op total.
//   · Inputs hostiles (null/undefined/no-objeto) → no-op sin tirar.
// =============================================================================

import { describe, it, expect } from "vitest";
import {
  convertBalanceBreakdownInPlace,
  convertSalesPreviewResponseInPlace,
} from "../pricing-currency-display.js";

// Helper: deep-clone para que cada test arranque con fixture limpio.
function clone<T>(v: T): T { return JSON.parse(JSON.stringify(v)); }

function fixtureBreakdownBASE() {
  // Snapshot canónico EN BASE (ARS). Total doc en USD a rate=1000.
  return {
    metals: [
      {
        metalParentId:         "oro-fino",
        metalParentName:       "Oro Fino",
        gramsOriginal:         1,
        purity:                0.75,
        gramsPure:             0.75,
        quotePriceSnapshot:    100000,  // BASE ARS/g
        valuationMonetary:     75000,   // BASE ARS
        valuationCurrencyCode: "ARS",
        sourceLineIds:         ["line-1"],
      },
    ],
    monetaryBalance: {
      amount:       25000,    // BASE ARS
      currencyCode: "ARS",
      currencyRate: 1,
      amountBase:   25000,
      components: [
        { type: "HECHURA", label: "Hechura", amount: 25000 },
        { type: "TAX",     label: "IVA 21%", amount: 4250 },
      ],
    },
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// convertBalanceBreakdownInPlace
// ─────────────────────────────────────────────────────────────────────────────

describe("convertBalanceBreakdownInPlace — campos monetarios convertidos, gramos invariantes", () => {
  it("divide monetary.amount por rate (BASE → doc)", () => {
    const bd = fixtureBreakdownBASE();
    convertBalanceBreakdownInPlace(bd, 1000);
    expect(bd.monetaryBalance.amount).toBeCloseTo(25, 6); // 25000 / 1000
  });

  it("NO toca monetary.amountBase (queda en BASE por definición)", () => {
    const bd = fixtureBreakdownBASE();
    convertBalanceBreakdownInPlace(bd, 1000);
    expect(bd.monetaryBalance.amountBase).toBe(25000);
  });

  it("NO toca monetary.currencyRate (snapshot histórico)", () => {
    const bd = fixtureBreakdownBASE();
    convertBalanceBreakdownInPlace(bd, 1000);
    expect(bd.monetaryBalance.currencyRate).toBe(1);
  });

  it("divide cada components[].amount por rate", () => {
    const bd = fixtureBreakdownBASE();
    convertBalanceBreakdownInPlace(bd, 1000);
    const comps = bd.monetaryBalance.components;
    expect(comps[0].amount).toBeCloseTo(25, 6);    // 25000 / 1000
    expect(comps[1].amount).toBeCloseTo(4.25, 6);  // 4250 / 1000
  });

  it("conserva component metadata: type, label, source*", () => {
    const bd = fixtureBreakdownBASE();
    convertBalanceBreakdownInPlace(bd, 1000);
    expect(bd.monetaryBalance.components[0].type).toBe("HECHURA");
    expect(bd.monetaryBalance.components[0].label).toBe("Hechura");
    expect(bd.monetaryBalance.components[1].type).toBe("TAX");
  });

  it("divide metals[].valuationMonetary y quotePriceSnapshot", () => {
    const bd = fixtureBreakdownBASE();
    convertBalanceBreakdownInPlace(bd, 1000);
    expect(bd.metals[0].valuationMonetary).toBeCloseTo(75, 6);     // 75000 / 1000
    expect(bd.metals[0].quotePriceSnapshot).toBeCloseTo(100, 6);   // 100000 / 1000
  });

  it("NUNCA divide gramsOriginal / gramsPure / purity", () => {
    const bd = fixtureBreakdownBASE();
    convertBalanceBreakdownInPlace(bd, 1000);
    expect(bd.metals[0].gramsOriginal).toBe(1);
    expect(bd.metals[0].gramsPure).toBe(0.75);
    expect(bd.metals[0].purity).toBe(0.75);
  });

  it("rate === 1 → no-op total (no muta el breakdown)", () => {
    const bd = fixtureBreakdownBASE();
    const snapshot = JSON.stringify(bd);
    convertBalanceBreakdownInPlace(bd, 1);
    expect(JSON.stringify(bd)).toBe(snapshot);
  });

  it("inputs hostiles (null/undefined/no-objeto) → no-op sin tirar", () => {
    expect(() => convertBalanceBreakdownInPlace(null,      1000)).not.toThrow();
    expect(() => convertBalanceBreakdownInPlace(undefined, 1000)).not.toThrow();
    expect(() => convertBalanceBreakdownInPlace("foo",     1000)).not.toThrow();
    expect(() => convertBalanceBreakdownInPlace(42,        1000)).not.toThrow();
  });

  it("breakdown sin metals (UNIFIED) — solo convierte monetary", () => {
    const bd = {
      metals: [],
      monetaryBalance: { amount: 1000, currencyCode: "ARS", currencyRate: 1, amountBase: 1000 },
    };
    convertBalanceBreakdownInPlace(bd, 1000);
    expect(bd.metals).toEqual([]);
    expect(bd.monetaryBalance.amount).toBeCloseTo(1, 6);
    expect(bd.monetaryBalance.amountBase).toBe(1000);
  });

  it("metal sin valuationMonetary/quotePriceSnapshot (legacy) — no rompe", () => {
    const bd = {
      metals: [{
        metalParentId: "oro-fino", metalParentName: "Oro Fino",
        gramsOriginal: 1, purity: 0.75, gramsPure: 0.75,
        // sin quotePriceSnapshot / valuationMonetary
        valuationCurrencyCode: "ARS",
        sourceLineIds: [],
      }],
      monetaryBalance: { amount: 100, currencyCode: "ARS", currencyRate: 1, amountBase: 100 },
    };
    convertBalanceBreakdownInPlace(bd, 1000);
    expect(bd.metals[0].gramsPure).toBe(0.75); // intacto
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Integración: convertSalesPreviewResponseInPlace
// ─────────────────────────────────────────────────────────────────────────────

describe("convertSalesPreviewResponseInPlace — incluye balanceBreakdown", () => {
  it("convierte balanceBreakdown.monetaryBalance.amount junto con el resto del response", () => {
    const res: any = {
      lines: [],
      subtotal: 100000,
      total: 100000,
      channelResult: null,
      couponResult: null,
      checkoutResult: null,
      documentTotals: null,
      balanceBreakdown: clone(fixtureBreakdownBASE()),
    };
    convertSalesPreviewResponseInPlace(res, 1000);
    expect(res.subtotal).toBeCloseTo(100, 6);
    expect(res.total).toBeCloseTo(100, 6);
    expect(res.balanceBreakdown.monetaryBalance.amount).toBeCloseTo(25, 6);
    expect(res.balanceBreakdown.metals[0].valuationMonetary).toBeCloseTo(75, 6);
    // Invariantes:
    expect(res.balanceBreakdown.metals[0].gramsPure).toBe(0.75);
    expect(res.balanceBreakdown.monetaryBalance.amountBase).toBe(25000);
  });

  it("rate === 1 → response NO se muta (paridad con sin-conversión)", () => {
    const res: any = {
      lines: [],
      subtotal: 100, total: 100,
      balanceBreakdown: clone(fixtureBreakdownBASE()),
    };
    const before = JSON.stringify(res);
    convertSalesPreviewResponseInPlace(res, 1);
    expect(JSON.stringify(res)).toBe(before);
  });

  it("response sin balanceBreakdown (legacy/UNIFIED implícito) — no rompe", () => {
    const res: any = {
      lines: [],
      subtotal: 100,
      total:    100,
      // sin balanceBreakdown
    };
    expect(() => convertSalesPreviewResponseInPlace(res, 1000)).not.toThrow();
    expect(res.subtotal).toBeCloseTo(0.1, 6);
  });
});
