// src/modules/cross-settlements/__tests__/cross-settlements.test.ts
// Tests unitarios puros de buildCrossSettlementEntries (sin DB).

import { describe, it, expect } from "vitest";
import { buildCrossSettlementEntries } from "../cross-settlements.service.js";
import type { CrossSettlementInput } from "../cross-settlements.service.js";
import {
  aggregateEntityBalance,
} from "../../commercial-entities/balance.utils.js";
import type { BalanceEntryLike } from "../../commercial-entities/balance.utils.js";
import type { BalanceBreakdown } from "../../../lib/pricing-engine/pricing-engine.balance.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const FAKE_ID = "settlement-abc123";

function makeInput(
  from: CrossSettlementInput["from"],
  to: CrossSettlementInput["to"],
): CrossSettlementInput {
  return {
    supplierId: "supplier-1",
    from,
    to,
    conversion: {},
  };
}

/** Convierte un snapshot en BalanceEntryLike para usar con aggregateEntityBalance. */
function toEntry(
  snapshot: BalanceBreakdown,
  voided = false,
): BalanceEntryLike {
  return {
    amount:            { toString: () => "0" },
    voidedAt:          voided ? new Date() : null,
    breakdownSnapshot: snapshot,
  };
}

// ---------------------------------------------------------------------------
// Test 1: MONEY → MONEY (USD cancela ARS)
// ---------------------------------------------------------------------------
describe("buildCrossSettlementEntries", () => {
  it("MONEY→MONEY: genera deltas de hechura correctos en USD y ARS", () => {
    const input = makeInput(
      { componentType: "MONEY", currency: "USD", amount: 100 },
      { componentType: "MONEY", currency: "ARS", amount: 50000 },
    );
    const { entryA, entryB } = buildCrossSettlementEntries(input, FAKE_ID);

    const snapA = entryA.breakdownSnapshot as BalanceBreakdown;
    const snapB = entryB.breakdownSnapshot as BalanceBreakdown;

    expect(snapA.metals).toHaveLength(0);
    expect(snapA.hechura.currency).toBe("USD");
    expect(snapA.hechura.amount).toBe(-100);

    expect(snapB.metals).toHaveLength(0);
    expect(snapB.hechura.currency).toBe("ARS");
    expect(snapB.hechura.amount).toBe(-50000);
  });

  // -------------------------------------------------------------------------
  // Test 2: MONEY → METAL (USD cancela deuda en Au)
  // -------------------------------------------------------------------------
  it("MONEY→METAL: entryA tiene hechura USD negativa, entryB tiene metal Au negativo", () => {
    const input = makeInput(
      { componentType: "MONEY",  currency: "USD", amount: 300 },
      { componentType: "METAL",  metalId: "Au",   variantId: "v-Au18",
        gramsOriginal: 10, purity: 0.75, gramsPure: 7.5 },
    );
    const { entryA, entryB } = buildCrossSettlementEntries(input, FAKE_ID);

    const snapA = entryA.breakdownSnapshot as BalanceBreakdown;
    const snapB = entryB.breakdownSnapshot as BalanceBreakdown;

    // Entry A: dinero entregado (hechura negativa en USD)
    expect(snapA.metals).toHaveLength(0);
    expect(snapA.hechura.currency).toBe("USD");
    expect(snapA.hechura.amount).toBe(-300);

    // Entry B: metal cancelado (gramsPure negativo)
    expect(snapB.metals).toHaveLength(1);
    expect(snapB.metals[0].metalId).toBe("Au");
    expect(snapB.metals[0].gramsPure).toBe(-7.5);
    expect(snapB.hechura.amount).toBe(0);
  });

  // -------------------------------------------------------------------------
  // Test 3: METAL → MONEY (Au cancela deuda en USD)
  // -------------------------------------------------------------------------
  it("METAL→MONEY: entryA tiene metal Au negativo, entryB tiene hechura USD negativa", () => {
    const input = makeInput(
      { componentType: "METAL", metalId: "Au", variantId: "v-Au18",
        gramsOriginal: 5, purity: 0.75, gramsPure: 3.75 },
      { componentType: "MONEY", currency: "USD", amount: 150 },
    );
    const { entryA, entryB } = buildCrossSettlementEntries(input, FAKE_ID);

    const snapA = entryA.breakdownSnapshot as BalanceBreakdown;
    const snapB = entryB.breakdownSnapshot as BalanceBreakdown;

    // Entry A: metal entregado (gramsPure negativo)
    expect(snapA.metals).toHaveLength(1);
    expect(snapA.metals[0].metalId).toBe("Au");
    expect(snapA.metals[0].gramsPure).toBe(-3.75);
    expect(snapA.hechura.amount).toBe(0);

    // Entry B: dinero cancelado (hechura negativa)
    expect(snapB.metals).toHaveLength(0);
    expect(snapB.hechura.currency).toBe("USD");
    expect(snapB.hechura.amount).toBe(-150);
  });

  // -------------------------------------------------------------------------
  // Test 4: METAL → METAL lanza error
  // -------------------------------------------------------------------------
  it("METAL→METAL: lanza error 'Liquidación metal→metal no implementada.'", () => {
    const input = makeInput(
      { componentType: "METAL", metalId: "Au", variantId: "v-Au18", gramsPure: 5 },
      { componentType: "METAL", metalId: "Ag", variantId: "v-Ag925", gramsPure: 20 },
    );
    expect(() => buildCrossSettlementEntries(input, FAKE_ID)).toThrow(
      "Liquidación metal→metal no implementada.",
    );
  });

  // -------------------------------------------------------------------------
  // Test 5: Mismo componente contra sí mismo (USD → USD) lanza error
  // -------------------------------------------------------------------------
  it("USD→USD: lanza error 'No se puede liquidar un componente contra sí mismo.'", () => {
    const input = makeInput(
      { componentType: "MONEY", currency: "USD", amount: 100 },
      { componentType: "MONEY", currency: "USD", amount: 100 },
    );
    expect(() => buildCrossSettlementEntries(input, FAKE_ID)).toThrow(
      "No se puede liquidar un componente contra sí mismo.",
    );
  });

  // -------------------------------------------------------------------------
  // Test 6: Las notas contienen "XSETTLE-" y "entregado" / "cancelado"
  // -------------------------------------------------------------------------
  it("Las notas de las entradas contienen el ID de liquidación y los labels correctos", () => {
    const myId = "test-settlement-999";
    const input = makeInput(
      { componentType: "MONEY", currency: "USD", amount: 200 },
      { componentType: "MONEY", currency: "ARS", amount: 80000 },
    );
    const { entryA, entryB } = buildCrossSettlementEntries(input, myId);

    expect(entryA.notes).toContain(`XSETTLE-${myId}`);
    expect(entryA.notes).toContain("entregado");
    expect(entryB.notes).toContain(`XSETTLE-${myId}`);
    expect(entryB.notes).toContain("cancelado");
  });

  // -------------------------------------------------------------------------
  // Test 7: Múltiples liquidaciones cruzadas aplicadas → saldo neto correcto
  // -------------------------------------------------------------------------
  it("Múltiples liquidaciones aplicadas a aggregateEntityBalance → saldo neto correcto", () => {
    // Situación: el proveedor nos debe 10g Au (gramsPure positivo = deuda)
    // y nosotros le debemos 500 USD (hechura positiva = deuda nuestra).
    // Aplicamos una liquidación cruzada MONEY→METAL: entregamos 300 USD,
    // cancelamos 3.75g Au.
    // Resultado esperado: Au neto = 6.25g, USD neto = 200.

    // Entrada original de deuda en Au (+10g)
    const debtAuSnap: BalanceBreakdown = {
      metals: [{ metalId: "Au", variantId: "v-Au18", gramsOriginal: 13.33, purity: 0.75, gramsPure: 10 }],
      hechura: { amount: 0, currency: "BASE" },
    };
    // Entrada original de deuda en USD (+500)
    const debtUsdSnap: BalanceBreakdown = {
      metals: [],
      hechura: { amount: 500, currency: "USD" },
    };

    // Liquidación: MONEY→METAL (300 USD cancela 3.75g Au)
    const input = makeInput(
      { componentType: "MONEY", currency: "USD", amount: 300 },
      { componentType: "METAL", metalId: "Au", variantId: "v-Au18",
        gramsOriginal: 5, purity: 0.75, gramsPure: 3.75 },
    );
    const { entryA, entryB } = buildCrossSettlementEntries(input, "settle-1");
    const snapA = entryA.breakdownSnapshot as BalanceBreakdown;
    const snapB = entryB.breakdownSnapshot as BalanceBreakdown;

    const entries: BalanceEntryLike[] = [
      toEntry(debtAuSnap),
      toEntry(debtUsdSnap),
      toEntry(snapA),
      toEntry(snapB),
    ];

    const balance = aggregateEntityBalance(entries, "BREAKDOWN");
    if (balance.mode !== "BREAKDOWN") throw new Error("Modo inesperado");

    // Au: 10 - 3.75 = 6.25
    const auBalance = balance.metals.find((m) => m.metalId === "Au");
    expect(auBalance?.gramsPure).toBeCloseTo(6.25, 4);

    // USD: 500 - 300 = 200
    expect(balance.hechura.byCurrency["USD"]).toBeCloseTo(200, 2);
  });

  // -------------------------------------------------------------------------
  // Test 8: Anular liquidación (entradas voided) → saldo se restaura al original
  // -------------------------------------------------------------------------
  it("Anular liquidación (entradas voided) → saldo vuelve al original", () => {
    // Deuda base: 8g Au
    const debtAuSnap: BalanceBreakdown = {
      metals: [{ metalId: "Au", variantId: "v-Au18", gramsOriginal: 10.67, purity: 0.75, gramsPure: 8 }],
      hechura: { amount: 0, currency: "BASE" },
    };

    // Liquidación METAL→MONEY: 3g Au cancela 120 USD
    const input = makeInput(
      { componentType: "METAL", metalId: "Au", variantId: "v-Au18",
        gramsOriginal: 4, purity: 0.75, gramsPure: 3 },
      { componentType: "MONEY", currency: "USD", amount: 120 },
    );
    const { entryA, entryB } = buildCrossSettlementEntries(input, "settle-void");
    const snapA = entryA.breakdownSnapshot as BalanceBreakdown;
    const snapB = entryB.breakdownSnapshot as BalanceBreakdown;

    // Saldo CON la liquidación activa
    const entriesActive: BalanceEntryLike[] = [
      toEntry(debtAuSnap),
      toEntry(snapA),         // -3g Au activo
      toEntry(snapB),         // -120 USD activo
    ];
    const balanceActive = aggregateEntityBalance(entriesActive, "BREAKDOWN");
    if (balanceActive.mode !== "BREAKDOWN") throw new Error("Modo inesperado");
    expect(balanceActive.metals.find((m) => m.metalId === "Au")?.gramsPure).toBeCloseTo(5, 4);

    // Saldo CON la liquidación ANULADA (entradas voided=true)
    const entriesVoided: BalanceEntryLike[] = [
      toEntry(debtAuSnap),
      toEntry(snapA, true),   // -3g Au ANULADO → no cuenta
      toEntry(snapB, true),   // -120 USD ANULADO → no cuenta
    ];
    const balanceVoided = aggregateEntityBalance(entriesVoided, "BREAKDOWN");
    if (balanceVoided.mode !== "BREAKDOWN") throw new Error("Modo inesperado");

    // Debe volver a 8g Au (como si nunca hubiera habido liquidación)
    expect(balanceVoided.metals.find((m) => m.metalId === "Au")?.gramsPure).toBeCloseTo(8, 4);

    // No debe haber saldo en USD (la entrada de 120 USD también está anulada)
    expect(balanceVoided.hechura.byCurrency["USD"] ?? 0).toBeCloseTo(0, 2);
  });
});
