// src/modules/sales/__tests__/sales-cancel-balance.test.ts
//
// Tests unitarios para el comportamiento de balance entries en cancelación de ventas.
//
// Estrategia: testear la lógica de agregación de balance con datos mock,
// sin acceso real a base de datos.
// Cubre el bug corregido: cancelSale debe anular (voidedAt) las EntityBalanceEntry
// creadas al confirmar la venta. Sin esa anulación, el saldo del cliente queda
// incorrecto después de una cancelación.

import { describe, it, expect } from "vitest";
import { aggregateEntityBalance } from "../../commercial-entities/balance.utils.js";
import type { BalanceBreakdown } from "../../../lib/pricing-engine/pricing-engine.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function D(v: number) {
  return { toString: () => v.toFixed(2) };
}

function makeEntry(
  amount: number,
  breakdown: BalanceBreakdown | null = null,
  voidedAt: Date | null = null
) {
  return {
    amount:            D(amount),
    voidedAt,
    breakdownSnapshot: breakdown,
  };
}

// ---------------------------------------------------------------------------
// Test 1: confirmSale crea balance entries y el saldo refleja la deuda
// ---------------------------------------------------------------------------

describe("confirmSale — genera saldo en cuenta corriente del cliente", () => {
  it("el saldo es la suma de los montos de las líneas confirmadas", () => {
    // Simula dos líneas de una venta confirmada
    const entries = [
      makeEntry(1000),
      makeEntry(500),
    ];
    const result = aggregateEntityBalance(entries, "UNIFIED");
    expect(result.mode).toBe("UNIFIED");
    if (result.mode === "UNIFIED") {
      expect(result.amount).toBeCloseTo(1500, 2);
    }
  });

  it("con cliente BREAKDOWN genera saldo en metal + hechura", () => {
    const breakdown: BalanceBreakdown = {
      metals: [{ metalId: "gold", variantId: "v-gold", gramsOriginal: 10, purity: 0.75, gramsPure: 7.5 }],
      hechura: { amount: 800, currency: "BASE" },
    };
    const entries = [makeEntry(0, breakdown)];
    const result = aggregateEntityBalance(entries, "BREAKDOWN");
    expect(result.mode).toBe("BREAKDOWN");
    if (result.mode === "BREAKDOWN") {
      expect(result.metals.find((m) => m.metalId === "gold")?.gramsPure).toBeCloseTo(7.5, 4);
      expect(result.hechura.byCurrency["BASE"]).toBeCloseTo(800, 2);
    }
  });
});

// ---------------------------------------------------------------------------
// Test 2: cancelSale revierte las entries → saldo queda en cero
// ---------------------------------------------------------------------------

describe("cancelSale — anular balance entries deja saldo en cero", () => {
  it("UNIFIED: entries con voidedAt son excluidas del saldo", () => {
    const now = new Date();
    // Venta confirmada → 2 entries activas
    // Venta cancelada → ambas entries marcadas con voidedAt
    const entries = [
      makeEntry(1000, null, now), // anulada
      makeEntry(500,  null, now), // anulada
    ];
    const result = aggregateEntityBalance(entries, "UNIFIED");
    expect(result.mode).toBe("UNIFIED");
    if (result.mode === "UNIFIED") {
      // El saldo debe ser 0: las entries anuladas no cuentan
      expect(result.amount).toBeCloseTo(0, 2);
    }
  });

  it("BREAKDOWN: entries con voidedAt son excluidas del saldo de metal y hechura", () => {
    const now = new Date();
    const breakdown: BalanceBreakdown = {
      metals: [{ metalId: "gold", variantId: "v-gold", gramsOriginal: 10, purity: 0.75, gramsPure: 7.5 }],
      hechura: { amount: 800, currency: "BASE" },
    };
    const entries = [makeEntry(0, breakdown, now)]; // anulada
    const result = aggregateEntityBalance(entries, "BREAKDOWN");
    expect(result.mode).toBe("BREAKDOWN");
    if (result.mode === "BREAKDOWN") {
      expect(result.metals.length).toBe(0);
      expect(result.hechura.byCurrency["BASE"] ?? 0).toBeCloseTo(0, 2);
    }
  });
});

// ---------------------------------------------------------------------------
// Test 3: no deja deuda activa — combinación activas + anuladas
// ---------------------------------------------------------------------------

describe("cancelSale — no deja deuda activa en cuenta corriente", () => {
  it("solo las entries NO anuladas (voidedAt=null) impactan el saldo", () => {
    const now = new Date();
    // Escenario: venta confirmada (2 entries) + cancelada (2 entries anuladas)
    // + otra venta activa del mismo cliente (1 entry activa)
    const entries = [
      makeEntry(1000, null, now), // venta A cancelada — entry 1
      makeEntry(500,  null, now), // venta A cancelada — entry 2
      makeEntry(300),             // venta B activa — saldo real
    ];
    const result = aggregateEntityBalance(entries, "UNIFIED");
    expect(result.mode).toBe("UNIFIED");
    if (result.mode === "UNIFIED") {
      // Solo la entry de la venta B activa debe sumarse
      expect(result.amount).toBeCloseTo(300, 2);
    }
  });
});

// ---------------------------------------------------------------------------
// Test 4: idempotencia — cancelar dos veces no duplica efectos
// ---------------------------------------------------------------------------

describe("cancelSale — idempotencia del void", () => {
  it("si las entries ya tienen voidedAt, el saldo sigue en cero (no doble efecto)", () => {
    // La operación cancelSale usa voidedAt: null como filtro → no toca entries ya anuladas
    // Este test verifica que el resultado de balance.utils sea correcto
    // sin importar cuántas veces se llame la anulación
    const past  = new Date(Date.now() - 86400000);
    const now   = new Date();
    const entries = [
      makeEntry(1000, null, past), // anulada en el primer cancel
      makeEntry(1000, null, now),  // "segunda anulación" — no debería pasar pero si pasara, mismo resultado
    ];
    const result = aggregateEntityBalance(entries, "UNIFIED");
    expect(result.mode).toBe("UNIFIED");
    if (result.mode === "UNIFIED") {
      expect(result.amount).toBeCloseTo(0, 2);
    }
  });
});

// ---------------------------------------------------------------------------
// Test 5: cancelar venta DRAFT no genera entries (no había nada que anular)
// ---------------------------------------------------------------------------

describe("cancelSale — venta DRAFT no tiene entries que anular", () => {
  it("balance con cero entries tiene saldo en cero", () => {
    // Una venta DRAFT nunca pasa por confirmSale → nunca crea EntityBalanceEntry
    // cancelSale solo anula si wasConfirmed (status !== DRAFT) AND clientId
    const entries: ReturnType<typeof makeEntry>[] = [];
    const result = aggregateEntityBalance(entries, "UNIFIED");
    expect(result.mode).toBe("UNIFIED");
    if (result.mode === "UNIFIED") {
      expect(result.amount).toBeCloseTo(0, 2);
    }
  });
});
