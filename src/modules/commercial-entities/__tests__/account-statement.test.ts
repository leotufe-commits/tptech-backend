// src/modules/commercial-entities/__tests__/account-statement.test.ts
// Tests unitarios puros para el extracto de cuenta corriente.
// Sin acceso a DB — solo lógica de buildStatementFromEntries y helpers.

import { describe, it, expect } from "vitest";
import {
  buildStatementFromEntries,
  extractDeltas,
  applyDelta,
  cleanZeros,
  resolveTypeLabel,
  type StatementEntry,
} from "../account-statement.service.js";

// ---------------------------------------------------------------------------
// Helpers de test
// ---------------------------------------------------------------------------

const BASE_ENTITY = {
  id: "entity-1",
  displayName: "Proveedor Test",
  code: "CE-0001",
  documentNumber: "20-12345678-1",
  email: "proveedor@test.com",
  balanceType: "BREAKDOWN",
};

function makeEntry(overrides: Partial<StatementEntry> & { id: string }): StatementEntry {
  return {
    id:                overrides.id,
    entryType:         overrides.entryType         ?? "PURCHASE_INVOICE",
    amount:            overrides.amount             ?? { toString: () => "0" },
    currency:          overrides.currency           ?? "ARS",
    documentRef:       overrides.documentRef        ?? "",
    notes:             overrides.notes              ?? "",
    createdAt:         overrides.createdAt          ?? new Date("2026-01-01T10:00:00Z"),
    voidedAt:          overrides.voidedAt           ?? null,
    breakdownSnapshot: overrides.breakdownSnapshot  ?? null,
  };
}

function makeBreakdownSnapshot(metalId: string, gramsPure: number, hechura: number, currency = "ARS") {
  return {
    metals: [{ metalId, variantId: `v-${metalId}`, gramsOriginal: gramsPure, purity: 1, gramsPure }],
    hechura: { amount: hechura, currency },
  };
}

// ---------------------------------------------------------------------------
// Test 1: Extracto simple — 1 compra, 1 pago, saldos correctos
// ---------------------------------------------------------------------------

describe("Test 1: extracto simple", () => {
  it("compra + pago dan saldo correcto", () => {
    const entries: StatementEntry[] = [
      makeEntry({
        id: "e1",
        entryType: "PURCHASE_INVOICE",
        notes: "Compra confirmada #001",
        createdAt: new Date("2026-01-10T10:00:00Z"),
        breakdownSnapshot: makeBreakdownSnapshot("Au", 5.0, 1500, "ARS"),
      }),
      makeEntry({
        id: "e2",
        entryType: "SUPPLIER_PAYMENT",
        notes: "Pago a proveedor #001",
        createdAt: new Date("2026-01-15T10:00:00Z"),
        breakdownSnapshot: makeBreakdownSnapshot("Au", -2.0, -800, "ARS"),
      }),
    ];

    const stmt = buildStatementFromEntries(BASE_ENTITY, entries, { from: null, to: null });

    expect(stmt.openingBalance.metal).toEqual({});
    expect(stmt.openingBalance.hechura).toEqual({});

    expect(stmt.movements).toHaveLength(2);
    expect(stmt.movements[0].typeLabel).toBe("Compra");
    expect(stmt.movements[1].typeLabel).toBe("Pago");

    // Closing: Au = 5 - 2 = 3, ARS = 1500 - 800 = 700
    expect(stmt.closingBalance.metal["Au"]).toBeCloseTo(3.0, 4);
    expect(stmt.closingBalance.hechura["ARS"]).toBeCloseTo(700, 2);
  });
});

// ---------------------------------------------------------------------------
// Test 2: Multi-moneda — ARS y USD se acumulan por separado
// ---------------------------------------------------------------------------

describe("Test 2: multi-moneda", () => {
  it("ARS y USD en hechura se separan correctamente", () => {
    const entries: StatementEntry[] = [
      makeEntry({
        id: "e1",
        entryType: "PURCHASE_INVOICE",
        notes: "Compra confirmada",
        createdAt: new Date("2026-01-10T10:00:00Z"),
        breakdownSnapshot: {
          metals: [{ metalId: "Au", variantId: "v-Au", gramsOriginal: 3, purity: 1, gramsPure: 3 }],
          hechura: { amount: 1000, currency: "ARS" },
        },
      }),
      makeEntry({
        id: "e2",
        entryType: "PURCHASE_INVOICE",
        notes: "Compra confirmada USD",
        createdAt: new Date("2026-01-12T10:00:00Z"),
        breakdownSnapshot: {
          metals: [],
          hechura: { amount: 50, currency: "USD" },
        },
      }),
    ];

    const stmt = buildStatementFromEntries(BASE_ENTITY, entries, { from: null, to: null });

    expect(stmt.closingBalance.hechura["ARS"]).toBeCloseTo(1000, 2);
    expect(stmt.closingBalance.hechura["USD"]).toBeCloseTo(50, 2);
  });
});

// ---------------------------------------------------------------------------
// Test 3: Multi-metal — Au y Ag se rastrean por separado
// ---------------------------------------------------------------------------

describe("Test 3: multi-metal", () => {
  it("Au y Ag se acumulan en claves separadas", () => {
    const entries: StatementEntry[] = [
      makeEntry({
        id: "e1",
        entryType: "PURCHASE_INVOICE",
        notes: "Compra confirmada Au",
        createdAt: new Date("2026-01-10T10:00:00Z"),
        breakdownSnapshot: {
          metals: [
            { metalId: "Au", variantId: "v-Au", gramsOriginal: 10, purity: 0.75, gramsPure: 7.5 },
            { metalId: "Ag", variantId: "v-Ag", gramsOriginal: 20, purity: 0.925, gramsPure: 18.5 },
          ],
          hechura: { amount: 500, currency: "ARS" },
        },
      }),
    ];

    const stmt = buildStatementFromEntries(BASE_ENTITY, entries, { from: null, to: null });

    expect(stmt.closingBalance.metal["Au"]).toBeCloseTo(7.5, 4);
    expect(stmt.closingBalance.metal["Ag"]).toBeCloseTo(18.5, 4);
  });
});

// ---------------------------------------------------------------------------
// Test 4: Saldo a favor — pago excedente genera saldo negativo
// ---------------------------------------------------------------------------

describe("Test 4: saldo a favor", () => {
  it("overpayment genera balance negativo en hechura", () => {
    const entries: StatementEntry[] = [
      makeEntry({
        id: "e1",
        entryType: "PURCHASE_INVOICE",
        notes: "Compra confirmada",
        createdAt: new Date("2026-01-10T10:00:00Z"),
        breakdownSnapshot: makeBreakdownSnapshot("Au", 5, 1000, "ARS"),
      }),
      makeEntry({
        id: "e2",
        entryType: "SUPPLIER_PAYMENT",
        notes: "Pago a proveedor",
        createdAt: new Date("2026-01-11T10:00:00Z"),
        breakdownSnapshot: makeBreakdownSnapshot("Au", -5, -1500, "ARS"),
      }),
    ];

    const stmt = buildStatementFromEntries(BASE_ENTITY, entries, { from: null, to: null });

    // Metal saldo 0 → limpiado por cleanZeros
    expect(stmt.closingBalance.metal["Au"]).toBeUndefined();
    // ARS 1000 - 1500 = -500
    expect(stmt.closingBalance.hechura["ARS"]).toBeCloseTo(-500, 2);
  });
});

// ---------------------------------------------------------------------------
// Test 5: Entrada anulada — no afecta el running balance pero aparece en movimientos
// ---------------------------------------------------------------------------

describe("Test 5: entrada anulada", () => {
  it("entrada voidedAt aparece en movements con isVoided=true y no modifica el saldo", () => {
    const entries: StatementEntry[] = [
      makeEntry({
        id: "e1",
        entryType: "PURCHASE_INVOICE",
        notes: "Compra confirmada normal",
        createdAt: new Date("2026-01-10T10:00:00Z"),
        breakdownSnapshot: makeBreakdownSnapshot("Au", 5, 1000, "ARS"),
      }),
      makeEntry({
        id: "e2",
        entryType: "PURCHASE_INVOICE",
        notes: "Compra anulada",
        createdAt: new Date("2026-01-11T10:00:00Z"),
        voidedAt: new Date("2026-01-12T10:00:00Z"),
        breakdownSnapshot: makeBreakdownSnapshot("Au", 10, 2000, "ARS"),
      }),
    ];

    const stmt = buildStatementFromEntries(BASE_ENTITY, entries, { from: null, to: null });

    expect(stmt.movements).toHaveLength(2);
    expect(stmt.movements[1].isVoided).toBe(true);
    expect(stmt.movements[1].metalDelta).toEqual({});
    expect(stmt.movements[1].hechuraDelta).toEqual({});

    // Solo cuenta la primera entrada
    expect(stmt.closingBalance.metal["Au"]).toBeCloseTo(5, 4);
    expect(stmt.closingBalance.hechura["ARS"]).toBeCloseTo(1000, 2);
  });
});

// ---------------------------------------------------------------------------
// Test 6: Aplicación de crédito — reduce saldo existente
// ---------------------------------------------------------------------------

describe("Test 6: aplicación de crédito", () => {
  it("nota 'Saldo a favor' mapea typeLabel correcto y ajusta el balance", () => {
    const entries: StatementEntry[] = [
      makeEntry({
        id: "e1",
        entryType: "PURCHASE_INVOICE",
        notes: "Compra confirmada",
        createdAt: new Date("2026-01-10T10:00:00Z"),
        breakdownSnapshot: makeBreakdownSnapshot("Au", 10, 2000, "ARS"),
      }),
      makeEntry({
        id: "e2",
        entryType: "ADJUSTMENT",
        notes: "Saldo a favor aplicado al pedido #5",
        createdAt: new Date("2026-01-15T10:00:00Z"),
        breakdownSnapshot: {
          metals: [],
          hechura: { amount: -500, currency: "ARS" },
        },
      }),
    ];

    const stmt = buildStatementFromEntries(BASE_ENTITY, entries, { from: null, to: null });

    const creditMovement = stmt.movements.find((m) => m.id === "e2")!;
    expect(creditMovement.typeLabel).toBe("Aplicación de crédito");

    // ARS: 2000 - 500 = 1500
    expect(stmt.closingBalance.hechura["ARS"]).toBeCloseTo(1500, 2);
  });
});

// ---------------------------------------------------------------------------
// Tests de helpers auxiliares
// ---------------------------------------------------------------------------

describe("Helpers: cleanZeros", () => {
  it("elimina valores con abs < 0.0001", () => {
    const result = cleanZeros({ Au: 0.00005, Ag: 3.5, Cu: 0 });
    expect(result).toEqual({ Ag: 3.5 });
  });
});

describe("Helpers: resolveTypeLabel", () => {
  it("detecta por prefijo de notes primero", () => {
    expect(resolveTypeLabel("ADJUSTMENT", "Compra confirmada xyz")).toBe("Compra");
    expect(resolveTypeLabel("ADJUSTMENT", "Saldo a favor #3")).toBe("Aplicación de crédito");
    expect(resolveTypeLabel("ADJUSTMENT", "Pago a proveedor #7")).toBe("Pago");
  });

  it("usa el mapa de entryType cuando no hay prefijo especial", () => {
    expect(resolveTypeLabel("METAL_RETURN", "Nota random")).toBe("Devolución de metal");
    expect(resolveTypeLabel("INVOICE", "Descripcion")).toBe("Factura");
    expect(resolveTypeLabel("CREDIT_NOTE", "")).toBe("Nota de crédito");
  });
});

describe("Helpers: applyDelta", () => {
  it("suma correctamente metal y hechura", () => {
    const balance = { metal: { Au: 5 }, hechura: { ARS: 1000 } };
    const delta   = { metalDelta: { Au: 2, Ag: 3 }, hechuraDelta: { ARS: 500, USD: 100 } };
    const result  = applyDelta(balance, delta);
    expect(result.metal["Au"]).toBeCloseTo(7, 4);
    expect(result.metal["Ag"]).toBeCloseTo(3, 4);
    expect(result.hechura["ARS"]).toBeCloseTo(1500, 2);
    expect(result.hechura["USD"]).toBeCloseTo(100, 2);
  });
});
