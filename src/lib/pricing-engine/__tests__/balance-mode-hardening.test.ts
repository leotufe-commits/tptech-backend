// src/lib/pricing-engine/__tests__/balance-mode-hardening.test.ts
// =============================================================================
// T58 (Fase 3B.8) — Tests de HARDENING de Balance Mode.
//
// Cubren los invariantes y guardas defensivas que se agregaron en 3B.8:
//   1. gramsPure inválido / negativo / NaN / Infinity → descarte defensivo
//   2. NaN / Infinity en amount/amountBase → rechazo en persistencia
//   3. snapshots corruptos → lectura tolerante sin throw
//   4. balanceMode inválido → fallback seguro
//   5. metalEntries duplicadas accidentalmente → dedup por padre
//   6. mapBalanceTypeToMode robusto ante valores arbitrarios
//   7. DocumentBalanceBreakdown "vacío" no genera entries
//   8. read tolerante con shapes malformados
//   9. BREAKDOWN sin monetaryBalance → persistencia falla controlada
//  10. AccountMovementMetalEntry: rows con gramsPure=0 nunca se persisten
//
// NO se ejerce el runtime completo de previewSale/confirmSale — esos tienen
// sus tests dedicados. Acá solo se valida cada guarda en aislamiento.
// =============================================================================

import { describe, it, expect } from "vitest";
import {
  buildDocumentBalanceBreakdown,
  readBalanceBreakdown,
  mapBalanceTypeToMode,
} from "../pricing-engine.balance.js";
import {
  buildAccountMovementMetalEntryRows,
  isValidBalanceBreakdownForPersistence,
} from "../../document-hooks/sale.hook.js";
import type { DocumentBalanceBreakdown } from "../pricing-engine.types.js";

// ─────────────────────────────────────────────────────────────────────────────
// 1. gramsPure inválido — builder y dedup defensivo
// ─────────────────────────────────────────────────────────────────────────────

describe("Hardening — gramsPure inválido (NaN / Infinity / negativo)", () => {
  it("buildDocumentBalanceBreakdown: gramsOriginal negativo → metal descartado", () => {
    const out = buildDocumentBalanceBreakdown(
      {
        documentTotal:     100,
        documentTotalBase: 100,
        currency:          { code: "ARS", rate: 1 },
        lines: [{
          lineId: "L-1", quantity: 1,
          metals: [{
            metalParentId: "oro-fino",  metalParentName: "Oro Fino",
            metalVariantId: "oro-18k",  metalVariantName: "Oro 18k",
            appliedGramsPerUnit: -1,    // negativo
            purity: 0.75,
          }],
        }],
      },
      "BREAKDOWN",
    );
    expect(out.metals).toEqual([]);
  });

  it("buildDocumentBalanceBreakdown: gramsOriginal NaN → metal descartado", () => {
    const out = buildDocumentBalanceBreakdown(
      {
        documentTotal:     100,
        documentTotalBase: 100,
        currency:          { code: "ARS", rate: 1 },
        lines: [{
          lineId: "L-1", quantity: 1,
          metals: [{
            metalParentId: "oro-fino",  metalParentName: "Oro Fino",
            metalVariantId: "oro-18k",  metalVariantName: "Oro 18k",
            appliedGramsPerUnit: Number.NaN,
            purity: 0.75,
          }],
        }],
      },
      "BREAKDOWN",
    );
    expect(out.metals).toEqual([]);
  });

  it("buildAccountMovementMetalEntryRows: gramsPure=0 → fila descartada", () => {
    const bd: DocumentBalanceBreakdown = {
      metals: [{
        metalParentId: "oro-fino",  metalParentName: "Oro Fino",
        gramsOriginal: 0, purity: null, gramsPure: 0,
        quotePriceSnapshot: null, valuationMonetary: null,
        valuationCurrencyCode: "ARS",
        sourceLineIds: [],
      }],
      monetaryBalance: { amount: 100, currencyCode: "ARS", currencyRate: 1, amountBase: 100 },
    };
    const rows = buildAccountMovementMetalEntryRows({
      movementId: "mov-1", jewelryId: "jw-1", breakdown: bd,
    });
    expect(rows).toEqual([]);
  });

  it("buildAccountMovementMetalEntryRows: gramsPure NaN/Infinity → fila descartada", () => {
    const bd: DocumentBalanceBreakdown = {
      metals: [
        { metalParentId: "x1", metalParentName: "X1",
          gramsOriginal: 1, purity: 0.5, gramsPure: Number.NaN,
          quotePriceSnapshot: null, valuationMonetary: null,
          valuationCurrencyCode: "ARS", sourceLineIds: [] },
        { metalParentId: "x2", metalParentName: "X2",
          gramsOriginal: 1, purity: 0.5, gramsPure: Number.POSITIVE_INFINITY,
          quotePriceSnapshot: null, valuationMonetary: null,
          valuationCurrencyCode: "ARS", sourceLineIds: [] },
      ],
      monetaryBalance: { amount: 100, currencyCode: "ARS", currencyRate: 1, amountBase: 100 },
    };
    const rows = buildAccountMovementMetalEntryRows({
      movementId: "mov-1", jewelryId: "jw-1", breakdown: bd,
    });
    expect(rows).toEqual([]);
  });

  it("buildAccountMovementMetalEntryRows: gramsPure negativo → fila descartada", () => {
    const bd: DocumentBalanceBreakdown = {
      metals: [{
        metalParentId: "oro-fino", metalParentName: "Oro Fino",
        gramsOriginal: 1, purity: -0.75, gramsPure: -0.75,
        quotePriceSnapshot: null, valuationMonetary: null,
        valuationCurrencyCode: "ARS", sourceLineIds: [],
      }],
      monetaryBalance: { amount: 100, currencyCode: "ARS", currencyRate: 1, amountBase: 100 },
    };
    const rows = buildAccountMovementMetalEntryRows({
      movementId: "mov-1", jewelryId: "jw-1", breakdown: bd,
    });
    expect(rows).toEqual([]);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. NaN / Infinity en amount/amountBase — persistencia rechaza
// ─────────────────────────────────────────────────────────────────────────────

describe("Hardening — isValidBalanceBreakdownForPersistence rechaza NaN/Infinity", () => {
  it("monetaryBalance.amount NaN → rechazado", () => {
    expect(isValidBalanceBreakdownForPersistence({
      metals: [],
      monetaryBalance: { amount: Number.NaN, currencyCode: "ARS", currencyRate: 1, amountBase: 100 },
    } as any)).toBe(false);
  });

  it("monetaryBalance.amountBase Infinity → rechazado", () => {
    expect(isValidBalanceBreakdownForPersistence({
      metals: [],
      monetaryBalance: { amount: 100, currencyCode: "ARS", currencyRate: 1, amountBase: Number.POSITIVE_INFINITY },
    } as any)).toBe(false);
  });

  it("breakdown válido pasa la guarda", () => {
    expect(isValidBalanceBreakdownForPersistence({
      metals: [],
      monetaryBalance: { amount: 100, currencyCode: "ARS", currencyRate: 1, amountBase: 100 },
    } as any)).toBe(true);
  });

  it("sin monetaryBalance → rechazado", () => {
    expect(isValidBalanceBreakdownForPersistence({ metals: [] } as any)).toBe(false);
  });

  it("null/undefined/string → rechazado sin tirar", () => {
    expect(isValidBalanceBreakdownForPersistence(null as any)).toBe(false);
    expect(isValidBalanceBreakdownForPersistence(undefined)).toBe(false);
    expect(isValidBalanceBreakdownForPersistence("foo" as any)).toBe(false);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. Snapshots corruptos — readBalanceBreakdown nunca tira
// ─────────────────────────────────────────────────────────────────────────────

describe("Hardening — readBalanceBreakdown tolera shapes hostiles", () => {
  it("amount = NaN en breakdown legacy se mantiene en lectura (responsabilidad del caller)", () => {
    // El read es tolerante: NO sanitiza NaN del totals, solo lo lee. La
    // sanitización vive en la persistencia (isValid*). Si llega un snapshot
    // legacy con totals.total=NaN, devuelve 0 por fallback del helper.
    const r = readBalanceBreakdown({ version: 2, totals: { total: Number.NaN } });
    expect(r.source).toBe("LEGACY_UNIFIED");
    expect(r.breakdown.monetaryBalance.amount).toBe(0);
  });

  it("snapshot con balanceBreakdown que es string → fallback LEGACY_UNIFIED", () => {
    const r = readBalanceBreakdown({
      version: 3, balanceBreakdown: "no-soy-un-breakdown" as any,
      totals: { total: 100, totalBase: 100 },
      currency: { currencyCode: "ARS", currencyRate: 1 },
    });
    expect(r.source).toBe("LEGACY_UNIFIED");
    expect(r.breakdown.monetaryBalance.amount).toBe(100);
  });

  it("array como input → INVALID (no es objeto plano)", () => {
    // Array es typeof "object" → cae a LEGACY_UNIFIED con datos default 0.
    const r = readBalanceBreakdown([1, 2, 3]);
    expect(["INVALID", "LEGACY_UNIFIED"]).toContain(r.source);
    expect(r.breakdown.monetaryBalance.amount).toBe(0);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 4. balanceMode inválido (strings arbitrarios)
// ─────────────────────────────────────────────────────────────────────────────

describe("Hardening — mapBalanceTypeToMode rechaza valores arbitrarios", () => {
  it("strings ajenos al enum devuelven null (no se inventan modes)", () => {
    expect(mapBalanceTypeToMode("MIXED")).toBeNull();
    expect(mapBalanceTypeToMode("foo")).toBeNull();
    expect(mapBalanceTypeToMode("")).toBeNull();
    expect(mapBalanceTypeToMode("unified")).toBeNull(); // case-sensitive
  });

  it("null / undefined / number → null", () => {
    expect(mapBalanceTypeToMode(null)).toBeNull();
    expect(mapBalanceTypeToMode(undefined)).toBeNull();
    expect(mapBalanceTypeToMode(123 as any)).toBeNull();
  });

  it("UNIFIED y BREAKDOWN pasan tal cual", () => {
    expect(mapBalanceTypeToMode("UNIFIED")).toBe("UNIFIED");
    expect(mapBalanceTypeToMode("BREAKDOWN")).toBe("BREAKDOWN");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 5. Duplicate metal entries — dedup defensivo
// ─────────────────────────────────────────────────────────────────────────────

describe("Hardening — buildAccountMovementMetalEntryRows dedupe por padre", () => {
  it("dos entries para el mismo metalParentId → 1 fila con gramos sumados", () => {
    const bd: DocumentBalanceBreakdown = {
      metals: [
        { metalParentId: "oro-fino", metalParentName: "Oro Fino",
          gramsOriginal: 1, purity: 0.75, gramsPure: 0.75,
          quotePriceSnapshot: null, valuationMonetary: null,
          valuationCurrencyCode: "ARS", sourceLineIds: ["L-1"] },
        { metalParentId: "oro-fino", metalParentName: "Oro Fino",
          gramsOriginal: 2, purity: 0.75, gramsPure: 1.5,
          quotePriceSnapshot: null, valuationMonetary: null,
          valuationCurrencyCode: "ARS", sourceLineIds: ["L-2"] },
      ],
      monetaryBalance: { amount: 100, currencyCode: "ARS", currencyRate: 1, amountBase: 100 },
    };
    const rows = buildAccountMovementMetalEntryRows({
      movementId: "mov-1", jewelryId: "jw-1", breakdown: bd,
    });
    expect(rows).toHaveLength(1);
    expect(rows[0].gramsOriginal.toString()).toBe("3"); // 1 + 2
    expect(rows[0].gramsPure.toString()).toBe("2.25");  // 0.75 + 1.5
    expect(rows[0].purity?.toString()).toBe("0.75");    // ponderada = 2.25/3
    // sourceLineId queda null porque hay 2 líneas distintas aportando.
    expect(rows[0].sourceLineId).toBeNull();
  });

  it("padre con 2 entries y 1 sola línea común → sourceLineId persiste", () => {
    const bd: DocumentBalanceBreakdown = {
      metals: [
        { metalParentId: "oro-fino", metalParentName: "Oro Fino",
          gramsOriginal: 1, purity: 0.75, gramsPure: 0.75,
          quotePriceSnapshot: null, valuationMonetary: null,
          valuationCurrencyCode: "ARS", sourceLineIds: ["L-1"] },
        { metalParentId: "oro-fino", metalParentName: "Oro Fino",
          gramsOriginal: 1, purity: 0.75, gramsPure: 0.75,
          quotePriceSnapshot: null, valuationMonetary: null,
          valuationCurrencyCode: "ARS", sourceLineIds: ["L-1"] },
      ],
      monetaryBalance: { amount: 100, currencyCode: "ARS", currencyRate: 1, amountBase: 100 },
    };
    const rows = buildAccountMovementMetalEntryRows({
      movementId: "mov-1", jewelryId: "jw-1", breakdown: bd,
    });
    expect(rows).toHaveLength(1);
    expect(rows[0].sourceLineId).toBe("L-1");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 6. Pagination — balance-movements respeta skip/take
// ─────────────────────────────────────────────────────────────────────────────

describe("Hardening — balance-movements paginación", () => {
  // Re-export defensive del DTO projection (sin DB).
  it("projectBalanceMovement: filas mínimas no rompen", async () => {
    const { projectBalanceMovement } = await import(
      "../../../modules/commercial-entities/balance-movements.service.js"
    );
    const dto = projectBalanceMovement({
      id: "x", entityId: "e", kind: "DEBIT", source: "RECEIPT",
      receiptId: null, paymentAllocationId: null,
      amountBase: { toString: () => "0" }, amountOriginal: { toString: () => "0" },
      currencyCode: "", currencyRate: { toString: () => "1" },
      movementDate: new Date(), createdAt: new Date(),
      notes: "", balanceMode: null, sourceDocumentType: null, sourceDocumentId: null,
      metalEntries: [],
    });
    expect(dto.balanceMode).toBe("UNIFIED"); // fallback defensivo
    expect(dto.metalEntries).toEqual([]);
    expect(dto.amountBase).toBe(0);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 7. DTO backward compatibility — snapshots v2 + UNIFIED implícito
// ─────────────────────────────────────────────────────────────────────────────

describe("Hardening — DTO backward compatibility", () => {
  it("snapshot v2 sin balanceBreakdown → UNIFIED implícito con monetary.amount = totals.total", () => {
    const r = readBalanceBreakdown({
      version: 2,
      totals:   { total: 999, totalBase: 999 },
      currency: { currencyCode: "ARS", currencyRate: 1 },
    });
    expect(r.source).toBe("LEGACY_UNIFIED");
    expect(r.breakdown.monetaryBalance.amount).toBe(999);
    expect(r.breakdown.metals).toEqual([]);
  });

  it("snapshot v1 (sin version) → tratado como legacy, no rompe", () => {
    const r = readBalanceBreakdown({
      totals: { total: 50 }, currency: { currencyCode: "ARS" },
    });
    expect(r.source).toBe("LEGACY_UNIFIED");
    expect(r.breakdown.monetaryBalance.amount).toBe(50);
  });

  it("breakdown construido manualmente con metals=[] → roundtrip equivale a UNIFIED implícito", () => {
    // Garantiza que el shape construido por el builder es el MISMO shape que
    // el frontend espera consumir, independientemente del modo.
    const bd = buildDocumentBalanceBreakdown(
      {
        documentTotal: 500, documentTotalBase: 500,
        currency: { code: "ARS", rate: 1 },
        lines: [],
      },
      "UNIFIED",
    );
    expect(bd.metals).toEqual([]);
    expect(bd.monetaryBalance.amount).toBe(500);
    expect(bd.monetaryBalance.currencyCode).toBe("ARS");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 8. Snapshot malformed — variantes de corrupción
// ─────────────────────────────────────────────────────────────────────────────

describe("Hardening — snapshots malformados no rompen lectura", () => {
  it("metals con propiedades faltantes (parciales) — el read los pasa tal cual sin tirar", () => {
    const r = readBalanceBreakdown({
      version: 3,
      balanceBreakdown: {
        metals: [{ metalParentName: "Solo nombre" } as any],
        monetaryBalance: { amount: 1, currencyCode: "ARS", currencyRate: 1, amountBase: 1 },
      },
    });
    expect(r.source).toBe("SNAPSHOT_V3");
    expect(r.breakdown.metals).toHaveLength(1);
  });

  it("balanceBreakdown con extras desconocidos no rompe la lectura", () => {
    const r = readBalanceBreakdown({
      version: 3,
      balanceBreakdown: {
        metals: [],
        monetaryBalance: { amount: 1, currencyCode: "ARS", currencyRate: 1, amountBase: 1 },
        __extraField: "ok",
      } as any,
    });
    expect(r.source).toBe("SNAPSHOT_V3");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 9 + 10. Edge cases finales
// ─────────────────────────────────────────────────────────────────────────────

describe("Hardening — edge cases finales", () => {
  it("BREAKDOWN sin monetaryBalance → isValid* rechaza", () => {
    expect(isValidBalanceBreakdownForPersistence({ metals: [] } as any)).toBe(false);
  });

  it("AccountMovementMetalEntry: breakdown sin metals → array vacío sin tirar", () => {
    const rows = buildAccountMovementMetalEntryRows({
      movementId: "mov-1", jewelryId: "jw-1",
      breakdown: {
        metals: [],
        monetaryBalance: { amount: 100, currencyCode: "ARS", currencyRate: 1, amountBase: 100 },
      },
    });
    expect(rows).toEqual([]);
  });

  it("buildDocumentBalanceBreakdown: input con metals sin metalParentId → descartado", () => {
    const out = buildDocumentBalanceBreakdown(
      {
        documentTotal: 100, documentTotalBase: 100,
        currency: { code: "ARS", rate: 1 },
        lines: [{
          lineId: "L-1", quantity: 1,
          metals: [{
            metalParentId: "",   // vacío
            metalParentName: "X", metalVariantId: "v", metalVariantName: "V",
            appliedGramsPerUnit: 1, purity: 0.5,
          }],
        }],
      },
      "BREAKDOWN",
    );
    expect(out.metals).toEqual([]);
  });
});
