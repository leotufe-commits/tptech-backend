// src/modules/commercial-entities/__tests__/balance-movements.test.ts
// =============================================================================
// T57 (Fase 3B.7) — Tests del DTO de balance movements.
//
// Función pura `projectBalanceMovement(row)`: proyecta una fila de
// `CurrentAccountMovement` (con metalEntries hidratadas) al DTO público
// que consume el frontend.
//
// Reglas testeadas:
//   · `balanceMode` siempre presente (default UNIFIED si la fila no lo trae).
//   · `metalEntries[]` viajan con todos sus campos físicos (gramos, purity).
//   · `sourceDocumentType` y `sourceDocumentId` viajan tal cual.
//   · Decimals (Prisma) se convierten a number en el DTO.
//   · Dates a ISO string.
//   · Históricos pre-3B.6 (sin metalEntries) → array vacío, no rompe.
// =============================================================================

import { describe, it, expect } from "vitest";
import {
  projectBalanceMovement,
  projectMetalEntry,
} from "../balance-movements.service.js";

// Mock minimal de Prisma.Decimal — solo necesitamos `.toString()` para que
// `toNum` lo procese igual que en runtime real.
function dec(value: string | number) {
  return { toString: () => String(value) };
}

// ─────────────────────────────────────────────────────────────────────────────
// projectBalanceMovement — UNIFIED
// ─────────────────────────────────────────────────────────────────────────────

describe("projectBalanceMovement — UNIFIED", () => {
  it("proyecta correctamente un movimiento UNIFIED con metalEntries vacío", () => {
    const row = {
      id:                  "mov-1",
      entityId:            "ent-1",
      kind:                "DEBIT",
      source:              "RECEIPT",
      receiptId:           "rcp-1",
      paymentAllocationId: null,
      amountBase:          dec("1000.50"),
      amountOriginal:      dec("1000.50"),
      currencyCode:        "ARS",
      currencyRate:        dec("1"),
      movementDate:        new Date("2026-05-22T10:00:00Z"),
      createdAt:           new Date("2026-05-22T10:00:00Z"),
      notes:               "Receipt A-0001-0001",
      balanceMode:         "UNIFIED",
      sourceDocumentType:  "SALE",
      sourceDocumentId:    "sale-1",
      metalEntries:        [],
    };
    const dto = projectBalanceMovement(row);
    expect(dto.balanceMode).toBe("UNIFIED");
    expect(dto.amountBase).toBe(1000.5);
    expect(dto.amountOriginal).toBe(1000.5);
    expect(dto.currencyCode).toBe("ARS");
    expect(dto.sourceDocumentType).toBe("SALE");
    expect(dto.sourceDocumentId).toBe("sale-1");
    expect(dto.metalEntries).toEqual([]);
  });

  it("fallback balanceMode=UNIFIED cuando la fila lo trae null/undefined (histórico)", () => {
    const row = {
      id: "mov-old", entityId: "ent-1", kind: "DEBIT", source: "RECEIPT",
      receiptId: null, paymentAllocationId: null,
      amountBase: dec("500"), amountOriginal: dec("500"),
      currencyCode: "ARS", currencyRate: dec("1"),
      movementDate: new Date(), createdAt: new Date(),
      notes: "", balanceMode: null,
      sourceDocumentType: null, sourceDocumentId: null,
      metalEntries: [],
    };
    const dto = projectBalanceMovement(row);
    expect(dto.balanceMode).toBe("UNIFIED");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// projectBalanceMovement — BREAKDOWN
// ─────────────────────────────────────────────────────────────────────────────

describe("projectBalanceMovement — BREAKDOWN con metalEntries", () => {
  it("metalEntries viajan completas (gramos físicos + purity + sourceLineId)", () => {
    const row = {
      id: "mov-2", entityId: "ent-1", kind: "DEBIT", source: "RECEIPT",
      receiptId: "rcp-2", paymentAllocationId: null,
      amountBase: dec("25000"), amountOriginal: dec("25"),
      currencyCode: "USD", currencyRate: dec("1000"),
      movementDate: new Date("2026-05-22T10:00:00Z"),
      createdAt:    new Date("2026-05-22T10:00:00Z"),
      notes: "Receipt A-0002",
      balanceMode: "BREAKDOWN",
      sourceDocumentType: "SALE",
      sourceDocumentId:   "sale-2",
      metalEntries: [
        {
          id:              "me-1",
          metalParentId:   "oro-fino",
          metalParentName: "Oro Fino",
          gramsOriginal:   dec("2"),
          purity:          dec("0.75"),
          gramsPure:       dec("1.5"),
          sourceLineId:    "line-1",
          createdAt:       new Date("2026-05-22T10:00:00Z"),
        },
      ],
    };
    const dto = projectBalanceMovement(row);
    expect(dto.balanceMode).toBe("BREAKDOWN");
    expect(dto.metalEntries).toHaveLength(1);
    const entry = dto.metalEntries[0];
    expect(entry.metalParentId).toBe("oro-fino");
    expect(entry.metalParentName).toBe("Oro Fino");
    expect(entry.gramsOriginal).toBe(2);
    expect(entry.purity).toBe(0.75);
    expect(entry.gramsPure).toBe(1.5);
    expect(entry.sourceLineId).toBe("line-1");
  });

  it("multi-metal: Oro + Plata viajan como entries separadas", () => {
    const row = {
      id: "mov-3", entityId: "ent-1", kind: "DEBIT", source: "RECEIPT",
      receiptId: "rcp-3", paymentAllocationId: null,
      amountBase: dec("0"), amountOriginal: dec("0"),
      currencyCode: "ARS", currencyRate: dec("1"),
      movementDate: new Date(), createdAt: new Date(),
      notes: "", balanceMode: "BREAKDOWN",
      sourceDocumentType: "SALE", sourceDocumentId: "sale-3",
      metalEntries: [
        { id: "me-1", metalParentId: "oro-fino",  metalParentName: "Oro Fino",
          gramsOriginal: dec("1"),  purity: dec("0.75"),  gramsPure: dec("0.75"),
          sourceLineId: null, createdAt: new Date() },
        { id: "me-2", metalParentId: "plata-925", metalParentName: "Plata 925",
          gramsOriginal: dec("10"), purity: dec("0.925"), gramsPure: dec("9.25"),
          sourceLineId: null, createdAt: new Date() },
      ],
    };
    const dto = projectBalanceMovement(row);
    expect(dto.metalEntries).toHaveLength(2);
    expect(dto.metalEntries[0].metalParentName).toBe("Oro Fino");
    expect(dto.metalEntries[1].metalParentName).toBe("Plata 925");
    expect(dto.metalEntries[1].gramsPure).toBe(9.25);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// projectMetalEntry — purity null
// ─────────────────────────────────────────────────────────────────────────────

describe("projectMetalEntry — edge cases", () => {
  it("purity = null se preserva (caso edge gramos=0 / legacy)", () => {
    const row = {
      id: "me-x", metalParentId: "oro-fino", metalParentName: "Oro Fino",
      gramsOriginal: dec("0.5"), purity: null, gramsPure: dec("0.5"),
      sourceLineId: null, createdAt: new Date(),
    };
    const dto = projectMetalEntry(row);
    expect(dto.purity).toBeNull();
    expect(dto.gramsPure).toBe(0.5);
  });

  it("metalParentId null (edge) se preserva", () => {
    const row = {
      id: "me-y", metalParentId: null, metalParentName: "Sin padre",
      gramsOriginal: dec("1"), purity: dec("1"), gramsPure: dec("1"),
      sourceLineId: null, createdAt: new Date(),
    };
    const dto = projectMetalEntry(row);
    expect(dto.metalParentId).toBeNull();
    expect(dto.metalParentName).toBe("Sin padre");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Trazabilidad "Ver origen"
// ─────────────────────────────────────────────────────────────────────────────

describe("projectBalanceMovement — trazabilidad (Ver origen)", () => {
  it("sourceDocumentType y sourceDocumentId viajan correctamente", () => {
    const row = {
      id: "mov-tr", entityId: "ent-1", kind: "DEBIT", source: "RECEIPT",
      receiptId: "rcp-tr", paymentAllocationId: null,
      amountBase: dec("1"), amountOriginal: dec("1"),
      currencyCode: "ARS", currencyRate: dec("1"),
      movementDate: new Date(), createdAt: new Date(),
      notes: "", balanceMode: "UNIFIED",
      sourceDocumentType: "SALE",
      sourceDocumentId:   "sale-abc123",
      metalEntries: [],
    };
    const dto = projectBalanceMovement(row);
    expect(dto.sourceDocumentType).toBe("SALE");
    expect(dto.sourceDocumentId).toBe("sale-abc123");
    // El receiptId también viaja (trazabilidad pre-3B.6).
    expect(dto.receiptId).toBe("rcp-tr");
  });

  it("documentos pre-3B.6 sin sourceDocument* → null + UNIFIED implícito", () => {
    const row = {
      id: "mov-legacy", entityId: "ent-1", kind: "DEBIT", source: "RECEIPT",
      receiptId: "rcp-legacy", paymentAllocationId: null,
      amountBase: dec("100"), amountOriginal: dec("100"),
      currencyCode: "ARS", currencyRate: dec("1"),
      movementDate: new Date(), createdAt: new Date(),
      notes: "", balanceMode: null,
      sourceDocumentType: null, sourceDocumentId: null,
      metalEntries: [],
    };
    const dto = projectBalanceMovement(row);
    expect(dto.balanceMode).toBe("UNIFIED");
    expect(dto.sourceDocumentType).toBeNull();
    expect(dto.sourceDocumentId).toBeNull();
    expect(dto.metalEntries).toEqual([]);
  });
});
