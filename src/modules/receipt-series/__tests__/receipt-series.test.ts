// src/modules/receipt-series/__tests__/receipt-series.test.ts
// ============================================================================
// Tests del CRUD admin de ReceiptSeries — Etapa A (2026-05-29).
//
// Estrategia: mockeamos `prisma` por completo. Validamos la SEMÁNTICA del
// service (multi-tenant en where clause, soft-delete con guard, validación
// de nextNumber ≥ último + 1, manejo de unicidad, select público sin
// `deletedAt`/`jewelryId`).
//
// Schemas Zod se testean tangencialmente (creación valida regex de prefix
// y pointOfSale). Tests dedicados de schema se podrían sumar después, pero
// los regex son simples y el cubrimiento via integración alcanza por ahora.
// ============================================================================

import { describe, it, expect, vi, beforeEach } from "vitest";

const mockPrisma = vi.hoisted(() => ({
  receiptSeries: {
    findMany:   vi.fn(),
    findFirst:  vi.fn(),
    create:     vi.fn(),
    update:     vi.fn(),
  },
  receipt: {
    findFirst:  vi.fn(),
    count:      vi.fn(),
  },
}));
vi.mock("../../../lib/prisma.js", () => ({ prisma: mockPrisma }));

import * as service from "../receipt-series.service.js";
import { parseTrailingNumber } from "../receipt-series.service.js";
import {
  createReceiptSeriesSchema,
  updateReceiptSeriesSchema,
} from "../receipt-series.schemas.js";

beforeEach(() => {
  vi.clearAllMocks();
});

// ─────────────────────────────────────────────────────────────────────────────
// 1) Schemas — validación de formato
// ─────────────────────────────────────────────────────────────────────────────

describe("receipt-series.schemas — createReceiptSeriesSchema", () => {
  const valid = {
    name:        "Factura A",
    type:        "INVOICE" as const,
    direction:   "OUTBOUND" as const,
    prefix:      "A",
    pointOfSale: "0001",
    nextNumber:  1,
  };

  it("acepta payload válido", () => {
    const result = createReceiptSeriesSchema.safeParse(valid);
    expect(result.success).toBe(true);
  });

  it("aplica defaults cuando se omiten campos opcionales", () => {
    const result = createReceiptSeriesSchema.safeParse({
      name: "Factura A", type: "INVOICE", direction: "OUTBOUND",
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.prefix).toBe("");
      expect(result.data.pointOfSale).toBe("0001");
      expect(result.data.nextNumber).toBe(1);
      expect(result.data.isActive).toBe(true);
    }
  });

  it("rechaza prefix con minúsculas", () => {
    const result = createReceiptSeriesSchema.safeParse({ ...valid, prefix: "fa" });
    expect(result.success).toBe(false);
  });

  it("rechaza prefix con 4 caracteres", () => {
    const result = createReceiptSeriesSchema.safeParse({ ...valid, prefix: "ABCD" });
    expect(result.success).toBe(false);
  });

  it("acepta prefix vacío y de 1, 2 o 3 letras mayúsculas", () => {
    for (const prefix of ["", "A", "FA", "ABC"]) {
      const result = createReceiptSeriesSchema.safeParse({ ...valid, prefix });
      expect(result.success, `prefix="${prefix}" debería pasar`).toBe(true);
    }
  });

  it("rechaza pointOfSale != 4 dígitos", () => {
    for (const pos of ["1", "001", "00001", "abcd"]) {
      const result = createReceiptSeriesSchema.safeParse({ ...valid, pointOfSale: pos });
      expect(result.success).toBe(false);
    }
  });

  it("rechaza nextNumber < 1", () => {
    const result = createReceiptSeriesSchema.safeParse({ ...valid, nextNumber: 0 });
    expect(result.success).toBe(false);
  });

  it("rechaza nextNumber no entero", () => {
    const result = createReceiptSeriesSchema.safeParse({ ...valid, nextNumber: 1.5 });
    expect(result.success).toBe(false);
  });

  it("rechaza type no soportado", () => {
    const result = createReceiptSeriesSchema.safeParse({ ...valid, type: "GARBAGE" });
    expect(result.success).toBe(false);
  });
});

describe("receipt-series.schemas — updateReceiptSeriesSchema", () => {
  it("acepta patch parcial (solo isActive)", () => {
    const result = updateReceiptSeriesSchema.safeParse({ isActive: false });
    expect(result.success).toBe(true);
  });

  it("NO acepta type ni direction (campos inmutables)", () => {
    expect(updateReceiptSeriesSchema.safeParse({ type: "QUOTE" }).success).toBe(false);
    expect(updateReceiptSeriesSchema.safeParse({ direction: "INBOUND" }).success).toBe(false);
  });

  it("acepta nextNumber válido", () => {
    expect(updateReceiptSeriesSchema.safeParse({ nextNumber: 100 }).success).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 2) parseTrailingNumber (helper puro)
// ─────────────────────────────────────────────────────────────────────────────

describe("parseTrailingNumber", () => {
  it("'A-0001-00000025' → 25", () => {
    expect(parseTrailingNumber("A-0001-00000025")).toBe(25);
  });

  it("'B-0002-00000001' → 1", () => {
    expect(parseTrailingNumber("B-0002-00000001")).toBe(1);
  });

  it("'-0001-00000999' → 999 (prefix vacío)", () => {
    expect(parseTrailingNumber("-0001-00000999")).toBe(999);
  });

  it("'DRAFT-uuid' → null (no termina en dígitos)", () => {
    expect(parseTrailingNumber("DRAFT-abc123-no-digits")).toBe(null);
  });

  it("'sin-numero' → null", () => {
    expect(parseTrailingNumber("sin-numero")).toBe(null);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 3) listReceiptSeries
// ─────────────────────────────────────────────────────────────────────────────

describe("listReceiptSeries", () => {
  it("filtra por jewelryId + deletedAt null + orden canónico + select público", async () => {
    mockPrisma.receiptSeries.findMany.mockResolvedValueOnce([]);
    await service.listReceiptSeries("jw-1");

    expect(mockPrisma.receiptSeries.findMany).toHaveBeenCalledTimes(1);
    const args = mockPrisma.receiptSeries.findMany.mock.calls[0]![0]!;
    expect(args.where).toEqual({ jewelryId: "jw-1", deletedAt: null });
    expect(args.orderBy).toEqual([
      { type:        "asc" },
      { direction:   "asc" },
      { prefix:      "asc" },
      { pointOfSale: "asc" },
    ]);
    // Select público: contiene los campos visibles y NO deletedAt / jewelryId.
    expect(args.select.id).toBe(true);
    expect(args.select.type).toBe(true);
    expect(args.select.deletedAt).toBeUndefined();
    expect(args.select.jewelryId).toBeUndefined();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 4) getReceiptSeries — multi-tenant + 404
// ─────────────────────────────────────────────────────────────────────────────

describe("getReceiptSeries", () => {
  it("happy path: devuelve la serie del tenant correcto", async () => {
    mockPrisma.receiptSeries.findFirst.mockResolvedValueOnce({
      id: "s-1", name: "Factura A", type: "INVOICE", direction: "OUTBOUND",
      prefix: "A", pointOfSale: "0001", nextNumber: 5, isActive: true,
      createdAt: new Date(), updatedAt: new Date(),
    });
    const out = await service.getReceiptSeries("s-1", "jw-1");
    expect(out.id).toBe("s-1");

    const args = mockPrisma.receiptSeries.findFirst.mock.calls[0]![0]!;
    expect(args.where).toEqual({ id: "s-1", jewelryId: "jw-1", deletedAt: null });
  });

  it("404 cuando no existe en el tenant (cross-tenant safe)", async () => {
    mockPrisma.receiptSeries.findFirst.mockResolvedValueOnce(null);
    await expect(service.getReceiptSeries("s-1", "jw-other"))
      .rejects.toMatchObject({ status: 404 });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 5) createReceiptSeries
// ─────────────────────────────────────────────────────────────────────────────

describe("createReceiptSeries", () => {
  const validInput = {
    name:        "Factura A",
    type:        "INVOICE" as const,
    direction:   "OUTBOUND" as const,
    prefix:      "A",
    pointOfSale: "0001",
    nextNumber:  1,
    isActive:    true,
  };

  it("happy path: crea con jewelryId y devuelve select público", async () => {
    mockPrisma.receiptSeries.create.mockResolvedValueOnce({
      id: "s-new", ...validInput,
      createdAt: new Date(), updatedAt: new Date(),
    });
    const row = await service.createReceiptSeries("jw-1", validInput);
    expect(row.id).toBe("s-new");

    const args = mockPrisma.receiptSeries.create.mock.calls[0]![0]!;
    expect(args.data.jewelryId).toBe("jw-1");
    expect(args.data.type).toBe("INVOICE");
    expect(args.data.prefix).toBe("A");
    expect(args.data.pointOfSale).toBe("0001");
    expect(args.data.nextNumber).toBe(1);
    expect(args.data.isActive).toBe(true);
  });

  it("conflicto de unicidad (P2002) → 409 con mensaje accionable", async () => {
    const p2002: any = new Error("Unique constraint failed");
    p2002.code = "P2002";
    mockPrisma.receiptSeries.create.mockRejectedValueOnce(p2002);
    await expect(service.createReceiptSeries("jw-1", validInput))
      .rejects.toMatchObject({
        status: 409,
        message: expect.stringMatching(/Ya existe una serie/),
      });
  });

  it("error genérico se propaga (no se traga)", async () => {
    mockPrisma.receiptSeries.create.mockRejectedValueOnce(new Error("DB caída"));
    await expect(service.createReceiptSeries("jw-1", validInput))
      .rejects.toThrow("DB caída");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 6) updateReceiptSeries
// ─────────────────────────────────────────────────────────────────────────────

describe("updateReceiptSeries", () => {
  const baseSeries = {
    id: "s-1", type: "INVOICE", direction: "OUTBOUND",
    prefix: "A", pointOfSale: "0001", nextNumber: 5,
  };

  it("404 si la serie no pertenece al tenant", async () => {
    mockPrisma.receiptSeries.findFirst.mockResolvedValueOnce(null);
    await expect(service.updateReceiptSeries("s-1", "jw-other", { name: "X" }))
      .rejects.toMatchObject({ status: 404 });
    expect(mockPrisma.receiptSeries.update).not.toHaveBeenCalled();
  });

  it("happy path: cambia name + isActive", async () => {
    mockPrisma.receiptSeries.findFirst.mockResolvedValueOnce(baseSeries);
    mockPrisma.receiptSeries.update.mockResolvedValueOnce({
      id: "s-1", name: "Renombrada", type: "INVOICE", direction: "OUTBOUND",
      prefix: "A", pointOfSale: "0001", nextNumber: 5, isActive: false,
      createdAt: new Date(), updatedAt: new Date(),
    });
    const out = await service.updateReceiptSeries("s-1", "jw-1", {
      name: "Renombrada", isActive: false,
    });
    expect(out.name).toBe("Renombrada");
    expect(out.isActive).toBe(false);

    const args = mockPrisma.receiptSeries.update.mock.calls[0]![0]!;
    expect(args.where).toEqual({ id: "s-1" });
    expect(args.data).toEqual({ name: "Renombrada", isActive: false });
  });

  it("nextNumber válido (mayor al último emitido) → permite", async () => {
    mockPrisma.receiptSeries.findFirst.mockResolvedValueOnce(baseSeries);
    mockPrisma.receipt.findFirst.mockResolvedValueOnce({ code: "A-0001-00000025" });
    mockPrisma.receiptSeries.update.mockResolvedValueOnce({
      id: "s-1", name: "Factura A", type: "INVOICE", direction: "OUTBOUND",
      prefix: "A", pointOfSale: "0001", nextNumber: 30, isActive: true,
      createdAt: new Date(), updatedAt: new Date(),
    });
    const out = await service.updateReceiptSeries("s-1", "jw-1", { nextNumber: 30 });
    expect(out.nextNumber).toBe(30);
  });

  it("nextNumber ≤ último emitido → 400 con mensaje accionable (BLOQUEO CRÍTICO)", async () => {
    mockPrisma.receiptSeries.findFirst.mockResolvedValueOnce(baseSeries);
    mockPrisma.receipt.findFirst.mockResolvedValueOnce({ code: "A-0001-00000025" });
    await expect(service.updateReceiptSeries("s-1", "jw-1", { nextNumber: 10 }))
      .rejects.toMatchObject({
        status: 400,
        message: expect.stringMatching(/No se puede establecer un próximo número menor/),
      });
    expect(mockPrisma.receiptSeries.update).not.toHaveBeenCalled();
  });

  it("nextNumber = último emitido exacto → 400 (debe ser estrictamente mayor)", async () => {
    mockPrisma.receiptSeries.findFirst.mockResolvedValueOnce(baseSeries);
    mockPrisma.receipt.findFirst.mockResolvedValueOnce({ code: "A-0001-00000025" });
    await expect(service.updateReceiptSeries("s-1", "jw-1", { nextNumber: 25 }))
      .rejects.toMatchObject({ status: 400 });
  });

  it("nextNumber sin Receipts emitidos previos → permite cualquier valor ≥ 1", async () => {
    mockPrisma.receiptSeries.findFirst.mockResolvedValueOnce(baseSeries);
    mockPrisma.receipt.findFirst.mockResolvedValueOnce(null); // sin emitidos
    mockPrisma.receiptSeries.update.mockResolvedValueOnce({
      id: "s-1", name: "Factura A", type: "INVOICE", direction: "OUTBOUND",
      prefix: "A", pointOfSale: "0001", nextNumber: 100, isActive: true,
      createdAt: new Date(), updatedAt: new Date(),
    });
    const out = await service.updateReceiptSeries("s-1", "jw-1", { nextNumber: 100 });
    expect(out.nextNumber).toBe(100);
  });

  it("conflicto de unicidad al cambiar prefix → 409", async () => {
    mockPrisma.receiptSeries.findFirst.mockResolvedValueOnce(baseSeries);
    const p2002: any = new Error("Unique constraint failed");
    p2002.code = "P2002";
    mockPrisma.receiptSeries.update.mockRejectedValueOnce(p2002);
    await expect(service.updateReceiptSeries("s-1", "jw-1", { prefix: "B" }))
      .rejects.toMatchObject({ status: 409 });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 7) softDeleteReceiptSeries
// ─────────────────────────────────────────────────────────────────────────────

describe("softDeleteReceiptSeries", () => {
  it("404 si la serie no pertenece al tenant", async () => {
    mockPrisma.receiptSeries.findFirst.mockResolvedValueOnce(null);
    await expect(service.softDeleteReceiptSeries("s-1", "jw-other"))
      .rejects.toMatchObject({ status: 404 });
    expect(mockPrisma.receiptSeries.update).not.toHaveBeenCalled();
  });

  it("happy path: sin receipts emitidos → soft-delete con deletedAt", async () => {
    mockPrisma.receiptSeries.findFirst.mockResolvedValueOnce({ id: "s-1" });
    mockPrisma.receipt.count.mockResolvedValueOnce(0);
    mockPrisma.receiptSeries.update.mockResolvedValueOnce({ id: "s-1" });

    const out = await service.softDeleteReceiptSeries("s-1", "jw-1");
    expect(out).toEqual({ id: "s-1" });

    // El update setea deletedAt (no borra físicamente).
    const args = mockPrisma.receiptSeries.update.mock.calls[0]![0]!;
    expect(args.where).toEqual({ id: "s-1" });
    expect(args.data.deletedAt).toBeInstanceOf(Date);
  });

  it("BLOQUEO: serie con ≥1 receipt ISSUED → 409 con mensaje accionable", async () => {
    mockPrisma.receiptSeries.findFirst.mockResolvedValueOnce({ id: "s-1" });
    mockPrisma.receipt.count.mockResolvedValueOnce(3); // 3 emitidos
    await expect(service.softDeleteReceiptSeries("s-1", "jw-1"))
      .rejects.toMatchObject({
        status: 409,
        message: "No se puede eliminar una serie con comprobantes emitidos.",
      });
    expect(mockPrisma.receiptSeries.update).not.toHaveBeenCalled();
  });

  it("count usa filtros status=ISSUED + jewelryId (multi-tenant + scope correcto)", async () => {
    mockPrisma.receiptSeries.findFirst.mockResolvedValueOnce({ id: "s-1" });
    mockPrisma.receipt.count.mockResolvedValueOnce(0);
    mockPrisma.receiptSeries.update.mockResolvedValueOnce({ id: "s-1" });
    await service.softDeleteReceiptSeries("s-1", "jw-1");

    const countArgs = mockPrisma.receipt.count.mock.calls[0]![0]!;
    expect(countArgs.where).toEqual({
      seriesId: "s-1",
      jewelryId: "jw-1",
      status: "ISSUED",
    });
  });

  it("draftReceipts NO bloquean el delete (solo ISSUED bloquea)", async () => {
    // Validamos via el filtro del count: solo cuenta status=ISSUED.
    // Si hay 0 ISSUED, el delete procede aunque haya 100 DRAFTs.
    mockPrisma.receiptSeries.findFirst.mockResolvedValueOnce({ id: "s-1" });
    mockPrisma.receipt.count.mockResolvedValueOnce(0); // 0 ISSUED, drafts no se cuentan
    mockPrisma.receiptSeries.update.mockResolvedValueOnce({ id: "s-1" });
    const out = await service.softDeleteReceiptSeries("s-1", "jw-1");
    expect(out.id).toBe("s-1");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 8) Multi-tenant safety — verificación cross-cutting
// ─────────────────────────────────────────────────────────────────────────────

describe("Multi-tenant safety — todas las queries filtran por jewelryId", () => {
  it("list: where incluye jewelryId", async () => {
    mockPrisma.receiptSeries.findMany.mockResolvedValueOnce([]);
    await service.listReceiptSeries("jw-X");
    expect(mockPrisma.receiptSeries.findMany.mock.calls[0]![0]!.where.jewelryId).toBe("jw-X");
  });

  it("get: where incluye jewelryId", async () => {
    mockPrisma.receiptSeries.findFirst.mockResolvedValueOnce({
      id: "s-1", name: "x", type: "INVOICE", direction: "OUTBOUND",
      prefix: "A", pointOfSale: "0001", nextNumber: 1, isActive: true,
      createdAt: new Date(), updatedAt: new Date(),
    });
    await service.getReceiptSeries("s-1", "jw-X");
    expect(mockPrisma.receiptSeries.findFirst.mock.calls[0]![0]!.where.jewelryId).toBe("jw-X");
  });

  it("create: data incluye jewelryId del caller", async () => {
    mockPrisma.receiptSeries.create.mockResolvedValueOnce({
      id: "s-1", name: "x", type: "INVOICE", direction: "OUTBOUND",
      prefix: "", pointOfSale: "0001", nextNumber: 1, isActive: true,
      createdAt: new Date(), updatedAt: new Date(),
    });
    await service.createReceiptSeries("jw-X", {
      name: "x", type: "INVOICE", direction: "OUTBOUND",
      prefix: "", pointOfSale: "0001", nextNumber: 1, isActive: true,
    });
    expect(mockPrisma.receiptSeries.create.mock.calls[0]![0]!.data.jewelryId).toBe("jw-X");
  });

  it("update: findFirst usa jewelryId del caller para 404 cross-tenant", async () => {
    mockPrisma.receiptSeries.findFirst.mockResolvedValueOnce(null);
    await expect(service.updateReceiptSeries("s-1", "jw-X", { name: "y" }))
      .rejects.toMatchObject({ status: 404 });
    expect(mockPrisma.receiptSeries.findFirst.mock.calls[0]![0]!.where.jewelryId).toBe("jw-X");
  });

  it("delete: findFirst usa jewelryId + count usa jewelryId", async () => {
    mockPrisma.receiptSeries.findFirst.mockResolvedValueOnce({ id: "s-1" });
    mockPrisma.receipt.count.mockResolvedValueOnce(0);
    mockPrisma.receiptSeries.update.mockResolvedValueOnce({ id: "s-1" });
    await service.softDeleteReceiptSeries("s-1", "jw-X");
    expect(mockPrisma.receiptSeries.findFirst.mock.calls[0]![0]!.where.jewelryId).toBe("jw-X");
    expect(mockPrisma.receipt.count.mock.calls[0]![0]!.where.jewelryId).toBe("jw-X");
  });
});
