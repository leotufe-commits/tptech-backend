// src/modules/sales/__tests__/cancel-emits-credit-note.test.ts
//
// Etapa 1.2 — Verifica que `cancelSale` + `onSaleCancelled` emiten una
// Nota de Crédito + movimiento de cuenta corriente CREDIT reverso,
// dejando intacto el Receipt INVOICE original y el movimiento DEBIT
// original. Regla "nada se pisa, todo se encadena".
//
// Cubre:
//   1. NC emitida con correctedReceiptId apuntando al original.
//   2. CurrentAccountMovement CREDIT con sourceDocumentType=SALE_CANCEL.
//   3. Receipt original intacto.
//   4. BREAKDOWN: AccountMovementMetalEntry reversas positivas.
//   5. paidAmount > 0 bloquea cancelación (409).
//   6. Sale DRAFT (sin Receipt original) no emite NC.
//   7. Auto-provisión de serie CREDIT_NOTE si no existe.
//   8. Convención de signos: todos positivos.

import { describe, it, expect, vi, beforeEach } from "vitest";
import { Prisma } from "@prisma/client";

// ── Mocks Prisma ────────────────────────────────────────────────────────────
const mockPrisma = vi.hoisted(() => ({
  sale: { findFirst: vi.fn(), findUnique: vi.fn(), update: vi.fn() },
  articleMovement: { findUnique: vi.fn(), update: vi.fn() },
  entityBalanceEntry: { updateMany: vi.fn() },
  receipt: { findFirst: vi.fn(), create: vi.fn() },
  receiptLine: { createMany: vi.fn() },
  receiptSeries: { findFirst: vi.fn(), create: vi.fn(), update: vi.fn() },
  currentAccountMovement: { findFirst: vi.fn(), create: vi.fn() },
  accountMovementMetalEntry: { createMany: vi.fn() },
  $transaction: vi.fn(),
}));
vi.mock("../../../lib/prisma.js", () => ({ prisma: mockPrisma }));

vi.mock("../../../lib/stock-engine.js", () => ({
  applyMovementImpact:   vi.fn(),
  reverseMovementImpact: vi.fn(),
}));

import { onSaleCancelled } from "../../../lib/document-hooks/sale.hook.js";
import { cancelSale } from "../sales.service.js";

const D = Prisma.Decimal;

// ── Helpers ─────────────────────────────────────────────────────────────────

function fakeOriginalReceipt(over: Record<string, any> = {}) {
  return {
    id:               "rec-orig",
    jewelryId:        "j1",
    code:             "A-0001-00000001",
    counterpartyId:   "client-1",
    pricingSnapshot:  { version: 4, totals: { total: 1000 } },
    currencySnapshot: { currencyCode: "ARS", currencyRate: 1 },
    currencyCode:     "ARS",
    currencyRate:     new D("1"),
    subtotal:         new D("1000"),
    discountAmount:   new D("0"),
    taxAmount:        new D("0"),
    total:            new D("1000"),
    totalBase:        new D("1000"),
    issueDate:        new Date("2026-05-20"),
    lines: [{
      articleId:       "a1",
      variantId:       null,
      itemKind:        "ARTICLE_SIMPLE",
      name:            "Anillo",
      code:            "AN-001",
      sku:             "SKU-1",
      barcode:         "",
      quantity:        new D("1"),
      unitPrice:       new D("1000"),
      subtotal:        new D("1000"),
      discountAmount:  new D("0"),
      lineTotal:       new D("1000"),
      taxAmount:       new D("0"),
      totalWithTax:    new D("1000"),
      totalCost:       new D("400"),
      totalMargin:     new D("600"),
      pricingSnapshot: { unitPrice: 1000 },
      sortOrder:       0,
    }],
    ...over,
  };
}

function fakeOriginalMov(over: Record<string, any> = {}) {
  return {
    id:               "mov-debit-orig",
    entityId:         "client-1",
    amountOriginal:   new D("1000"),
    amountBase:       new D("1000"),
    currencySnapshot: { currencyCode: "ARS", currencyRate: 1 },
    currencyCode:     "ARS",
    currencyRate:     new D("1"),
    balanceMode:      "UNIFIED",
    metalEntries:     [],
    ...over,
  };
}

function fakeTx() {
  return {
    receipt: {
      findFirst: vi.fn(),
      create:    vi.fn().mockImplementation(async ({ data, select }) => ({
        id:                 "nc-1",
        code:               data.code,
        total:              data.total,
        correctedReceiptId: data.correctedReceiptId,
      })),
    },
    receiptLine: {
      createMany: vi.fn().mockResolvedValue({ count: 1 }),
    },
    receiptSeries: {
      findFirst: vi.fn(),
      create:    vi.fn(),
      update:    vi.fn(),
    },
    currentAccountMovement: {
      findFirst: vi.fn(),
      create:    vi.fn().mockImplementation(async ({ data }) => ({
        id:         "mov-credit-1",
        kind:       data.kind,
        amountBase: data.amountBase,
      })),
    },
    accountMovementMetalEntry: {
      createMany: vi.fn().mockResolvedValue({ count: 0 }),
    },
    sale: {
      findUnique: vi.fn(),
      update:     vi.fn().mockResolvedValue({}),
    },
    articleMovement: {
      findUnique: vi.fn(),
      update:     vi.fn(),
    },
    entityBalanceEntry: {
      updateMany: vi.fn(),
    },
  };
}

beforeEach(() => {
  vi.clearAllMocks();
});

// ────────────────────────────────────────────────────────────────────────────
// 1. onSaleCancelled directo — NC + correctedReceiptId
// ────────────────────────────────────────────────────────────────────────────
describe("onSaleCancelled — emisión de Nota de Crédito", () => {
  it("emite Receipt CREDIT_NOTE con correctedReceiptId al original", async () => {
    const tx = fakeTx() as any;
    tx.receipt.findFirst.mockResolvedValue(fakeOriginalReceipt());
    tx.currentAccountMovement.findFirst.mockResolvedValue(fakeOriginalMov());
    tx.receiptSeries.findFirst.mockResolvedValue({ id: "series-nc" });
    tx.receiptSeries.update.mockResolvedValue({
      nextNumber: 2, prefix: "NC", pointOfSale: "0001",
    });

    const out = await onSaleCancelled(tx, "sale-1", { issuedById: "u1", note: "" });

    expect(out.creditNote).not.toBeNull();
    expect(out.creditNote?.correctedReceiptId).toBe("rec-orig");

    expect(tx.receipt.create).toHaveBeenCalledTimes(1);
    const createArgs = tx.receipt.create.mock.calls[0][0].data;
    expect(createArgs.type).toBe("CREDIT_NOTE");
    expect(createArgs.direction).toBe("OUTBOUND");
    expect(createArgs.status).toBe("ISSUED");
    expect(createArgs.correctedReceiptId).toBe("rec-orig");
    expect(createArgs.saleId).toBe("sale-1");
    expect(createArgs.counterpartyId).toBe("client-1");
    // Convención: positivos (signo lo da type=CREDIT_NOTE).
    expect(createArgs.total.toString()).toBe("1000");
    expect(createArgs.subtotal.toString()).toBe("1000");
  });

  it("incrementa atómicamente nextNumber de la serie CREDIT_NOTE", async () => {
    const tx = fakeTx() as any;
    tx.receipt.findFirst.mockResolvedValue(fakeOriginalReceipt());
    tx.currentAccountMovement.findFirst.mockResolvedValue(null);
    tx.receiptSeries.findFirst.mockResolvedValue({ id: "series-nc" });
    tx.receiptSeries.update.mockResolvedValue({
      nextNumber: 5, prefix: "NC", pointOfSale: "0001",
    });

    const out = await onSaleCancelled(tx, "sale-1", {});

    expect(tx.receiptSeries.update).toHaveBeenCalledWith({
      where: { id: "series-nc" },
      data:  { nextNumber: { increment: 1 } },
      select: { nextNumber: true, prefix: true, pointOfSale: true },
    });
    expect(out.creditNote?.code).toBe("NC-0001-00000004");
  });

  it("auto-provisiona serie CREDIT_NOTE si no existe", async () => {
    const tx = fakeTx() as any;
    tx.receipt.findFirst.mockResolvedValue(fakeOriginalReceipt());
    tx.currentAccountMovement.findFirst.mockResolvedValue(null);
    tx.receiptSeries.findFirst.mockResolvedValue(null);  // No hay serie
    tx.receiptSeries.create.mockResolvedValue({ id: "series-nc-new" });
    tx.receiptSeries.update.mockResolvedValue({
      nextNumber: 2, prefix: "NC", pointOfSale: "0001",
    });

    const out = await onSaleCancelled(tx, "sale-1", {});

    expect(tx.receiptSeries.create).toHaveBeenCalledTimes(1);
    const createArgs = tx.receiptSeries.create.mock.calls[0][0].data;
    expect(createArgs.type).toBe("CREDIT_NOTE");
    expect(createArgs.direction).toBe("OUTBOUND");
    expect(createArgs.prefix).toBe("NC");
    expect(createArgs.pointOfSale).toBe("0001");
    expect(createArgs.nextNumber).toBe(1);
    expect(out.creditNote?.code).toBe("NC-0001-00000001");
  });

  it("Sale DRAFT (sin Receipt original) → no emite NC, devuelve nulls", async () => {
    const tx = fakeTx() as any;
    tx.receipt.findFirst.mockResolvedValue(null);  // No hay receipt

    const out = await onSaleCancelled(tx, "sale-draft", {});

    expect(out.creditNote).toBeNull();
    expect(out.reverseMovement).toBeNull();
    expect(tx.receipt.create).not.toHaveBeenCalled();
    expect(tx.receiptSeries.update).not.toHaveBeenCalled();
  });
});

// ────────────────────────────────────────────────────────────────────────────
// 2. onSaleCancelled — Receipt original intacto + ReceiptLines espejo
// ────────────────────────────────────────────────────────────────────────────
describe("onSaleCancelled — Receipt original queda intacto", () => {
  it("NO modifica el Receipt original (no se llama update sobre él)", async () => {
    const tx = fakeTx() as any;
    tx.receipt.findFirst.mockResolvedValue(fakeOriginalReceipt());
    tx.currentAccountMovement.findFirst.mockResolvedValue(fakeOriginalMov());
    tx.receiptSeries.findFirst.mockResolvedValue({ id: "series-nc" });
    tx.receiptSeries.update.mockResolvedValue({
      nextNumber: 2, prefix: "NC", pointOfSale: "0001",
    });
    // Anotar si alguien llama a update del receipt — no debería.
    tx.receipt.update = vi.fn();

    await onSaleCancelled(tx, "sale-1", {});

    expect(tx.receipt.update).not.toHaveBeenCalled();
  });

  it("crea ReceiptLine espejo desde las líneas originales", async () => {
    const tx = fakeTx() as any;
    tx.receipt.findFirst.mockResolvedValue(fakeOriginalReceipt());
    tx.currentAccountMovement.findFirst.mockResolvedValue(null);
    tx.receiptSeries.findFirst.mockResolvedValue({ id: "series-nc" });
    tx.receiptSeries.update.mockResolvedValue({
      nextNumber: 2, prefix: "NC", pointOfSale: "0001",
    });

    await onSaleCancelled(tx, "sale-1", {});

    expect(tx.receiptLine.createMany).toHaveBeenCalledTimes(1);
    const lineRows = tx.receiptLine.createMany.mock.calls[0][0].data;
    expect(lineRows).toHaveLength(1);
    expect(lineRows[0].receiptId).toBe("nc-1");
    expect(lineRows[0].articleId).toBe("a1");
    expect(lineRows[0].quantity.toString()).toBe("1");
    // Positivos: el lineTotal copia del original.
    expect(lineRows[0].lineTotal.toString()).toBe("1000");
  });
});

// ────────────────────────────────────────────────────────────────────────────
// 3. onSaleCancelled — CurrentAccountMovement CREDIT reverso
// ────────────────────────────────────────────────────────────────────────────
describe("onSaleCancelled — CurrentAccountMovement reverso", () => {
  it("crea movimiento CREDIT positivo con sourceDocumentType=SALE_CANCEL", async () => {
    const tx = fakeTx() as any;
    tx.receipt.findFirst.mockResolvedValue(fakeOriginalReceipt());
    tx.currentAccountMovement.findFirst.mockResolvedValue(fakeOriginalMov({
      amountBase: new D("1500"), amountOriginal: new D("1500"),
    }));
    tx.receiptSeries.findFirst.mockResolvedValue({ id: "series-nc" });
    tx.receiptSeries.update.mockResolvedValue({
      nextNumber: 2, prefix: "NC", pointOfSale: "0001",
    });

    const out = await onSaleCancelled(tx, "sale-1", { note: "Cliente devolvió producto" });

    expect(tx.currentAccountMovement.create).toHaveBeenCalledTimes(1);
    const movData = tx.currentAccountMovement.create.mock.calls[0][0].data;
    expect(movData.kind).toBe("CREDIT");
    expect(movData.source).toBe("RECEIPT");
    expect(movData.receiptId).toBe("nc-1");
    expect(movData.entityId).toBe("client-1");
    expect(movData.sourceDocumentType).toBe("SALE_CANCEL");
    expect(movData.sourceDocumentId).toBe("sale-1");
    // Convención: positivos. El signo lo da kind=CREDIT.
    expect(movData.amountBase.toString()).toBe("1500");
    expect(movData.amountOriginal.toString()).toBe("1500");
    expect(movData.notes).toContain("Cliente devolvió producto");
    expect(movData.notes).toContain("A-0001-00000001");  // referencia al original

    expect(out.reverseMovement?.kind).toBe("CREDIT");
    expect(out.reverseMovement?.amountBase).toBe(1500);
  });

  it("consumidor final (sin DEBIT original) → emite NC pero NO crea movimiento", async () => {
    const tx = fakeTx() as any;
    tx.receipt.findFirst.mockResolvedValue(fakeOriginalReceipt({ counterpartyId: null }));
    tx.currentAccountMovement.findFirst.mockResolvedValue(null);  // No había DEBIT
    tx.receiptSeries.findFirst.mockResolvedValue({ id: "series-nc" });
    tx.receiptSeries.update.mockResolvedValue({
      nextNumber: 2, prefix: "NC", pointOfSale: "0001",
    });

    const out = await onSaleCancelled(tx, "sale-cf", {});

    expect(out.creditNote).not.toBeNull();
    expect(out.reverseMovement).toBeNull();
    expect(tx.currentAccountMovement.create).not.toHaveBeenCalled();
  });
});

// ────────────────────────────────────────────────────────────────────────────
// 4. onSaleCancelled — BREAKDOWN: metal entries positivas
// ────────────────────────────────────────────────────────────────────────────
describe("onSaleCancelled — BREAKDOWN", () => {
  it("copia AccountMovementMetalEntry positivos al movimiento reverso", async () => {
    const tx = fakeTx() as any;
    tx.receipt.findFirst.mockResolvedValue(fakeOriginalReceipt());
    tx.currentAccountMovement.findFirst.mockResolvedValue(fakeOriginalMov({
      balanceMode: "BREAKDOWN",
      metalEntries: [
        {
          metalParentId:   "metal-au",
          metalParentName: "Oro",
          gramsOriginal:   new D("10"),
          purity:          new D("0.75"),
          gramsPure:       new D("7.5"),
          sourceLineId:    "L1",
        },
        {
          metalParentId:   "metal-ag",
          metalParentName: "Plata",
          gramsOriginal:   new D("20"),
          purity:          new D("0.925"),
          gramsPure:       new D("18.5"),
          sourceLineId:    "L2",
        },
      ],
    }));
    tx.receiptSeries.findFirst.mockResolvedValue({ id: "series-nc" });
    tx.receiptSeries.update.mockResolvedValue({
      nextNumber: 2, prefix: "NC", pointOfSale: "0001",
    });

    await onSaleCancelled(tx, "sale-1", {});

    expect(tx.accountMovementMetalEntry.createMany).toHaveBeenCalledTimes(1);
    const rows = tx.accountMovementMetalEntry.createMany.mock.calls[0][0].data;
    expect(rows).toHaveLength(2);
    expect(rows[0].metalParentId).toBe("metal-au");
    expect(rows[0].gramsOriginal.toString()).toBe("10");
    expect(rows[0].gramsPure.toString()).toBe("7.5");
    expect(rows[0].movementId).toBe("mov-credit-1");
    expect(rows[1].metalParentId).toBe("metal-ag");
    expect(rows[1].gramsPure.toString()).toBe("18.5");
    // Todos positivos (signo lo da el movimiento CREDIT padre).
    for (const r of rows) {
      expect(parseFloat(r.gramsOriginal.toString())).toBeGreaterThan(0);
      expect(parseFloat(r.gramsPure.toString())).toBeGreaterThan(0);
    }
  });

  it("BREAKDOWN sin metal entries → no llama createMany", async () => {
    const tx = fakeTx() as any;
    tx.receipt.findFirst.mockResolvedValue(fakeOriginalReceipt());
    tx.currentAccountMovement.findFirst.mockResolvedValue(fakeOriginalMov({
      balanceMode: "BREAKDOWN", metalEntries: [],
    }));
    tx.receiptSeries.findFirst.mockResolvedValue({ id: "series-nc" });
    tx.receiptSeries.update.mockResolvedValue({
      nextNumber: 2, prefix: "NC", pointOfSale: "0001",
    });

    await onSaleCancelled(tx, "sale-1", {});

    expect(tx.accountMovementMetalEntry.createMany).not.toHaveBeenCalled();
  });
});

// ────────────────────────────────────────────────────────────────────────────
// 5. cancelSale — flujo end-to-end (paidAmount > 0 + atomicidad)
// ────────────────────────────────────────────────────────────────────────────
describe("cancelSale — bloqueo por cobros y atomicidad", () => {
  it("rechaza con 409 si paidAmount > 0", async () => {
    mockPrisma.sale.findFirst.mockResolvedValue({
      id: "s1", status: "CONFIRMED",
      stockMovementId: "mov-1", componentMovementId: null,
      clientId: "client-1",
      paidAmount: new D("500"),
    });

    await expect(cancelSale("s1", "j1", "u1", ""))
      .rejects.toMatchObject({ status: 409, code: "SALE_CANCEL_BLOCKED_BY_PAYMENTS" });

    expect(mockPrisma.$transaction).not.toHaveBeenCalled();
  });

  it("paidAmount = 0 entra a la TX y dispara el hook (sale CONFIRMED)", async () => {
    mockPrisma.sale.findFirst.mockResolvedValue({
      id: "s1", status: "CONFIRMED",
      stockMovementId: null, componentMovementId: null,
      clientId: "client-1",
      paidAmount: new D("0"),
    });

    const tx = fakeTx() as any;
    tx.receipt.findFirst.mockResolvedValue(fakeOriginalReceipt());
    tx.currentAccountMovement.findFirst.mockResolvedValue(fakeOriginalMov());
    tx.receiptSeries.findFirst.mockResolvedValue({ id: "series-nc" });
    tx.receiptSeries.update.mockResolvedValue({
      nextNumber: 2, prefix: "NC", pointOfSale: "0001",
    });
    tx.sale.update.mockResolvedValue({ id: "s1", status: "CANCELLED" });

    mockPrisma.$transaction.mockImplementation(async (cb: any) => cb(tx));

    await cancelSale("s1", "j1", "u1", "test cancel");

    // El hook se invocó dentro de la TX: NC creada.
    expect(tx.receipt.create).toHaveBeenCalledTimes(1);
    expect(tx.currentAccountMovement.create).toHaveBeenCalledTimes(1);
    // Sale pasó a CANCELLED.
    expect(tx.sale.update).toHaveBeenCalledTimes(1);
    expect(tx.sale.update.mock.calls[0][0].data.status).toBe("CANCELLED");
  });

  it("atomicidad: si el hook falla, la TX entera revierte", async () => {
    mockPrisma.sale.findFirst.mockResolvedValue({
      id: "s1", status: "CONFIRMED",
      stockMovementId: null, componentMovementId: null,
      clientId: "client-1",
      paidAmount: new D("0"),
    });

    const tx = fakeTx() as any;
    tx.receipt.findFirst.mockResolvedValue(fakeOriginalReceipt());
    tx.currentAccountMovement.findFirst.mockResolvedValue(fakeOriginalMov());
    tx.receiptSeries.findFirst.mockResolvedValue({ id: "series-nc" });
    tx.receiptSeries.update.mockResolvedValue({
      nextNumber: 2, prefix: "NC", pointOfSale: "0001",
    });
    // Forzar fallo al crear la NC.
    tx.receipt.create.mockRejectedValue(new Error("DB error simulada"));

    mockPrisma.$transaction.mockImplementation(async (cb: any) => {
      // Si el callback throwea, la TX entera se aborta — propagamos el error.
      return cb(tx);
    });

    await expect(cancelSale("s1", "j1", "u1", "")).rejects.toThrow("DB error simulada");
    // Sale.update no debe haberse llamado (la TX abortó antes).
    expect(tx.sale.update).not.toHaveBeenCalled();
  });

  it("Sale DRAFT (sin stockMovement, sin Receipt) cancela sin emitir NC", async () => {
    mockPrisma.sale.findFirst.mockResolvedValue({
      id: "s-draft", status: "DRAFT",
      stockMovementId: null, componentMovementId: null,
      clientId: "client-1",
      paidAmount: new D("0"),
    });

    const tx = fakeTx() as any;
    tx.sale.update.mockResolvedValue({ id: "s-draft", status: "CANCELLED" });
    mockPrisma.$transaction.mockImplementation(async (cb: any) => cb(tx));

    await cancelSale("s-draft", "j1", "u1", "");

    // wasConfirmed = false → no se invoca el hook.
    expect(tx.receipt.findFirst).not.toHaveBeenCalled();
    expect(tx.receipt.create).not.toHaveBeenCalled();
    expect(tx.sale.update).toHaveBeenCalledTimes(1);
  });
});
