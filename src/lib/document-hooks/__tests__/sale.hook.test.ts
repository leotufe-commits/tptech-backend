// src/lib/document-hooks/__tests__/sale.hook.test.ts
// =============================================================================
// Tests para onSaleConfirmed — hook transaccional de Fase 5.
//
// Se mockea una TransactionClient con métodos que simulan las tablas tocadas:
//   sale, receiptSeries, receipt, receiptLine, currentAccountMovement.
//
// Cubre:
//   · Auto-provisión de ReceiptSeries si no existe
//   · Incremento atómico del nextNumber (update con increment:1)
//   · Formato del code "A-0001-00000001"
//   · Creación de Receipt con status ISSUED + snapshots congelados
//   · Creación de ReceiptLine por cada línea de venta
//   · Creación de CurrentAccountMovement DEBIT solo si hay clientId
//   · Consumidor final (clientId null): no genera movimiento
//   · issueInvoice: false → no crea nada
// =============================================================================

import { describe, it, expect, vi, beforeEach } from "vitest";
import { onSaleConfirmed } from "../sale.hook.js";

function makeSaleRecord(over: Partial<any> = {}) {
  return {
    id:             "sale-1",
    jewelryId:      "jw-1",
    code:           "VTA-0001",
    clientId:       "cli-1",
    saleDate:       new Date("2026-04-23T10:00:00Z"),
    subtotal:       { toString: () => "200" },
    discountAmount: { toString: () => "0" },
    taxAmount:      { toString: () => "42" },
    total:          { toString: () => "242" },
    currencyId:     null,
    currencySnapshot: {
      id: "cur-ars", currencyCode: "ARS", symbol: "$",
      currencyRate: 1, baseCurrencyCode: "ARS",
    },
    clientSnapshot: null,
    channelSnapshot: null,
    couponSnapshot: null,
    issuerSnapshot: null,
    jewelry: { id: "jw-1", name: "Joyería", cuit: "20-11-1", ivaCondition: "RI" },
    client: {
      id: "cli-1", displayName: "Cliente SA",
      isClient: true, isSupplier: false,
      documentType: "DNI", documentNumber: "12345678", ivaCondition: "CF",
    },
    channel: null,
    coupon: null,
    lines: [
      {
        id: "line-1",
        articleId: "art-1",
        variantId: null as string | null,
        articleName: "Producto 1",
        variantName: "",
        sku: "SKU1",
        barcode: "",
        quantity:    { toString: () => "2" },
        unitPrice:   { toString: () => "100" },
        discountPct: { toString: () => "0" },
        lineTotal:   { toString: () => "200" },
        priceSource: "MANUAL_FALLBACK",
        appliedPriceListId: null,
        appliedPromotionId: null,
        appliedDiscountId: null,
        unitCost:       { toString: () => "60" },
        totalCost:      { toString: () => "120" },
        unitMargin:     { toString: () => "40" },
        totalMargin:    { toString: () => "80" },
        marginPercent:  { toString: () => "40" },
        taxAmount:      { toString: () => "42" },
        breakdownSnapshot: null,
        taxSnapshot:       [],
        pricingSnapshot:   null,
        sortOrder: 0,
        article: { id: "art-1", code: "A001", articleType: "PRODUCT", commercialMode: "NORMAL" },
      },
    ],
    ...over,
  };
}

function buildMockTx(opts: {
  sale?: any;
  existingSeries?: any;
} = {}) {
  const state = {
    nextNumberByseries: new Map<string, number>(),
    createdReceipts:    [] as any[],
    createdLines:       [] as any[],
    createdMovements:   [] as any[],
    createdSeries:      null as any,
  };

  const seriesRow = opts.existingSeries ?? null;
  if (seriesRow) state.nextNumberByseries.set(seriesRow.id, seriesRow.nextNumber ?? 1);

  const tx = {
    sale: {
      findUnique: vi.fn(async (_args: any) => opts.sale ?? null),
    },
    receiptSeries: {
      findFirst: vi.fn(async (_args: any) => seriesRow),
      create: vi.fn(async (args: any) => {
        state.createdSeries = { id: "series-new", ...args.data };
        state.nextNumberByseries.set("series-new", args.data.nextNumber ?? 1);
        return { id: "series-new" };
      }),
      update: vi.fn(async (args: any) => {
        const seriesId = args.where.id as string;
        const current = state.nextNumberByseries.get(seriesId) ?? 1;
        const next = current + (args.data.nextNumber?.increment ?? 1);
        state.nextNumberByseries.set(seriesId, next);
        const base = seriesId === "series-new" ? state.createdSeries : seriesRow;
        return {
          nextNumber:  next,
          prefix:      base?.prefix ?? "",
          pointOfSale: base?.pointOfSale ?? "0001",
        };
      }),
    },
    receipt: {
      create: vi.fn(async (args: any) => {
        const receipt = {
          id:    `receipt-${state.createdReceipts.length + 1}`,
          code:  args.data.code,
          type:  args.data.type,
          total: args.data.total,
          ...args.data,
        };
        state.createdReceipts.push(receipt);
        return {
          id:    receipt.id,
          code:  receipt.code,
          type:  receipt.type,
          total: { toString: () => String(receipt.total?.toString?.() ?? receipt.total) },
        };
      }),
    },
    receiptLine: {
      createMany: vi.fn(async (args: any) => {
        for (const row of args.data) state.createdLines.push(row);
        return { count: args.data.length };
      }),
    },
    currentAccountMovement: {
      create: vi.fn(async (args: any) => {
        const mov = { id: `mov-${state.createdMovements.length + 1}`, ...args.data };
        state.createdMovements.push(mov);
        return {
          id:         mov.id,
          kind:       mov.kind,
          amountBase: { toString: () => String(mov.amountBase?.toString?.() ?? mov.amountBase) },
        };
      }),
    },
  };

  return { tx, state };
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

describe("onSaleConfirmed — happy path con cliente", () => {
  it("auto-provisiona ReceiptSeries cuando no existe y crea factura + movimiento", async () => {
    const { tx, state } = buildMockTx({ sale: makeSaleRecord() });

    const result = await onSaleConfirmed(tx as any, "sale-1", { issueInvoice: true, issuedById: "user-1" });

    // Series auto-provisioned
    expect(tx.receiptSeries.create).toHaveBeenCalledTimes(1);
    expect(state.createdSeries.type).toBe("INVOICE");
    expect(state.createdSeries.direction).toBe("OUTBOUND");

    // Incremento atómico de nextNumber
    expect(tx.receiptSeries.update).toHaveBeenCalledWith(expect.objectContaining({
      data: { nextNumber: { increment: 1 } },
    }));

    // Un receipt + una línea + un movimiento DEBIT
    expect(state.createdReceipts).toHaveLength(1);
    expect(state.createdLines).toHaveLength(1);
    expect(state.createdMovements).toHaveLength(1);

    const receipt = state.createdReceipts[0];
    expect(receipt.code).toBe("A-0001-00000001");
    expect(receipt.status).toBe("ISSUED");
    expect(receipt.saleId).toBe("sale-1");
    expect(receipt.pricingSnapshot).toBeDefined();
    expect(receipt.currencySnapshot).toBeDefined();
    expect(receipt.currencyCode).toBe("ARS");

    const line = state.createdLines[0];
    expect(line.articleId).toBe("art-1");
    expect(line.itemKind).toBe("ARTICLE_SIMPLE");
    expect(line.pricingSnapshot).toBeDefined();

    const mov = state.createdMovements[0];
    expect(mov.kind).toBe("DEBIT");
    expect(mov.source).toBe("RECEIPT");
    expect(mov.entityId).toBe("cli-1");
    expect(mov.receiptId).toBe("receipt-1");
    expect(mov.currencySnapshot).toBeDefined();

    // Result exposé
    expect(result.receipts).toHaveLength(1);
    expect(result.receipts[0].code).toBe("A-0001-00000001");
    expect(result.accountMovements).toHaveLength(1);
    expect(result.accountMovements[0].kind).toBe("DEBIT");
  });

  it("reutiliza ReceiptSeries existente e incrementa su nextNumber", async () => {
    const { tx, state } = buildMockTx({
      sale: makeSaleRecord(),
      existingSeries: {
        id: "series-existing", prefix: "A", pointOfSale: "0001", nextNumber: 5,
      },
    });

    await onSaleConfirmed(tx as any, "sale-1", {});

    expect(tx.receiptSeries.create).not.toHaveBeenCalled();
    expect(tx.receiptSeries.update).toHaveBeenCalledWith(expect.objectContaining({
      where: { id: "series-existing" },
    }));
    // El receipt reservó el numero 5 (que era nextNumber antes de incrementar)
    expect(state.createdReceipts[0].code).toBe("A-0001-00000005");
  });
});

describe("onSaleConfirmed — consumidor final", () => {
  it("sin clientId NO crea CurrentAccountMovement pero sí emite Receipt", async () => {
    const sale = makeSaleRecord({ clientId: null, client: null });
    const { tx, state } = buildMockTx({ sale });

    const result = await onSaleConfirmed(tx as any, "sale-1", {});

    expect(state.createdReceipts).toHaveLength(1);
    expect(state.createdLines).toHaveLength(1);
    expect(state.createdMovements).toHaveLength(0);
    expect(result.accountMovements).toHaveLength(0);

    // Counterparty queda null en el receipt
    expect(state.createdReceipts[0].counterpartyId).toBeNull();
  });
});

describe("onSaleConfirmed — opt-out", () => {
  it("issueInvoice:false no crea nada y retorna arrays vacíos", async () => {
    const { tx, state } = buildMockTx({ sale: makeSaleRecord() });

    const result = await onSaleConfirmed(tx as any, "sale-1", { issueInvoice: false });

    expect(tx.sale.findUnique).not.toHaveBeenCalled();
    expect(state.createdReceipts).toHaveLength(0);
    expect(state.createdMovements).toHaveLength(0);
    expect(result.receipts).toHaveLength(0);
    expect(result.accountMovements).toHaveLength(0);
  });
});

describe("onSaleConfirmed — validaciones", () => {
  it("sale inexistente → error 404", async () => {
    const { tx } = buildMockTx({ sale: null });
    await expect(onSaleConfirmed(tx as any, "nope", {})).rejects.toThrow(/no encontrada/);
  });

  it("seriesId explícito inexistente → error 404", async () => {
    const { tx } = buildMockTx({ sale: makeSaleRecord() });
    // findFirst default devuelve null → aun con seriesId explícito, no existe
    await expect(
      onSaleConfirmed(tx as any, "sale-1", { invoiceSeriesId: "no-existe" }),
    ).rejects.toThrow(/ReceiptSeries/);
  });
});

describe("onSaleConfirmed — detección de itemKind", () => {
  it("articleType=SERVICE → itemKind SERVICE en la línea", async () => {
    const sale = makeSaleRecord();
    sale.lines[0].article.articleType = "SERVICE";
    const { tx, state } = buildMockTx({ sale });
    await onSaleConfirmed(tx as any, "sale-1", {});
    expect(state.createdLines[0].itemKind).toBe("SERVICE");
  });

  it("commercialMode=COMBO_COMMERCIAL → itemKind COMBO", async () => {
    const sale = makeSaleRecord();
    sale.lines[0].article.commercialMode = "COMBO_COMMERCIAL";
    const { tx, state } = buildMockTx({ sale });
    await onSaleConfirmed(tx as any, "sale-1", {});
    expect(state.createdLines[0].itemKind).toBe("COMBO");
  });

  it("variantId presente → itemKind ARTICLE_VARIANT", async () => {
    const sale = makeSaleRecord();
    sale.lines[0].variantId = "var-9";
    const { tx, state } = buildMockTx({ sale });
    await onSaleConfirmed(tx as any, "sale-1", {});
    expect(state.createdLines[0].itemKind).toBe("ARTICLE_VARIANT");
    expect(state.createdLines[0].variantId).toBe("var-9");
  });
});
