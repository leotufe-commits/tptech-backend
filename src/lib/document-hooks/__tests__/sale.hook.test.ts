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
    // T56 (Fase 3B.6) — registro de las metalEntries que el hook crea.
    createdMetalEntries: [] as any[],
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
    // T56 (Fase 3B.6) — tabla AccountMovementMetalEntry. Mock minimal:
    // sólo expone `createMany` que es lo único que el hook necesita.
    accountMovementMetalEntry: {
      createMany: vi.fn(async (args: any) => {
        for (const row of args.data) state.createdMetalEntries.push(row);
        return { count: args.data.length };
      }),
    },
  };

  return { tx, state };
}

// Fixture de breakdown BREAKDOWN reusable.
function makeBreakdown(over: Partial<any> = {}): any {
  return {
    metals: [
      {
        metalParentId:    "oro-fino",
        metalParentName:  "Oro Fino",
        gramsOriginal:    2,
        purity:           0.75,
        gramsPure:        1.5,
        quotePriceSnapshot:    100000,
        valuationMonetary:     150000,
        valuationCurrencyCode: "ARS",
        sourceLineIds:    ["line-1"],
      },
    ],
    monetaryBalance: {
      amount:       50000,
      currencyCode: "ARS",
      currencyRate: 1,
      amountBase:   50000,
    },
    ...over,
  };
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

// =============================================================================
// T49 → T56 (Fase 3B.6) — Balance Mode persiste en cuenta corriente.
//
// Antes (T49, Fase 2): el hook NO seteaba `balanceMode`, `sourceDocumentType`
// ni `sourceDocumentId` (la DB caía a `UNIFIED` por default del schema).
// Tampoco creaba `AccountMovementMetalEntry`.
//
// Ahora (T56, Fase 3B.6, POLICY.md §11 R11.7):
//   · `balanceMode` SIEMPRE se setea explícito (UNIFIED por default).
//   · `sourceDocumentType = "SALE"` / `sourceDocumentId = sale.id` siempre.
//   · BREAKDOWN crea una `AccountMovementMetalEntry` por metal padre.
//   · UNIFIED preserva back-compat: no se crean metalEntries.
// =============================================================================

describe("T56 — Fase 3B.6: balanceMode + trazabilidad en cuenta corriente", () => {
  it("UNIFIED implícito (sin opts.balanceMode): mov.balanceMode=UNIFIED + sourceDocument SALE + sin metalEntries", async () => {
    const { tx, state } = buildMockTx({ sale: makeSaleRecord() });
    await onSaleConfirmed(tx as any, "sale-1", {});

    expect(state.createdMovements).toHaveLength(1);
    const mov = state.createdMovements[0];
    expect(mov.balanceMode).toBe("UNIFIED");
    expect(mov.sourceDocumentType).toBe("SALE");
    expect(mov.sourceDocumentId).toBe("sale-1");
    // amountBase desde el snapshot (back-compat exacta) — el snapshot tiene
    // total=242 + totalBase=242 según `computeTotalsFromLines` del hook.
    expect(mov.amountBase.toString()).toBe("242");
    // NO se crearon filas en la tabla nueva.
    expect(state.createdMetalEntries).toHaveLength(0);
  });

  it("UNIFIED explícito (opts.balanceMode='UNIFIED'): mismo comportamiento", async () => {
    const { tx, state } = buildMockTx({ sale: makeSaleRecord() });
    await onSaleConfirmed(tx as any, "sale-1", {
      balanceMode:       "UNIFIED",
      balanceModeSource: "TENANT_DEFAULT",
      balanceBreakdown:  {
        metals: [],
        monetaryBalance: { amount: 242, currencyCode: "ARS", currencyRate: 1, amountBase: 242 },
      },
    });

    const mov = state.createdMovements[0];
    expect(mov.balanceMode).toBe("UNIFIED");
    expect(state.createdMetalEntries).toHaveLength(0);
  });
});

describe("T56 — Fase 3B.6: BREAKDOWN crea metalEntries", () => {
  it("BREAKDOWN con un metal: mov.balanceMode=BREAKDOWN + amountBase desde monetaryBalance + 1 metalEntry", async () => {
    const { tx, state } = buildMockTx({ sale: makeSaleRecord() });
    const bd = makeBreakdown();  // 1 metal Oro Fino, monetary.amount=50000
    await onSaleConfirmed(tx as any, "sale-1", {
      balanceMode:       "BREAKDOWN",
      balanceModeSource: "ENTITY_DEFAULT",
      balanceBreakdown:  bd,
    });

    expect(state.createdMovements).toHaveLength(1);
    const mov = state.createdMovements[0];
    expect(mov.balanceMode).toBe("BREAKDOWN");
    expect(mov.sourceDocumentType).toBe("SALE");
    expect(mov.sourceDocumentId).toBe("sale-1");
    // amountBase y amountOriginal vienen del breakdown, no del snapshot total.
    expect(mov.amountBase.toString()).toBe("50000");
    expect(mov.amountOriginal.toString()).toBe("50000");
    expect(mov.currencyCode).toBe("ARS");

    expect(state.createdMetalEntries).toHaveLength(1);
    const entry = state.createdMetalEntries[0];
    expect(entry.movementId).toBe(mov.id);
    expect(entry.jewelryId).toBe("jw-1");
    expect(entry.metalParentId).toBe("oro-fino");
    expect(entry.metalParentName).toBe("Oro Fino");
    expect(entry.gramsOriginal.toString()).toBe("2");
    expect(entry.purity.toString()).toBe("0.75");
    expect(entry.gramsPure.toString()).toBe("1.5");
    expect(entry.sourceLineId).toBe("line-1");
  });

  it("BREAKDOWN multi-metal (Oro + Plata) → 2 metalEntries", async () => {
    const { tx, state } = buildMockTx({ sale: makeSaleRecord() });
    const bd = makeBreakdown({
      metals: [
        {
          metalParentId: "oro-fino", metalParentName: "Oro Fino",
          gramsOriginal: 1, purity: 0.75, gramsPure: 0.75,
          quotePriceSnapshot: 100000, valuationMonetary: 75000,
          valuationCurrencyCode: "ARS",
          sourceLineIds: ["line-1"],
        },
        {
          metalParentId: "plata-925", metalParentName: "Plata 925",
          gramsOriginal: 10, purity: 0.925, gramsPure: 9.25,
          quotePriceSnapshot: 5000, valuationMonetary: 46250,
          valuationCurrencyCode: "ARS",
          sourceLineIds: ["line-2"],
        },
      ],
    });
    await onSaleConfirmed(tx as any, "sale-1", {
      balanceMode: "BREAKDOWN", balanceBreakdown: bd,
    });

    expect(state.createdMetalEntries).toHaveLength(2);
    const oro   = state.createdMetalEntries.find((e: any) => e.metalParentId === "oro-fino");
    const plata = state.createdMetalEntries.find((e: any) => e.metalParentId === "plata-925");
    expect(oro.gramsPure.toString()).toBe("0.75");
    expect(plata.gramsPure.toString()).toBe("9.25");
    expect(plata.metalParentName).toBe("Plata 925");
  });

  it("BREAKDOWN sin metales (línea solo hechura) → movimiento sin metalEntries", async () => {
    const { tx, state } = buildMockTx({ sale: makeSaleRecord() });
    const bd = makeBreakdown({ metals: [] });
    await onSaleConfirmed(tx as any, "sale-1", {
      balanceMode: "BREAKDOWN", balanceBreakdown: bd,
    });
    expect(state.createdMovements).toHaveLength(1);
    expect(state.createdMovements[0].balanceMode).toBe("BREAKDOWN");
    expect(state.createdMetalEntries).toHaveLength(0);
    // El createMany NO debe invocarse cuando no hay filas que crear.
    expect((tx as any).accountMovementMetalEntry.createMany).not.toHaveBeenCalled();
  });

  it("BREAKDOWN con metal de gramsPure=0 → fila descartada defensivamente", async () => {
    const { tx, state } = buildMockTx({ sale: makeSaleRecord() });
    const bd = makeBreakdown({
      metals: [
        {
          metalParentId: "oro-fino", metalParentName: "Oro Fino",
          gramsOriginal: 0, purity: null, gramsPure: 0,
          quotePriceSnapshot: null, valuationMonetary: null,
          valuationCurrencyCode: "ARS",
          sourceLineIds: [],
        },
      ],
    });
    await onSaleConfirmed(tx as any, "sale-1", {
      balanceMode: "BREAKDOWN", balanceBreakdown: bd,
    });
    // Fila descartada → tabla vacía. El movimiento monetario sigue siendo válido.
    expect(state.createdMovements).toHaveLength(1);
    expect(state.createdMetalEntries).toHaveLength(0);
  });

  it("sourceLineId persiste cuando una sola línea aportó al padre", async () => {
    const { tx, state } = buildMockTx({ sale: makeSaleRecord() });
    const bd = makeBreakdown({
      metals: [{
        metalParentId: "oro-fino", metalParentName: "Oro Fino",
        gramsOriginal: 1, purity: 0.75, gramsPure: 0.75,
        quotePriceSnapshot: null, valuationMonetary: null,
        valuationCurrencyCode: "ARS",
        sourceLineIds: ["line-42"],
      }],
    });
    await onSaleConfirmed(tx as any, "sale-1", {
      balanceMode: "BREAKDOWN", balanceBreakdown: bd,
    });
    expect(state.createdMetalEntries[0].sourceLineId).toBe("line-42");
  });

  it("sourceLineId queda null cuando >1 línea aportó al mismo padre", async () => {
    const { tx, state } = buildMockTx({ sale: makeSaleRecord() });
    const bd = makeBreakdown({
      metals: [{
        metalParentId: "oro-fino", metalParentName: "Oro Fino",
        gramsOriginal: 3, purity: 0.75, gramsPure: 2.25,
        quotePriceSnapshot: null, valuationMonetary: null,
        valuationCurrencyCode: "ARS",
        sourceLineIds: ["line-1", "line-2"],   // dos líneas
      }],
    });
    await onSaleConfirmed(tx as any, "sale-1", {
      balanceMode: "BREAKDOWN", balanceBreakdown: bd,
    });
    expect(state.createdMetalEntries[0].sourceLineId).toBeNull();
  });
});

describe("T56 — Fase 3B.6: validación BREAKDOWN", () => {
  it("BREAKDOWN sin balanceBreakdown → throw controlado (no escribe nada)", async () => {
    const { tx, state } = buildMockTx({ sale: makeSaleRecord() });
    await expect(
      onSaleConfirmed(tx as any, "sale-1", {
        balanceMode: "BREAKDOWN",
        // ¡falta balanceBreakdown!
      }),
    ).rejects.toThrow(/BREAKDOWN.*balanceBreakdown/i);
    // No se llegó a crear el movement (la validación es ANTES del create).
    expect(state.createdMovements).toHaveLength(0);
    expect(state.createdMetalEntries).toHaveLength(0);
  });

  it("BREAKDOWN con balanceBreakdown corrupto (sin monetaryBalance) → throw controlado", async () => {
    const { tx, state } = buildMockTx({ sale: makeSaleRecord() });
    await expect(
      onSaleConfirmed(tx as any, "sale-1", {
        balanceMode:      "BREAKDOWN",
        balanceBreakdown: { metals: [] } as any,  // sin monetaryBalance
      }),
    ).rejects.toThrow(/BREAKDOWN/);
    expect(state.createdMovements).toHaveLength(0);
  });

  it("BREAKDOWN con metals no-array → throw", async () => {
    const { tx, state } = buildMockTx({ sale: makeSaleRecord() });
    await expect(
      onSaleConfirmed(tx as any, "sale-1", {
        balanceMode:      "BREAKDOWN",
        balanceBreakdown: { metals: "oops", monetaryBalance: { amount: 1, currencyCode: "ARS", currencyRate: 1, amountBase: 1 } } as any,
      }),
    ).rejects.toThrow(/BREAKDOWN/);
    expect(state.createdMovements).toHaveLength(0);
  });
});

describe("T56 — Fase 3B.6: consumidor final (sin cliente)", () => {
  it("BREAKDOWN sin clientId → no se crea movimiento ni metalEntries (consumidor final)", async () => {
    const sale = makeSaleRecord({ clientId: null, client: null });
    const { tx, state } = buildMockTx({ sale });
    await onSaleConfirmed(tx as any, "sale-1", {
      balanceMode: "BREAKDOWN",
      balanceBreakdown: makeBreakdown(),
    });
    // Receipt sí se emite, pero sin cuenta corriente.
    expect(state.createdReceipts).toHaveLength(1);
    expect(state.createdMovements).toHaveLength(0);
    expect(state.createdMetalEntries).toHaveLength(0);
  });
});

describe("T56 — Fase 3B.6: históricos pre-3B.5 (callers sin opts.balanceMode)", () => {
  it("caller que NO pasa balanceMode → UNIFIED implícito, snapshot legacy intacto, sin metalEntries", async () => {
    // Reproduce el caso de un caller (ej. legacy) que llama al hook sin
    // pasar Balance Mode. Comportamiento debe ser idéntico a pre-3B.5:
    // UNIFIED, sin metalEntries, amount desde snapshot.totals.
    const { tx, state } = buildMockTx({ sale: makeSaleRecord() });
    await onSaleConfirmed(tx as any, "sale-1", { issueInvoice: true });
    expect(state.createdMovements).toHaveLength(1);
    expect(state.createdMovements[0].balanceMode).toBe("UNIFIED");
    expect(state.createdMetalEntries).toHaveLength(0);
  });
});
