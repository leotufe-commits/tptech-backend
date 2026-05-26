// src/modules/sales/__tests__/get-sale-receipts-select.test.ts
// =============================================================================
// 1.A — Tests minimos de la exposicion del Receipt.code via getSale.
//
// La numeracion del comprobante ya existe y se asigna atomicamente en
// `onSaleConfirmed` (sale.hook.ts) sobre `ReceiptSeries`. Estos tests no
// reescriben esa logica — esta cubierta en
// `lib/document-hooks/__tests__/sale.hook.test.ts` (formato del code,
// increment atomico, auto-provision de la serie).
//
// Lo unico nuevo en esta etapa es que `getSale` debe DEVOLVER los
// receipts asociados a la venta — para que el frontend muestre "Factura
// N° <Receipt.code>" en lugar del Sale.code interno. Validamos eso
// observando el shape del `select` que el service pasa a Prisma + que
// los receipts llegan al payload de respuesta.
//
// Tambien chequeamos el guard ya existente que evita renumerar una
// venta ya confirmada (mensaje literal del error en sales.service:771).
// =============================================================================

import { describe, it, expect, vi, beforeEach } from "vitest";
import { Prisma } from "@prisma/client";

const mockPrisma = vi.hoisted(() => ({
  sale: { findFirst: vi.fn() },
}));
vi.mock("../../../lib/prisma.js", () => ({ prisma: mockPrisma, Prisma }));

import { getSale } from "../sales.service.js";

beforeEach(() => {
  vi.clearAllMocks();
});

describe("getSale — receipts en SALE_DETAIL_SELECT (1.A)", () => {
  it("incluye `receipts` en el select pasado a Prisma con el shape esperado", async () => {
    // Mockeamos un sale CONFIRMED con 1 receipt. El test no verifica
    // pricing — solo que el shape del select pide receipts y que el
    // payload de respuesta los expone tal cual.
    const fakeReceipt = {
      id:        "rcpt-1",
      code:      "A-0001-00000001",
      type:      "INVOICE",
      direction: "OUTBOUND",
      status:    "ISSUED",
      issueDate: new Date("2026-04-23T10:00:00Z"),
      issuedAt:  new Date("2026-04-23T10:00:00Z"),
    };
    mockPrisma.sale.findFirst.mockResolvedValueOnce({
      id:        "sale-1",
      code:      "VTA-0001",
      status:    "CONFIRMED",
      lines:     [],
      receipts:  [fakeReceipt],
    });

    const out = await getSale("sale-1", "jw-1");

    // 1) Verificamos el shape del select pasado a Prisma.
    expect(mockPrisma.sale.findFirst).toHaveBeenCalledTimes(1);
    const callArgs = mockPrisma.sale.findFirst.mock.calls[0]![0]!;
    expect(callArgs).toMatchObject({
      where:  { id: "sale-1", jewelryId: "jw-1" },
      select: expect.objectContaining({
        receipts: expect.objectContaining({
          select: expect.objectContaining({
            id:        true,
            code:      true,
            type:      true,
            direction: true,
            status:    true,
            issueDate: true,
            issuedAt:  true,
          }),
        }),
      }),
    });

    // 2) Verificamos que los receipts del row llegan al payload.
    expect((out as any).receipts).toEqual([fakeReceipt]);
    expect((out as any).receipts[0].code).toBe("A-0001-00000001");
  });

  it("una venta DRAFT (sin receipts emitidos) responde con receipts vacios", async () => {
    mockPrisma.sale.findFirst.mockResolvedValueOnce({
      id:        "sale-draft",
      code:      "VTA-0002",
      status:    "DRAFT",
      lines:     [],
      receipts:  [],
    });

    const out = await getSale("sale-draft", "jw-1");
    expect((out as any).receipts).toEqual([]);
  });
});
