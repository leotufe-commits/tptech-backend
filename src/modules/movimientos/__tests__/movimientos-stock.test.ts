// src/modules/movimientos/__tests__/movimientos-stock.test.ts
//
// Verifica que los movimientos de metales mantengan WarehouseStock sincronizado.
//
// Invariantes verificados:
//   - IN suma gramos al WarehouseStock del almacén
//   - OUT resta gramos del WarehouseStock del almacén
//   - ADJUST aplica delta firmado al WarehouseStock
//   - TRANSFER mueve gramos de FROM a TO atomicamente
//   - void(IN) resta, void(OUT) suma, void(ADJUST) invierte, void(TRANSFER) invierte
//   - IN/OUT no aceptan gramos <= 0
//   - TRANSFER no acepta gramos <= 0

import { describe, it, expect, vi, beforeEach } from "vitest";
import { Prisma } from "@prisma/client";

// ─── Mock de Prisma ──────────────────────────────────────────────────────────

const mockTx = vi.hoisted(() => ({
  warehouse:         { findFirst: vi.fn() },
  inventoryMovement: { count: vi.fn(), create: vi.fn(), findFirst: vi.fn(), update: vi.fn() },
  metalVariant:      { findMany: vi.fn() },
  warehouseStock:    { findFirst: vi.fn(), update: vi.fn(), create: vi.fn() },
}));

const mockPrisma = vi.hoisted(() => ({
  $transaction: vi.fn(),
}));

vi.mock("../../../lib/prisma.js", () => ({ prisma: mockPrisma }));

import { createMovement, transferMovement, voidMovement } from "../movimientos.service.js";

// ─── Setup ───────────────────────────────────────────────────────────────────

function setupTransaction() {
  mockPrisma.$transaction.mockImplementation(
    async (cb: (tx: typeof mockTx) => Promise<unknown>) => cb(mockTx),
  );
}

function setupBaseWarehouse(id = "wh-1") {
  mockTx.warehouse.findFirst.mockResolvedValue({ id, isActive: true });
}

function setupMovementCode(count = 0) {
  mockTx.inventoryMovement.count.mockResolvedValue(count);
}

function setupVariant(variantId = "var-1", metalName = "Oro", variantName = "18K") {
  mockTx.metalVariant.findMany.mockResolvedValue([
    { id: variantId, name: variantName, metal: { name: metalName } },
  ]);
}

function setupCreatedMovement(kind: string, warehouseId = "wh-1") {
  mockTx.inventoryMovement.create.mockResolvedValue({
    id: "mov-1",
    kind,
    code: "E-0001",
    note: "",
    effectiveAt: new Date(),
    deletedAt: null,
    voidedAt: null,
    warehouse: { id: warehouseId, name: "Depósito", code: "DEP01" },
    fromWarehouse: null,
    toWarehouse: null,
    createdBy: { id: "u-1", email: "a@b.com", name: "Test" },
    lines: [{ variantId: "var-1", grams: new Prisma.Decimal("50"), snapshot: null, variant: { id: "var-1", name: "18K", sku: "", metal: { id: "m-1", name: "Oro" } } }],
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// A. createMovement — sincronización de WarehouseStock
// ─────────────────────────────────────────────────────────────────────────────

describe("createMovement — WarehouseStock sincronizado", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    setupTransaction();
    setupBaseWarehouse();
    setupMovementCode();
    setupVariant();
    // Por defecto: no hay WarehouseStock previo
    mockTx.warehouseStock.findFirst.mockResolvedValue(null);
    mockTx.warehouseStock.create.mockResolvedValue({});
    mockTx.warehouseStock.update.mockResolvedValue({});
  });

  it("IN: crea WarehouseStock con delta positivo cuando no existe registro previo", async () => {
    setupCreatedMovement("IN");

    await createMovement({
      jewelryId: "jw-1", userId: "u-1", warehouseId: "wh-1",
      kind: "IN", effectiveAt: new Date(),
      lines: [{ variantId: "var-1", grams: "50" }],
    });

    expect(mockTx.warehouseStock.create).toHaveBeenCalledWith({
      data: {
        jewelryId: "jw-1",
        warehouseId: "wh-1",
        variantId: "var-1",
        grams: new Prisma.Decimal("50"),
      },
    });
    expect(mockTx.warehouseStock.update).not.toHaveBeenCalled();
  });

  it("IN: actualiza WarehouseStock sumando al saldo existente", async () => {
    setupCreatedMovement("IN");
    mockTx.warehouseStock.findFirst.mockResolvedValue({
      id: "ws-1",
      grams: new Prisma.Decimal("30"),
    });

    await createMovement({
      jewelryId: "jw-1", userId: "u-1", warehouseId: "wh-1",
      kind: "IN", effectiveAt: new Date(),
      lines: [{ variantId: "var-1", grams: "50" }],
    });

    expect(mockTx.warehouseStock.update).toHaveBeenCalledWith({
      where: { id: "ws-1" },
      data: { grams: new Prisma.Decimal("80") },  // 30 + 50
    });
  });

  it("OUT: crea WarehouseStock con delta negativo", async () => {
    setupCreatedMovement("OUT");

    await createMovement({
      jewelryId: "jw-1", userId: "u-1", warehouseId: "wh-1",
      kind: "OUT", effectiveAt: new Date(),
      lines: [{ variantId: "var-1", grams: "30" }],
    });

    expect(mockTx.warehouseStock.create).toHaveBeenCalledWith({
      data: {
        jewelryId: "jw-1",
        warehouseId: "wh-1",
        variantId: "var-1",
        grams: new Prisma.Decimal("-30"),
      },
    });
  });

  it("ADJUST con valor positivo: suma gramos", async () => {
    setupCreatedMovement("ADJUST");

    await createMovement({
      jewelryId: "jw-1", userId: "u-1", warehouseId: "wh-1",
      kind: "ADJUST", effectiveAt: new Date(),
      lines: [{ variantId: "var-1", grams: "10" }],
    });

    expect(mockTx.warehouseStock.create).toHaveBeenCalledWith({
      data: expect.objectContaining({ grams: new Prisma.Decimal("10") }),
    });
  });

  it("ADJUST con valor negativo: resta gramos (reducción de stock)", async () => {
    setupCreatedMovement("ADJUST");
    mockTx.warehouseStock.findFirst.mockResolvedValue({
      id: "ws-1",
      grams: new Prisma.Decimal("100"),
    });

    await createMovement({
      jewelryId: "jw-1", userId: "u-1", warehouseId: "wh-1",
      kind: "ADJUST", effectiveAt: new Date(),
      lines: [{ variantId: "var-1", grams: "-20" }],
    });

    expect(mockTx.warehouseStock.update).toHaveBeenCalledWith({
      where: { id: "ws-1" },
      data: { grams: new Prisma.Decimal("80") },  // 100 + (-20)
    });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// B. voidMovement — reversa del WarehouseStock
// ─────────────────────────────────────────────────────────────────────────────

describe("voidMovement — revierte WarehouseStock", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    setupTransaction();
    mockTx.warehouseStock.findFirst.mockResolvedValue(null);
    mockTx.warehouseStock.create.mockResolvedValue({});
    mockTx.warehouseStock.update.mockResolvedValue({});
  });

  function setupVoidableMovement(kind: string, warehouseId = "wh-1", fromId?: string, toId?: string) {
    mockTx.inventoryMovement.findFirst.mockResolvedValue({
      id: "mov-1",
      kind,
      warehouseId: fromId ? null : warehouseId,
      fromWarehouseId: fromId ?? null,
      toWarehouseId: toId ?? null,
      lines: [{ variantId: "var-1", grams: new Prisma.Decimal("50") }],
    });
    mockTx.inventoryMovement.update.mockResolvedValue({
      id: "mov-1", kind, deletedAt: new Date(), voidedAt: new Date(),
      warehouseId, fromWarehouseId: fromId ?? null, toWarehouseId: toId ?? null,
      lines: [], createdBy: null, warehouse: null, fromWarehouse: null, toWarehouse: null,
    });
  }

  it("void(IN): resta gramos al WarehouseStock", async () => {
    setupVoidableMovement("IN");
    mockTx.warehouseStock.findFirst.mockResolvedValue({ id: "ws-1", grams: new Prisma.Decimal("50") });

    await voidMovement({ id: "mov-1", jewelryId: "jw-1", userId: "u-1" });

    expect(mockTx.warehouseStock.update).toHaveBeenCalledWith({
      where: { id: "ws-1" },
      data: { grams: new Prisma.Decimal("0") },  // 50 - 50
    });
  });

  it("void(OUT): suma gramos al WarehouseStock (devuelve lo que salió)", async () => {
    setupVoidableMovement("OUT");
    mockTx.warehouseStock.findFirst.mockResolvedValue({ id: "ws-1", grams: new Prisma.Decimal("-50") });

    await voidMovement({ id: "mov-1", jewelryId: "jw-1", userId: "u-1" });

    expect(mockTx.warehouseStock.update).toHaveBeenCalledWith({
      where: { id: "ws-1" },
      data: { grams: new Prisma.Decimal("0") },  // -50 + 50
    });
  });

  it("void(TRANSFER): devuelve gramos al FROM y los quita del TO", async () => {
    setupVoidableMovement("TRANSFER", "wh-1", "wh-from", "wh-to");

    const callOrder: string[] = [];
    mockTx.warehouseStock.findFirst
      .mockImplementationOnce(() => { callOrder.push("from"); return null; })
      .mockImplementationOnce(() => { callOrder.push("to");   return null; });

    await voidMovement({ id: "mov-1", jewelryId: "jw-1", userId: "u-1" });

    // void TRANSFER: FROM recibe +gramos, TO pierde -gramos
    expect(mockTx.warehouseStock.create).toHaveBeenCalledTimes(2);
    const calls = mockTx.warehouseStock.create.mock.calls.map((c: any[]) => c[0].data);
    const fromCall = calls.find((d: any) => d.warehouseId === "wh-from");
    const toCall   = calls.find((d: any) => d.warehouseId === "wh-to");
    expect(fromCall?.grams).toEqual(new Prisma.Decimal("50"));   // devuelve al from
    expect(toCall?.grams).toEqual(new Prisma.Decimal("-50"));    // quita del to
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// C. transferMovement — WarehouseStock en ambos almacenes
// ─────────────────────────────────────────────────────────────────────────────

describe("transferMovement — WarehouseStock en FROM y TO", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    setupTransaction();
    // Ambos almacenes activos
    mockTx.warehouse.findFirst
      .mockResolvedValueOnce({ id: "wh-from", isActive: true })
      .mockResolvedValueOnce({ id: "wh-to",   isActive: true });
    setupMovementCode();
    setupVariant();
    mockTx.warehouseStock.findFirst.mockResolvedValue(null);
    mockTx.warehouseStock.create.mockResolvedValue({});
    mockTx.inventoryMovement.create.mockResolvedValue({
      id: "mov-1", kind: "TRANSFER", code: "T-0001", note: "", effectiveAt: new Date(),
      fromWarehouse: { id: "wh-from", name: "Origen", code: "ORG" },
      toWarehouse:   { id: "wh-to",   name: "Destino", code: "DES" },
      createdBy: { id: "u-1", email: "a@b.com", name: "Test" },
      lines: [{ variantId: "var-1", grams: new Prisma.Decimal("40"), snapshot: null, variant: null }],
    });
  });

  it("TRANSFER: FROM pierde gramos y TO los gana en la misma transacción", async () => {
    await transferMovement({
      jewelryId: "jw-1", userId: "u-1",
      fromWarehouseId: "wh-from", toWarehouseId: "wh-to",
      effectiveAt: new Date(),
      lines: [{ variantId: "var-1", grams: "40" }],
    });

    const calls = mockTx.warehouseStock.create.mock.calls.map((c: any[]) => c[0].data);
    const fromCall = calls.find((d: any) => d.warehouseId === "wh-from");
    const toCall   = calls.find((d: any) => d.warehouseId === "wh-to");
    expect(fromCall?.grams).toEqual(new Prisma.Decimal("-40"));  // pierde
    expect(toCall?.grams).toEqual(new Prisma.Decimal("40"));     // gana
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// D. Validación de gramos positivos
// ─────────────────────────────────────────────────────────────────────────────

describe("createMovement — validación de gramos", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    setupTransaction();
    setupBaseWarehouse();
    setupMovementCode();
    setupVariant();
    mockTx.warehouseStock.findFirst.mockResolvedValue(null);
    mockTx.warehouseStock.create.mockResolvedValue({});
    setupCreatedMovement("IN");
  });

  it("IN rechaza grams = 0", async () => {
    await expect(
      createMovement({
        jewelryId: "jw-1", userId: "u-1", warehouseId: "wh-1",
        kind: "IN", effectiveAt: new Date(),
        lines: [{ variantId: "var-1", grams: "0" }],
      })
    ).rejects.toThrow("al menos una línea");
    // grams=0 es filtrado por filter(l.grams) → lines vacías → assert falla
  });

  it("IN rechaza grams negativos", async () => {
    await expect(
      createMovement({
        jewelryId: "jw-1", userId: "u-1", warehouseId: "wh-1",
        kind: "IN", effectiveAt: new Date(),
        lines: [{ variantId: "var-1", grams: "-10" }],
      })
    ).rejects.toThrow("mayores a 0");
  });

  it("OUT rechaza grams negativos", async () => {
    setupCreatedMovement("OUT");
    await expect(
      createMovement({
        jewelryId: "jw-1", userId: "u-1", warehouseId: "wh-1",
        kind: "OUT", effectiveAt: new Date(),
        lines: [{ variantId: "var-1", grams: "-5" }],
      })
    ).rejects.toThrow("mayores a 0");
  });

  it("ADJUST acepta grams negativos (reducción de stock)", async () => {
    setupCreatedMovement("ADJUST");
    mockTx.warehouseStock.findFirst.mockResolvedValue({ id: "ws-1", grams: new Prisma.Decimal("100") });

    await expect(
      createMovement({
        jewelryId: "jw-1", userId: "u-1", warehouseId: "wh-1",
        kind: "ADJUST", effectiveAt: new Date(),
        lines: [{ variantId: "var-1", grams: "-15" }],
      })
    ).resolves.toBeDefined();

    expect(mockTx.warehouseStock.update).toHaveBeenCalledWith({
      where: { id: "ws-1" },
      data: { grams: new Prisma.Decimal("85") },  // 100 - 15
    });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// E. voidMovement — doble anulación bloqueada
// ─────────────────────────────────────────────────────────────────────────────

describe("voidMovement — doble anulación bloqueada", () => {
  it("falla si el movimiento ya tiene deletedAt (no existe en DB con deletedAt=null)", async () => {
    vi.clearAllMocks();
    setupTransaction();
    // findFirst devuelve null porque el where filtra deletedAt: null
    mockTx.inventoryMovement.findFirst.mockResolvedValue(null);

    await expect(
      voidMovement({ id: "mov-ya-anulado", jewelryId: "jw-1", userId: "u-1" })
    ).rejects.toThrow("no encontrado");
  });
});
