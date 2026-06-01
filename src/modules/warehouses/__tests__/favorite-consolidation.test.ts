// src/modules/warehouses/__tests__/favorite-consolidation.test.ts
//
// Fase 2 — La estrella de Almacenes es PERSONAL por usuario y su fuente de
// verdad pasó a ser UserPreference.defaultWarehouseId.
// Invariantes:
//   - setFavoriteWarehouse escribe UserPreference (upsert), NO el legacy
//     User.favoriteWarehouseId (prisma.user.updateMany NO se llama).
//   - Valida que el almacén pertenezca al tenant y esté activo.

import { describe, it, expect, vi, beforeEach } from "vitest";

const mockPrisma = vi.hoisted(() => ({
  user:           { findFirst: vi.fn(), updateMany: vi.fn() },
  warehouse:      { findFirst: vi.fn() },
  userPreference: { findUnique: vi.fn(), upsert: vi.fn(), updateMany: vi.fn() },
}));

vi.mock("../../../lib/prisma.js", () => ({ prisma: mockPrisma }));

import { setFavoriteWarehouse } from "../warehouses.service.js";

const JID = "jew-1";
const UID = "user-1";

beforeEach(() => {
  vi.clearAllMocks();
});

describe("setFavoriteWarehouse (consolidación UserPreference)", () => {
  it("escribe UserPreference y NO el legacy User.favoriteWarehouseId", async () => {
    mockPrisma.user.findFirst.mockResolvedValue({ id: UID });
    mockPrisma.warehouse.findFirst.mockResolvedValue({ id: "wh-1" });
    mockPrisma.userPreference.upsert.mockResolvedValue({});

    const out = await setFavoriteWarehouse({ userId: UID, jewelryId: JID, warehouseId: "wh-1" });

    expect(out).toEqual({ ok: true, favoriteWarehouseId: "wh-1" });

    // Escribió la NUEVA fuente de verdad...
    expect(mockPrisma.userPreference.upsert).toHaveBeenCalledOnce();
    const arg = mockPrisma.userPreference.upsert.mock.calls[0][0];
    expect(arg.where).toEqual({ userId_scope: { userId: UID, scope: "SALES_INVOICE" } });
    expect(arg.update).toEqual({ jewelryId: JID, defaultWarehouseId: "wh-1" });

    // ...y NO el legacy.
    expect(mockPrisma.user.updateMany).not.toHaveBeenCalled();
  });

  it("rechaza un almacén inexistente/inactivo del tenant", async () => {
    mockPrisma.user.findFirst.mockResolvedValue({ id: UID });
    mockPrisma.warehouse.findFirst.mockResolvedValue(null); // no activo / no del tenant

    await expect(
      setFavoriteWarehouse({ userId: UID, jewelryId: JID, warehouseId: "wh-x" })
    ).rejects.toThrow(/no se puede marcar como favorito/i);

    expect(mockPrisma.userPreference.upsert).not.toHaveBeenCalled();
    expect(mockPrisma.user.updateMany).not.toHaveBeenCalled();
  });
});
