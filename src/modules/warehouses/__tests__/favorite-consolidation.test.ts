// src/modules/warehouses/__tests__/favorite-consolidation.test.ts
//
// UX 2026-06-14 — La estrella de Almacenes pasó a representar el favorito
// GENERAL de la joyería (compartido), igual que SalesChannel / PriceList /
// Seller. La preferencia PERSONAL del usuario vive en
// UserPreference.defaultWarehouseId (override, se setea desde "Mis preferencias").
//
// Invariantes de `setFavoriteWarehouse`:
//   - Marca `Warehouse.isFavorite=true` en el objetivo y desmarca los demás de
//     la joyería (único favorito por joyería).
//   - Re-click sobre el favorito actual → lo desmarca (toggle off).
//   - NO escribe UserPreference (la estrella ya no es per-usuario).
//   - NO escribe el legacy User.favoriteWarehouseId.
//   - Valida que el almacén pertenezca al tenant y esté activo.

import { describe, it, expect, vi, beforeEach } from "vitest";

const mockPrisma = vi.hoisted(() => ({
  user:           { findFirst: vi.fn(), updateMany: vi.fn() },
  warehouse:      { findFirst: vi.fn(), updateMany: vi.fn(), update: vi.fn() },
  userPreference: { findUnique: vi.fn(), upsert: vi.fn(), updateMany: vi.fn() },
}));

vi.mock("../../../lib/prisma.js", () => ({ prisma: mockPrisma }));

import { setFavoriteWarehouse } from "../warehouses.service.js";

const JID = "jew-1";
const UID = "user-1";

beforeEach(() => {
  vi.clearAllMocks();
});

describe("setFavoriteWarehouse (favorito GENERAL de la joyería)", () => {
  it("marca el almacén como favorito de joyería y desmarca los demás; NO toca UserPreference ni el legacy", async () => {
    mockPrisma.user.findFirst.mockResolvedValue({ id: UID });
    mockPrisma.warehouse.findFirst.mockResolvedValue({ id: "wh-1", isFavorite: false });
    mockPrisma.warehouse.updateMany.mockResolvedValue({ count: 1 });
    mockPrisma.warehouse.update.mockResolvedValue({ id: "wh-1", isFavorite: true });

    const out = await setFavoriteWarehouse({ userId: UID, jewelryId: JID, warehouseId: "wh-1" });

    expect(out).toEqual({ ok: true, favoriteWarehouseId: "wh-1" });

    // Desmarca los OTROS de la joyería...
    expect(mockPrisma.warehouse.updateMany).toHaveBeenCalledOnce();
    const many = mockPrisma.warehouse.updateMany.mock.calls[0][0];
    expect(many.where).toEqual({ jewelryId: JID, deletedAt: null, id: { not: "wh-1" } });
    expect(many.data).toEqual({ isFavorite: false });
    // ...y marca ESTE.
    expect(mockPrisma.warehouse.update).toHaveBeenCalledWith({
      where: { id: "wh-1" },
      data: { isFavorite: true },
    });

    // NO escribe la preferencia personal ni el legacy.
    expect(mockPrisma.userPreference.upsert).not.toHaveBeenCalled();
    expect(mockPrisma.user.updateMany).not.toHaveBeenCalled();
  });

  it("re-click sobre el favorito actual → lo desmarca (toggle off)", async () => {
    mockPrisma.user.findFirst.mockResolvedValue({ id: UID });
    mockPrisma.warehouse.findFirst.mockResolvedValue({ id: "wh-1", isFavorite: true });
    mockPrisma.warehouse.update.mockResolvedValue({ id: "wh-1", isFavorite: false });

    const out = await setFavoriteWarehouse({ userId: UID, jewelryId: JID, warehouseId: "wh-1" });

    expect(out).toEqual({ ok: true, favoriteWarehouseId: null });
    expect(mockPrisma.warehouse.update).toHaveBeenCalledWith({
      where: { id: "wh-1" },
      data: { isFavorite: false },
    });
    // No reordena los demás cuando es un toggle-off.
    expect(mockPrisma.warehouse.updateMany).not.toHaveBeenCalled();
    expect(mockPrisma.userPreference.upsert).not.toHaveBeenCalled();
  });

  it("rechaza un almacén inexistente/inactivo del tenant", async () => {
    mockPrisma.user.findFirst.mockResolvedValue({ id: UID });
    mockPrisma.warehouse.findFirst.mockResolvedValue(null); // no activo / no del tenant

    await expect(
      setFavoriteWarehouse({ userId: UID, jewelryId: JID, warehouseId: "wh-x" })
    ).rejects.toThrow(/no se puede marcar como favorito/i);

    expect(mockPrisma.warehouse.updateMany).not.toHaveBeenCalled();
    expect(mockPrisma.warehouse.update).not.toHaveBeenCalled();
    expect(mockPrisma.userPreference.upsert).not.toHaveBeenCalled();
  });
});
