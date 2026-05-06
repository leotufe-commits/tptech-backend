// src/modules/units/__tests__/units.service.test.ts
// Smoke tests para el service de Units (Fase 3).
// No tocan DB real — mockean prisma.unit y verifican comportamiento.

import { describe, it, expect, vi, beforeEach } from "vitest";

const mockPrisma = vi.hoisted(() => ({
  unit: {
    findFirst: vi.fn(),
    findMany:  vi.fn(),
    create:    vi.fn(),
    update:    vi.fn(),
    updateMany: vi.fn(),
  },
}));
vi.mock("../../../lib/prisma.js", () => ({ prisma: mockPrisma }));

import * as service from "../units.service.js";

const J = "jew-1";

beforeEach(() => {
  vi.clearAllMocks();
});

describe("listUnits", () => {
  it("filtra por jewelryId, type, isActive y q; ordena por type/sortOrder/name", async () => {
    mockPrisma.unit.findMany.mockResolvedValue([{ id: "u1", code: "g", name: "Gramo" }]);

    const out = await service.listUnits(J, { type: "WEIGHT", isActive: true, q: "gr" });

    expect(out.items).toEqual([{ id: "u1", code: "g", name: "Gramo" }]);
    const [args] = mockPrisma.unit.findMany.mock.calls[0];
    expect(args.where.jewelryId).toBe(J);
    expect(args.where.deletedAt).toBeNull();
    expect(args.where.type).toBe("WEIGHT");
    expect(args.where.isActive).toBe(true);
    expect(args.where.OR).toEqual([
      { name: { contains: "gr", mode: "insensitive" } },
      { code: { contains: "gr", mode: "insensitive" } },
    ]);
    expect(args.orderBy).toEqual([
      { type: "asc" }, { sortOrder: "asc" }, { name: "asc" },
    ]);
  });
});

describe("createUnit", () => {
  it("crea unidad nueva sin duplicado", async () => {
    mockPrisma.unit.findFirst.mockResolvedValueOnce(null); // no duplicado activo
    mockPrisma.unit.findFirst.mockResolvedValueOnce(null); // no soft-deleted
    mockPrisma.unit.create.mockResolvedValue({
      id: "u1", jewelryId: J, name: "Onza", code: "oz", type: "WEIGHT",
      isFavorite: false, isActive: true, sortOrder: 5, isSystem: false,
    });

    const out = await service.createUnit(J, {
      name: "Onza", code: "oz", type: "WEIGHT", sortOrder: 5,
    });

    expect(out.item.code).toBe("oz");
    expect(mockPrisma.unit.create).toHaveBeenCalledWith({
      data: expect.objectContaining({
        jewelryId: J, name: "Onza", code: "oz", type: "WEIGHT", sortOrder: 5,
      }),
      select: expect.any(Object),
    });
  });

  it("rechaza duplicados (409)", async () => {
    mockPrisma.unit.findFirst.mockResolvedValueOnce({ id: "dup", code: "g", name: "Gramo" });

    await expect(
      service.createUnit(J, { name: "Gramo", code: "g", type: "WEIGHT" })
    ).rejects.toMatchObject({ status: 409 });
  });

  it("normaliza code (trim) y name (collapse spaces)", async () => {
    mockPrisma.unit.findFirst.mockResolvedValue(null);
    mockPrisma.unit.create.mockResolvedValue({ isFavorite: false });

    await service.createUnit(J, {
      name: "  Centímetro  cuadrado  ", code: "  cm2  ", type: "LENGTH",
    });

    const [{ data }] = mockPrisma.unit.create.mock.calls[0];
    expect(data.name).toBe("Centímetro cuadrado");
    expect(data.code).toBe("cm2");
  });

  it("si crea como favorita, limpia otras favoritas del mismo type", async () => {
    mockPrisma.unit.findFirst.mockResolvedValue(null);
    mockPrisma.unit.create.mockResolvedValue({
      id: "u1", type: "WEIGHT", isFavorite: true,
    });

    await service.createUnit(J, {
      name: "Onza", code: "oz", type: "WEIGHT", isFavorite: true,
    });

    expect(mockPrisma.unit.updateMany).toHaveBeenCalledWith({
      where: { jewelryId: J, type: "WEIGHT", isFavorite: true, NOT: { id: "u1" } },
      data: { isFavorite: false },
    });
  });
});

describe("updateUnit", () => {
  it("rechaza cuando no existe (404)", async () => {
    mockPrisma.unit.findFirst.mockResolvedValue(null);
    await expect(
      service.updateUnit("u-x", J, { name: "x" })
    ).rejects.toMatchObject({ status: 404 });
  });

  it("detecta duplicado al cambiar code/type/name (409)", async () => {
    mockPrisma.unit.findFirst.mockResolvedValueOnce({
      id: "u1", type: "WEIGHT", code: "g", name: "Gramo", isSystem: false,
    });
    mockPrisma.unit.findFirst.mockResolvedValueOnce({ id: "u-other" }); // duplicado encontrado

    await expect(
      service.updateUnit("u1", J, { code: "kg" })
    ).rejects.toMatchObject({ status: 409 });
  });

  it("actualiza campos y rechaza body vacío", async () => {
    mockPrisma.unit.findFirst.mockResolvedValueOnce({
      id: "u1", type: "WEIGHT", code: "g", name: "Gramo", isSystem: false,
    });
    await expect(
      service.updateUnit("u1", J, {})
    ).rejects.toMatchObject({ status: 400 });
  });
});

describe("setFavoriteUnit", () => {
  it("al marcar favorita, limpia otras del mismo type primero", async () => {
    mockPrisma.unit.findFirst.mockResolvedValue({ id: "u1", type: "LENGTH" });
    mockPrisma.unit.update.mockResolvedValue({ id: "u1", isFavorite: true });

    await service.setFavoriteUnit("u1", J, true);

    expect(mockPrisma.unit.updateMany).toHaveBeenCalledWith({
      where: { jewelryId: J, type: "LENGTH", isFavorite: true, NOT: { id: "u1" } },
      data: { isFavorite: false },
    });
    expect(mockPrisma.unit.update).toHaveBeenCalledWith({
      where: { id: "u1" }, data: { isFavorite: true }, select: expect.any(Object),
    });
  });

  it("al desmarcar favorita, NO toca a las demás", async () => {
    mockPrisma.unit.findFirst.mockResolvedValue({ id: "u1", type: "LENGTH" });
    mockPrisma.unit.update.mockResolvedValue({ id: "u1", isFavorite: false });

    await service.setFavoriteUnit("u1", J, false);

    expect(mockPrisma.unit.updateMany).not.toHaveBeenCalled();
  });
});

describe("deleteUnit", () => {
  it("aplica soft delete (deletedAt + isActive=false + isFavorite=false)", async () => {
    mockPrisma.unit.findFirst.mockResolvedValue({ id: "u1", isSystem: false });
    mockPrisma.unit.update.mockResolvedValue({ id: "u1" });

    await service.deleteUnit("u1", J);

    const [{ where, data }] = mockPrisma.unit.update.mock.calls[0];
    expect(where).toEqual({ id: "u1" });
    expect(data.deletedAt).toBeInstanceOf(Date);
    expect(data.isActive).toBe(false);
    expect(data.isFavorite).toBe(false);
  });

  it("404 si no existe", async () => {
    mockPrisma.unit.findFirst.mockResolvedValue(null);
    await expect(service.deleteUnit("u-x", J)).rejects.toMatchObject({ status: 404 });
  });
});
