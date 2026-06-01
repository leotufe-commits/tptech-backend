// src/modules/user-preferences/__tests__/user-preferences.service.test.ts
//
// Invariantes Fase 1 (scope SALES_INVOICE):
//   - getMyPreference sin fila → DTO con todos los defaults en null
//   - updateMyPreference rechaza un id que pertenece a OTRA joyería
//   - updateMyPreference upsertea cuando los ids son válidos
//   - null limpia la preferencia de ese campo

import { describe, it, expect, vi, beforeEach } from "vitest";
import { Prisma } from "@prisma/client";

const mockPrisma = vi.hoisted(() => ({
  userPreference: {
    findUnique: vi.fn(),
    upsert: vi.fn(),
    updateMany: vi.fn(),
  },
  user:        { findFirst: vi.fn() },
  warehouse:   { findFirst: vi.fn() },
  seller:      { findFirst: vi.fn() },
  priceList:   { findFirst: vi.fn() },
  salesChannel:{ findFirst: vi.fn() },
  currency:    { findFirst: vi.fn() },
}));

vi.mock("../../../lib/prisma.js", () => ({ prisma: mockPrisma }));

import {
  getMyPreference,
  updateMyPreference,
  getSalesDefaultWarehouseId,
  setSalesDefaultWarehouseId,
  reassignSalesDefaultWarehouse,
} from "../user-preferences.service.js";

const JID = "jew-1";
const UID = "user-1";

beforeEach(() => {
  vi.clearAllMocks();
});

describe("getMyPreference", () => {
  it("devuelve DTO con defaults en null cuando no hay fila", async () => {
    mockPrisma.userPreference.findUnique.mockResolvedValue(null);
    const dto = await getMyPreference(JID, UID);
    expect(dto).toEqual({
      scope: "SALES_INVOICE",
      defaultWarehouseId: null,
      defaultSellerId: null,
      defaultPriceListId: null,
      defaultChannelId: null,
      defaultCurrencyId: null,
      defaultGlobalDiscountType: null,
      invoiceLayoutConfig: null,
      preferredInvoiceViewPreset: null,
      invoiceUiPreferences: null,
    });
  });

  it("mapea la fila existente al DTO", async () => {
    mockPrisma.userPreference.findUnique.mockResolvedValue({
      defaultWarehouseId: "wh-9",
      defaultSellerId: null,
      defaultPriceListId: null,
      defaultChannelId: null,
      defaultCurrencyId: null,
    });
    const dto = await getMyPreference(JID, UID);
    expect(dto.defaultWarehouseId).toBe("wh-9");
    expect(dto.scope).toBe("SALES_INVOICE");
  });
});

describe("updateMyPreference", () => {
  it("rechaza un almacén de otra joyería (no hace upsert)", async () => {
    mockPrisma.warehouse.findFirst.mockResolvedValue(null); // no pertenece
    await expect(
      updateMyPreference(JID, UID, { defaultWarehouseId: "wh-otra-joyeria" })
    ).rejects.toThrow(/no pertenece a la joyería/i);
    expect(mockPrisma.userPreference.upsert).not.toHaveBeenCalled();
  });

  it("upsertea cuando los ids son válidos", async () => {
    mockPrisma.warehouse.findFirst.mockResolvedValue({ id: "wh-1" });
    mockPrisma.userPreference.upsert.mockResolvedValue({
      defaultWarehouseId: "wh-1",
      defaultSellerId: null,
      defaultPriceListId: null,
      defaultChannelId: null,
      defaultCurrencyId: null,
    });

    const dto = await updateMyPreference(JID, UID, { defaultWarehouseId: "wh-1" });

    expect(mockPrisma.userPreference.upsert).toHaveBeenCalledOnce();
    const arg = mockPrisma.userPreference.upsert.mock.calls[0][0];
    expect(arg.where).toEqual({ userId_scope: { userId: UID, scope: "SALES_INVOICE" } });
    expect(arg.create).toMatchObject({ jewelryId: JID, userId: UID, scope: "SALES_INVOICE", defaultWarehouseId: "wh-1" });
    expect(dto.defaultWarehouseId).toBe("wh-1");
  });

  it("valida pertenencia de TODOS los campos y rechaza moneda de otra joyería", async () => {
    mockPrisma.warehouse.findFirst.mockResolvedValue({ id: "wh-1" });
    mockPrisma.seller.findFirst.mockResolvedValue({ id: "se-1" });
    mockPrisma.priceList.findFirst.mockResolvedValue({ id: "pl-1" });
    mockPrisma.salesChannel.findFirst.mockResolvedValue({ id: "ch-1" });
    mockPrisma.currency.findFirst.mockResolvedValue(null); // moneda ajena

    await expect(
      updateMyPreference(JID, UID, {
        defaultWarehouseId: "wh-1",
        defaultSellerId: "se-1",
        defaultPriceListId: "pl-1",
        defaultChannelId: "ch-1",
        defaultCurrencyId: "cur-otra",
      })
    ).rejects.toThrow(/moneda seleccionada no pertenece/i);
    expect(mockPrisma.userPreference.upsert).not.toHaveBeenCalled();
  });

  it("upsertea los 5 campos cuando todos son válidos", async () => {
    mockPrisma.warehouse.findFirst.mockResolvedValue({ id: "wh-1" });
    mockPrisma.seller.findFirst.mockResolvedValue({ id: "se-1" });
    mockPrisma.priceList.findFirst.mockResolvedValue({ id: "pl-1" });
    mockPrisma.salesChannel.findFirst.mockResolvedValue({ id: "ch-1" });
    mockPrisma.currency.findFirst.mockResolvedValue({ id: "cu-1" });
    mockPrisma.userPreference.upsert.mockResolvedValue({
      defaultWarehouseId: "wh-1",
      defaultSellerId: "se-1",
      defaultPriceListId: "pl-1",
      defaultChannelId: "ch-1",
      defaultCurrencyId: "cu-1",
    });

    const dto = await updateMyPreference(JID, UID, {
      defaultWarehouseId: "wh-1",
      defaultSellerId: "se-1",
      defaultPriceListId: "pl-1",
      defaultChannelId: "ch-1",
      defaultCurrencyId: "cu-1",
    });

    const arg = mockPrisma.userPreference.upsert.mock.calls[0][0];
    expect(arg.create).toMatchObject({
      jewelryId: JID, userId: UID, scope: "SALES_INVOICE",
      defaultWarehouseId: "wh-1", defaultSellerId: "se-1",
      defaultPriceListId: "pl-1", defaultChannelId: "ch-1", defaultCurrencyId: "cu-1",
    });
    expect(dto.defaultCurrencyId).toBe("cu-1");
  });

  it("null limpia el campo y no valida pertenencia (regresión)", async () => {
    mockPrisma.userPreference.upsert.mockResolvedValue({
      defaultWarehouseId: null,
      defaultSellerId: null,
      defaultPriceListId: null,
      defaultChannelId: null,
      defaultCurrencyId: null,
    });

    await updateMyPreference(JID, UID, { defaultWarehouseId: null });

    expect(mockPrisma.warehouse.findFirst).not.toHaveBeenCalled();
    const arg = mockPrisma.userPreference.upsert.mock.calls[0][0];
    expect(arg.update.defaultWarehouseId).toBeNull();
  });

  // ────────────────────────────────────────────────────────────────────────
  // defaultGlobalDiscountType (PERCENT | AMOUNT | null) — no es un id de
  // entidad: NO pasa por validateOwnership y se persiste tal cual.
  // ────────────────────────────────────────────────────────────────────────
  it("persiste defaultGlobalDiscountType='PERCENT' sin tocar validateOwnership", async () => {
    mockPrisma.userPreference.upsert.mockResolvedValue({
      defaultGlobalDiscountType: "PERCENT",
    });
    const dto = await updateMyPreference(JID, UID, { defaultGlobalDiscountType: "PERCENT" });
    expect(mockPrisma.warehouse.findFirst).not.toHaveBeenCalled();
    const arg = mockPrisma.userPreference.upsert.mock.calls[0][0];
    expect(arg.create).toMatchObject({ defaultGlobalDiscountType: "PERCENT" });
    expect(dto.defaultGlobalDiscountType).toBe("PERCENT");
  });

  it("persiste defaultGlobalDiscountType='AMOUNT'", async () => {
    mockPrisma.userPreference.upsert.mockResolvedValue({
      defaultGlobalDiscountType: "AMOUNT",
    });
    const dto = await updateMyPreference(JID, UID, { defaultGlobalDiscountType: "AMOUNT" });
    expect(arg(mockPrisma.userPreference.upsert).update.defaultGlobalDiscountType).toBe("AMOUNT");
    expect(dto.defaultGlobalDiscountType).toBe("AMOUNT");
  });

  it("string desconocido → null (sanitización defensiva)", async () => {
    mockPrisma.userPreference.upsert.mockResolvedValue({
      defaultGlobalDiscountType: null,
    });
    await updateMyPreference(JID, UID, { defaultGlobalDiscountType: "BOGUS" as any });
    expect(arg(mockPrisma.userPreference.upsert).update.defaultGlobalDiscountType).toBeNull();
  });

  it("null limpia el favorito", async () => {
    mockPrisma.userPreference.upsert.mockResolvedValue({
      defaultGlobalDiscountType: null,
    });
    await updateMyPreference(JID, UID, { defaultGlobalDiscountType: null });
    expect(arg(mockPrisma.userPreference.upsert).update.defaultGlobalDiscountType).toBeNull();
  });

  // ────────────────────────────────────────────────────────────────────────
  // REGRESIÓN — PATCH parcial: el endpoint debe tocar SOLO los campos cuya
  // key esté en el body. Antes era REPLACE → marcar el favorito del tipo de
  // descuento borraba warehouseId/seller/etc., e inversamente guardar Mis
  // preferencias borraba el favorito recién marcado. El bug reportado del
  // usuario ("el favorito no se recuerda") venía de esta interacción.
  // ────────────────────────────────────────────────────────────────────────
  it("PATCH parcial: mandar solo defaultGlobalDiscountType NO incluye los otros ids en `update`", async () => {
    mockPrisma.userPreference.upsert.mockResolvedValue({
      defaultGlobalDiscountType: "PERCENT",
    });
    await updateMyPreference(JID, UID, { defaultGlobalDiscountType: "PERCENT" });
    const u = arg(mockPrisma.userPreference.upsert).update;
    // El único campo que se actualiza es el que vino en body. Los demás
    // NO aparecen en `update` → Prisma los deja intactos.
    expect(u.defaultGlobalDiscountType).toBe("PERCENT");
    expect("defaultWarehouseId" in u).toBe(false);
    expect("defaultSellerId" in u).toBe(false);
    expect("defaultPriceListId" in u).toBe(false);
    expect("defaultChannelId" in u).toBe(false);
    expect("defaultCurrencyId" in u).toBe(false);
  });

  it("PATCH parcial: mandar solo defaultWarehouseId NO toca defaultGlobalDiscountType existente", async () => {
    mockPrisma.warehouse.findFirst.mockResolvedValue({ id: "wh-1" });
    mockPrisma.userPreference.upsert.mockResolvedValue({
      defaultWarehouseId: "wh-1",
      defaultGlobalDiscountType: "AMOUNT", // ya existía en DB
    });
    await updateMyPreference(JID, UID, { defaultWarehouseId: "wh-1" });
    const u = arg(mockPrisma.userPreference.upsert).update;
    // Solo el campo enviado aparece en update.
    expect(u.defaultWarehouseId).toBe("wh-1");
    expect("defaultGlobalDiscountType" in u).toBe(false);
  });

  it("PATCH parcial: mandar los 5 ids legacy (sin tipo descuento) NO borra el favorito de tipo", async () => {
    mockPrisma.warehouse.findFirst.mockResolvedValue({ id: "wh-1" });
    mockPrisma.seller.findFirst.mockResolvedValue({ id: "se-1" });
    mockPrisma.priceList.findFirst.mockResolvedValue({ id: "pl-1" });
    mockPrisma.salesChannel.findFirst.mockResolvedValue({ id: "ch-1" });
    mockPrisma.currency.findFirst.mockResolvedValue({ id: "cu-1" });
    mockPrisma.userPreference.upsert.mockResolvedValue({
      defaultWarehouseId: "wh-1", defaultSellerId: "se-1",
      defaultPriceListId: "pl-1", defaultChannelId: "ch-1",
      defaultCurrencyId: "cu-1",
      defaultGlobalDiscountType: "PERCENT",
    });
    await updateMyPreference(JID, UID, {
      defaultWarehouseId: "wh-1", defaultSellerId: "se-1",
      defaultPriceListId: "pl-1", defaultChannelId: "ch-1",
      defaultCurrencyId: "cu-1",
    });
    const u = arg(mockPrisma.userPreference.upsert).update;
    // Los 5 ids enviados se actualizan. `defaultGlobalDiscountType` NO se
    // incluye en update → la columna en DB queda intacta.
    expect(u.defaultWarehouseId).toBe("wh-1");
    expect(u.defaultSellerId).toBe("se-1");
    expect("defaultGlobalDiscountType" in u).toBe(false);
  });

  // ────────────────────────────────────────────────────────────────────────
  // invoiceLayoutConfig — JSON opaco. Backend solo persiste forma mínima
  // `{ version: number, cards: array }`. El frontend valida más estricto.
  // ────────────────────────────────────────────────────────────────────────
  it("persiste invoiceLayoutConfig con shape válido", async () => {
    const layout = {
      version: 1,
      cards: [
        { id: "discount", slot: "aside", order: 0, width: "full" },
        { id: "shipping", slot: "aside", order: 1, width: "full" },
      ],
    };
    mockPrisma.userPreference.upsert.mockResolvedValue({ invoiceLayoutConfig: layout });
    const dto = await updateMyPreference(JID, UID, { invoiceLayoutConfig: layout });
    expect(arg(mockPrisma.userPreference.upsert).update.invoiceLayoutConfig).toEqual(layout);
    expect(dto.invoiceLayoutConfig).toEqual(layout);
  });

  it("invoiceLayoutConfig inválido (sin version) → null", async () => {
    mockPrisma.userPreference.upsert.mockResolvedValue({ invoiceLayoutConfig: null });
    await updateMyPreference(JID, UID, { invoiceLayoutConfig: { cards: [] } as any });
    // Prisma 7 mapea `null` para Json? como `Prisma.JsonNull` (objeto del enum).
    // Equivalente semántico de "limpia el campo" en DB.
    expect(arg(mockPrisma.userPreference.upsert).update.invoiceLayoutConfig).toEqual(Prisma.JsonNull);
  });

  it("invoiceLayoutConfig inválido (cards no array) → null", async () => {
    mockPrisma.userPreference.upsert.mockResolvedValue({ invoiceLayoutConfig: null });
    await updateMyPreference(JID, UID, { invoiceLayoutConfig: { version: 1, cards: "nope" } as any });
    // Prisma 7 mapea `null` para Json? como `Prisma.JsonNull` (objeto del enum).
    // Equivalente semántico de "limpia el campo" en DB.
    expect(arg(mockPrisma.userPreference.upsert).update.invoiceLayoutConfig).toEqual(Prisma.JsonNull);
  });

  it("null limpia el layout (restaura default del frontend)", async () => {
    mockPrisma.userPreference.upsert.mockResolvedValue({ invoiceLayoutConfig: null });
    await updateMyPreference(JID, UID, { invoiceLayoutConfig: null });
    // Prisma 7 mapea `null` para Json? como `Prisma.JsonNull` (objeto del enum).
    // Equivalente semántico de "limpia el campo" en DB.
    expect(arg(mockPrisma.userPreference.upsert).update.invoiceLayoutConfig).toEqual(Prisma.JsonNull);
  });

  it("PATCH parcial: mandar solo invoiceLayoutConfig NO toca los otros defaults", async () => {
    const layout = { version: 1, cards: [] };
    mockPrisma.userPreference.upsert.mockResolvedValue({ invoiceLayoutConfig: layout });
    await updateMyPreference(JID, UID, { invoiceLayoutConfig: layout });
    const u = arg(mockPrisma.userPreference.upsert).update;
    expect(u.invoiceLayoutConfig).toEqual(layout);
    expect("defaultWarehouseId" in u).toBe(false);
    expect("defaultGlobalDiscountType" in u).toBe(false);
  });

  it("PATCH parcial: mandar solo defaultWarehouseId NO toca invoiceLayoutConfig existente", async () => {
    mockPrisma.warehouse.findFirst.mockResolvedValue({ id: "wh-1" });
    mockPrisma.userPreference.upsert.mockResolvedValue({ defaultWarehouseId: "wh-1" });
    await updateMyPreference(JID, UID, { defaultWarehouseId: "wh-1" });
    const u = arg(mockPrisma.userPreference.upsert).update;
    expect("invoiceLayoutConfig" in u).toBe(false);
  });

  it("CREATE inicial sí lleva todos los campos (incluso los no enviados, como null)", async () => {
    // Cuando es la primera vez que el usuario guarda preferencias, Prisma
    // hace CREATE. Debemos inicializar TODOS los campos (las keys ausentes
    // quedan en null). Si no, la columna no existiría y un GET posterior
    // devolvería undefined → el frontend no podría distinguir "sin
    // preferencia" de "campo borrado".
    mockPrisma.userPreference.upsert.mockResolvedValue({
      defaultGlobalDiscountType: "PERCENT",
    });
    await updateMyPreference(JID, UID, { defaultGlobalDiscountType: "PERCENT" });
    const c = arg(mockPrisma.userPreference.upsert).create;
    expect(c.defaultGlobalDiscountType).toBe("PERCENT");
    expect(c.defaultWarehouseId).toBeNull();
    expect(c.defaultSellerId).toBeNull();
    expect(c.defaultPriceListId).toBeNull();
    expect(c.defaultChannelId).toBeNull();
    expect(c.defaultCurrencyId).toBeNull();
    // create con valor null en Json? → Prisma.JsonNull (equivalente a "limpia el campo").
    expect(c.invoiceLayoutConfig).toEqual(Prisma.JsonNull);
    // preferredInvoiceViewPreset también se incluye en CREATE como null.
    expect(c.preferredInvoiceViewPreset).toBeNull();
    // invoiceUiPreferences (UX.20) — JsonNull en CREATE inicial.
    expect(c.invoiceUiPreferences).toEqual(Prisma.JsonNull);
  });

  // ────────────────────────────────────────────────────────────────────────
  // invoiceUiPreferences — Configuraciones finas de UI (UX.20)
  // JSON opaco. Backend solo persiste — el frontend valida con
  // `resolveInvoiceUiPreferences`.
  // ────────────────────────────────────────────────────────────────────────
  describe("invoiceUiPreferences", () => {
    it("persiste objeto JSON arbitrario tal cual", async () => {
      const ui = { density: "COMPACT", stickyActions: true, foo: 42 };
      mockPrisma.userPreference.upsert.mockResolvedValue({
        invoiceUiPreferences: ui,
      });
      await updateMyPreference(JID, UID, { invoiceUiPreferences: ui });
      const c = arg(mockPrisma.userPreference.upsert).create;
      expect(c.invoiceUiPreferences).toEqual(ui);
    });

    it("null limpia el JSON (Prisma.JsonNull en update)", async () => {
      mockPrisma.userPreference.upsert.mockResolvedValue({ invoiceUiPreferences: null });
      await updateMyPreference(JID, UID, { invoiceUiPreferences: null });
      const u = arg(mockPrisma.userPreference.upsert).update;
      expect(u.invoiceUiPreferences).toEqual(Prisma.JsonNull);
    });

    it("array → null (sanitización defensiva: solo acepta objetos)", async () => {
      mockPrisma.userPreference.upsert.mockResolvedValue({ invoiceUiPreferences: null });
      await updateMyPreference(JID, UID, { invoiceUiPreferences: [1, 2, 3] as any });
      const c = arg(mockPrisma.userPreference.upsert).create;
      expect(c.invoiceUiPreferences).toEqual(Prisma.JsonNull);
    });

    it("PATCH parcial: mandar solo invoiceUiPreferences NO toca otros defaults", async () => {
      const ui = { density: "COMFORTABLE" };
      mockPrisma.userPreference.upsert.mockResolvedValue({ invoiceUiPreferences: ui });
      await updateMyPreference(JID, UID, { invoiceUiPreferences: ui });
      const u = arg(mockPrisma.userPreference.upsert).update;
      expect("preferredInvoiceViewPreset" in u).toBe(false);
      expect("invoiceLayoutConfig" in u).toBe(false);
      expect("defaultWarehouseId" in u).toBe(false);
    });

    it("PATCH parcial: mandar solo preferredInvoiceViewPreset NO toca invoiceUiPreferences existente", async () => {
      mockPrisma.userPreference.upsert.mockResolvedValue({
        preferredInvoiceViewPreset: "CLASSIC",
        invoiceUiPreferences: { density: "NORMAL" },
      });
      await updateMyPreference(JID, UID, { preferredInvoiceViewPreset: "CLASSIC" });
      const u = arg(mockPrisma.userPreference.upsert).update;
      expect("invoiceUiPreferences" in u).toBe(false);
    });

    it("mapea el campo en el DTO al hacer getMyPreference", async () => {
      const ui = { density: "COMPACT", stickyActions: false };
      mockPrisma.userPreference.findUnique.mockResolvedValue({
        invoiceUiPreferences: ui,
      });
      const dto = await getMyPreference(JID, UID);
      expect(dto.invoiceUiPreferences).toEqual(ui);
    });
  });

  // ────────────────────────────────────────────────────────────────────────
  // preferredInvoiceViewPreset — Plantillas de vista (UX.16 rename)
  // Enum: COMPACT (default) | CLASSIC | SINGLE_COLUMN | CUSTOM.
  // Legacy: "BALANCED" en DB se mapea automáticamente a "COMPACT".
  // ────────────────────────────────────────────────────────────────────────
  describe("preferredInvoiceViewPreset", () => {
    it("persiste COMPACT sin tocar validateOwnership (no es un id)", async () => {
      mockPrisma.userPreference.upsert.mockResolvedValue({
        preferredInvoiceViewPreset: "COMPACT",
      });
      await updateMyPreference(JID, UID, { preferredInvoiceViewPreset: "COMPACT" });
      // Ningún findFirst de ownership fue invocado (no son ids).
      expect(mockPrisma.warehouse.findFirst).not.toHaveBeenCalled();
      expect(mockPrisma.seller.findFirst).not.toHaveBeenCalled();
      const c = arg(mockPrisma.userPreference.upsert).create;
      expect(c.preferredInvoiceViewPreset).toBe("COMPACT");
    });

    it.each(["CLASSIC", "ONE_LINE"] as const)(
      "persiste preset oficial %s",
      async (preset) => {
        mockPrisma.userPreference.upsert.mockResolvedValue({
          preferredInvoiceViewPreset: preset,
        });
        await updateMyPreference(JID, UID, { preferredInvoiceViewPreset: preset });
        const c = arg(mockPrisma.userPreference.upsert).create;
        expect(c.preferredInvoiceViewPreset).toBe(preset);
      },
    );

    it.each(["SINGLE_COLUMN", "CUSTOM"] as const)(
      "LEGACY: preset '%s' se mapea a 'COMPACT'",
      async (legacy) => {
        mockPrisma.userPreference.upsert.mockResolvedValue({
          preferredInvoiceViewPreset: "COMPACT",
        });
        await updateMyPreference(JID, UID, { preferredInvoiceViewPreset: legacy });
        const c = arg(mockPrisma.userPreference.upsert).create;
        expect(c.preferredInvoiceViewPreset).toBe("COMPACT");
      },
    );

    it("LEGACY: 'BALANCED' enviado por cliente viejo se mapea a 'COMPACT'", async () => {
      mockPrisma.userPreference.upsert.mockResolvedValue({
        preferredInvoiceViewPreset: "COMPACT",
      });
      await updateMyPreference(JID, UID, { preferredInvoiceViewPreset: "BALANCED" });
      const c = arg(mockPrisma.userPreference.upsert).create;
      // El service mapea BALANCED → COMPACT antes del upsert.
      expect(c.preferredInvoiceViewPreset).toBe("COMPACT");
    });

    it("LEGACY: 'BALANCED' leído del DB se mapea a 'COMPACT' en el DTO", async () => {
      // Usuarios existentes que tenían "BALANCED" persistido siguen
      // funcionando — getMyPreference traduce al enum nuevo sin migración SQL.
      mockPrisma.userPreference.findUnique.mockResolvedValue({
        preferredInvoiceViewPreset: "BALANCED",
      });
      const dto = await getMyPreference(JID, UID);
      expect(dto.preferredInvoiceViewPreset).toBe("COMPACT");
    });

    it("string desconocido → null (sanitización defensiva)", async () => {
      mockPrisma.userPreference.upsert.mockResolvedValue({ preferredInvoiceViewPreset: null });
      await updateMyPreference(JID, UID, { preferredInvoiceViewPreset: "GARBAGE_VALUE" });
      const c = arg(mockPrisma.userPreference.upsert).create;
      expect(c.preferredInvoiceViewPreset).toBeNull();
    });

    it("LEGACY: 'FINANCIAL' (eliminado del enum) se mapea a 'COMPACT'", async () => {
      mockPrisma.userPreference.upsert.mockResolvedValue({
        preferredInvoiceViewPreset: "COMPACT",
      });
      await updateMyPreference(JID, UID, { preferredInvoiceViewPreset: "FINANCIAL" });
      const c = arg(mockPrisma.userPreference.upsert).create;
      // El service mapea FINANCIAL → COMPACT (en lugar de null) para
      // que el preset persistido sea explicito en DB. El frontend ya
      // recibe un preset valido sin tener que caer a un default local.
      expect(c.preferredInvoiceViewPreset).toBe("COMPACT");
    });

    it("null limpia el preset (vuelve al default COMPACT del frontend)", async () => {
      mockPrisma.userPreference.upsert.mockResolvedValue({ preferredInvoiceViewPreset: null });
      await updateMyPreference(JID, UID, { preferredInvoiceViewPreset: null });
      const u = arg(mockPrisma.userPreference.upsert).update;
      expect(u.preferredInvoiceViewPreset).toBeNull();
    });

    it("PATCH parcial: mandar solo preferredInvoiceViewPreset NO toca los otros defaults", async () => {
      mockPrisma.userPreference.upsert.mockResolvedValue({
        preferredInvoiceViewPreset: "COMPACT",
      });
      await updateMyPreference(JID, UID, { preferredInvoiceViewPreset: "COMPACT" });
      const u = arg(mockPrisma.userPreference.upsert).update;
      // Solo el campo del preset queda en update; los otros no.
      expect(u).toEqual({ jewelryId: JID, preferredInvoiceViewPreset: "COMPACT" });
      expect("defaultWarehouseId" in u).toBe(false);
      expect("defaultGlobalDiscountType" in u).toBe(false);
      expect("invoiceLayoutConfig" in u).toBe(false);
    });

    it("PATCH parcial: mandar solo defaultWarehouseId NO toca preferredInvoiceViewPreset existente", async () => {
      mockPrisma.warehouse.findFirst.mockResolvedValue({ id: "wh-1" });
      mockPrisma.userPreference.upsert.mockResolvedValue({
        defaultWarehouseId: "wh-1",
        preferredInvoiceViewPreset: "CUSTOM",
      });
      await updateMyPreference(JID, UID, { defaultWarehouseId: "wh-1" });
      const u = arg(mockPrisma.userPreference.upsert).update;
      expect("preferredInvoiceViewPreset" in u).toBe(false);
    });

    it("mapea legacy 'SINGLE_COLUMN' a 'COMPACT' en el DTO al hacer getMyPreference", async () => {
      mockPrisma.userPreference.findUnique.mockResolvedValue({
        preferredInvoiceViewPreset: "SINGLE_COLUMN",
      });
      const dto = await getMyPreference(JID, UID);
      expect(dto.preferredInvoiceViewPreset).toBe("COMPACT");
    });

    it("mapea preset oficial 'ONE_LINE' como-tal en el DTO", async () => {
      mockPrisma.userPreference.findUnique.mockResolvedValue({
        preferredInvoiceViewPreset: "ONE_LINE",
      });
      const dto = await getMyPreference(JID, UID);
      expect(dto.preferredInvoiceViewPreset).toBe("ONE_LINE");
    });

    it("string desconocido leído del DB → null en el DTO (defensa contra drift)", async () => {
      mockPrisma.userPreference.findUnique.mockResolvedValue({
        preferredInvoiceViewPreset: "LEGACY_TYPO",
      });
      const dto = await getMyPreference(JID, UID);
      expect(dto.preferredInvoiceViewPreset).toBeNull();
    });
  });
});

/** Helper local para acceder al último arg pasado a upsert sin repetir el path. */
function arg(spy: { mock: { calls: any[][] } }): { create: any; update: any; where: any } {
  return spy.mock.calls[spy.mock.calls.length - 1][0];
}

/* =========================================================================
   Consolidación Fase 2: almacén por defecto (UserPreference fuente de verdad,
   legacy User.favoriteWarehouseId solo lectura).
   ========================================================================= */
describe("getSalesDefaultWarehouseId", () => {
  it("devuelve el valor de UserPreference cuando existe", async () => {
    mockPrisma.userPreference.findUnique.mockResolvedValue({ defaultWarehouseId: "wh-pref" });
    const id = await getSalesDefaultWarehouseId(JID, UID);
    expect(id).toBe("wh-pref");
    expect(mockPrisma.user.findFirst).not.toHaveBeenCalled(); // no toca legacy
  });

  it("cae al legacy User.favoriteWarehouseId SOLO si UserPreference está vacío", async () => {
    mockPrisma.userPreference.findUnique.mockResolvedValue({ defaultWarehouseId: null });
    mockPrisma.user.findFirst.mockResolvedValue({ favoriteWarehouseId: "wh-legacy" });
    const id = await getSalesDefaultWarehouseId(JID, UID);
    expect(id).toBe("wh-legacy");
  });

  it("null si no hay ni preferencia ni legacy", async () => {
    mockPrisma.userPreference.findUnique.mockResolvedValue(null);
    mockPrisma.user.findFirst.mockResolvedValue({ favoriteWarehouseId: null });
    expect(await getSalesDefaultWarehouseId(JID, UID)).toBeNull();
  });
});

describe("setSalesDefaultWarehouseId", () => {
  it("upsertea SOLO defaultWarehouseId en UserPreference (no toca legacy)", async () => {
    mockPrisma.userPreference.upsert.mockResolvedValue({});
    await setSalesDefaultWarehouseId(JID, UID, "wh-9");

    const arg = mockPrisma.userPreference.upsert.mock.calls[0][0];
    expect(arg.where).toEqual({ userId_scope: { userId: UID, scope: "SALES_INVOICE" } });
    expect(arg.create).toEqual({ jewelryId: JID, userId: UID, scope: "SALES_INVOICE", defaultWarehouseId: "wh-9" });
    expect(arg.update).toEqual({ jewelryId: JID, defaultWarehouseId: "wh-9" });
  });
});

describe("reassignSalesDefaultWarehouse", () => {
  it("reasigna SOLO sobre UserPreference (scope SALES_INVOICE)", async () => {
    mockPrisma.userPreference.updateMany.mockResolvedValue({ count: 2 });
    await reassignSalesDefaultWarehouse(JID, "wh-borrado", "wh-nuevo");

    const arg = mockPrisma.userPreference.updateMany.mock.calls[0][0];
    expect(arg.where).toEqual({ jewelryId: JID, scope: "SALES_INVOICE", defaultWarehouseId: "wh-borrado" });
    expect(arg.data).toEqual({ defaultWarehouseId: "wh-nuevo" });
  });
});
