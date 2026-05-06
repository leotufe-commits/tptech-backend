// src/lib/pricing-engine/__tests__/double-rounding-trap.test.ts
// =============================================================================
// SPRINT 1 — Detección de doble redondeo (POLICY.md §1)
//
// Riesgo:
//   Si el tenant tiene `documentRoundingEnabled = true` y al mismo tiempo una
//   PriceList se guarda con redondeo comercial propio (roundingTarget=METAL o
//   roundingApplyOn=PRICE con mode≠NONE), el sistema aplica DOBLE redondeo:
//   primero la lista, después el documento. Esto rompe paridad simulador↔factura.
//
// Mitigación testeada:
//   `validateRoundingPolicy` en `src/modules/price-lists/price-lists.service.ts`
//   debe rechazar al guardar/actualizar una lista con configuración incompatible.
//
// Casos:
//   1. Rechaza roundingTarget=METAL si tenant tiene redondeo doc activo.
//   2. Rechaza roundingApplyOn=PRICE + mode≠NONE si tenant tiene redondeo doc.
//   3. Acepta roundingApplyOn=NET / TOTAL (se difieren al doc).
//   4. Acepta cualquier configuración si el tenant NO tiene redondeo doc.
//   5. Mismas reglas en updatePriceList.
// =============================================================================

import { describe, it, expect, vi, beforeEach } from "vitest";

// ── Mock Prisma ──────────────────────────────────────────────────────────────

const mockPrisma = vi.hoisted(() => ({
  priceList: {
    findFirst:  vi.fn(),
    findMany:   vi.fn(),
    count:      vi.fn(),
    create:     vi.fn(),
    update:     vi.fn(),
    updateMany: vi.fn(),
  },
  articleCategory: { findFirst: vi.fn() },
  jewelry:         { findUnique: vi.fn() },
}));

vi.mock("../../prisma.js", () => ({ prisma: mockPrisma }));

import { createPriceList, updatePriceList } from "../../../modules/price-lists/price-lists.service.js";

const TENANT_ID = "j1";

beforeEach(() => {
  vi.clearAllMocks();
  // Defaults: sin duplicados, sin listas existentes, create echo-back
  mockPrisma.priceList.findFirst.mockResolvedValue(null);
  mockPrisma.priceList.count.mockResolvedValue(0);
  mockPrisma.priceList.create.mockImplementation(async (args: any) => ({ id: "pl-new", ...args.data }));
  mockPrisma.priceList.update.mockImplementation(async (args: any) => ({ id: args.where.id, ...args.data }));
  mockPrisma.priceList.updateMany.mockResolvedValue({ count: 0 });
  mockPrisma.articleCategory.findFirst.mockResolvedValue({ id: "cat1" });
});

// Datos base de una lista válida (margen, scope GENERAL, mode MARGIN_TOTAL)
function basePriceListData(overrides: Record<string, any> = {}) {
  return {
    name: "Lista Test",
    code: "LT01",
    description: "",
    scope: "GENERAL",
    mode: "MARGIN_TOTAL",
    marginTotal: "100",
    isActive: true,
    isFavorite: false,
    ...overrides,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Rechazos cuando tenant tiene redondeo de documento activo
// ─────────────────────────────────────────────────────────────────────────────

describe("validateRoundingPolicy — rechazos con tenant.documentRoundingEnabled=true", () => {
  beforeEach(() => {
    // Tenant con redondeo de documento activo (INTEGER)
    mockPrisma.jewelry.findUnique.mockResolvedValue({
      documentRoundingEnabled: true,
      documentRoundingMode:    "INTEGER",
    });
  });

  it("rechaza roundingTarget=METAL", async () => {
    const data = basePriceListData({
      roundingTarget:    "METAL",
      roundingMode:      "TEN",
      roundingDirection: "NEAREST",
      roundingApplyOn:   "PRICE",
    });

    await expect(createPriceList(TENANT_ID, data)).rejects.toMatchObject({
      status:  400,
      message: expect.stringMatching(/doble redondeo/i),
    });

    // No se llegó a crear nada
    expect(mockPrisma.priceList.create).not.toHaveBeenCalled();
  });

  it("rechaza roundingApplyOn=PRICE con roundingMode≠NONE", async () => {
    const data = basePriceListData({
      roundingTarget:    "FINAL_PRICE",
      roundingMode:      "DECIMAL_2",
      roundingDirection: "NEAREST",
      roundingApplyOn:   "PRICE",
    });

    await expect(createPriceList(TENANT_ID, data)).rejects.toMatchObject({
      status:  400,
      message: expect.stringMatching(/doble redondeo/i),
    });
    expect(mockPrisma.priceList.create).not.toHaveBeenCalled();
  });

  it("acepta roundingApplyOn=NET (se difiere y el doc lo neutraliza)", async () => {
    const data = basePriceListData({
      roundingTarget:    "FINAL_PRICE",
      roundingMode:      "TEN",
      roundingDirection: "NEAREST",
      roundingApplyOn:   "NET",
    });

    await expect(createPriceList(TENANT_ID, data)).resolves.toBeDefined();
    expect(mockPrisma.priceList.create).toHaveBeenCalledTimes(1);
  });

  it("acepta roundingApplyOn=TOTAL (se difiere y el doc lo neutraliza)", async () => {
    const data = basePriceListData({
      roundingTarget:    "FINAL_PRICE",
      roundingMode:      "INTEGER",
      roundingDirection: "UP",
      roundingApplyOn:   "TOTAL",
    });

    await expect(createPriceList(TENANT_ID, data)).resolves.toBeDefined();
    expect(mockPrisma.priceList.create).toHaveBeenCalledTimes(1);
  });

  it("acepta roundingTarget=NONE (sin redondeo de lista)", async () => {
    const data = basePriceListData({
      roundingTarget:    "NONE",
      roundingMode:      "NONE",
      roundingDirection: "NEAREST",
      roundingApplyOn:   "PRICE",
    });

    await expect(createPriceList(TENANT_ID, data)).resolves.toBeDefined();
    expect(mockPrisma.priceList.create).toHaveBeenCalledTimes(1);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. Tenant sin redondeo de documento → cualquier configuración vale
// ─────────────────────────────────────────────────────────────────────────────

describe("validateRoundingPolicy — tenant.documentRoundingEnabled=false → libre", () => {
  it("acepta roundingTarget=METAL si tenant.documentRoundingEnabled=false", async () => {
    mockPrisma.jewelry.findUnique.mockResolvedValue({
      documentRoundingEnabled: false,
      documentRoundingMode:    "INTEGER", // mode != NONE pero enabled=false
    });

    const data = basePriceListData({
      roundingTarget:    "METAL",
      roundingMode:      "TEN",
      roundingDirection: "NEAREST",
      roundingApplyOn:   "PRICE",
    });

    await expect(createPriceList(TENANT_ID, data)).resolves.toBeDefined();
    expect(mockPrisma.priceList.create).toHaveBeenCalledTimes(1);
  });

  it("acepta roundingApplyOn=PRICE+mode si tenant.documentRoundingMode=NONE", async () => {
    mockPrisma.jewelry.findUnique.mockResolvedValue({
      documentRoundingEnabled: true,   // enabled pero modo NONE → no aplica
      documentRoundingMode:    "NONE",
    });

    const data = basePriceListData({
      roundingTarget:    "FINAL_PRICE",
      roundingMode:      "DECIMAL_2",
      roundingDirection: "NEAREST",
      roundingApplyOn:   "PRICE",
    });

    await expect(createPriceList(TENANT_ID, data)).resolves.toBeDefined();
    expect(mockPrisma.priceList.create).toHaveBeenCalledTimes(1);
  });

  it("acepta cualquier configuración si el tenant no existe (defensivo)", async () => {
    mockPrisma.jewelry.findUnique.mockResolvedValue(null);

    const data = basePriceListData({
      roundingTarget:    "METAL",
      roundingMode:      "HUNDRED",
      roundingDirection: "DOWN",
      roundingApplyOn:   "PRICE",
    });

    // Si no hay tenant, la validación no aplica → la lista pasa
    await expect(createPriceList(TENANT_ID, data)).resolves.toBeDefined();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. updatePriceList — mismas reglas
// ─────────────────────────────────────────────────────────────────────────────

describe("validateRoundingPolicy — aplica también en updatePriceList", () => {
  it("rechaza updatePriceList si la nueva configuración produciría doble redondeo", async () => {
    mockPrisma.jewelry.findUnique.mockResolvedValue({
      documentRoundingEnabled: true,
      documentRoundingMode:    "INTEGER",
    });

    // Lista existente (mock devuelve la lista que se va a actualizar)
    mockPrisma.priceList.findFirst.mockImplementation(async (args: any) => {
      // El service llama findFirst dos veces:
      //  1. Para chequear que la lista existe (id + jewelryId)
      //  2. Para chequear duplicados de nombre (excluyendo este id)
      const where = args.where ?? {};
      if (where.id && !where.id.not) {
        return { id: "pl-existing", code: "EXIST", isActive: true, isFavorite: false };
      }
      return null; // sin duplicados
    });

    const data = basePriceListData({
      roundingTarget:    "METAL",
      roundingMode:      "TEN",
      roundingDirection: "NEAREST",
      roundingApplyOn:   "PRICE",
    });

    await expect(
      updatePriceList("pl-existing", TENANT_ID, data),
    ).rejects.toMatchObject({
      status:  400,
      message: expect.stringMatching(/doble redondeo/i),
    });

    expect(mockPrisma.priceList.update).not.toHaveBeenCalled();
  });

  it("acepta updatePriceList con applyOn=TOTAL aunque tenant tenga redondeo doc", async () => {
    mockPrisma.jewelry.findUnique.mockResolvedValue({
      documentRoundingEnabled: true,
      documentRoundingMode:    "INTEGER",
    });

    mockPrisma.priceList.findFirst.mockImplementation(async (args: any) => {
      const where = args.where ?? {};
      if (where.id && !where.id.not) {
        return { id: "pl-existing", code: "EXIST", isActive: true, isFavorite: false };
      }
      return null;
    });

    const data = basePriceListData({
      roundingTarget:    "FINAL_PRICE",
      roundingMode:      "INTEGER",
      roundingDirection: "NEAREST",
      roundingApplyOn:   "TOTAL",
    });

    await expect(
      updatePriceList("pl-existing", TENANT_ID, data),
    ).resolves.toBeDefined();
    expect(mockPrisma.priceList.update).toHaveBeenCalledTimes(1);
  });
});
