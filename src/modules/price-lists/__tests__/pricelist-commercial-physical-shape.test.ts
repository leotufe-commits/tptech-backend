// src/modules/price-lists/__tests__/pricelist-commercial-physical-shape.test.ts
// =============================================================================
// Etapa C-comercial / C1 — Shape del schema aditivo para redondeo COMERCIAL
// PHYSICAL en `PriceList`.
//
// Verifica que:
//   1. Listas existentes (sin tocar) reciben default `MONETARY` y null.
//   2. Crear lista con `commercialRoundingMetalDomain="PHYSICAL"` + config
//      válida persiste y devuelve.
//   3. Crear con `MONETARY` ignora cualquier config (no persiste JSON huérfano).
//   4. Crear con `PHYSICAL` + config inválida (`Array` / `string` / etc.) cae
//      a `null` por la degradación segura del helper.
//   5. Update de `PHYSICAL → MONETARY` limpia la config persistida (null).
//   6. Update de `MONETARY → PHYSICAL` con config nueva persiste.
//
// **C1 NO toca runtime del motor** — la persistencia y el shape devuelto al
// cliente es lo único que se verifica acá. Etapa C2 (helper) y C3 (motor)
// vendrán después.
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

vi.mock("../../../lib/prisma.js", () => ({ prisma: mockPrisma }));

import { createPriceList, updatePriceList } from "../price-lists.service.js";

const TENANT_ID = "j1";

beforeEach(() => {
  vi.clearAllMocks();
  mockPrisma.priceList.findFirst.mockResolvedValue(null);
  mockPrisma.priceList.count.mockResolvedValue(0);
  mockPrisma.priceList.create.mockImplementation(async (args: any) => ({
    id: "pl-new", ...args.data,
  }));
  mockPrisma.priceList.update.mockImplementation(async (args: any) => ({
    id: args.where.id, ...args.data,
  }));
  mockPrisma.priceList.updateMany.mockResolvedValue({ count: 0 });
  mockPrisma.articleCategory.findFirst.mockResolvedValue({ id: "cat1" });
  // Tenant sin política — para que `validateRoundingPolicy` deshabilitada
  // no interfiera (ya fue eliminada).
  mockPrisma.jewelry.findUnique.mockResolvedValue({ documentRoundingEnabled: false });
});

function baseData(over: Record<string, any> = {}) {
  return {
    name: "Lista Test",
    scope: "GENERAL",
    mode: "MARGIN_TOTAL",
    marginTotal: "100",
    isActive: true,
    ...over,
  };
}

// ──────────────────────────────────────────────────────────────────────────
// (1) Default MONETARY + null
// ──────────────────────────────────────────────────────────────────────────

describe("PriceList C1 — defaults aditivos", () => {
  it("crear sin los campos nuevos → commercialRoundingMetalDomain=MONETARY + config null", async () => {
    await createPriceList(TENANT_ID, baseData());
    const createCall = mockPrisma.priceList.create.mock.calls[0]![0];
    expect(createCall.data.commercialRoundingMetalDomain).toBe("MONETARY");
    expect(createCall.data.commercialPhysicalRoundingConfig).toBeNull();
  });

  it("crear con commercialRoundingMetalDomain garbage → cae a MONETARY (degradación segura)", async () => {
    await createPriceList(TENANT_ID, baseData({ commercialRoundingMetalDomain: "BANANA" }));
    const call = mockPrisma.priceList.create.mock.calls[0]![0];
    expect(call.data.commercialRoundingMetalDomain).toBe("MONETARY");
    expect(call.data.commercialPhysicalRoundingConfig).toBeNull();
  });
});

// ──────────────────────────────────────────────────────────────────────────
// (2) Persiste PHYSICAL + config válida
// ──────────────────────────────────────────────────────────────────────────

describe("PriceList C1 — PHYSICAL persiste shape canónico", () => {
  it("crear con PHYSICAL + config completa → persiste tal cual", async () => {
    const config = {
      byMetalParentId: {
        "oro-fino": { mode: "INTEGER", direction: "NEAREST" },
        "plata":    { mode: "HALF",    direction: "DOWN" },
      },
      fallback: { mode: "NONE", direction: "NEAREST" },
    };
    await createPriceList(TENANT_ID, baseData({
      commercialRoundingMetalDomain: "PHYSICAL",
      commercialPhysicalRoundingConfig: config,
    }));
    const call = mockPrisma.priceList.create.mock.calls[0]![0];
    expect(call.data.commercialRoundingMetalDomain).toBe("PHYSICAL");
    expect(call.data.commercialPhysicalRoundingConfig).toEqual(config);
  });
});

// ──────────────────────────────────────────────────────────────────────────
// (3) MONETARY + config payload → config descartada (no JSON huérfano)
// ──────────────────────────────────────────────────────────────────────────

describe("PriceList C1 — MONETARY descarta config huérfana", () => {
  it("crear MONETARY con config payload → persiste config=null", async () => {
    const config = {
      byMetalParentId: { "oro-fino": { mode: "INTEGER", direction: "NEAREST" } },
    };
    await createPriceList(TENANT_ID, baseData({
      commercialRoundingMetalDomain: "MONETARY",
      commercialPhysicalRoundingConfig: config,
    }));
    const call = mockPrisma.priceList.create.mock.calls[0]![0];
    expect(call.data.commercialRoundingMetalDomain).toBe("MONETARY");
    expect(call.data.commercialPhysicalRoundingConfig).toBeNull();
  });
});

// ──────────────────────────────────────────────────────────────────────────
// (4) PHYSICAL + config inválida → degrada a null
// ──────────────────────────────────────────────────────────────────────────

describe("PriceList C1 — PHYSICAL + config inválida cae a null", () => {
  const malformed = [
    { label: "array",         value: [{ mode: "INTEGER" }] },
    { label: "string",        value: "garbage" },
    { label: "number",        value: 42 },
    { label: "null explícito",value: null },
  ];

  for (const { label, value } of malformed) {
    it(`crear PHYSICAL + config inválida (${label}) → config=null sin romper`, async () => {
      await createPriceList(TENANT_ID, baseData({
        commercialRoundingMetalDomain: "PHYSICAL",
        commercialPhysicalRoundingConfig: value,
      }));
      const call = mockPrisma.priceList.create.mock.calls[0]![0];
      expect(call.data.commercialRoundingMetalDomain).toBe("PHYSICAL");
      expect(call.data.commercialPhysicalRoundingConfig).toBeNull();
    });
  }

  it("crear PHYSICAL con shape parcialmente válido (byMetalParentId garbage adentro) → persiste tal cual; el parser runtime de C2 lo descartará", async () => {
    // En C1 NO validamos el contenido del JSON — el helper de Etapa C2
    // (`resolveDocumentPhysicalRoundingConfig`) ya hace el descarte por entry.
    // Acá solo verificamos que objetos arbitrarios pasen el guardado.
    const partial = { byMetalParentId: { "oro-fino": "garbage" }, fallback: null };
    await createPriceList(TENANT_ID, baseData({
      commercialRoundingMetalDomain: "PHYSICAL",
      commercialPhysicalRoundingConfig: partial,
    }));
    const call = mockPrisma.priceList.create.mock.calls[0]![0];
    expect(call.data.commercialPhysicalRoundingConfig).toEqual(partial);
  });
});

// ──────────────────────────────────────────────────────────────────────────
// (5) Update PHYSICAL → MONETARY limpia config
// ──────────────────────────────────────────────────────────────────────────

describe("PriceList C1 — update PHYSICAL → MONETARY limpia config (anti huérfano)", () => {
  it("editar lista existente a MONETARY → persiste commercialPhysicalRoundingConfig=null", async () => {
    mockPrisma.priceList.findFirst.mockImplementation(async (args: any) => {
      const where = args.where ?? {};
      if (where.id && !where.id.not) {
        return { id: "pl-existing", code: "EXIST", isActive: true, isFavorite: false };
      }
      return null;
    });

    await updatePriceList("pl-existing", TENANT_ID, baseData({
      commercialRoundingMetalDomain: "MONETARY",
      commercialPhysicalRoundingConfig: {
        byMetalParentId: { "oro-fino": { mode: "INTEGER", direction: "NEAREST" } },
      }, // payload viejo del operador que olvidó vaciar
    }));

    const upd = mockPrisma.priceList.update.mock.calls[0]![0];
    expect(upd.data.commercialRoundingMetalDomain).toBe("MONETARY");
    expect(upd.data.commercialPhysicalRoundingConfig).toBeNull();
  });
});

// ──────────────────────────────────────────────────────────────────────────
// (6) Update MONETARY → PHYSICAL guarda la config nueva
// ──────────────────────────────────────────────────────────────────────────

describe("PriceList C1 — update MONETARY → PHYSICAL graba la config", () => {
  it("editar a PHYSICAL con config nueva → persiste exacto", async () => {
    mockPrisma.priceList.findFirst.mockImplementation(async (args: any) => {
      const where = args.where ?? {};
      if (where.id && !where.id.not) {
        return { id: "pl-existing", code: "EXIST", isActive: true, isFavorite: false };
      }
      return null;
    });
    const config = {
      byMetalParentId: { "oro-fino": { mode: "HALF", direction: "DOWN" } },
      fallback: { mode: "NONE", direction: "NEAREST" },
    };
    await updatePriceList("pl-existing", TENANT_ID, baseData({
      commercialRoundingMetalDomain: "PHYSICAL",
      commercialPhysicalRoundingConfig: config,
    }));
    const upd = mockPrisma.priceList.update.mock.calls[0]![0];
    expect(upd.data.commercialRoundingMetalDomain).toBe("PHYSICAL");
    expect(upd.data.commercialPhysicalRoundingConfig).toEqual(config);
  });
});

// ──────────────────────────────────────────────────────────────────────────
// (7) PL_SELECT — verificar que los nuevos campos se devuelven
// ──────────────────────────────────────────────────────────────────────────

describe("PriceList C1 — PL_SELECT expone los nuevos campos", () => {
  it("create devuelve commercialRoundingMetalDomain + commercialPhysicalRoundingConfig en el select", async () => {
    const config = { byMetalParentId: { "oro-fino": { mode: "INTEGER", direction: "NEAREST" } } };
    await createPriceList(TENANT_ID, baseData({
      commercialRoundingMetalDomain: "PHYSICAL",
      commercialPhysicalRoundingConfig: config,
    }));
    const call = mockPrisma.priceList.create.mock.calls[0]![0];
    expect(call.select).toMatchObject({
      commercialRoundingMetalDomain: true,
      commercialPhysicalRoundingConfig: true,
    });
  });
});
