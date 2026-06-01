// src/lib/pricing-engine/__tests__/double-rounding-trap.test.ts
// =============================================================================
// CONTRATO ACTUALIZADO — la prevención de doble redondeo vive en el RUNTIME,
// no en la validación de creación/edición de PriceList.
//
// Decisión arquitectónica (ver `src/modules/price-lists/price-lists.service.ts`,
// bloque "Prevención de doble redondeo (DECISIÓN ARQUITECTÓNICA)"):
//
//   La lista de precios es una regla COMERCIAL REUSABLE. Su configuración no
//   debe depender del estado vigente de `Jewelry.documentRounding*`. La
//   colisión de redondeos se resuelve en el motor:
//
//     · `loadDocumentRoundingConfig` (src/lib/document-rounding.ts:154)
//       emite `suppressListDeferredRounding = true` cuando la política del
//       documento está activa.
//     · `pricing-engine.sale.ts:1620` neutraliza el rounding diferido de la
//       lista (`applyOn = NET | TOTAL`) cuando ese flag llega `true`.
//
// Estos tests cubren los puntos obligatorios pedidos en la auditoría:
//   1. create/update PriceList con `mode=METAL_HECHURA` + roundingMetal/Hechura
//      debe permitirse aunque `Jewelry.documentRoundingScope = "BREAKDOWN"`.
//   2. El guard de doble redondeo NO vive en la validación del modal de
//      creación — se permite cualquier combinación que antes rechazaba.
//   3. El runtime del documento sigue evitando doble redondeo
//      (`loadDocumentRoundingConfig` emite `suppressListDeferredRounding=true`).
//   4. Crear/editar listas desglosadas NO modifica la config del documento.
//   5. La config del documento NO impide guardar la PriceList.
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
  jewelry:         { findUnique: vi.fn(), update: vi.fn() },
}));

vi.mock("../../prisma.js", () => ({ prisma: mockPrisma }));

import { createPriceList, updatePriceList } from "../../../modules/price-lists/price-lists.service.js";
import { loadDocumentRoundingConfig } from "../../document-rounding.js";

const TENANT_ID = "j1";

beforeEach(() => {
  vi.clearAllMocks();
  // Defaults: sin duplicados, sin listas existentes, create echo-back.
  mockPrisma.priceList.findFirst.mockResolvedValue(null);
  mockPrisma.priceList.count.mockResolvedValue(0);
  mockPrisma.priceList.create.mockImplementation(async (args: any) => ({ id: "pl-new", ...args.data }));
  mockPrisma.priceList.update.mockImplementation(async (args: any) => ({ id: args.where.id, ...args.data }));
  mockPrisma.priceList.updateMany.mockResolvedValue({ count: 0 });
  mockPrisma.articleCategory.findFirst.mockResolvedValue({ id: "cat1" });
  // Default jewelry mock — política del documento activa pero el test puede
  // sobrescribirla.
  mockPrisma.jewelry.findUnique.mockResolvedValue({
    documentRoundingEnabled: true,
    documentRoundingMode:    "INTEGER",
    documentRoundingScope:   "BREAKDOWN",
    documentRoundingModeMetal:   "INTEGER",
    documentRoundingModeHechura: "INTEGER",
  });
});

// Datos base de una lista válida.
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
// (1) PriceList con BREAKDOWN debe permitirse aunque el tenant tenga
//     documentRoundingScope = BREAKDOWN.
// ─────────────────────────────────────────────────────────────────────────────

describe("PriceList — BREAKDOWN permitido aunque tenant tenga documentRoundingScope=BREAKDOWN", () => {
  it("createPriceList con mode=METAL_HECHURA + roundingMetal/Hechura PASA", async () => {
    mockPrisma.jewelry.findUnique.mockResolvedValue({
      documentRoundingEnabled:     true,
      documentRoundingScope:       "BREAKDOWN",
      documentRoundingModeMetal:   "INTEGER",
      documentRoundingModeHechura: "INTEGER",
    });

    const data = basePriceListData({
      mode:                    "METAL_HECHURA",
      marginTotal:             null,
      marginMetal:             "120",
      marginHechura:           "200",
      roundingTarget:          "METAL",
      roundingModeMetal:       "INTEGER",
      roundingDirectionMetal:  "NEAREST",
      roundingModeHechura:     "HUNDRED",
      roundingDirectionHechura:"NEAREST",
    });

    const out = await createPriceList(TENANT_ID, data);
    expect(out).toBeDefined();
    expect(mockPrisma.priceList.create).toHaveBeenCalledTimes(1);
  });

  it("createPriceList con roundingTarget=METAL + roundingApplyOn=PRICE + mode=NONE config NO bloquea", async () => {
    // Caso que el guard antiguo rechazaba con HTTP 400.
    const data = basePriceListData({
      roundingTarget:    "METAL",
      roundingMode:      "TEN",
      roundingDirection: "NEAREST",
      roundingApplyOn:   "PRICE",
    });
    await expect(createPriceList(TENANT_ID, data)).resolves.toBeDefined();
    expect(mockPrisma.priceList.create).toHaveBeenCalledTimes(1);
  });

  it("createPriceList con roundingApplyOn=PRICE + roundingMode=INTEGER NO bloquea (antes 400)", async () => {
    const data = basePriceListData({
      roundingTarget:    "FINAL_PRICE",
      roundingMode:      "INTEGER",
      roundingDirection: "NEAREST",
      roundingApplyOn:   "PRICE",
    });
    await expect(createPriceList(TENANT_ID, data)).resolves.toBeDefined();
    expect(mockPrisma.priceList.create).toHaveBeenCalledTimes(1);
  });

  it("updatePriceList con la misma config peligrosa de antes tampoco bloquea", async () => {
    mockPrisma.priceList.findFirst.mockImplementation(async (args: any) => {
      const where = args.where ?? {};
      if (where.id && !where.id.not) {
        return { id: "pl-existing", code: "EXIST", isActive: true, isFavorite: false };
      }
      return null;
    });

    const data = basePriceListData({
      roundingTarget:    "METAL",
      roundingMode:      "TEN",
      roundingDirection: "NEAREST",
      roundingApplyOn:   "PRICE",
    });

    await expect(
      updatePriceList("pl-existing", TENANT_ID, data),
    ).resolves.toBeDefined();
    expect(mockPrisma.priceList.update).toHaveBeenCalledTimes(1);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// (2) El guard ya NO vive en la validación de la lista.
//     Verificamos que el service no rechaza con HTTP 400 por config de
//     redondeo "incompatible" — ni siquiera con todos los combos peligrosos.
// ─────────────────────────────────────────────────────────────────────────────

describe("PriceList — el guard de doble redondeo NO vive en el modal", () => {
  const dangerousConfigs = [
    { roundingTarget: "METAL",       roundingMode: "TEN",     roundingDirection: "NEAREST", roundingApplyOn: "PRICE" },
    { roundingTarget: "FINAL_PRICE", roundingMode: "INTEGER", roundingDirection: "NEAREST", roundingApplyOn: "PRICE" },
    { roundingTarget: "METAL",       roundingMode: "HUNDRED", roundingDirection: "DOWN",    roundingApplyOn: "NET"   },
  ];

  for (const cfg of dangerousConfigs) {
    it(`createPriceList(${JSON.stringify(cfg)}) NO falla con HTTP 400 por redondeo`, async () => {
      const data = basePriceListData(cfg);
      // No esperamos rejects con status:400 + message /doble redondeo/i.
      const fn = () => createPriceList(TENANT_ID, data);
      await expect(fn()).resolves.toBeDefined();
    });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// (3) El RUNTIME del documento sigue evitando el doble redondeo.
//     `loadDocumentRoundingConfig` emite `suppressListDeferredRounding=true`
//     cuando la política del tenant está activa — eso es lo que el motor
//     consulta para neutralizar el rounding diferido de la lista.
// ─────────────────────────────────────────────────────────────────────────────

describe("Runtime — loadDocumentRoundingConfig sigue suprimiendo el rounding diferido", () => {
  it("tenant con BREAKDOWN activo (metal+hechura) → suppressListDeferredRounding=true", async () => {
    mockPrisma.jewelry.findUnique.mockResolvedValue({
      documentRoundingEnabled:          true,
      documentRoundingMode:             "NONE",
      documentRoundingDirection:        "NEAREST",
      documentRoundingScope:            "BREAKDOWN",
      documentRoundingModeMetal:        "INTEGER",
      documentRoundingDirectionMetal:   "NEAREST",
      documentRoundingModeHechura:      "INTEGER",
      documentRoundingDirectionHechura: "NEAREST",
      documentRoundingMetalDomain:      "MONETARY",
      documentPhysicalRoundingConfig:   null,
    });
    const policy = await loadDocumentRoundingConfig(TENANT_ID);
    expect(policy.suppressListDeferredRounding).toBe(true);
    expect(policy.scope).toBe("BREAKDOWN");
    expect(policy.documentRounding).not.toBeNull();
  });

  it("tenant con UNIFIED activo → suppressListDeferredRounding=true", async () => {
    mockPrisma.jewelry.findUnique.mockResolvedValue({
      documentRoundingEnabled:          true,
      documentRoundingMode:             "INTEGER",
      documentRoundingDirection:        "NEAREST",
      documentRoundingScope:            "UNIFIED",
      documentRoundingModeMetal:        "NONE",
      documentRoundingDirectionMetal:   "NEAREST",
      documentRoundingModeHechura:      "NONE",
      documentRoundingDirectionHechura: "NEAREST",
      documentRoundingMetalDomain:      "MONETARY",
      documentPhysicalRoundingConfig:   null,
    });
    const policy = await loadDocumentRoundingConfig(TENANT_ID);
    expect(policy.suppressListDeferredRounding).toBe(true);
    expect(policy.scope).toBe("UNIFIED");
  });

  it("tenant SIN política activa → suppressListDeferredRounding=false (lista actúa libre)", async () => {
    mockPrisma.jewelry.findUnique.mockResolvedValue({
      documentRoundingEnabled:          false,
      documentRoundingMode:             "NONE",
      documentRoundingDirection:        "NEAREST",
      documentRoundingScope:            "UNIFIED",
      documentRoundingModeMetal:        "NONE",
      documentRoundingDirectionMetal:   "NEAREST",
      documentRoundingModeHechura:      "NONE",
      documentRoundingDirectionHechura: "NEAREST",
      documentRoundingMetalDomain:      "MONETARY",
      documentPhysicalRoundingConfig:   null,
    });
    const policy = await loadDocumentRoundingConfig(TENANT_ID);
    expect(policy.suppressListDeferredRounding).toBe(false);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// (4) Crear/editar listas NO modifica la config del documento.
// ─────────────────────────────────────────────────────────────────────────────

describe("PriceList — create/update NO toca documentRounding del tenant", () => {
  it("createPriceList no llama prisma.jewelry.update", async () => {
    const data = basePriceListData({
      mode:                    "METAL_HECHURA",
      marginTotal:             null,
      marginMetal:             "120",
      marginHechura:           "200",
      roundingTarget:          "METAL",
      roundingModeMetal:       "INTEGER",
      roundingDirectionMetal:  "NEAREST",
      roundingModeHechura:     "HUNDRED",
      roundingDirectionHechura:"NEAREST",
    });
    await createPriceList(TENANT_ID, data);
    expect(mockPrisma.jewelry.update).not.toHaveBeenCalled();
    // El select del create tampoco incluye campos documentRounding* del tenant
    // (es priceList.create — no toca Jewelry).
    const createArgs = mockPrisma.priceList.create.mock.calls[0]![0];
    for (const key of Object.keys(createArgs.data)) {
      expect(key).not.toMatch(/^documentRounding/i);
    }
  });

  it("updatePriceList tampoco llama prisma.jewelry.update", async () => {
    mockPrisma.priceList.findFirst.mockImplementation(async (args: any) => {
      const where = args.where ?? {};
      if (where.id && !where.id.not) {
        return { id: "pl-existing", code: "EXIST", isActive: true, isFavorite: false };
      }
      return null;
    });
    const data = basePriceListData({ roundingTarget: "METAL", roundingApplyOn: "PRICE" });
    await updatePriceList("pl-existing", TENANT_ID, data);
    expect(mockPrisma.jewelry.update).not.toHaveBeenCalled();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// (5) `documentRounding` config NO impide guardar PriceList — explícito:
//     ningún combo de Jewelry rounding fuerza un 400 al crear/editar lista.
// ─────────────────────────────────────────────────────────────────────────────

describe("PriceList — documentRounding NO bloquea guardar", () => {
  const tenantStates = [
    { name: "BREAKDOWN metal+hechura activos",
      mock: {
        documentRoundingEnabled:     true,
        documentRoundingScope:       "BREAKDOWN",
        documentRoundingModeMetal:   "INTEGER",
        documentRoundingModeHechura: "HUNDRED",
      },
    },
    { name: "UNIFIED activo (INTEGER)",
      mock: { documentRoundingEnabled: true, documentRoundingScope: "UNIFIED", documentRoundingMode: "INTEGER" } },
    { name: "BOTH activos",
      mock: {
        documentRoundingEnabled:     true,
        documentRoundingScope:       "BOTH",
        documentRoundingMode:        "INTEGER",
        documentRoundingModeMetal:   "INTEGER",
        documentRoundingModeHechura: "INTEGER",
      },
    },
    { name: "sin política (inerte)",
      mock: { documentRoundingEnabled: false } },
  ];

  for (const { name, mock } of tenantStates) {
    it(`createPriceList pasa con tenant: ${name}`, async () => {
      mockPrisma.jewelry.findUnique.mockResolvedValue(mock);
      const data = basePriceListData({
        roundingTarget: "METAL",
        roundingMode:   "TEN",
        roundingDirection: "NEAREST",
        roundingApplyOn: "PRICE",
      });
      await expect(createPriceList(TENANT_ID, data)).resolves.toBeDefined();
    });
  }
});
