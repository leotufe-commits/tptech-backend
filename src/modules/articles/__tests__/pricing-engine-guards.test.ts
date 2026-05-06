// src/modules/articles/__tests__/pricing-engine-guards.test.ts
// =============================================================================
// Tests para las validaciones defensivas que protegen el contrato con el
// pricing-engine:
//   · Variantes no aceptan overrides de precio/costo (solo weightOverride)
//   · Servicios no aceptan merma, METAL, metalVariantId ni PRODUCT con
//     affectsStock=true (HECHURA / SERVICE / MANUAL sí están permitidos).
//
// Estas validaciones viven en articles.service.ts y son invocadas desde
// create/update de artículos y variantes + setCostLines.
// =============================================================================

import { describe, it, expect, vi, beforeEach } from "vitest";

// ── Mock de Prisma (mismo patrón vi.hoisted que el resto de la suite) ────────
const mockPrisma = vi.hoisted(() => ({
  article:        { findFirst: vi.fn(), findUnique: vi.fn() },
  articleVariant: { findFirst: vi.fn() },
  articleCostLine:{ count: vi.fn() },
}));

vi.mock("../../../lib/prisma.js", () => ({ prisma: mockPrisma }));

// Silenciar llamadas al motor — estos tests no llegan hasta ahí.
vi.mock("../../../lib/pricing-engine/pricing-engine.js", () => ({
  resolvePriceList:        vi.fn(),
  applyPriceList:          vi.fn(),
  PL_COMPUTE_SELECT:       {},
  buildBatchCostContext:   vi.fn(),
  calculateCostFromLines:  vi.fn(),
  isPriceListValidNow:     vi.fn(() => false),
  isPromotionValid:        vi.fn(() => false),
  applyTaxesFromMap:       vi.fn(),
  computePurchaseTaxes:    vi.fn(),
}));

// combo.utils no se toca en estos tests (no llegamos al branch de combo).
vi.mock("../../../lib/combo.utils.js", () => ({
  normalizeComboFields:              () => ({ commercialMode: "NORMAL", comboAdjustmentKind: "NONE", comboAdjustmentValue: null }),
  validateComboComponentsShape:      vi.fn(),
  validateComboComponentsAgainstDb:  vi.fn(),
  computeComboAvailability:          vi.fn(),
}));

import { createVariant, updateVariant, createArticle, setCostLines } from "../articles.service.js";

beforeEach(() => {
  vi.clearAllMocks();
});

// ── 1. Variantes: overrides de precio/costo prohibidos ──────────────────────
describe("createVariant — overrides de precio/costo prohibidos", () => {
  beforeEach(() => {
    // assertArticleOwnership
    mockPrisma.article.findFirst.mockResolvedValue({ id: "art-1" });
    // articleType check
    mockPrisma.article.findUnique.mockResolvedValue({ articleType: "PRODUCT" });
  });

  const forbiddenCases: Array<[string, Record<string, unknown>]> = [
    ["salePrice",           { salePrice:           100 }],
    ["costPrice",           { costPrice:           50 }],
    ["useManualSalePrice",  { useManualSalePrice:  true }],
    ["manualSalePrice",     { manualSalePrice:     200 }],
    ["mermaPercent",        { mermaPercent:        3 }],
    ["manualTaxIds",        { manualTaxIds:        ["tax-1"] }],
    ["commercialMode",      { commercialMode:      "COMBO_COMMERCIAL" }],
  ];

  for (const [fieldName, override] of forbiddenCases) {
    it(`rechaza ${fieldName} en createVariant`, async () => {
      await expect(
        createVariant("art-1", "jw-1", {
          code: "V1",
          name: "Variante",
          ...override,
        }),
      ).rejects.toThrow(/no permitidos en variante|weightOverride/);
    });
  }

  it("acepta weightOverride (el único override permitido)", async () => {
    // Mockear resto mínimo para que no explote más adelante (pero el test
    // igual va a fallar al intentar hacer el create real — nos importa solo
    // que la validación defensiva NO se dispare).
    mockPrisma.articleVariant.findFirst.mockResolvedValue(null);

    // Esperamos que falle POR OTRA RAZÓN, no por el guard de overrides.
    await expect(
      createVariant("art-1", "jw-1", {
        code: "V1",
        name: "Variante",
        weightOverride: 5,
      }),
    ).rejects.not.toThrow(/no permitidos en variante/);
  });
});

describe("updateVariant — overrides de precio/costo prohibidos", () => {
  it("rechaza salePrice en updateVariant", async () => {
    mockPrisma.article.findFirst.mockResolvedValue({ id: "art-1" });

    await expect(
      updateVariant("art-1", "var-1", "jw-1", { salePrice: 100 }),
    ).rejects.toThrow(/no permitidos en variante/);
  });

  it("rechaza costPrice en updateVariant", async () => {
    mockPrisma.article.findFirst.mockResolvedValue({ id: "art-1" });

    await expect(
      updateVariant("art-1", "var-1", "jw-1", { costPrice: 50 }),
    ).rejects.toThrow(/no permitidos en variante/);
  });
});

// ── 2. Servicios: merma, HECHURA y metalVariantId prohibidos ────────────────
describe("createArticle — servicios con composición inválida", () => {
  beforeEach(() => {
    mockPrisma.article.findFirst.mockResolvedValue(null); // code no existe
  });

  it("rechaza SERVICE con mermaPercent > 0", async () => {
    await expect(
      createArticle("jw-1", {
        name: "Servicio",
        articleType: "SERVICE",
        stockMode: "NO_STOCK",
        mermaPercent: 5,
      }),
    ).rejects.toThrow(/servicios.*merma/i);
  });

  it("acepta SERVICE con línea HECHURA (regla TPTech: servicios pueden tener mano de obra)", async () => {
    // El createArticle real puede fallar en otros pasos por mocks incompletos,
    // pero NUNCA debe rechazar por la validación defensiva de servicios.
    await expect(
      createArticle("jw-1", {
        name: "Servicio",
        articleType: "SERVICE",
        stockMode: "NO_STOCK",
        costComposition: [
          { type: "HECHURA", label: "Hechura", quantity: 1, unitValue: 100 },
        ],
      }),
    ).rejects.not.toThrow(/servicios.*HECHURA/);
  });

  it("rechaza SERVICE con línea PRODUCT con affectsStock=true", async () => {
    await expect(
      createArticle("jw-1", {
        name: "Servicio",
        articleType: "SERVICE",
        stockMode: "NO_STOCK",
        costComposition: [
          { type: "PRODUCT", label: "Comp", quantity: 1, unitValue: 100, catalogItemId: "art-x", affectsStock: true },
        ],
      }),
    ).rejects.toThrow(/servicios.*stock/i);
  });

  it("rechaza SERVICE con línea METAL", async () => {
    await expect(
      createArticle("jw-1", {
        name: "Servicio",
        articleType: "SERVICE",
        stockMode: "NO_STOCK",
        costComposition: [
          { type: "METAL", label: "Oro", quantity: 1, unitValue: 100, metalVariantId: "mv-1" },
        ],
      }),
    ).rejects.toThrow(/servicios.*METAL/);
  });

  it("rechaza SERVICE con línea que referencia metalVariantId", async () => {
    await expect(
      createArticle("jw-1", {
        name: "Servicio",
        articleType: "SERVICE",
        stockMode: "NO_STOCK",
        costComposition: [
          // type SERVICE no es METAL pero incluye metalVariantId (caso malformado)
          { type: "SERVICE", label: "Servicio", quantity: 1, unitValue: 100, metalVariantId: "mv-1" },
        ],
      }),
    ).rejects.toThrow(/servicios.*metalVariantId/);
  });

  it("acepta SERVICE con composición vacía y sin merma", async () => {
    // mermaPercent null/undefined → OK; costLines vacías → OK.
    // El createArticle real va a fallar en otro paso (mocks incompletos),
    // pero NO por las validaciones defensivas.
    await expect(
      createArticle("jw-1", {
        name: "Servicio",
        articleType: "SERVICE",
        stockMode: "NO_STOCK",
      }),
    ).rejects.not.toThrow(/servicios/);
  });
});

describe("setCostLines — servicios con composición inválida", () => {
  beforeEach(() => {
    mockPrisma.article.findFirst.mockResolvedValue({ id: "art-svc" });
    mockPrisma.article.findUnique.mockResolvedValue({ articleType: "SERVICE" });
  });

  it("acepta HECHURA en artículo SERVICE", async () => {
    // Regla TPTech: los servicios pueden tener líneas HECHURA y SERVICE en su
    // composición de costo (mano de obra y sub-servicios).
    await expect(
      setCostLines("art-svc", "jw-1", [
        { type: "HECHURA", label: "Hechura", quantity: 1, unitValue: 100 },
      ]),
    ).rejects.not.toThrow(/servicios.*HECHURA/);
  });

  it("rechaza metalVariantId en artículo SERVICE", async () => {
    await expect(
      setCostLines("art-svc", "jw-1", [
        { type: "METAL", label: "Oro", quantity: 1, unitValue: 100, metalVariantId: "mv-1" },
      ]),
    ).rejects.toThrow(/servicios.*(METAL|metalVariantId)/);
  });
});
