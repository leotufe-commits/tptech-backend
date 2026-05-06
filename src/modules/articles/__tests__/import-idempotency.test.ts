// src/modules/articles/__tests__/import-idempotency.test.ts
//
// Regresión para dos bugs de idempotencia en la importación masiva:
//
//  A. executeImport v1 — variante sin código: modo skip no debía crear
//     duplicado si ya existía una variante con el mismo nombre bajo el mismo padre.
//
//  B. executeImportV2 — modo skip: las secciones de metales, stock y atributos
//     se ejecutaban igual aunque el artículo hubiese sido omitido, pudiendo
//     borrar y recrear cost-lines de artículos existentes.

import { describe, it, expect, vi, beforeEach } from "vitest";

// ── Mock Prisma ──────────────────────────────────────────────────────────────
const mockPrisma = vi.hoisted(() => ({
  articleCategory:             { findMany: vi.fn(), findFirst: vi.fn() },
  articleGroup:                { findMany: vi.fn() },
  commercialEntity:            { findMany: vi.fn() },
  article:                     { findMany: vi.fn(), findFirst: vi.fn(), count: vi.fn(), create: vi.fn(), update: vi.fn() },
  articleVariant:              { findMany: vi.fn(), findFirst: vi.fn(), count: vi.fn(), create: vi.fn(), update: vi.fn() },
  metal:                       { findMany: vi.fn() },
  warehouse:                   { findMany: vi.fn() },
  articleCostLine:             { deleteMany: vi.fn(), createMany: vi.fn() },
  articleStock:                { findFirst: vi.fn(), create: vi.fn(), update: vi.fn() },
  articleAttributeValue:       { upsert: vi.fn() },
  articleVariantAttributeValue: { upsert: vi.fn() },
  importBatch:                 { create: vi.fn().mockResolvedValue({ id: "batch-1" }) },
  importBatchRow:              { createMany: vi.fn().mockResolvedValue({ count: 0 }) },
}));

vi.mock("../../../lib/prisma.js", () => ({ prisma: mockPrisma }));
vi.mock("../../../lib/importBatch.helper.js", () => ({
  saveBatch:                         vi.fn().mockResolvedValue("batch-1"),
  buildBatchRowsFromArticleResults:  vi.fn().mockReturnValue([]),
}));

import { executeImport, executeImportV2, type V2ParsedData } from "../articles.import.service.js";

// ── Setup por defecto ─────────────────────────────────────────────────────────
beforeEach(() => {
  vi.clearAllMocks();
  mockPrisma.articleCostLine.deleteMany.mockResolvedValue({ count: 0 });
  mockPrisma.articleCostLine.createMany.mockResolvedValue({ count: 0 });
  mockPrisma.articleVariant.create.mockResolvedValue({ id: "var-new" });
  mockPrisma.articleVariant.update.mockResolvedValue({});
  mockPrisma.article.create.mockResolvedValue({ id: "art-new", code: "ART-0001" });
  mockPrisma.article.update.mockResolvedValue({});
  mockPrisma.articleStock.findFirst.mockResolvedValue(null);
  mockPrisma.articleStock.create.mockResolvedValue({});
});

// ─────────────────────────────────────────────────────────────────────────────
// A. executeImport v1 — variante sin código no se duplica en modo skip
// ─────────────────────────────────────────────────────────────────────────────

describe("executeImport v1 — idempotencia skip: variante sin código", () => {
  function setupV1Mocks({
    existingArticleId,
    existingVariantId,
  }: { existingArticleId?: string; existingVariantId?: string } = {}) {
    mockPrisma.articleCategory.findMany.mockResolvedValue([]);
    mockPrisma.articleGroup.findMany.mockResolvedValue([]);
    mockPrisma.commercialEntity.findMany.mockResolvedValue([]);

    // Existing articles by code
    mockPrisma.article.findMany
      .mockResolvedValueOnce(
        existingArticleId ? [{ id: existingArticleId, code: "ART-001" }] : [],
      )
      // Art SKUs
      .mockResolvedValueOnce([])
      // Var SKUs
      // (articleVariant.findMany for varSkuMap is separate — see below)
      // Parent cats for exec
      .mockResolvedValueOnce(
        existingArticleId ? [{ code: "ART-001", categoryId: null }] : [],
      );

    mockPrisma.articleVariant.findMany
      // varSkuMap (called inline for variant sku check — NOT Promise.all here)
      .mockResolvedValueOnce([]);

    if (existingVariantId) {
      // findFirst for variant by name (new fix: skip mode, no code)
      mockPrisma.articleVariant.findFirst.mockResolvedValueOnce({ id: existingVariantId });
    } else {
      mockPrisma.articleVariant.findFirst.mockResolvedValueOnce(null);
      // for create path: sortOrder count
      mockPrisma.articleVariant.count.mockResolvedValueOnce(0);
    }
  }

  it("cuando la variante YA existe por nombre y onConflict=skip → no llama a articleVariant.create", async () => {
    setupV1Mocks({ existingArticleId: "art-1", existingVariantId: "var-1" });

    const rows: Record<string, string>[] = [
      { "Nombre": "Anillo Test", "Codigo": "ART-001", "Es_Variante": "NO", "Articulo_Padre": "" },
      { "Nombre": "Talle 16", "Codigo": "", "Articulo_Padre": "ART-001", "Es_Variante": "SI" },
    ];

    const result = await executeImport(rows, "jw-1", { onConflict: "skip" });

    expect(mockPrisma.articleVariant.create).not.toHaveBeenCalled();
    expect(result.results.find(r => r.displayName === "[Variante] Talle 16")?.status).toBe("skipped");
  });

  it("cuando la variante NO existe por nombre y onConflict=skip → sí llama a articleVariant.create", async () => {
    setupV1Mocks({ existingArticleId: "art-1", existingVariantId: undefined });

    // Article doesn't exist either — make it create
    // Override: article doesn't exist
    mockPrisma.article.findMany
      .mockReset()
      .mockResolvedValueOnce([])   // existingCodesDb — art doesn't exist
      .mockResolvedValueOnce([])   // artSkuMap
      .mockResolvedValueOnce([]);  // parent cats

    mockPrisma.articleVariant.findMany.mockReset().mockResolvedValueOnce([]);
    mockPrisma.article.count.mockResolvedValue(0);
    mockPrisma.article.findFirst.mockResolvedValue(null); // code doesn't conflict
    mockPrisma.article.create.mockResolvedValue({ id: "art-new", code: "ART-001" });
    mockPrisma.articleVariant.findFirst.mockResolvedValueOnce(null); // name not found → create
    mockPrisma.articleVariant.count.mockResolvedValueOnce(0);
    mockPrisma.articleVariant.create.mockResolvedValue({ id: "var-new" });

    const rows: Record<string, string>[] = [
      { "Nombre": "Anillo Test", "Codigo": "ART-001", "Es_Variante": "NO", "Articulo_Padre": "" },
      { "Nombre": "Talle 16", "Codigo": "", "Articulo_Padre": "ART-001", "Es_Variante": "SI" },
    ];

    const result = await executeImport(rows, "jw-1", { onConflict: "skip" });

    expect(mockPrisma.articleVariant.create).toHaveBeenCalledOnce();
    expect(result.results.find(r => r.displayName === "[Variante] Talle 16")?.status).toBe("created");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// B. executeImportV2 — modo skip: metales no se procesan para artículos omitidos
// ─────────────────────────────────────────────────────────────────────────────

describe("executeImportV2 — idempotencia skip: metales/stock no se tocan", () => {
  function setupV2Mocks(existingArticles: { id: string; code: string }[]) {
    mockPrisma.articleCategory.findMany.mockResolvedValue([]);
    mockPrisma.articleGroup.findMany.mockResolvedValue([]);
    mockPrisma.commercialEntity.findMany.mockResolvedValue([]);

    // Promise.all order: [articleCategory, articleGroup, commercialEntity,
    //   article (existing), metal, warehouse, article (SKUs), articleVariant (SKUs)]
    mockPrisma.article.findMany
      .mockResolvedValueOnce(
        existingArticles.map(a => ({
          ...a,
          articleType: "PRODUCT",
          stockMode:   "NO_STOCK",
          categoryId:  null,
        })),
      )
      // allArtSkusRaw (second call in Promise.all)
      .mockResolvedValueOnce([]);

    mockPrisma.metal.findMany.mockResolvedValue([{
      id: "met-1",
      name: "Oro",
      variants: [{ id: "mv-1", name: "Oro 18K" }],
    }]);
    mockPrisma.warehouse.findMany.mockResolvedValue([]);
    mockPrisma.articleVariant.findMany
      // allVarSkusRaw (in Promise.all)
      .mockResolvedValueOnce([])
      // existingVarsRaw (after article section)
      .mockResolvedValueOnce([]);
  }

  it("cuando artículo existe y onConflict=skip → articleCostLine.deleteMany NO se llama", async () => {
    setupV2Mocks([{ id: "art-1", code: "ART-001" }]);

    const data: V2ParsedData = {
      articles: [{ "Nombre": "Anillo", "Codigo": "ART-001" }],
      variants: [],
      metals:   [{ "Articulo_Codigo": "ART-001", "Metal_Padre": "Oro", "Metal_Variante": "Oro 18K", "Gramos": "3.5" }],
      stock:    [],
      attributes: [],
    };

    const result = await executeImportV2(data, "jw-1", { onConflict: "skip" });

    expect(mockPrisma.articleCostLine.deleteMany).not.toHaveBeenCalled();
    expect(mockPrisma.articleCostLine.createMany).not.toHaveBeenCalled();
    expect(result.summary.skipped).toBe(1);
    expect(result.metalRows).toBe(0);
  });

  it("cuando artículo existe y onConflict=skip → articleStock.create NO se llama", async () => {
    setupV2Mocks([{ id: "art-1", code: "ART-001" }]);

    mockPrisma.warehouse.findMany.mockResolvedValue([{ id: "wh-1", name: "Principal", code: "ALM01" }]);

    const data: V2ParsedData = {
      articles:   [{ "Nombre": "Anillo", "Codigo": "ART-001" }],
      variants:   [],
      metals:     [],
      stock:      [{ "Articulo_Codigo": "ART-001", "Almacen": "ALM01", "Cantidad": "5", "Modo": "SET" }],
      attributes: [],
    };

    const result = await executeImportV2(data, "jw-1", { onConflict: "skip" });

    expect(mockPrisma.articleStock.create).not.toHaveBeenCalled();
    expect(mockPrisma.articleStock.update).not.toHaveBeenCalled();
    expect(result.summary.skipped).toBe(1);
    expect(result.stockRows).toBe(0);
  });

  it("cuando artículo es nuevo (created) con onConflict=skip → metales SÍ se procesan", async () => {
    // Article doesn't exist in DB → gets created
    setupV2Mocks([]); // no existing articles

    mockPrisma.article.count.mockResolvedValue(0);
    mockPrisma.article.findFirst.mockResolvedValue(null);
    mockPrisma.article.create.mockResolvedValue({ id: "art-new", code: "ART-001" });

    const data: V2ParsedData = {
      articles: [{ "Nombre": "Anillo", "Codigo": "ART-001", "Tipo": "PRODUCT" }],
      variants: [],
      metals:   [{ "Articulo_Codigo": "ART-001", "Metal_Padre": "Oro", "Metal_Variante": "Oro 18K", "Gramos": "3.5" }],
      stock:    [],
      attributes: [],
    };

    const result = await executeImportV2(data, "jw-1", { onConflict: "skip" });

    expect(mockPrisma.articleCostLine.deleteMany).toHaveBeenCalled();
    expect(mockPrisma.articleCostLine.createMany).toHaveBeenCalled();
    expect(result.summary.created).toBe(1);
    expect(result.metalRows).toBe(1);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// C. executeImportV2 — modo skip: atributos y stock no se tocan en variantes omitidas
// ─────────────────────────────────────────────────────────────────────────────

describe("executeImportV2 — idempotencia skip: atributos y stock de variantes omitidas", () => {
  function setupV2WithVariantMocks() {
    mockPrisma.articleCategory.findMany.mockResolvedValue([]);
    mockPrisma.articleGroup.findMany.mockResolvedValue([]);
    mockPrisma.commercialEntity.findMany.mockResolvedValue([]);
    mockPrisma.metal.findMany.mockResolvedValue([]);
    mockPrisma.warehouse.findMany.mockResolvedValue([
      { id: "wh-1", name: "Principal", code: "ALM01" },
    ]);

    // existingArticlesRaw: ART-001 existe
    mockPrisma.article.findMany
      .mockResolvedValueOnce([{ id: "art-1", code: "ART-001", articleType: "PRODUCT", stockMode: "BY_ARTICLE", categoryId: "cat-1" }])
      .mockResolvedValueOnce([]);  // allArtSkusRaw

    // allVarSkusRaw (in Promise.all)
    mockPrisma.articleVariant.findMany
      .mockResolvedValueOnce([])
      // existingVarsRaw (after article section): VAR-001 existe
      .mockResolvedValueOnce([{ id: "var-1", code: "VAR-001", articleId: "art-1" }]);
  }

  it("atributo de variante omitida no se procesa (upsert no se llama)", async () => {
    setupV2WithVariantMocks();

    const data: V2ParsedData = {
      articles:   [{ "Nombre": "Anillo", "Codigo": "ART-001" }],
      variants:   [{ "Articulo_Codigo": "ART-001", "Codigo": "VAR-001", "Nombre": "Talle 16" }],
      metals:     [],
      stock:      [],
      attributes: [{ "Articulo_Codigo": "ART-001", "Codigo_Variante": "VAR-001", "Atributo": "Color", "Valor": "Rojo" }],
    };

    const result = await executeImportV2(data, "jw-1", { onConflict: "skip" });

    expect(mockPrisma.articleVariantAttributeValue.upsert).not.toHaveBeenCalled();
    // Artículo y variante skipped
    expect(result.summary.skipped).toBe(2);
    expect(result.attributeRows).toBe(0);
  });

  it("stock de variante omitida no se procesa (create/update no se llama)", async () => {
    setupV2WithVariantMocks();

    mockPrisma.articleStock.findFirst.mockResolvedValue({ id: "st-1", quantity: 10 });

    const data: V2ParsedData = {
      articles:   [{ "Nombre": "Anillo", "Codigo": "ART-001" }],
      variants:   [{ "Articulo_Codigo": "ART-001", "Codigo": "VAR-001", "Nombre": "Talle 16" }],
      metals:     [],
      stock:      [{ "Articulo_Codigo": "ART-001", "Codigo_Variante": "VAR-001", "Almacen": "ALM01", "Cantidad": "5", "Modo": "ADD" }],
      attributes: [],
    };

    const result = await executeImportV2(data, "jw-1", { onConflict: "skip" });

    // Stock ADD sobre variante omitida no debe duplicar
    expect(mockPrisma.articleStock.update).not.toHaveBeenCalled();
    expect(result.summary.skipped).toBe(2);
    expect(result.stockRows).toBe(0);
  });

  it("atributo de variante NUEVA (created) sí se procesa aunque artículo sea omitido", async () => {
    // Article exists (skipped), but variant doesn't exist → created
    mockPrisma.articleCategory.findMany.mockResolvedValue([{ id: "cat-1", name: "Anillos" }]);
    // getEffectiveCategoryAxes walks parent chain via findFirst; return axis "Color"
    mockPrisma.articleCategory.findFirst.mockResolvedValue({
      parentId: null,
      attributes: [{ id: "assign-1", isRequired: false, definition: { name: "Color", code: "color", inputType: "TEXT", options: [] } }],
    });
    mockPrisma.articleGroup.findMany.mockResolvedValue([]);
    mockPrisma.commercialEntity.findMany.mockResolvedValue([]);
    mockPrisma.metal.findMany.mockResolvedValue([]);
    mockPrisma.warehouse.findMany.mockResolvedValue([]);

    mockPrisma.article.findMany
      .mockResolvedValueOnce([{ id: "art-1", code: "ART-001", articleType: "PRODUCT", stockMode: "NO_STOCK", categoryId: "cat-1" }])
      .mockResolvedValueOnce([]);

    mockPrisma.articleVariant.findMany
      .mockResolvedValueOnce([])    // allVarSkusRaw
      .mockResolvedValueOnce([]);   // existingVarsRaw — VAR-NEW no existe

    mockPrisma.articleVariant.count.mockResolvedValue(0);
    mockPrisma.articleVariant.create.mockResolvedValue({ id: "var-new" });
    mockPrisma.articleVariantAttributeValue.upsert.mockResolvedValue({});

    const data: V2ParsedData = {
      articles:   [{ "Nombre": "Anillo", "Codigo": "ART-001" }],
      variants:   [{ "Articulo_Codigo": "ART-001", "Codigo": "VAR-NEW", "Nombre": "Talle 18" }],
      metals:     [],
      stock:      [],
      attributes: [{ "Articulo_Codigo": "ART-001", "Codigo_Variante": "VAR-NEW", "Atributo": "Color", "Valor": "Azul" }],
    };

    const result = await executeImportV2(data, "jw-1", { onConflict: "skip" });

    // Artículo omitido pero variante nueva → atributo de la nueva variante sí se procesa
    expect(mockPrisma.articleVariantAttributeValue.upsert).toHaveBeenCalled();
    expect(result.summary.skipped).toBe(1);  // solo el artículo
    expect(result.summary.created).toBe(1);  // la variante nueva
    expect(result.attributeRows).toBe(1);
  });
});
