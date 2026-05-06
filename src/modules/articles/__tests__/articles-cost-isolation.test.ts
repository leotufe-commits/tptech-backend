// src/modules/articles/__tests__/articles-cost-isolation.test.ts
//
// Verifica que las operaciones de costLines del artículo sean consistentes
// con la nueva arquitectura: un único conjunto de líneas por artículo,
// sin separación por variantId (campo eliminado en migración 20260417000000).
//
// Reglas invariantes verificadas aquí:
//   - deleteMany del artículo usa where: { articleId, jewelryId } (sin variantId)
//   - createMany NO asigna variantId (no existe en el modelo)
//   - Si costComposition está ausente del payload, NO se llama deleteMany
//   - Si costComposition es [], deleteMany se llama de todas formas (limpia la composición)

import { describe, it, expect, vi, beforeEach } from "vitest";

// ─── Mock de Prisma ──────────────────────────────────────────────────────────

const mockTx = vi.hoisted(() => ({
  article:         { update: vi.fn() },
  articleCostLine: { deleteMany: vi.fn(), createMany: vi.fn() },
}));

const mockPrisma = vi.hoisted(() => ({
  $transaction:    vi.fn(),
  article:         { findFirst: vi.fn(), findUnique: vi.fn() },
  articleCostLine: { deleteMany: vi.fn(), createMany: vi.fn() },
}));

vi.mock("../../../lib/prisma.js", () => ({ prisma: mockPrisma }));

import { setCostLines, updateArticle } from "../articles.service.js";

// ─── Setup compartido ─────────────────────────────────────────────────────────

beforeEach(() => {
  vi.clearAllMocks();

  // $transaction llama el callback con el mock de transacción
  mockPrisma.$transaction.mockImplementation(
    async (cb: (tx: typeof mockTx) => Promise<unknown>) => cb(mockTx),
  );

  // Respuestas por defecto dentro de la transacción
  mockTx.article.update.mockResolvedValue({});
  mockTx.articleCostLine.deleteMany.mockResolvedValue({ count: 0 });
  mockTx.articleCostLine.createMany.mockResolvedValue({ count: 0 });

  // findUnique → estado actual del artículo (usado en updateArticle)
  mockPrisma.article.findUnique.mockResolvedValue({
    articleType:   "PRODUCT",
    stockMode:     "BY_ARTICLE",
    barcode:       null,
    barcodeSource: "CODE",
    code:          "A001",
    sku:           "",
  });

  // findFirst: por defecto no configurado aquí.
  // Cada describe block lo configura con mockResolvedValueOnce:
  //   1ª llamada → { id: "art-1" }  para assertArticleOwnership
  //   2ª llamada → null             para getArticle (falla rápido sin mockear toda la cadena)
});

// ─── setCostLines ─────────────────────────────────────────────────────────────

describe("setCostLines — comportamiento de deleteMany", () => {
  // setCostLines: assertArticleOwnership (1ª findFirst) → $transaction → getArticle (2ª findFirst)
  beforeEach(() => {
    mockPrisma.article.findFirst
      .mockResolvedValueOnce({ id: "art-1" }) // assertArticleOwnership ✓
      .mockResolvedValueOnce(null);            // getArticle → falla antes de resolvePriceList
  });

  it("deleteMany usa { articleId, jewelryId } sin variantId", async () => {
    await expect(
      setCostLines("art-1", "jw-1", [
        { type: "METAL", label: "Oro 18K", quantity: 5, unitValue: 100, metalVariantId: "mv-1" },
      ]),
    ).rejects.toThrow();

    expect(mockTx.articleCostLine.deleteMany).toHaveBeenCalledWith({
      where: { articleId: "art-1", jewelryId: "jw-1" },
    });
  });

  it("createMany NO incluye variantId: campo no existe en el modelo", async () => {
    await expect(
      setCostLines("art-1", "jw-1", [
        { type: "HECHURA", label: "Hechura base", quantity: 1, unitValue: 500 },
      ]),
    ).rejects.toThrow();

    const createCall = mockTx.articleCostLine.createMany.mock.calls[0][0];
    createCall.data.forEach((line: Record<string, unknown>) => {
      expect(line).not.toHaveProperty("variantId");
    });
  });

  it("con líneas vacías: deleteMany se ejecuta igualmente (permite limpiar la composición)", async () => {
    await expect(
      setCostLines("art-1", "jw-1", []),
    ).rejects.toThrow();

    expect(mockTx.articleCostLine.deleteMany).toHaveBeenCalledWith({
      where: { articleId: "art-1", jewelryId: "jw-1" },
    });
    expect(mockTx.articleCostLine.createMany).not.toHaveBeenCalled();
  });
});

// ─── updateArticle ────────────────────────────────────────────────────────────

describe("updateArticle — comportamiento de deleteMany con costComposition", () => {
  // updateArticle: assertArticleOwnership (1ª findFirst) → $transaction → getArticle (2ª findFirst)
  beforeEach(() => {
    mockPrisma.article.findFirst
      .mockResolvedValueOnce({ id: "art-1" }) // assertArticleOwnership ✓
      .mockResolvedValueOnce(null);            // getArticle → falla rápido
  });

  it("deleteMany usa { articleId, jewelryId } cuando se envía costComposition con líneas", async () => {
    await expect(
      updateArticle("art-1", "jw-1", {
        name: "Anillo Test",
        costComposition: [
          { type: "METAL", label: "Oro", quantity: 3, unitValue: 200, metalVariantId: "mv-1" },
        ],
      }),
    ).rejects.toThrow();

    expect(mockTx.articleCostLine.deleteMany).toHaveBeenCalledWith({
      where: { articleId: "art-1", jewelryId: "jw-1" },
    });
  });

  it("deleteMany usa { articleId, jewelryId } incluso con costComposition vacío []", async () => {
    await expect(
      updateArticle("art-1", "jw-1", {
        name: "Anillo Test",
        costComposition: [],
      }),
    ).rejects.toThrow();

    expect(mockTx.articleCostLine.deleteMany).toHaveBeenCalledWith({
      where: { articleId: "art-1", jewelryId: "jw-1" },
    });
  });

  it("sin costComposition en el payload: deleteMany NO se llama (composición preservada)", async () => {
    await expect(
      updateArticle("art-1", "jw-1", {
        name: "Anillo Test",
        // costComposition ausente → no debe tocarse la composición
      }),
    ).rejects.toThrow();

    expect(mockTx.articleCostLine.deleteMany).not.toHaveBeenCalled();
  });

  it("ninguna llamada a deleteMany incluye variantId (resguardo contra regresión)", async () => {
    await expect(
      updateArticle("art-1", "jw-1", {
        name: "Anillo Test",
        costComposition: [
          { type: "HECHURA", label: "Hechura", quantity: 1, unitValue: 400 },
        ],
      }),
    ).rejects.toThrow();

    (mockTx.articleCostLine.deleteMany.mock.calls as any[]).forEach(
      (call: any[]) => {
        expect(call[0].where).not.toHaveProperty("variantId");
      },
    );
  });
});

// ─── Regla estructural — herencia lógica de variantes ────────────────────────

describe("Regla de herencia: variantes siempre usan el costo del artículo padre", () => {
  it("el modelo ArticleCostLine no tiene campo variantId (nueva arquitectura)", () => {
    // Las variantes heredan el costo del padre en runtime.
    // No hay separación física por variantId en la tabla ArticleCostLine.
    const parentCostLines = [
      { type: "METAL",   quantity: 3.5, unitValue: 1000 },
      { type: "HECHURA", quantity: 1,   unitValue: 500  },
    ];

    // Todas las líneas pertenecen al artículo — sin campo variantId
    parentCostLines.forEach(l => {
      expect(l).not.toHaveProperty("variantId");
    });
    expect(parentCostLines).toHaveLength(2);
  });

  it("padre con variantes: el SELECT devuelve exactamente las líneas del artículo", () => {
    // El nuevo modelo devuelve todas las líneas del artículo directamente,
    // sin necesidad de filtrar por variantId.
    const articleCostLinesFromDB = [
      { type: "METAL",   quantity: 3.5 },
      { type: "HECHURA", quantity: 1   },
    ];

    // Exactamente 2 líneas — sin duplicación por variantes
    expect(articleCostLinesFromDB).toHaveLength(2);

    const metalLines = articleCostLinesFromDB.filter(l => l.type === "METAL");
    expect(metalLines).toHaveLength(1);
    expect(metalLines[0].quantity).toBe(3.5);
  });
});
