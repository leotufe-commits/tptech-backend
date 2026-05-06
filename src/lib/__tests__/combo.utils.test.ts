// ============================================================================
// combo.utils.test.ts — tests unitarios para validaciones y disponibilidad
// del modo COMBO_COMMERCIAL.
// ============================================================================

import { describe, it, expect, vi, beforeEach } from "vitest";

// ── Mock Prisma (patrón vi.hoisted como el resto de la suite) ───────────────
const mockPrisma = vi.hoisted(() => ({
  article:        { findFirst: vi.fn(), findMany: vi.fn() },
  articleStock:   { findMany: vi.fn() },
  articleCostLine:{ count: vi.fn() },
}));

vi.mock("../prisma.js", () => ({ prisma: mockPrisma }));

import {
  normalizeComboFields,
  validateComboComponentsShape,
  validateComboComponentsAgainstDb,
  computeComboAvailability,
  applyComboAdjustment,
} from "../combo.utils.js";

beforeEach(() => {
  vi.clearAllMocks();
});

// ── 1. normalizeComboFields ────────────────────────────────────────────────
describe("normalizeComboFields", () => {
  // (escenario 13) Artículo NORMAL: defaults seguros, no fuerza flags.
  it("NORMAL devuelve defaults seguros y no fuerza flags", () => {
    const r = normalizeComboFields({ articleType: "PRODUCT", commercialMode: "NORMAL" });
    expect(r.commercialMode).toBe("NORMAL");
    expect(r.comboAdjustmentKind).toBe("NONE");
    expect(r.comboAdjustmentValue).toBeNull();
    expect(r.stockMode).toBeUndefined();
    expect(r.sellWithoutVariants).toBeUndefined();
  });

  // Cambio semántico: useManualSalePrice ya NO se fuerza en combos.
  // El combo se trata como producto normal a nivel pricing comercial:
  // puede tener lista de precios o salePrice manual con override.
  // Los flags forzados que SÍ se mantienen: stockMode=NO_STOCK y sellWithoutVariants=true.
  it("COMBO_COMMERCIAL fuerza stockMode=NO_STOCK y sellWithoutVariants=true (no toca pricing)", () => {
    const r = normalizeComboFields({
      articleType: "PRODUCT",
      commercialMode: "COMBO_COMMERCIAL",
      comboAdjustmentKind: "NONE",
    });
    expect(r.commercialMode).toBe("COMBO_COMMERCIAL");
    expect(r.stockMode).toBe("NO_STOCK");
    expect(r.sellWithoutVariants).toBe(true);
    // useManualSalePrice ya no es parte del retorno (combo lo maneja como producto normal)
    expect((r as any).useManualSalePrice).toBeUndefined();
  });

  it("rechaza articleType != PRODUCT en combo", () => {
    expect(() =>
      normalizeComboFields({ articleType: "SERVICE", commercialMode: "COMBO_COMMERCIAL" }),
    ).toThrow(/PRODUCT/);
  });

  it("DISCOUNT_PERCENT exige value y lo valida en rango 0..100", () => {
    expect(() =>
      normalizeComboFields({
        articleType: "PRODUCT",
        commercialMode: "COMBO_COMMERCIAL",
        comboAdjustmentKind: "DISCOUNT_PERCENT",
      }),
    ).toThrow(/obligatorio/);

    expect(() =>
      normalizeComboFields({
        articleType: "PRODUCT",
        commercialMode: "COMBO_COMMERCIAL",
        comboAdjustmentKind: "DISCOUNT_PERCENT",
        comboAdjustmentValue: 150,
      }),
    ).toThrow(/0 y 100/);

    const ok = normalizeComboFields({
      articleType: "PRODUCT",
      commercialMode: "COMBO_COMMERCIAL",
      comboAdjustmentKind: "DISCOUNT_PERCENT",
      comboAdjustmentValue: "10",
    });
    expect(ok.comboAdjustmentValue).toBe(10);
  });

  it("DISCOUNT_FIXED rechaza valores negativos", () => {
    expect(() =>
      normalizeComboFields({
        articleType: "PRODUCT",
        commercialMode: "COMBO_COMMERCIAL",
        comboAdjustmentKind: "DISCOUNT_FIXED",
        comboAdjustmentValue: -50,
      }),
    ).toThrow(/no puede ser negativo/);
  });

  it("NONE descarta el value (lo deja null)", () => {
    const r = normalizeComboFields({
      articleType: "PRODUCT",
      commercialMode: "COMBO_COMMERCIAL",
      comboAdjustmentKind: "NONE",
      comboAdjustmentValue: 99,
    });
    expect(r.comboAdjustmentValue).toBeNull();
  });
});

// ── 2. validateComboComponentsShape ────────────────────────────────────────
describe("validateComboComponentsShape", () => {
  // (escenario 2) Combo sin componentes
  it("rechaza combo sin componentes", () => {
    expect(() =>
      validateComboComponentsShape({ ownArticleId: null, componentLines: [] }),
    ).toThrow(/al menos un componente/);
  });

  // (escenario 1) Combo válido
  it("acepta combo con 1+ componentes válidos", () => {
    expect(() =>
      validateComboComponentsShape({
        ownArticleId: "art-padre",
        componentLines: [
          { type: "PRODUCT", catalogItemId: "art-A", quantity: 1 },
          { type: "PRODUCT", catalogItemId: "art-B", quantity: 2 },
        ],
      }),
    ).not.toThrow();
  });

  // (parte de escenario 4: autorreferencia)
  it("rechaza autorreferencia (combo se incluye a sí mismo)", () => {
    expect(() =>
      validateComboComponentsShape({
        ownArticleId: "art-padre",
        componentLines: [{ type: "PRODUCT", catalogItemId: "art-padre", quantity: 1 }],
      }),
    ).toThrow(/sí mismo/);
  });

  it("rechaza componentes duplicados", () => {
    expect(() =>
      validateComboComponentsShape({
        ownArticleId: null,
        componentLines: [
          { type: "PRODUCT", catalogItemId: "art-A", quantity: 1 },
          { type: "PRODUCT", catalogItemId: "art-A", quantity: 2 },
        ],
      }),
    ).toThrow(/duplicados/);
  });

  it("rechaza cantidad <= 0", () => {
    expect(() =>
      validateComboComponentsShape({
        ownArticleId: null,
        componentLines: [{ type: "PRODUCT", catalogItemId: "art-A", quantity: 0 }],
      }),
    ).toThrow(/mayor a 0/);
  });
});

// ── 3. validateComboComponentsAgainstDb ────────────────────────────────────
describe("validateComboComponentsAgainstDb", () => {
  // (escenario 3) Componente servicio
  it("rechaza componente articleType=SERVICE", async () => {
    mockPrisma.article.findMany.mockResolvedValueOnce([
      { id: "svc-1", name: "Reparación", code: "REP001", articleType: "SERVICE", commercialMode: "NORMAL", isActive: true },
    ]);

    await expect(
      validateComboComponentsAgainstDb(mockPrisma as any, {
        jewelryId: "j1",
        ownArticleId: "art-padre",
        componentArticleIds: ["svc-1"],
      }),
    ).rejects.toThrow(/Servicio/);
  });

  it("rechaza componente inactivo", async () => {
    mockPrisma.article.findMany.mockResolvedValueOnce([
      { id: "art-A", name: "A", code: "A001", articleType: "PRODUCT", commercialMode: "NORMAL", isActive: false },
    ]);
    await expect(
      validateComboComponentsAgainstDb(mockPrisma as any, {
        jewelryId: "j1", ownArticleId: "art-padre", componentArticleIds: ["art-A"],
      }),
    ).rejects.toThrow(/inactivo/);
  });

  it("rechaza componente inexistente", async () => {
    mockPrisma.article.findMany.mockResolvedValueOnce([]); // ninguno encontrado
    await expect(
      validateComboComponentsAgainstDb(mockPrisma as any, {
        jewelryId: "j1", ownArticleId: "art-padre", componentArticleIds: ["fantasma"],
      }),
    ).rejects.toThrow(/no existe o fue eliminado/);
  });

  // (escenario 4) Ciclo entre combos
  it("detecta ciclo entre combos (A combo, contiene B; B combo, contiene A)", async () => {
    // 1ª llamada: validar componentes de A (B es PRODUCT activo)
    mockPrisma.article.findMany.mockResolvedValueOnce([
      { id: "B", name: "Combo B", code: "B001", articleType: "PRODUCT", commercialMode: "COMBO_COMMERCIAL", isActive: true },
    ]);
    // DFS desde B hacia A: B es combo y contiene a A
    mockPrisma.article.findFirst.mockResolvedValueOnce({
      commercialMode: "COMBO_COMMERCIAL",
      costComposition: [{ catalogItemId: "A" }],
    });

    await expect(
      validateComboComponentsAgainstDb(mockPrisma as any, {
        jewelryId: "j1", ownArticleId: "A", componentArticleIds: ["B"],
      }),
    ).rejects.toThrow(/[Cc]iclo/);
  });

  it("permite combo cuando los componentes son artículos NORMAL (sin ciclo posible)", async () => {
    mockPrisma.article.findMany.mockResolvedValueOnce([
      { id: "art-A", name: "A", code: "A001", articleType: "PRODUCT", commercialMode: "NORMAL", isActive: true },
      { id: "art-B", name: "B", code: "B001", articleType: "PRODUCT", commercialMode: "NORMAL", isActive: true },
    ]);
    // DFS desde A: NORMAL → no baja. Idem B.
    mockPrisma.article.findFirst.mockResolvedValue({
      commercialMode: "NORMAL",
      costComposition: [],
    });

    await expect(
      validateComboComponentsAgainstDb(mockPrisma as any, {
        jewelryId: "j1", ownArticleId: "art-padre", componentArticleIds: ["art-A", "art-B"],
      }),
    ).resolves.toBeUndefined();
  });

  // Combo recursivo válido: A (combo) contiene B (combo) que contiene C (NORMAL).
  // El DFS baja por B, ve un NORMAL y corta sin encontrar ciclo con A.
  it("permite combo recursivo válido (combo dentro de combo, sin ciclo)", async () => {
    // Validación inicial: B es un combo PRODUCT activo
    mockPrisma.article.findMany.mockResolvedValueOnce([
      { id: "B", name: "Combo B", code: "B001", articleType: "PRODUCT", commercialMode: "COMBO_COMMERCIAL", isActive: true },
    ]);
    // DFS desde B: B es combo, contiene a C
    mockPrisma.article.findFirst
      .mockResolvedValueOnce({
        commercialMode: "COMBO_COMMERCIAL",
        costComposition: [{ catalogItemId: "C" }],
      })
      // Siguiente paso del DFS: C es NORMAL → corta, no llega a A
      .mockResolvedValueOnce({
        commercialMode: "NORMAL",
        costComposition: [],
      });

    await expect(
      validateComboComponentsAgainstDb(mockPrisma as any, {
        jewelryId: "j1", ownArticleId: "A", componentArticleIds: ["B"],
      }),
    ).resolves.toBeUndefined();
  });
});

// ── 3.5 applyComboAdjustment (cálculo puro del precio combo) ──────────────
describe("applyComboAdjustment", () => {
  // (escenario 5) Cálculo correcto del precio automático
  it("NONE devuelve subtotal sin modificar", () => {
    const r = applyComboAdjustment(100, "NONE", null);
    expect(r.final).toBe(100);
    expect(r.adjustmentAmount).toBe(0);
  });

  it("DISCOUNT_PERCENT resta el porcentaje", () => {
    const r = applyComboAdjustment(200, "DISCOUNT_PERCENT", 10);
    expect(r.final).toBe(180);
    expect(r.adjustmentAmount).toBe(20);
  });

  it("SURCHARGE_PERCENT suma el porcentaje", () => {
    const r = applyComboAdjustment(200, "SURCHARGE_PERCENT", 15);
    expect(r.final).toBe(230);
    expect(r.adjustmentAmount).toBe(30);
  });

  it("DISCOUNT_FIXED resta el monto fijo", () => {
    const r = applyComboAdjustment(500, "DISCOUNT_FIXED", 75);
    expect(r.final).toBe(425);
    expect(r.adjustmentAmount).toBe(75);
  });

  // (escenario 6 — recalcular si cambia componente: la fórmula recibe nuevo subtotal)
  it("cuando cambia el subtotal el resultado se recalcula", () => {
    expect(applyComboAdjustment(100, "DISCOUNT_PERCENT", 10).final).toBe(90);
    expect(applyComboAdjustment(150, "DISCOUNT_PERCENT", 10).final).toBe(135);
  });

  it("clampa a 0 si el descuento excede el subtotal", () => {
    const r = applyComboAdjustment(50, "DISCOUNT_FIXED", 100);
    expect(r.final).toBe(0);
  });

  it("trata value=null como 0 (sin ajuste)", () => {
    const r = applyComboAdjustment(100, "DISCOUNT_PERCENT", null);
    expect(r.final).toBe(100);
  });
});

// ── 4. computeComboAvailability ────────────────────────────────────────────
describe("computeComboAvailability", () => {
  function setupCombo(opts: {
    components: Array<{ id: string; code: string; name: string; qty: number }>;
    stocks: Array<{ articleId: string; quantity: number }>;
  }) {
    mockPrisma.article.findFirst.mockResolvedValueOnce({
      commercialMode: "COMBO_COMMERCIAL",
      costComposition: opts.components.map(c => ({
        catalogItemId: c.id,
        quantity: c.qty,
        catalogItem: { id: c.id, code: c.code, name: c.name },
      })),
    });
    mockPrisma.articleStock.findMany.mockResolvedValueOnce(opts.stocks);
  }

  // (escenario 7) Disponibilidad según stock de componentes
  it("calcula disponibilidad como min(stock/qty) de los componentes", async () => {
    setupCombo({
      components: [
        { id: "A", code: "A", name: "A", qty: 1 },
        { id: "B", code: "B", name: "B", qty: 2 },
      ],
      stocks: [
        { articleId: "A", quantity: 10 }, // 10/1 = 10
        { articleId: "B", quantity: 8 },  //  8/2 = 4 ← cuello de botella
      ],
    });
    const r = await computeComboAvailability(mockPrisma as any, {
      jewelryId: "j1", articleId: "combo-1",
    });
    expect(r.available).toBe(4);
    expect(r.bottleneckArticleId).toBe("B");
    expect(r.components).toHaveLength(2);
  });

  // (escenario 11) Stock insuficiente: si un componente está en 0 → 0 disponibles
  it("devuelve 0 si algún componente tiene stock 0", async () => {
    setupCombo({
      components: [
        { id: "A", code: "A", name: "A", qty: 1 },
        { id: "B", code: "B", name: "B", qty: 1 },
      ],
      stocks: [
        { articleId: "A", quantity: 5 },
        // B sin entrada → stock 0
      ],
    });
    const r = await computeComboAvailability(mockPrisma as any, {
      jewelryId: "j1", articleId: "combo-1",
    });
    expect(r.available).toBe(0);
    expect(r.bottleneckArticleId).toBe("B");
  });

  // (escenario 12) Por almacén
  it("calcula stock filtrado por warehouseId cuando se provee", async () => {
    setupCombo({
      components: [{ id: "A", code: "A", name: "A", qty: 1 }],
      stocks: [{ articleId: "A", quantity: 3 }],
    });
    await computeComboAvailability(mockPrisma as any, {
      jewelryId: "j1", articleId: "combo-1", warehouseId: "wh-1",
    });
    // Verificar que el filtro warehouseId se aplicó al where
    expect(mockPrisma.articleStock.findMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: expect.objectContaining({ warehouseId: "wh-1" }),
      }),
    );
  });

  it("devuelve isCombo=false cuando el artículo no es combo", async () => {
    mockPrisma.article.findFirst.mockResolvedValueOnce({
      commercialMode: "NORMAL",
      costComposition: [],
    });
    const r = await computeComboAvailability(mockPrisma as any, {
      jewelryId: "j1", articleId: "art-normal",
    });
    expect(r.isCombo).toBe(false);
    expect(r.available).toBe(0);
  });
});
