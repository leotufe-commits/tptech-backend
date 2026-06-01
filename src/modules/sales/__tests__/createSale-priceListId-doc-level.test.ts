// src/modules/sales/__tests__/createSale-priceListId-doc-level.test.ts
// =============================================================================
// Etapa C16 — Test de regresión del fix del drift detectado en C15.
//
// Pre-C16: `createSale` / `updateSale` no leían `body.priceListId`. Cada línea
//          recibía solo su `priceListIdOverride`; sin override, el motor caía
//          a la cadena cliente → favorita. Resultado: el operador cambiaba la
//          lista del documento, el preview lo reflejaba, pero al guardar el
//          DRAFT el `appliedPriceListId` quedaba en la favorita.
//
// Post-C16: el motor de línea recibe como `priceListIdOverride` la cascada:
//             line.priceListIdOverride  > body.priceListId  > null
//           (mismo orden que `previewSale`). Esto se verifica acá inspeccionando
//           los argumentos con los que `resolveDraftSaleLinesPricing` invoca el
//           motor a través del flujo público.
//
// Estrategia del test: mockear `resolveFinalSalePrice` y verificar que el
// parámetro `priceListIdOverride` que le llega en cada línea respeta la
// cascada esperada según los inputs.
// =============================================================================

import { describe, it, expect, vi, beforeEach } from "vitest";

// ── Mocks ──────────────────────────────────────────────────────────────────

const calls: Array<Record<string, unknown>> = [];

vi.mock("../../../lib/pricing-engine/pricing-engine.js", async () => {
  const { Prisma } = await import("@prisma/client");
  return {
    resolveFinalSalePrice: vi.fn(async (_jewelryId: string, args: any) => {
      calls.push(args);
      return {
        unitPrice:           new Prisma.Decimal("1000"),
        discountPct:         new Prisma.Decimal("0"),
        appliedPriceListId:  args.priceListIdOverride ?? null,
        appliedPriceListName: null,
        appliedPriceListMode: null,
        appliedPromotionId:  null,
        appliedPromotionName: null,
        appliedDiscountId:   null,
        priceSource:         "PRICE_LIST",
        baseSource:          "PRICE_LIST",
        unitCost:            new Prisma.Decimal("500"),
        unitMargin:          new Prisma.Decimal("500"),
        marginPercent:       new Prisma.Decimal("100"),
        markupPercent:       new Prisma.Decimal("100"),
        steps:               [],
        alerts:              [],
        policy:              { canConfirm: true, blockingAlerts: [] },
        partial:             false,
        costPartial:         false,
        costMode:            "DETAILED",
        quantityDiscountAmount:  new Prisma.Decimal("0"),
        promotionDiscountAmount: new Prisma.Decimal("0"),
        customerDiscountAmount:  new Prisma.Decimal("0"),
        discountAmount:      new Prisma.Decimal("0"),
        stackingMode:        "ADDITIVE",
        appliedRounding:     null,
        deferredRounding:    null,
        metalHechuraBreakdown: null,
        componentSaleBreakdown: null,
        taxAmount:           new Prisma.Decimal("0"),
        taxBreakdown:        [],
        composition:         null,
      };
    }),
    // Mocks de helpers que `sales.service.ts` también importa del barrel:
    computePurchaseTaxes: vi.fn(async () => ({
      base: 0, taxAmount: 0, withTax: 0, breakdown: [],
    })),
    buildPricingSnapshot:        vi.fn((_r: any, _opts: any) => ({} as any)),
    deriveMetalHechuraBreakdown: vi.fn(() => null),
    resolveShippingAmount:       vi.fn(async () => 0),
    sumFixedTaxComponent:        vi.fn(() => 0),
  };
});

vi.mock("../../../lib/prisma.js", () => ({
  prisma: {
    article: {
      findMany: vi.fn(async () => [
        { id: "art-1", categoryId: null, brand: null, costComposition: [] },
      ]),
    },
    articleGroupItem: { findMany: vi.fn(async () => []) },
  },
}));

vi.mock("../../../lib/document-rounding.js", () => ({
  loadDocumentRoundingConfig: vi.fn(async () => ({ suppressListDeferredRounding: false })),
}));

vi.mock("../../articles/articles.service.js", () => ({
  buildCatalogItemsMapForCostLines: vi.fn(async () => new Map()),
}));

import { resolveDraftSaleLinesPricing } from "../sales.service.js";

beforeEach(() => {
  calls.length = 0;
  vi.clearAllMocks();
});

const TENANT_ID = "j1";

function lineInput(over: Record<string, unknown> = {}) {
  return {
    articleId:    "art-1",
    variantId:    null,
    quantity:     1,
    legacyClientUnitPrice:   1000,
    legacyClientDiscountPct: 0,
    ...over,
  };
}

// ──────────────────────────────────────────────────────────────────────────
// (1) Sin override + sin opts.priceListId → null (cae a cadena legacy)
// ──────────────────────────────────────────────────────────────────────────

describe("C16 — resolveDraftSaleLinesPricing propaga priceListId del doc", () => {
  it("(1) sin priceListIdOverride + opts.priceListId=undefined → motor recibe null", async () => {
    await resolveDraftSaleLinesPricing(TENANT_ID, [lineInput()], {});
    expect(calls).toHaveLength(1);
    expect(calls[0]!.priceListIdOverride).toBeNull();
  });

  it("(2) sin priceListIdOverride + opts.priceListId='prueba2' → motor recibe 'prueba2'", async () => {
    await resolveDraftSaleLinesPricing(
      TENANT_ID,
      [lineInput()],
      { priceListId: "prueba2" },
    );
    expect(calls).toHaveLength(1);
    expect(calls[0]!.priceListIdOverride).toBe("prueba2");
  });

  it("(3) priceListIdOverride='pl-otro' + opts.priceListId='prueba2' → override por línea gana", async () => {
    await resolveDraftSaleLinesPricing(
      TENANT_ID,
      [lineInput({ priceListIdOverride: "pl-otro" })],
      { priceListId: "prueba2" },
    );
    expect(calls).toHaveLength(1);
    expect(calls[0]!.priceListIdOverride).toBe("pl-otro");
  });

  it("(4) precedencia mixta: 2 líneas — una con override, una sin", async () => {
    await resolveDraftSaleLinesPricing(
      TENANT_ID,
      [
        lineInput({ priceListIdOverride: "pl-puntual" }),  // override gana
        lineInput({ priceListIdOverride: null }),          // hereda del doc
      ],
      { priceListId: "prueba2" },
    );
    expect(calls).toHaveLength(2);
    expect(calls[0]!.priceListIdOverride).toBe("pl-puntual");
    expect(calls[1]!.priceListIdOverride).toBe("prueba2");
  });

  it("(5) opts.priceListId=null y override=null → motor recibe null (cadena legacy)", async () => {
    await resolveDraftSaleLinesPricing(
      TENANT_ID,
      [lineInput({ priceListIdOverride: null })],
      { priceListId: null },
    );
    expect(calls).toHaveLength(1);
    expect(calls[0]!.priceListIdOverride).toBeNull();
  });
});
