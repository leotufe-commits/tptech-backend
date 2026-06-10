// src/modules/sales/__tests__/AUDIT-mixed-list-line-invariance.test.ts
// =============================================================================
// AUDITORÍA (solo lectura — NO valida un fix, NO cambia comportamiento).
//
// Pregunta central:
//   "Una pieza NO debe cambiar su valor porque agregué otra pieza con otra
//    lista al mismo comprobante."
//
// Reproduce dos documentos y compara LA MISMA Línea 1 (Artículo A, Lista
// Unificada) campo por campo:
//   · HOMOGÉNEO : [ Línea 1 (A, Lista Unificada) ]
//   · MIXTO     : [ Línea 1 (A, Lista Unificada), Línea 2 (B, Lista Desglosada) ]
//
// Imprime cada campo en ambos escenarios y marca el PRIMER campo que difiere.
//
// Diseño experimental:
//   · El motor de precios (`resolveFinalSalePrice`) está mockeado. Para la
//     línea Unificada devuelve EXACTAMENTE el mismo pricing en los dos
//     documentos cuando la lista es MARGIN_TOTAL (FINAL_PRICE) — así, cualquier
//     diferencia que aparezca viene del WIRING del servicio (no del motor).
//   · Para la variante METAL_HECHURA, el mock honra `suppressLineHechuraRounding`
//     (modela el redondeo PRE-TAX real de `applyPriceList`), de modo que se ve
//     el efecto pre-tax (homogéneo) vs post-tax (mixto / Opción α).
//   · `computeSaleDocumentTotals` y la familia de redondeo comercial quedan
//     REALES (no mockeados).
// =============================================================================

import { describe, it, expect, vi, beforeEach } from "vitest";
import { Prisma } from "@prisma/client";

const D = Prisma.Decimal;

// ── Config de la "Lista Unificada" a auditar (se reasigna por variante) ──────
let UNIF_MODE: "MARGIN_TOTAL" | "METAL_HECHURA" = "MARGIN_TOTAL";
let UNIF_ROUNDING_TARGET: "FINAL_PRICE" | "METAL" = "FINAL_PRICE";
let UNIF_ROUNDING_MODE_HECHURA: string = "NONE";
let UNIF_SCOPE: "PER_LINE_LEGACY" | "PER_DOCUMENT" = "PER_LINE_LEGACY";

// ── Parámetros de la pieza A (Lista Unificada) ───────────────────────────────
const TAX_RATE        = 0.21;
const A_METAL_ID      = "metal-oro";
const A_GRAMS_ORIG    = 5;       // gramos originales
const A_PURITY        = 0.75;    // pureza
const A_MERMA_MUL     = 1.10;    // +10% merma
const A_QUOTE_COST    = 100_000; // cotización de COSTO por gramo
const A_REF_VALUE     = 110_000; // valor comercial por gramo (referenceValue)
const A_METAL_COST    = +(A_GRAMS_ORIG * A_PURITY * A_MERMA_MUL * A_QUOTE_COST).toFixed(2); // 412500
const A_METAL_SALE    = +(A_METAL_COST * 1.10).toFixed(2);  // 453750 (10% margen metal)
const A_HECHURA_COST  = 50_000;
const A_HECHURA_RAW   = 79_850;  // hechura cruda (NO múltiplo de 100 → revela el redondeo)

const HUNDRED = (n: number) => Math.round(n / 100) * 100;

// ── Mocks de frontera (mismo molde que mixed-list-wiring-previewsale.test.ts) ─
const mockPrisma = vi.hoisted(() => ({
  article:          { findMany: vi.fn(), findFirst: vi.fn() },
  articleVariant:   { findMany: vi.fn(), findFirst: vi.fn() },
  articleGroupItem: { findMany: vi.fn() },
  metal:            { findMany: vi.fn() },
  sale:             { findFirst: vi.fn(), findMany: vi.fn(), create: vi.fn(), update: vi.fn(), count: vi.fn() },
  saleLine:         { update: vi.fn() },
  salesChannel:     { findFirst: vi.fn() },
  coupon:           { findFirst: vi.fn() },
  priceList:        { findMany: vi.fn(), findFirst: vi.fn() },
  promotion:        { findMany: vi.fn() },
  currency:         { findUnique: vi.fn() },
  jewelry:          { findUnique: vi.fn() },
  commercialEntity: { findFirst: vi.fn() },
  $transaction:     vi.fn(),
}));
vi.mock("../../../lib/prisma.js", () => ({ prisma: mockPrisma }));

const mockResolveFinalSalePrice  = vi.hoisted(() => vi.fn());
const mockBuildPricingSnapshot   = vi.hoisted(() => vi.fn());
const mockCalculateCostFromLines = vi.hoisted(() => vi.fn());
const mockBuildBatchCostContext  = vi.hoisted(() => vi.fn());
const mockComputeLineTaxes       = vi.hoisted(() => vi.fn());
const mockEvaluatePricingPolicy  = vi.hoisted(() => vi.fn());

vi.mock("../../../lib/pricing-engine/pricing-engine.js", async (importOriginal) => {
  const actual = await importOriginal<Record<string, any>>();
  return {
    ...actual,
    resolveFinalSalePrice:  (...a: any[]) => mockResolveFinalSalePrice(...a),
    buildPricingSnapshot:   (...a: any[]) => mockBuildPricingSnapshot(...a),
    calculateCostFromLines: (...a: any[]) => mockCalculateCostFromLines(...a),
    buildBatchCostContext:  (...a: any[]) => mockBuildBatchCostContext(...a),
    computeLineTaxes:       (...a: any[]) => mockComputeLineTaxes(...a),
    evaluatePricingPolicy:  (...a: any[]) => mockEvaluatePricingPolicy(...a),
    computePurchaseTaxes:   vi.fn().mockResolvedValue({ costBase: null, costTaxAmount: null, costWithTax: null, costTaxBreakdown: [] }),
    deriveMetalHechuraBreakdown: () => null,
    sumFixedTaxComponent:   () => 0,
  };
});

vi.mock("../../../lib/pricing-composition.js", () => ({
  buildComposition:                 () => ({ metal: null, hechura: null, metals: [], hechuras: [], products: [], services: [], taxes: [] }),
  fetchMetalVariantInfo:            vi.fn().mockResolvedValue({ purity: null, purityLabel: null, metalName: null }),
  fetchMetalVariantInfoMap:         vi.fn().mockResolvedValue(new Map()),
  resolveMetalVariantIdFromResult:  () => null,
  getAppliedMermaPercent:           () => null,
  buildCatalogItemsMapForCostLines: vi.fn().mockResolvedValue(new Map()),
  buildCatalogItemsMapForSteps:     vi.fn().mockResolvedValue(new Map()),
}));
vi.mock("../../../lib/pricing-engine/pricing-engine.currency.js", () => ({ getBaseCurrencyId: vi.fn().mockResolvedValue(null) }));
vi.mock("../../../lib/seller-commission.js", () => ({ calculateLineCommission: vi.fn().mockReturnValue({ base: null, amount: 0 }) }));

import { previewSale } from "../sales.service.js";

// ── Builders ─────────────────────────────────────────────────────────────────
function metalStepA() {
  return {
    key: "COST_LINES_METAL", status: "ok",
    meta: {
      metalId: A_METAL_ID, variantId: null,
      gramsOriginal: A_GRAMS_ORIG, qty: A_GRAMS_ORIG, purity: A_PURITY,
      quotePrice: A_QUOTE_COST,
      gramsFineEquivalent: +(A_GRAMS_ORIG * A_PURITY * A_MERMA_MUL).toFixed(6), // 4.125
    },
  };
}

function fakePrice(over: Record<string, any> = {}) {
  return {
    quantityDiscountAmount: new D("0"), promotionDiscountAmount: new D("0"), discountAmount: new D("0"),
    priceSource: "PRICE_LIST", baseSource: "PRICE_LIST",
    unitCost: new D("0"), unitMargin: new D("0"), marginPercent: new D("0"),
    costPartial: false, costMode: "COST_LINES", partial: false,
    appliedPriceListId: "pl-x", appliedPriceListName: "L", appliedPriceListMode: "MARGIN_TOTAL",
    appliedPromotionId: null, appliedPromotionName: null, appliedDiscountId: null,
    steps: [], alerts: [], policy: { canConfirm: true, blockingAlerts: [] },
    metalHechuraBreakdown: null, componentSaleBreakdown: null,
    taxAmount: new D("0"), taxBreakdown: [], totalWithTax: new D("0"), appliedRounding: null,
    ...over,
    unitPrice: over.unitPrice != null ? new D(String(over.unitPrice)) : new D("1000"),
    basePrice: over.basePrice != null ? new D(String(over.basePrice)) : new D("1000"),
  };
}

beforeEach(() => {
  vi.clearAllMocks();

  mockPrisma.article.findMany.mockResolvedValue([
    { id: "art-A", name: "Pieza A (Unificada)", categoryId: null, brand: null, manualTaxIds: ["tax-21"], costComposition: [], manualAdjustmentKind: null, manualAdjustmentType: null, manualAdjustmentValue: null },
    { id: "art-B", name: "Pieza B (Desglosada)", categoryId: null, brand: null, manualTaxIds: ["tax-21"], costComposition: [], manualAdjustmentKind: null, manualAdjustmentType: null, manualAdjustmentValue: null },
  ]);
  mockPrisma.articleVariant.findMany.mockResolvedValue([]);
  mockPrisma.articleGroupItem.findMany.mockResolvedValue([]);
  mockPrisma.metal.findMany.mockResolvedValue([
    { id: A_METAL_ID, name: "Oro Fino", referenceValue: new D(String(A_REF_VALUE)) },
  ]);
  mockPrisma.salesChannel.findFirst.mockResolvedValue(null);
  mockPrisma.coupon.findFirst.mockResolvedValue(null);
  mockPrisma.commercialEntity.findFirst.mockResolvedValue(null);
  mockPrisma.promotion.findMany.mockResolvedValue([]);
  mockPrisma.currency.findUnique.mockResolvedValue(null);
  mockPrisma.jewelry.findUnique.mockResolvedValue({ id: "j1", name: "J", numberFormat: null, defaultBalanceMode: null });
  mockPrisma.sale.findFirst.mockResolvedValue(null);

  // priceList: las dos listas. La Unificada toma su config de las globals.
  const plUnif = () => ({
    id: "pl-unif", name: "Lista Unificada",
    mode: UNIF_MODE, roundingTarget: UNIF_ROUNDING_TARGET,
    roundingMode: "NONE", roundingDirection: "NEAREST",
    roundingModeHechura: UNIF_ROUNDING_MODE_HECHURA, roundingDirectionHechura: "NEAREST",
    commercialRoundingMetalDomain: "MONETARY",
    commercialRoundingScope: UNIF_SCOPE,
    balanceMode: UNIF_MODE === "METAL_HECHURA" ? "BREAKDOWN" : "UNIFIED",
  });
  const plDesg = () => ({
    id: "pl-desg", name: "Lista Desglosada",
    mode: "METAL_HECHURA", roundingTarget: "METAL",
    roundingMode: "NONE", roundingDirection: "NEAREST",
    roundingModeHechura: "HUNDRED", roundingDirectionHechura: "NEAREST",
    commercialRoundingMetalDomain: "MONETARY",
    commercialRoundingScope: "PER_LINE_LEGACY",
    balanceMode: "BREAKDOWN",
  });
  mockPrisma.priceList.findMany.mockImplementation(({ where }: any) => {
    const ids: string[] = where?.id?.in ?? [];
    return Promise.resolve([plUnif(), plDesg()].filter((p) => ids.includes(p.id)));
  });
  mockPrisma.priceList.findFirst.mockImplementation(({ where }: any) => {
    if (where?.id === "pl-unif") return Promise.resolve(plUnif());
    if (where?.id === "pl-desg") return Promise.resolve(plDesg());
    return Promise.resolve(null);
  });

  mockEvaluatePricingPolicy.mockResolvedValue([]);
  mockBuildBatchCostContext.mockResolvedValue({ baseCurrencyId: "cur-1", defaultMermaPercent: null, metalVariantData: new Map(), rateMap: new Map() });
  mockCalculateCostFromLines.mockResolvedValue({ value: new D("400"), mode: "COST_LINES", partial: false, breakdown: null, steps: [] });

  mockComputeLineTaxes.mockImplementation((_jw: any, _ids: any, unitPriceDec: any) => {
    const up = Number(unitPriceDec?.toString?.() ?? unitPriceDec ?? 0);
    return Promise.resolve({ taxBreakdown: [], taxAmount: new D(String(Math.round(up * TAX_RATE * 100) / 100)) });
  });

  mockBuildPricingSnapshot.mockImplementation((res: any) => ({
    unitPrice: res.unitPrice?.toNumber?.() ?? null,
    basePrice: res.basePrice?.toNumber?.() ?? null,
    priceSource: res.priceSource, resolvedAt: "2026-06-04T00:00:00.000Z",
    appliedPriceListId: res.appliedPriceListId, appliedPriceListName: res.appliedPriceListName,
    appliedPriceListMode: res.appliedPriceListMode,
  }));

  // Modela el motor:
  //  · art-A: si la Unificada es MARGIN_TOTAL → hechura SIEMPRE cruda (el motor
  //    no cambia por contexto → toda diferencia es del wiring). Si es
  //    METAL_HECHURA → honra suppress (pre-tax real).
  //  · art-B (Desglosada): honra suppress (hechura cruda vs HUNDRED pre-tax).
  mockResolveFinalSalePrice.mockImplementation((_jw: any, opts: any) => {
    const suppress = opts?.applyPriceListOptions?.suppressLineHechuraRounding === true;
    if (opts.articleId === "art-A") {
      const hechura = (UNIF_MODE === "METAL_HECHURA" && !suppress)
        ? HUNDRED(A_HECHURA_RAW)
        : A_HECHURA_RAW;
      const unitPrice = +(A_METAL_SALE + hechura).toFixed(2);
      return Promise.resolve(fakePrice({
        unitPrice, basePrice: unitPrice,
        appliedPriceListId: "pl-unif", appliedPriceListName: "Lista Unificada",
        appliedPriceListMode: UNIF_MODE,
        steps: [metalStepA()],
        metalHechuraBreakdown: {
          metalCost: A_METAL_COST, metalSale: A_METAL_SALE, metalMarginPct: 10,
          hechuraCost: A_HECHURA_COST, hechuraSale: hechura, hechuraMarginPct: 0,
          hechuraSalePreRounding: (UNIF_MODE === "METAL_HECHURA" && !suppress) ? A_HECHURA_RAW : null,
          hechuraSaleRoundingDelta: (UNIF_MODE === "METAL_HECHURA" && !suppress) ? HUNDRED(A_HECHURA_RAW) - A_HECHURA_RAW : null,
        },
      }));
    }
    // art-B Desglosada: hechura cruda 60.000 → HUNDRED pre-tax salvo supresión.
    const hechuraB = suppress ? 60_000 : HUNDRED(60_000);
    return Promise.resolve(fakePrice({
      unitPrice: hechuraB, basePrice: hechuraB,
      appliedPriceListId: "pl-desg", appliedPriceListName: "Lista Desglosada",
      appliedPriceListMode: "METAL_HECHURA",
      metalHechuraBreakdown: {
        metalCost: 0, metalSale: 0, metalMarginPct: 0,
        hechuraCost: 60_000, hechuraSale: hechuraB, hechuraMarginPct: 0,
        hechuraSalePreRounding: suppress ? null : 60_000,
        hechuraSaleRoundingDelta: suppress ? null : (HUNDRED(60_000) - 60_000),
      },
    }));
  });
});

// ── Extracción de los campos auditados de la Línea 1 (Artículo A) ────────────
function snapshotLineA(res: any) {
  const l = res.lines[0];
  const mhb = l.metalHechuraBreakdown ?? {};
  const crm = (l.lineCommercialRoundingMetals ?? []) as any[];
  return {
    appliedPriceListId:    l.appliedPriceListId ?? null,
    appliedPriceListMode:  l.appliedPriceListMode ?? l.pricingMeta?.appliedPriceListMode ?? null,
    "precio de lista (unitPrice)": l.unitPrice ?? null,
    "metalSale":           mhb.metalSale ?? null,
    "gramos (postGrams Σ)": +crm.reduce((s, m) => s + (m.postGrams ?? 0), 0).toFixed(4),
    "valor comercial metal (metalSale+impacto)":
      (mhb.metalSale ?? 0) + (l.metalRoundingMonetaryImpact ?? 0),
    "monetario/hechura (saldo POST)":  l.lineMonetarySaldoPostCommercialRounding ?? null,
    "impuestos (lineTaxAmount)":       l.lineTaxAmount ?? null,
    "redondeo (hechuraImpact)":        l.hechuraRoundingMonetaryImpact ?? null,
    "redondeo (metalImpact)":          l.metalRoundingMonetaryImpact ?? null,
    "total línea (lineTotalWithTax)":  l.lineTotalWithTax ?? null,
    "total línea POST (lineTotalWithTaxPostCommercialRounding)": l.lineTotalWithTaxPostCommercialRounding ?? null,
    "lineCommercialSummary.mode":      l.lineCommercialSummary?.mode ?? null,
    "lineCommercialSummary.monetary.amount": l.lineCommercialSummary?.monetary?.amount ?? null,
    "lineCommercialSummary.totalLineAmount": l.lineCommercialSummary?.totalLineAmount ?? null,
    "lineCommercialSummary.source.documentContext": l.lineCommercialSummary?.source?.documentContext ?? null,
    "pricingSnapshot.unitPrice":       l.pricingSnapshot?.unitPrice ?? l.pricingMeta?.unitPrice ?? null,
    "commercialRoundingContext":       l.commercialRoundingContext ? "<objeto>" : null,
    commercialRoundingScope:           UNIF_SCOPE,
  };
}

function reportFirstDiff(label: string, homog: any, mixed: any) {
  const keys = Object.keys(homog);
  // eslint-disable-next-line no-console
  console.log(`\n================ ${label} ================`);
  // eslint-disable-next-line no-console
  console.log(`Lista Unificada: mode=${UNIF_MODE} target=${UNIF_ROUNDING_TARGET} hechura=${UNIF_ROUNDING_MODE_HECHURA} scope=${UNIF_SCOPE}\n`);
  let firstDiff: string | null = null;
  for (const k of keys) {
    const a = JSON.stringify(homog[k]);
    const b = JSON.stringify(mixed[k]);
    const same = a === b;
    if (!same && !firstDiff) firstDiff = k;
    const flag = same ? "   " : (firstDiff === k ? "▶▶▶" : " ✗ ");
    // eslint-disable-next-line no-console
    console.log(`${flag} ${k.padEnd(58)} | SOLO=${String(a).padEnd(16)} | MIXTO=${b}`);
  }
  // eslint-disable-next-line no-console
  console.log(`\n>>> PRIMER campo que cambia: ${firstDiff ?? "NINGUNO (línea idéntica)"}\n`);
  return firstDiff;
}

async function runScenario(label: string) {
  const homog: any = await previewSale("j1", {
    clientId: null,
    lines: [{ articleId: "art-A", quantity: 1, priceListIdOverride: "pl-unif" }],
  } as any);
  const mixed: any = await previewSale("j1", {
    clientId: null,
    lines: [
      { articleId: "art-A", quantity: 1, priceListIdOverride: "pl-unif" },
      { articleId: "art-B", quantity: 1, priceListIdOverride: "pl-desg" },
    ],
  } as any);
  return reportFirstDiff(label, snapshotLineA(homog), snapshotLineA(mixed));
}

describe("AUDITORÍA — invariancia de la línea Unificada en documento mixto", () => {
  it("V1 — Lista Unificada = MARGIN_TOTAL / FINAL_PRICE / PER_LINE_LEGACY", async () => {
    UNIF_MODE = "MARGIN_TOTAL"; UNIF_ROUNDING_TARGET = "FINAL_PRICE";
    UNIF_ROUNDING_MODE_HECHURA = "NONE"; UNIF_SCOPE = "PER_LINE_LEGACY";
    await runScenario("V1 · Unificada MARGIN_TOTAL · PER_LINE_LEGACY");
    expect(true).toBe(true);
  });

  it("V2 — Lista Unificada = MARGIN_TOTAL / FINAL_PRICE / PER_DOCUMENT", async () => {
    UNIF_MODE = "MARGIN_TOTAL"; UNIF_ROUNDING_TARGET = "FINAL_PRICE";
    UNIF_ROUNDING_MODE_HECHURA = "NONE"; UNIF_SCOPE = "PER_DOCUMENT";
    await runScenario("V2 · Unificada MARGIN_TOTAL · PER_DOCUMENT");
    expect(true).toBe(true);
  });

  it("V3 — Lista 'Unificada' = METAL_HECHURA / METAL / hechura HUNDRED / PER_LINE_LEGACY", async () => {
    UNIF_MODE = "METAL_HECHURA"; UNIF_ROUNDING_TARGET = "METAL";
    UNIF_ROUNDING_MODE_HECHURA = "HUNDRED"; UNIF_SCOPE = "PER_LINE_LEGACY";
    await runScenario("V3 · 'Unificada' METAL_HECHURA · PER_LINE_LEGACY");
    expect(true).toBe(true);
  });
});
