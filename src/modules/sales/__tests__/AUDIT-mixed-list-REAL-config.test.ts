// src/modules/sales/__tests__/AUDIT-mixed-list-REAL-config.test.ts
// =============================================================================
// AUDITORÍA (solo lectura — NO valida un fix, NO cambia comportamiento).
//
// Reproduce la config REAL de la "Lista de Precios Unificada" (de la DB):
//   mode=MARGIN_TOTAL · roundingTarget=FINAL_PRICE · roundingMode=HUNDRED
//   roundingDirection=NEAREST · roundingApplyOn=TOTAL · roundingModeHechura=HUNDRED
//   commercialRoundingScope=PER_LINE_LEGACY · commercialRoundingMetalDomain=MONETARY
//   marginTotal=85
//
// `computeSaleDocumentTotals` + la familia de redondeo quedan REALES. Solo se
// mockea `resolveFinalSalePrice` (frontera), modelando FIELMENTE el redondeo
// diferido `applyOn=TOTAL` tal como lo hace `pricing-engine.sale.ts:2637-2663`:
//   · si `suppressListDeferredRounding=false` → redondea el totalWithTax POR
//     UNIDAD (HUNDRED) y emite `appliedRounding{applyOn:TOTAL}`.
//   · si `suppressListDeferredRounding=true`  → NO redondea la línea; el
//     redondeo FINANCIERO del comprobante (Jewelry) lo hace una sola vez.
//
// Se corren 2 variantes de tenant: SIN y CON redondeo financiero del comprobante.
// =============================================================================

import { describe, it, vi, beforeEach, expect } from "vitest";
import { Prisma } from "@prisma/client";

const D = Prisma.Decimal;

// ── Flags de escenario ───────────────────────────────────────────────────────
let TENANT_FINANCIAL_ROUNDING = false; // activa Jewelry.documentRoundingEnabled

// ── Config REAL de la Unificada ──────────────────────────────────────────────
const TAX_RATE   = 0.21;
const A_UNIT     = 200_294.42;  // unitPrice pre-redondeo → tWt = 242.356,25
const round100   = (n: number) => Math.round(n / 100) * 100;
const r2         = (n: number) => Math.round(n * 100) / 100;

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
function metalStepB() {
  return { key: "COST_LINES_METAL", status: "ok", meta: {
    metalId: "metal-oro", variantId: null, gramsOriginal: 3, qty: 3, purity: 0.75,
    quotePrice: 100_000, gramsFineEquivalent: +(3 * 0.75 * 1.1).toFixed(6),
  } };
}

beforeEach(() => {
  vi.clearAllMocks();
  mockPrisma.article.findMany.mockResolvedValue([
    { id: "art-A", name: "Pieza A (Unificada)", categoryId: null, brand: null, manualTaxIds: ["tax-21"], costComposition: [], manualAdjustmentKind: null, manualAdjustmentType: null, manualAdjustmentValue: null },
    { id: "art-B", name: "Pieza B (Desglosada)", categoryId: null, brand: null, manualTaxIds: ["tax-21"], costComposition: [], manualAdjustmentKind: null, manualAdjustmentType: null, manualAdjustmentValue: null },
  ]);
  mockPrisma.articleVariant.findMany.mockResolvedValue([]);
  mockPrisma.articleGroupItem.findMany.mockResolvedValue([]);
  mockPrisma.metal.findMany.mockResolvedValue([{ id: "metal-oro", name: "Oro Fino", referenceValue: new D("110000") }]);
  mockPrisma.salesChannel.findFirst.mockResolvedValue(null);
  mockPrisma.coupon.findFirst.mockResolvedValue(null);
  mockPrisma.commercialEntity.findFirst.mockResolvedValue(null);
  mockPrisma.promotion.findMany.mockResolvedValue([]);
  mockPrisma.currency.findUnique.mockResolvedValue(null);
  mockPrisma.sale.findFirst.mockResolvedValue(null);

  // Jewelry: con/sin redondeo FINANCIERO del comprobante.
  mockPrisma.jewelry.findUnique.mockImplementation(() => Promise.resolve({
    id: "j1", name: "J", numberFormat: null, defaultBalanceMode: null,
    documentRoundingEnabled:          TENANT_FINANCIAL_ROUNDING,
    documentRoundingMode:             TENANT_FINANCIAL_ROUNDING ? "HUNDRED" : "NONE",
    documentRoundingDirection:        "NEAREST",
    documentRoundingScope:            "UNIFIED",
    documentRoundingModeMetal:        "NONE",
    documentRoundingDirectionMetal:   "NEAREST",
    documentRoundingModeHechura:      "NONE",
    documentRoundingDirectionHechura: "NEAREST",
    documentRoundingMetalDomain:      "MONETARY",
  }));

  // Listas REALES.
  const plUnif = {
    id: "pl-unif", name: "Lista de Precios Unificada",
    mode: "MARGIN_TOTAL", roundingTarget: "FINAL_PRICE",
    roundingMode: "HUNDRED", roundingDirection: "NEAREST", roundingApplyOn: "TOTAL",
    roundingModeHechura: "HUNDRED", roundingDirectionHechura: "NEAREST",
    commercialRoundingMetalDomain: "MONETARY", commercialRoundingScope: "PER_LINE_LEGACY",
    balanceMode: null,
  };
  const plDesg = {
    id: "pl-desg", name: "Lista de Precios Desglosadaa",
    mode: "METAL_HECHURA", roundingTarget: "METAL",
    roundingMode: "DECIMAL_1", roundingDirection: "NEAREST", roundingApplyOn: "TOTAL",
    roundingModeHechura: "HUNDRED", roundingDirectionHechura: "NEAREST",
    commercialRoundingMetalDomain: "PHYSICAL", commercialRoundingScope: "PER_DOCUMENT",
    balanceMode: null,
  };
  mockPrisma.priceList.findMany.mockImplementation(({ where }: any) => {
    const ids: string[] = where?.id?.in ?? [];
    return Promise.resolve([plUnif, plDesg].filter((p) => ids.includes(p.id)));
  });
  mockPrisma.priceList.findFirst.mockImplementation(({ where }: any) => {
    if (where?.id === "pl-unif") return Promise.resolve(plUnif);
    if (where?.id === "pl-desg") return Promise.resolve(plDesg);
    return Promise.resolve(null);
  });

  mockEvaluatePricingPolicy.mockResolvedValue([]);
  mockBuildBatchCostContext.mockResolvedValue({ baseCurrencyId: "cur-1", defaultMermaPercent: null, metalVariantData: new Map(), rateMap: new Map() });
  mockCalculateCostFromLines.mockResolvedValue({ value: new D("400"), mode: "COST_LINES", partial: false, breakdown: null, steps: [] });
  mockComputeLineTaxes.mockImplementation((_jw: any, _ids: any, unitPriceDec: any) => {
    const up = Number(unitPriceDec?.toString?.() ?? unitPriceDec ?? 0);
    return Promise.resolve({ taxBreakdown: [], taxAmount: new D(String(r2(up * TAX_RATE))) });
  });
  mockBuildPricingSnapshot.mockImplementation((res: any) => ({
    unitPrice: res.unitPrice?.toNumber?.() ?? null, basePrice: res.basePrice?.toNumber?.() ?? null,
    priceSource: res.priceSource, resolvedAt: "2026-06-04T00:00:00.000Z",
    appliedPriceListId: res.appliedPriceListId, appliedPriceListName: res.appliedPriceListName,
    appliedPriceListMode: res.appliedPriceListMode,
  }));

  // Motor fiel:
  mockResolveFinalSalePrice.mockImplementation((_jw: any, opts: any) => {
    const suppressDeferred = opts?.suppressListDeferredRounding === true;
    if (opts.articleId === "art-A") {
      // Unificada MARGIN_TOTAL: redondeo diferido HUNDRED sobre el totalWithTax/unidad.
      const unitTax = r2(A_UNIT * TAX_RATE);
      const tWtPre  = r2(A_UNIT + unitTax);          // 242.356,25
      const tWtPost = round100(tWtPre);              // 242.400
      const applied = (!suppressDeferred && tWtPost !== tWtPre)
        ? { applyOn: "TOTAL", mode: "HUNDRED", direction: "NEAREST",
            preRounding: new D(String(tWtPre)), postRounding: new D(String(tWtPost)),
            unitAdjustment: r2(tWtPost - tWtPre), priceListId: "pl-unif", priceListName: "Lista de Precios Unificada",
            source: "PRICE_LIST" }
        : null;
      return Promise.resolve(fakePrice({
        unitPrice: A_UNIT, basePrice: A_UNIT,
        appliedPriceListId: "pl-unif", appliedPriceListName: "Lista de Precios Unificada",
        appliedPriceListMode: "MARGIN_TOTAL",
        metalHechuraBreakdown: null, steps: [], appliedRounding: applied,
      }));
    }
    // Desglosada METAL_HECHURA: hechura HUNDRED pre-tax salvo supresión comercial.
    const suppressHechura = opts?.applyPriceListOptions?.suppressLineHechuraRounding === true;
    const hechura = suppressHechura ? 60_000 : round100(60_000);
    const unitPrice = +(330_000 + hechura).toFixed(2);
    return Promise.resolve(fakePrice({
      unitPrice, basePrice: unitPrice,
      appliedPriceListId: "pl-desg", appliedPriceListName: "Lista de Precios Desglosadaa",
      appliedPriceListMode: "METAL_HECHURA", steps: [metalStepB()],
      metalHechuraBreakdown: { metalCost: 300_000, metalSale: 330_000, metalMarginPct: 10,
        hechuraCost: 40_000, hechuraSale: hechura, hechuraMarginPct: 50,
        hechuraSalePreRounding: suppressHechura ? null : 60_000,
        hechuraSaleRoundingDelta: suppressHechura ? null : 0 },
    }));
  });
});

function snapLineA(res: any) {
  const l = res.lines[0];
  const ar = l.appliedRounding ?? l.pricingMeta?.appliedRounding ?? null;
  return {
    appliedPriceListId:   l.appliedPriceListId ?? null,
    appliedPriceListMode: l.appliedPriceListMode ?? l.pricingMeta?.appliedPriceListMode ?? null,
    "precio lista (unitPrice)":      l.unitPrice ?? null,
    "redondeo applyOn":              ar?.applyOn ?? null,
    "precio ANTES redondeo (pre)":   ar?.preRounding != null ? Number(ar.preRounding.toString?.() ?? ar.preRounding) : null,
    "precio DESPUES redondeo (post)":ar?.postRounding != null ? Number(ar.postRounding.toString?.() ?? ar.postRounding) : null,
    "impuestos (lineTaxAmount)":     l.lineTaxAmount ?? null,
    "total línea (lineTotalWithTax)":l.lineTotalWithTax ?? null,
    "total línea POST":              l.lineTotalWithTaxPostCommercialRounding ?? null,
    "summary.mode":                  l.lineCommercialSummary?.mode ?? null,
    "MONETARIO (summary.monetary.amount)": l.lineCommercialSummary?.monetary?.amount ?? null,
    "summary.totalLineAmount":       l.lineCommercialSummary?.totalLineAmount ?? null,
    "summary.documentContext":       l.lineCommercialSummary?.source?.documentContext ?? null,
    "commercialRoundingContext":     l.commercialRoundingContext ? "<objeto>" : null,
  };
}
function snapDoc(res: any) {
  return {
    "documentTotals.total":         res.documentTotals?.total ?? res.total ?? null,
    "documentTotals.roundingAdjustment": res.documentTotals?.roundingAdjustment ?? null,
    "documentTotals.roundingInfo.source": res.documentTotals?.roundingInfo?.source ?? null,
    "documentTotals.roundingInfo.mode":   res.documentTotals?.roundingInfo?.mode ?? null,
  };
}

function report(label: string, hA: any, mA: any, hD: any, mD: any) {
  // eslint-disable-next-line no-console
  console.log(`\n================ ${label} ================`);
  let first: string | null = null;
  const row = (obj: string, k: string, a: any, b: any) => {
    const ja = JSON.stringify(a), jb = JSON.stringify(b);
    const same = ja === jb;
    if (!same && !first && obj === "LÍNEA A") first = k;
    const flag = same ? "   " : (first === k ? "▶▶▶" : " ✗ ");
    // eslint-disable-next-line no-console
    console.log(`${flag} [${obj}] ${k.padEnd(38)} | SOLO=${String(ja).padEnd(14)} | MIXTO=${jb}`);
  };
  for (const k of Object.keys(hA)) row("LÍNEA A", k, hA[k], mA[k]);
  for (const k of Object.keys(hD)) row("DOC",     k, hD[k], mD[k]);
  // eslint-disable-next-line no-console
  console.log(`\n>>> PRIMER campo de la LÍNEA A que cambia: ${first ?? "NINGUNO (pieza invariante)"}\n`);
}

async function run(label: string) {
  const homog: any = await previewSale("j1", { clientId: null, lines: [{ articleId: "art-A", quantity: 1, priceListIdOverride: "pl-unif" }] } as any);
  const mixed: any = await previewSale("j1", { clientId: null, lines: [
    { articleId: "art-A", quantity: 1, priceListIdOverride: "pl-unif" },
    { articleId: "art-B", quantity: 1, priceListIdOverride: "pl-desg" },
  ] } as any);
  report(label, snapLineA(homog), snapLineA(mixed), snapDoc(homog), snapDoc(mixed));
}

describe("AUDITORÍA — config REAL Unificada en documento mixto", () => {
  it("A) tenant SIN redondeo financiero (redondeo HUNDRED de la lista → POR LÍNEA)", async () => {
    TENANT_FINANCIAL_ROUNDING = false;
    await run("A · SIN redondeo financiero · redondeo lista por línea");
    expect(true).toBe(true);
  });
  it("B) tenant CON redondeo financiero (lista diferida suprimida → redondeo POR COMPROBANTE)", async () => {
    TENANT_FINANCIAL_ROUNDING = true;
    await run("B · CON redondeo financiero · redondeo por comprobante");
    expect(true).toBe(true);
  });
});
