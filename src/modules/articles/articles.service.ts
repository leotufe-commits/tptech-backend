import { Prisma, BarcodeSource } from "@prisma/client";
import { prisma } from "../../lib/prisma.js";
import { resolvePriceList, applyPriceList, type CostBreakdown } from "../../lib/pricing.utils.js";
// computeCostPrice: importado para uso interno y re-exportado para compatibilidad
import { computeCostPrice } from "../../lib/article-cost.utils.js";
export { computeCostPrice };

function s(v: any): string { return String(v ?? "").trim(); }
function assert(cond: any, msg: string, status = 400): void {
  if (!cond) { const e: any = new Error(msg); e.status = status; throw e; }
}

// ===========================================================================
// Constantes de validación
// ===========================================================================
const VALID_ARTICLE_TYPES  = new Set(["PRODUCT", "SERVICE", "MATERIAL"]);
const VALID_STATUS         = new Set(["DRAFT", "ACTIVE", "DISCONTINUED", "ARCHIVED"]);
const VALID_STOCK_MODE     = new Set(["NO_STOCK", "BY_ARTICLE", "BY_MATERIAL"]);
const VALID_HECHURA_MODE   = new Set(["FIXED", "PER_GRAM"]);
const VALID_BARCODE_TYPES   = new Set(["CODE128", "EAN13", "QR"]);
const VALID_BARCODE_SOURCES = new Set(["CODE", "SKU", "CUSTOM"]);
const VALID_COST_MODES     = new Set(["MANUAL", "METAL_MERMA_HECHURA", "MULTIPLIER"]);

// ===========================================================================
// Reglas de negocio: articleType ↔ stockMode
//
// SERVICE  → solo NO_STOCK
// MATERIAL → NO_STOCK o BY_ARTICLE (sin composición metálica propia)
// PRODUCT  → cualquier stockMode
// ===========================================================================
function validateTypeStockMode(articleType: string, stockMode: string): void {
  if (articleType === "SERVICE") {
    assert(stockMode === "NO_STOCK",
      "Los servicios no pueden tener stock. stockMode debe ser NO_STOCK.");
  }
  if (articleType === "MATERIAL") {
    assert(stockMode !== "BY_MATERIAL",
      "Los materiales no pueden usar BY_MATERIAL. Usá NO_STOCK o BY_ARTICLE.");
  }
}

// ===========================================================================
// Validación: costCalculationMode + campos requeridos según modo
// ===========================================================================
function validateCostMode(data: {
  costCalculationMode?: string;
  costPrice?: any;
  multiplierBase?: string;
  multiplierValue?: any;
  multiplierQuantity?: any;
}): void {
  const mode = data.costCalculationMode;
  if (!mode) return; // sin modo en el payload → sin validación (update parcial)

  if (mode === "MANUAL") {
    // costPrice puede ser null (sin costo definido) — no obligatorio
    return;
  }

  if (mode === "METAL_MERMA_HECHURA") {
    // La composición metálica se gestiona por separado (POST /compositions).
    // No validamos aquí si existen composiciones porque pueden agregarse después.
    return;
  }

  if (mode === "MULTIPLIER") {
    assert(
      (data.multiplierBase ?? "").trim() !== "",
      "Para modo MULTIPLIER, la base del multiplicador es obligatoria."
    );
    assert(
      data.multiplierValue != null && Number(data.multiplierValue) > 0,
      "Para modo MULTIPLIER, multiplierValue es obligatorio y debe ser mayor que cero."
    );
    // multiplierQuantity puede ser null (calculada al momento del uso)
    return;
  }
}

// ===========================================================================
// Cálculo de costo computado (runtime, no persistido)
// Implementación en src/lib/article-cost.utils.ts — re-exportado arriba.
// ===========================================================================

// ===========================================================================
// Barcode helpers
// ===========================================================================

/** Valida dígito verificador de EAN13. Retorna true si es válido. */
function isValidEAN13(barcode: string): boolean {
  if (!/^\d{13}$/.test(barcode)) return false;
  const digits = barcode.split("").map(Number);
  const sum = digits
    .slice(0, 12)
    .reduce((acc, d, i) => acc + d * (i % 2 === 0 ? 1 : 3), 0);
  const check = (10 - (sum % 10)) % 10;
  return check === digits[12];
}

/** Genera un barcode CODE128 interno. Formato: prefijo "ART" + secuencia 8 dígitos. */
async function generateInternalBarcode(jewelryId: string): Promise<string> {
  // Cuenta artículos + variantes para la secuencia global
  const [artCount, varCount] = await Promise.all([
    prisma.article.count({ where: { jewelryId } }),
    prisma.articleVariant.count({ where: { jewelryId } }),
  ]);
  let seq = artCount + varCount + 1;
  while (true) {
    const candidate = `ART${String(seq).padStart(8, "0")}`;
    const existsArt = await prisma.article.findFirst({
      where: { jewelryId, barcode: candidate }, select: { id: true },
    });
    const existsVar = !existsArt && await prisma.articleVariant.findFirst({
      where: { jewelryId, barcode: candidate }, select: { id: true },
    });
    if (!existsArt && !existsVar) return candidate;
    seq++;
  }
}

/** Valida barcode según su tipo y lo normaliza. */
function validateBarcode(barcode: string, barcodeType: string): void {
  if (!barcode) return;
  if (barcodeType === "EAN13") {
    assert(isValidEAN13(barcode),
      `El barcode "${barcode}" no es un EAN13 válido. Debe tener 13 dígitos con dígito verificador correcto.`);
  }
  if (barcodeType === "CODE128") {
    assert(/^[\x20-\x7E]+$/.test(barcode),
      "El barcode CODE128 solo puede contener caracteres ASCII imprimibles.");
    assert(barcode.length >= 1 && barcode.length <= 80,
      "El barcode CODE128 debe tener entre 1 y 80 caracteres.");
  }
}

/** Verifica unicidad de SKU en el tenant (cruza Article y ArticleVariant). Si el SKU está vacío, no hace nada. */
async function assertSkuUnique(
  jewelryId: string,
  sku: string,
  excludeArticleId?: string,
  excludeVariantId?: string
): Promise<void> {
  if (!sku) return;

  const inArt = await prisma.article.findFirst({
    where: {
      jewelryId,
      sku,
      deletedAt: null,
      ...(excludeArticleId ? { id: { not: excludeArticleId } } : {}),
    },
    select: { id: true, code: true, name: true },
  });
  assert(!inArt, `El SKU "${sku}" ya está en uso por el artículo ${inArt?.code} — ${inArt?.name}.`);

  const inVar = await prisma.articleVariant.findFirst({
    where: {
      jewelryId,
      sku,
      deletedAt: null,
      ...(excludeVariantId ? { id: { not: excludeVariantId } } : {}),
    },
    select: { id: true, code: true },
  });
  assert(!inVar, `El SKU "${sku}" ya está en uso por la variante ${inVar?.code}.`);
}

/** Verifica unicidad de barcode en el tenant (cruza Article y ArticleVariant). */
async function assertBarcodeUnique(
  jewelryId: string,
  barcode: string,
  excludeArticleId?: string,
  excludeVariantId?: string
): Promise<void> {
  const inArt = await prisma.article.findFirst({
    where: {
      jewelryId,
      barcode,
      deletedAt: null,
      ...(excludeArticleId ? { id: { not: excludeArticleId } } : {}),
    },
    select: { id: true, code: true, name: true },
  });
  assert(!inArt, `El barcode "${barcode}" ya está en uso por el artículo ${inArt?.code} — ${inArt?.name}.`);

  const inVar = await prisma.articleVariant.findFirst({
    where: {
      jewelryId,
      barcode,
      deletedAt: null,
      ...(excludeVariantId ? { id: { not: excludeVariantId } } : {}),
    },
    select: { id: true, code: true },
  });
  assert(!inVar, `El barcode "${barcode}" ya está en uso por la variante ${inVar?.code}.`);
}

// ===========================================================================
// resolveBarcode — aplica lógica de barcodeSource
// ===========================================================================
/**
 * Resuelve el valor final de barcode según la fuente indicada:
 * - CODE   → barcode = code  (se sincroniza con el código del artículo/variante)
 * - SKU    → barcode = sku   (se sincroniza con el SKU)
 * - CUSTOM → barcode = valor provisto por el usuario (comportamiento original)
 *
 * Si el barcode resultante no está vacío, valida formato y unicidad.
 */
async function resolveBarcode(opts: {
  jewelryId: string;
  source: string;           // "CODE" | "SKU" | "CUSTOM"
  code?: string;            // código resuelto del registro
  sku?: string;             // sku resuelto del registro
  customBarcode?: string | null;  // barcode manual (solo para CUSTOM)
  autoBarcode?: boolean;    // generar barcode automático (solo CUSTOM)
  barcodeType?: string;
  excludeArticleId?: string;
  excludeVariantId?: string;
}): Promise<{ barcode: string | null; barcodeSource: BarcodeSource }> {
  const barcodeSource = (VALID_BARCODE_SOURCES.has(opts.source) ? opts.source : "CUSTOM") as BarcodeSource;
  const barcodeType   = VALID_BARCODE_TYPES.has(opts.barcodeType ?? "") ? opts.barcodeType! : "CODE128";
  let barcode: string | null = null;

  if (barcodeSource === "CODE") {
    barcode = s(opts.code) || null;
  } else if (barcodeSource === "SKU") {
    barcode = s(opts.sku) || null;
  } else {
    // CUSTOM
    if (opts.autoBarcode === true) {
      barcode = await generateInternalBarcode(opts.jewelryId);
    } else if (opts.customBarcode != null && opts.customBarcode !== "") {
      barcode = s(opts.customBarcode);
    }
    // si customBarcode es null o "" → barcode = null (limpiar)
  }

  if (barcode) {
    validateBarcode(barcode, barcodeType);
    await assertBarcodeUnique(opts.jewelryId, barcode, opts.excludeArticleId, opts.excludeVariantId);
  }

  return { barcode, barcodeSource };
}

// ===========================================================================
// Code generation — ART-NNNN, unique per tenant
// ===========================================================================
async function generateArticleCode(jewelryId: string): Promise<string> {
  const count = await prisma.article.count({ where: { jewelryId } });
  let n = count + 1;
  while (true) {
    const candidate = `ART-${String(n).padStart(4, "0")}`;
    const exists = await prisma.article.findFirst({
      where: { jewelryId, code: candidate }, select: { id: true },
    });
    if (!exists) return candidate;
    n++;
  }
}

// ===========================================================================
// Selects
// ===========================================================================
const ARTICLE_LIST_SELECT = {
  id: true,
  code: true,
  name: true,
  description: true,
  categoryId: true,
  articleType: true,
  status: true,
  stockMode: true,
  sku: true,
  barcode: true,
  barcodeType: true,
  barcodeSource: true,
  brand: true,
  manufacturer: true,
  costPrice: true,
  salePrice: true,
  hechuraPrice: true,
  hechuraPriceMode: true,
  mermaPercent: true,
  costCalculationMode: true,
  multiplierBase: true,
  multiplierValue: true,
  multiplierQuantity: true,
  multiplierCurrencyId: true,
  manualBaseCost: true,
  manualCurrencyId: true,
  manualAdjustmentKind: true,
  manualAdjustmentType: true,
  manualAdjustmentValue: true,
  manualTaxIds: true,
  sellWithoutVariants: true,
  showInStore: true,
  unitOfMeasure: true,
  reorderPoint: true,
  mainImageUrl: true,
  isFavorite: true,
  isActive: true,
  useManualSalePrice: true,
  createdAt: true,
  updatedAt: true,
  category:          { select: { id: true, name: true, mermaPercent: true } },
  preferredSupplier: { select: { id: true, code: true, displayName: true } },
  costComposition: {
    select: {
      type:           true,
      label:          true,
      quantity:       true,
      unitValue:      true,
      currencyId:     true,
      mermaPercent:   true,
      metalVariantId: true,
      sortOrder:      true,
      currency: {
        select: { id: true, code: true, symbol: true },
      },
      metalVariant: {
        select: {
          id: true, name: true, sku: true, purity: true,
          metal: { select: { id: true, name: true } },
        },
      },
    },
    orderBy: { sortOrder: "asc" as const },
  },
  compositions: {
    select: { variantId: true, grams: true, isBase: true },
  },
  variants: {
    where: { deletedAt: null },
    select: {
      id: true,
      code: true,
      name: true,
      sku: true,
      barcode: true,
      barcodeType: true,
      barcodeSource: true,
      imageUrl: true,
      isActive: true,
      sortOrder: true,
      priceOverride: true,
      costPrice: true,
      reorderPoint: true,
    },
    orderBy: { sortOrder: "asc" as const },
  },
} as const;

const ARTICLE_DETAIL_SELECT = {
  id: true,
  jewelryId: true,
  code: true,
  name: true,
  description: true,
  categoryId: true,
  articleType: true,
  status: true,
  stockMode: true,
  sku: true,
  barcode: true,
  barcodeType: true,
  barcodeSource: true,
  brand: true,
  manufacturer: true,
  supplierCode: true,
  preferredSupplierId: true,
  costPrice: true,
  salePrice: true,
  useManualSalePrice: true,
  hechuraPrice: true,
  hechuraPriceMode: true,
  mermaPercent: true,
  costCalculationMode: true,
  multiplierBase: true,
  multiplierValue: true,
  multiplierQuantity: true,
  multiplierCurrencyId: true,
  manualBaseCost: true,
  manualCurrencyId: true,
  manualAdjustmentKind: true,
  manualAdjustmentType: true,
  manualAdjustmentValue: true,
  manualTaxIds: true,
  sellWithoutVariants: true,
  isReturnable: true,
  showInStore: true,
  unitOfMeasure: true,
  reorderPoint: true,
  mainImageUrl: true,
  isFavorite: true,
  isActive: true,
  notes: true,
  createdAt: true,
  updatedAt: true,
  category:          { select: { id: true, name: true, mermaPercent: true } },
  preferredSupplier: { select: { id: true, code: true, displayName: true } },
  compositions: {
    select: {
      id: true,
      variantId: true,
      grams: true,
      isBase: true,
      sortOrder: true,
      metalVariant: {
        select: {
          id: true, name: true, sku: true, purity: true,
          metal: { select: { id: true, name: true } },
        },
      },
    },
    orderBy: [{ sortOrder: "asc" as const }, { createdAt: "asc" as const }],
  },
  variants: {
    where: { deletedAt: null },
    select: {
      id: true,
      code: true,
      name: true,
      sku: true,
      barcode: true,
      barcodeType: true,
      barcodeSource: true,
      weightOverride: true,
      hechuraPriceOverride: true,
      priceOverride: true,
      costPrice: true,
      imageUrl: true,
      notes: true,
      isActive: true,
      sortOrder: true,
      attributeValues: {
        select: {
          id: true,
          assignmentId: true,
          value: true,
          assignment: {
            select: {
              id: true,
              isRequired: true,
              sortOrder: true,
              isVariantAxis: true,
              definition: {
                select: {
                  id: true, name: true, code: true, inputType: true,
                  options: { select: { id: true, label: true, value: true } },
                },
              },
            },
          },
        },
      },
    },
    orderBy: [{ sortOrder: "asc" as const }, { createdAt: "asc" as const }],
  },
  attributeValues: {
    select: {
      id: true,
      assignmentId: true,
      value: true,
      assignment: {
        select: {
          id: true,
          isRequired: true,
          sortOrder: true,
          definition: {
            select: {
              id: true, name: true, code: true, inputType: true,
              options: { select: { id: true, label: true, value: true } },
            },
          },
        },
      },
    },
  },
  images: {
    select: { id: true, url: true, label: true, isMain: true, sortOrder: true },
    orderBy: [{ sortOrder: "asc" as const }, { createdAt: "asc" as const }],
  },
  costComposition: {
    select: {
      id: true,
      type: true,
      label: true,
      quantity: true,
      unitValue: true,
      currencyId: true,
      metalVariantId: true,
      mermaPercent: true,
      catalogItemId: true,
      sortOrder: true,
      currency: { select: { id: true, code: true, symbol: true } },
      metalVariant: {
        select: {
          id: true, name: true, sku: true, purity: true,
          metal: { select: { id: true, name: true } },
        },
      },
      catalogItem: { select: { id: true, name: true, salePrice: true } },
    },
    orderBy: [{ sortOrder: "asc" as const }, { createdAt: "asc" as const }],
  },
} as const;

const VARIANT_IMAGE_SELECT = { id: true, url: true, label: true, isMain: true, sortOrder: true } as const;

const VARIANT_SELECT = {
  id: true,
  code: true,
  name: true,
  sku: true,
  barcode: true,
  barcodeType: true,
  barcodeSource: true,
  weightOverride: true,
  hechuraPriceOverride: true,
  priceOverride: true,
  costPrice: true,
  reorderPoint: true,
  imageUrl: true,
  notes: true,
  isActive: true,
  sortOrder: true,
  createdAt: true,
  images: {
    select: VARIANT_IMAGE_SELECT,
    orderBy: [{ sortOrder: "asc" }, { createdAt: "asc" }] as { sortOrder?: "asc" | "desc"; createdAt?: "asc" | "desc" }[],
  },
  attributeValues: {
    select: {
      id: true,
      assignmentId: true,
      value: true,
      assignment: {
        select: {
          id: true,
          isRequired: true,
          sortOrder: true,
          isVariantAxis: true,
          definition: {
            select: {
              id: true,
              name: true,
              code: true,
              inputType: true,
              options: { select: { id: true, label: true, value: true } },
            },
          },
        },
      },
    },
  },
} as const;

// ===========================================================================
// Helpers
// ===========================================================================
async function assertArticleOwnership(articleId: string, jewelryId: string) {
  const a = await prisma.article.findFirst({
    where: { id: articleId, jewelryId, deletedAt: null },
    select: { id: true },
  });
  assert(a, "Artículo no encontrado.", 404);
}

/** Verifica que el proveedor preferido exista y sea proveedor dentro del tenant. */
async function validatePreferredSupplier(jewelryId: string, preferredSupplierId: string): Promise<void> {
  const supplier = await prisma.commercialEntity.findFirst({
    where: { id: preferredSupplierId, jewelryId, isSupplier: true, deletedAt: null },
    select: { id: true },
  });
  assert(supplier, "Proveedor preferido no encontrado o no es un proveedor activo.");
}

// ===========================================================================
// Stock summary helper — para detalle de artículo con BY_ARTICLE
// ===========================================================================
async function getStockSummary(articleId: string, jewelryId: string) {
  const rows = await prisma.articleStock.findMany({
    where: { articleId, jewelryId },
    select: {
      id: true,
      variantId: true,
      warehouseId: true,
      quantity: true,
      reservedQty: true,
      warehouse: { select: { id: true, name: true, code: true } },
      variant: { select: { id: true, code: true, name: true } },
    },
    orderBy: { warehouse: { name: "asc" as const } },
  });

  const total = rows.reduce((sum, r) => sum.add(r.quantity), new Prisma.Decimal(0));
  return { total, byWarehouse: rows };
}

// ===========================================================================
// Batch cost computation for list
// ===========================================================================

/**
 * Aplica bonus/recargo sobre una base. Idéntico a applyAdjustment() en article-cost.utils.ts.
 * Duplicado local para evitar coupling con el módulo lib; mantener en sincronía si cambia la lógica.
 */
function applyAdj(
  base:     Prisma.Decimal,
  kind?:    string | null,
  adjType?: string | null,
  adjRaw?:  any,
): Prisma.Decimal {
  if (!kind || kind === "" || adjRaw == null) return base;
  const absVal    = new Prisma.Decimal(Math.abs(Number(adjRaw)).toString());
  const adjAmount = adjType === "PERCENTAGE" ? base.mul(absVal.div(100)) : absVal;
  return kind === "SURCHARGE" ? base.add(adjAmount) : base.sub(adjAmount);
}

function computeArticleCostBase(
  row: any,
  baseCurrencyId: string,
  rateMap: Map<string, Prisma.Decimal>,
  metalQuoteMap: Map<string, Prisma.Decimal>,
  defaultMermaPercent: any,
): Prisma.Decimal | null {
  const lines: any[] = row.costComposition ?? [];

  // COST_LINES takes priority — aplica ajuste sobre la suma total de líneas
  if (lines.length > 0) {
    let total = new Prisma.Decimal(0);
    for (const line of lines) {
      const qty = new Prisma.Decimal(line.quantity?.toString() ?? "0");
      if (line.type === "METAL") {
        if (!line.metalVariantId) return null;
        const quote = metalQuoteMap.get(line.metalVariantId);
        if (!quote) return null;
        const mermaFactor = new Prisma.Decimal(1).add(
          new Prisma.Decimal(line.mermaPercent?.toString() ?? "0").div(100)
        );
        total = total.add(qty.mul(mermaFactor).mul(quote));
      } else {
        const unitVal = new Prisma.Decimal(line.unitValue?.toString() ?? "0");
        let lineValue = qty.mul(unitVal);
        if (line.currencyId && line.currencyId !== baseCurrencyId) {
          const rate = rateMap.get(line.currencyId);
          if (!rate) return null;
          lineValue = lineValue.mul(rate);
        }
        total = total.add(lineValue);
      }
    }
    return applyAdj(total, row.manualAdjustmentKind, row.manualAdjustmentType, row.manualAdjustmentValue);
  }

  const mode: string = row.costCalculationMode ?? "MANUAL";

  if (mode === "MANUAL") {
    // costPrice se persiste ya ajustado (draftToPayload envía computeManualFinalCost).
    // No aplicar applyAdj para evitar doble ajuste.
    if (row.costPrice == null) return null;
    let val = new Prisma.Decimal(row.costPrice.toString());
    if (row.manualCurrencyId && row.manualCurrencyId !== baseCurrencyId) {
      const rate = rateMap.get(row.manualCurrencyId);
      if (!rate) return null;
      val = val.mul(rate);
    }
    return val;
  }

  if (mode === "MULTIPLIER") {
    if (row.multiplierValue == null || row.multiplierQuantity == null) return null;
    let val = new Prisma.Decimal(row.multiplierQuantity.toString())
      .mul(new Prisma.Decimal(row.multiplierValue.toString()));
    if (row.multiplierCurrencyId && row.multiplierCurrencyId !== baseCurrencyId) {
      const rate = rateMap.get(row.multiplierCurrencyId);
      if (!rate) return null;
      val = val.mul(rate);
    }
    return applyAdj(val, row.manualAdjustmentKind, row.manualAdjustmentType, row.manualAdjustmentValue);
  }

  if (mode === "METAL_MERMA_HECHURA") {
    const comps: any[] = row.compositions ?? [];
    if (comps.length === 0) return null;
    const rawMerma = row.mermaPercent ?? row.category?.mermaPercent ?? defaultMermaPercent ?? 0;
    const mermaFactor = new Prisma.Decimal(1).add(
      new Prisma.Decimal(rawMerma.toString()).div(100)
    );
    let metalCost = new Prisma.Decimal(0);
    let totalGrams = new Prisma.Decimal(0);
    for (const comp of comps) {
      const quote = metalQuoteMap.get(comp.variantId);
      if (!quote) return null;
      const grams = new Prisma.Decimal(comp.grams.toString());
      metalCost = metalCost.add(grams.mul(mermaFactor).mul(quote));
      totalGrams = totalGrams.add(grams);
    }
    let hechura = new Prisma.Decimal(0);
    if (row.hechuraPrice != null) {
      const hp = new Prisma.Decimal(row.hechuraPrice.toString());
      hechura = row.hechuraPriceMode === "PER_GRAM" ? hp.mul(totalGrams) : hp;
    }
    return applyAdj(
      metalCost.add(hechura),
      row.manualAdjustmentKind,
      row.manualAdjustmentType,
      row.manualAdjustmentValue,
    );
  }

  return null;
}

function applyTaxes(
  costBase: Prisma.Decimal,
  taxIds: string[],
  taxMap: Map<string, { rate: Prisma.Decimal; fixedAmount: Prisma.Decimal; calculationType: string }>,
): Prisma.Decimal {
  let total = costBase;
  for (const tid of taxIds) {
    const tax = taxMap.get(tid);
    if (!tax) continue;
    if (tax.calculationType === "PERCENTAGE") {
      total = total.add(costBase.mul(tax.rate.div(100)));
    } else if (tax.calculationType === "FIXED_AMOUNT") {
      total = total.add(tax.fixedAmount);
    } else if (tax.calculationType === "PERCENTAGE_PLUS_FIXED") {
      total = total.add(costBase.mul(tax.rate.div(100))).add(tax.fixedAmount);
    }
  }
  return total;
}

// ===========================================================================
// Batch stock summary — una sola query para todos los artículos BY_ARTICLE
// ===========================================================================
async function batchLoadStockSummary(
  jewelryId: string,
  articleIds: string[],
): Promise<Map<string, { total: number; byVariant: Record<string, number> }>> {
  const result = new Map<string, { total: number; byVariant: Record<string, number> }>();
  if (articleIds.length === 0) return result;

  const stocks = await prisma.articleStock.findMany({
    where: { jewelryId, articleId: { in: articleIds } },
    select: { articleId: true, variantId: true, quantity: true },
  });

  for (const s of stocks) {
    const qty = parseFloat(s.quantity.toString());
    if (!result.has(s.articleId)) result.set(s.articleId, { total: 0, byVariant: {} });
    const entry = result.get(s.articleId)!;
    entry.total += qty;
    if (s.variantId) {
      entry.byVariant[s.variantId] = (entry.byVariant[s.variantId] ?? 0) + qty;
    }
  }
  return result;
}

// ===========================================================================
// Batch resolve sale price — sin contexto de cliente
// 3 queries paralelas al inicio, resto en memoria.
// ===========================================================================
type NoClientPriceResult = {
  resolvedSalePrice:   string | null;
  resolvedPriceSource: "PROMOTION" | "PRICE_LIST_CATEGORY" | "PRICE_LIST_GENERAL" | "MANUAL_OVERRIDE" | "MANUAL_FALLBACK" | "NONE";
  resolvedPriceName:   string | null;
};

// Select mínimo para listas de precio (replica local de PL_COMPUTE_SELECT de pricing.utils.ts)
const PL_LIST_SELECT = {
  id: true, name: true, mode: true,
  marginTotal: true, marginMetal: true, marginHechura: true,
  costPerGram: true, surcharge: true, minimumPrice: true,
  roundingTarget: true, roundingMode: true, roundingDirection: true,
  validFrom: true, validTo: true, isActive: true,
} as const;

function _isPLValidNow(pl: { isActive: boolean; validFrom: Date | null; validTo: Date | null }): boolean {
  if (!pl.isActive) return false;
  const now = new Date();
  if (pl.validFrom && pl.validFrom > now) return false;
  if (pl.validTo   && pl.validTo   < now) return false;
  return true;
}

function _isPromoValid(p: {
  isActive: boolean; deletedAt: Date | null;
  validFrom: Date | null; validTo: Date | null;
}): boolean {
  if (!p.isActive || p.deletedAt) return false;
  const now = new Date();
  if (p.validFrom && p.validFrom > now) return false;
  if (p.validTo   && p.validTo   < now) return false;
  return true;
}

async function batchResolveSalePricesNoClient(
  jewelryId: string,
  rows: any[],
): Promise<Map<string, NoClientPriceResult>> {
  const result = new Map<string, NoClientPriceResult>();
  if (rows.length === 0) return result;

  const D = Prisma.Decimal;
  const articleIds      = rows.map((r) => r.id);
  const uniqueCatIds    = [...new Set(rows.map((r: any) => r.categoryId).filter(Boolean) as string[])];

  // ── 3 queries paralelas ──────────────────────────────────────────────────
  const [promotions, categories, generalPL] = await Promise.all([
    prisma.promotion.findMany({
      where: {
        jewelryId, isActive: true, deletedAt: null,
        OR: [
          { scope: "ALL" },
          { scope: "ARTICLE", articles: { some: { articleId: { in: articleIds } } } },
        ],
      },
      select: {
        id: true, name: true, type: true, value: true,
        scope: true,
        articles: { select: { articleId: true } },
        validFrom: true, validTo: true, isActive: true, deletedAt: true,
        priority: true,
      },
      orderBy: [{ priority: "asc" }, { createdAt: "asc" }],
    }),
    uniqueCatIds.length > 0
      ? prisma.articleCategory.findMany({
          where: { id: { in: uniqueCatIds }, jewelryId, deletedAt: null },
          select: { id: true, defaultPriceList: { select: PL_LIST_SELECT } },
        })
      : Promise.resolve([]),
    prisma.priceList.findFirst({
      where: { jewelryId, scope: "GENERAL", isFavorite: true, isActive: true, deletedAt: null },
      select: PL_LIST_SELECT,
      orderBy: { sortOrder: "asc" },
    }),
  ]);

  // Indexar listas por categoría
  const catPLMap = new Map<string, any>();
  for (const cat of categories) {
    const pl = (cat as any).defaultPriceList;
    if (pl && _isPLValidNow(pl)) catPLMap.set(cat.id, pl);
  }

  const validGeneralPL = generalPL && _isPLValidNow(generalPL as any) ? generalPL : null;

  // ── Resolver por artículo (en memoria) ───────────────────────────────────
  for (const row of rows) {
    const none: NoClientPriceResult = { resolvedSalePrice: null, resolvedPriceSource: "NONE", resolvedPriceName: null };

    // CostBreakdown mínimo: value + totalGrams (para COST_PER_GRAM)
    const costValue = row.computedCostBase != null ? new D(row.computedCostBase) : null;
    let totalGrams: Prisma.Decimal | null = null;
    const metalLines = (row.costComposition ?? []).filter((l: any) => l.type === "METAL");
    if (metalLines.length > 0) {
      totalGrams = metalLines.reduce(
        (acc: Prisma.Decimal, l: any) => acc.add(new D(l.quantity?.toString() ?? "0")),
        new D(0),
      );
    } else if ((row.compositions ?? []).length > 0) {
      totalGrams = (row.compositions ?? []).reduce(
        (acc: Prisma.Decimal, c: any) => acc.add(new D(c.grams?.toString() ?? "0")),
        new D(0),
      );
    }
    const costBreakdown: CostBreakdown = { value: costValue, metalCost: null, hechuraCost: null, totalGrams };

    // ── Precio base ─────────────────────────────────────────────────────────
    let basePrice: Prisma.Decimal | null = null;
    let baseSource: NoClientPriceResult["resolvedPriceSource"] = "NONE";
    let baseName: string | null = null;

    // 1. Lista de categoría
    if (row.categoryId) {
      const catPL = catPLMap.get(row.categoryId);
      if (catPL) {
        const res = applyPriceList(catPL, costBreakdown);
        if (res.value != null) {
          basePrice = res.value; baseSource = "PRICE_LIST_CATEGORY"; baseName = catPL.name;
        }
      }
    }
    // 2. Lista general
    if (basePrice == null && validGeneralPL) {
      const res = applyPriceList(validGeneralPL as any, costBreakdown);
      if (res.value != null) {
        basePrice = res.value; baseSource = "PRICE_LIST_GENERAL"; baseName = (validGeneralPL as any).name;
      }
    }
    // 3. Manual override
    if (basePrice == null && row.useManualSalePrice && row.salePrice != null) {
      basePrice = new D(row.salePrice.toString()); baseSource = "MANUAL_OVERRIDE"; baseName = null;
    }
    // 4. Fallback manual
    if (basePrice == null && row.salePrice != null) {
      basePrice = new D(row.salePrice.toString()); baseSource = "MANUAL_FALLBACK"; baseName = null;
    }

    if (basePrice == null) { result.set(row.id, none); continue; }

    // ── Promoción activa para este artículo ──────────────────────────────────
    const activePromo = promotions.find((p) =>
      _isPromoValid(p) && (
        p.scope === "ALL" ||
        (p.scope === "ARTICLE" && p.articles.some((a) => a.articleId === row.id))
      )
    ) ?? null;

    let finalPrice = basePrice;
    let finalSource: NoClientPriceResult["resolvedPriceSource"] = baseSource;
    let finalName   = baseName;

    if (activePromo) {
      const discVal = new D(activePromo.value.toString());
      let discount: Prisma.Decimal;
      if (activePromo.type === "PERCENTAGE") {
        discount = basePrice.mul(discVal).div(100);
      } else {
        discount = D.min(discVal, basePrice);
      }
      finalPrice  = basePrice.sub(discount);
      if (finalPrice.lessThan(0)) finalPrice = new D(0);
      finalSource = "PROMOTION";
      finalName   = activePromo.name;
    }

    result.set(row.id, {
      resolvedSalePrice:   finalPrice.toFixed(4),
      resolvedPriceSource: finalSource,
      resolvedPriceName:   finalName,
    });
  }

  return result;
}

async function batchComputeCosts(
  jewelryId: string,
  rows: any[],
): Promise<Map<string, { computedCostBase: string | null; computedCostWithTax: string | null }>> {
  const result = new Map<string, { computedCostBase: string | null; computedCostWithTax: string | null }>();
  if (rows.length === 0) return result;

  const baseCurrency = await prisma.currency.findFirst({
    where: { jewelryId, isBase: true, deletedAt: null },
    select: { id: true },
  });
  if (!baseCurrency) {
    rows.forEach((r) => result.set(r.id, { computedCostBase: null, computedCostWithTax: null }));
    return result;
  }

  // Collect unique currency IDs
  const currencyIds = new Set<string>();
  for (const row of rows) {
    if (row.manualCurrencyId && row.manualCurrencyId !== baseCurrency.id) currencyIds.add(row.manualCurrencyId);
    if (row.multiplierCurrencyId && row.multiplierCurrencyId !== baseCurrency.id) currencyIds.add(row.multiplierCurrencyId);
    for (const line of row.costComposition ?? []) {
      if (line.currencyId && line.currencyId !== baseCurrency.id) currencyIds.add(line.currencyId);
    }
  }

  // Collect unique metal variant IDs
  const variantIds = new Set<string>();
  for (const row of rows) {
    for (const line of row.costComposition ?? []) {
      if (line.type === "METAL" && line.metalVariantId) variantIds.add(line.metalVariantId);
    }
    for (const comp of row.compositions ?? []) {
      if (comp.variantId) variantIds.add(comp.variantId);
    }
  }

  // Collect unique tax IDs
  const taxIds = new Set<string>();
  for (const row of rows) {
    for (const tid of row.manualTaxIds ?? []) taxIds.add(tid);
  }

  // Batch fetch currency rates (latest per currency)
  const rateMap = new Map<string, Prisma.Decimal>();
  if (currencyIds.size > 0) {
    const allRates = await prisma.currencyRate.findMany({
      where: { currencyId: { in: Array.from(currencyIds) } },
      orderBy: { createdAt: "desc" },
      select: { currencyId: true, rate: true },
    });
    for (const r of allRates) {
      if (!rateMap.has(r.currencyId)) rateMap.set(r.currencyId, new Prisma.Decimal(r.rate.toString()));
    }
  }

  // Batch fetch metal quotes (latest per variant, in base currency)
  const metalQuoteMap = new Map<string, Prisma.Decimal>();
  if (variantIds.size > 0) {
    const allQuotes = await prisma.metalQuote.findMany({
      where: { variantId: { in: Array.from(variantIds) }, currencyId: baseCurrency.id },
      orderBy: { effectiveAt: "desc" },
      select: { variantId: true, price: true },
    });
    for (const q of allQuotes) {
      if (!metalQuoteMap.has(q.variantId)) metalQuoteMap.set(q.variantId, new Prisma.Decimal(q.price.toString()));
    }
  }

  // Batch fetch taxes
  const taxMap = new Map<string, { rate: Prisma.Decimal; fixedAmount: Prisma.Decimal; calculationType: string }>();
  if (taxIds.size > 0) {
    const taxes = await prisma.tax.findMany({
      where: { id: { in: Array.from(taxIds) }, deletedAt: null },
      select: { id: true, rate: true, fixedAmount: true, calculationType: true },
    });
    for (const t of taxes) {
      taxMap.set(t.id, {
        rate:            new Prisma.Decimal((t.rate ?? 0).toString()),
        fixedAmount:     new Prisma.Decimal((t.fixedAmount ?? 0).toString()),
        calculationType: t.calculationType,
      });
    }
  }

  // Jewelry default merma
  const jewelry = await prisma.jewelry.findUnique({
    where: { id: jewelryId },
    select: { defaultMermaPercent: true },
  });

  // Compute per article
  for (const row of rows) {
    const costBase = computeArticleCostBase(
      row, baseCurrency.id, rateMap, metalQuoteMap, jewelry?.defaultMermaPercent,
    );
    const costWithTax = costBase != null
      ? applyTaxes(costBase, row.manualTaxIds ?? [], taxMap)
      : null;
    result.set(row.id, {
      computedCostBase:    costBase    != null ? costBase.toFixed(4)    : null,
      computedCostWithTax: costWithTax != null ? costWithTax.toFixed(4) : null,
    });
  }

  return result;
}

// ===========================================================================
// List
// ===========================================================================
export async function listArticles(
  jewelryId: string,
  opts: {
    q?: string;
    categoryId?: string;
    articleType?: string;
    status?: string;
    stockMode?: string;
    isFavorite?: boolean;
    showInActive?: boolean;
    showInStore?: boolean;
    barcode?: string;
    sku?: string;
    preferredSupplierId?: string;
    skip?: number;
    take?: number;
    page?: number;
    pageSize?: number;
  }
) {
  const {
    q, categoryId, articleType, status, stockMode, isFavorite,
    showInActive, showInStore, barcode, sku, preferredSupplierId,
  } = opts;

  // Soporte page/pageSize (prioridad) ó skip/take (legacy)
  const pageSize = opts.pageSize ?? opts.take ?? 50;
  const page     = opts.page ?? (opts.skip != null ? Math.floor(opts.skip / pageSize) + 1 : 1);
  const take     = Math.min(200, Math.max(1, pageSize));
  const skip     = Math.max(0, (page - 1) * take);

  const where: any = { jewelryId, deletedAt: null };
  if (!showInActive) where.isActive = true;
  if (categoryId)           where.categoryId = categoryId;
  if (articleType && VALID_ARTICLE_TYPES.has(articleType)) where.articleType = articleType;
  if (status && VALID_STATUS.has(status)) where.status = status;
  if (stockMode && VALID_STOCK_MODE.has(stockMode)) where.stockMode = stockMode;
  if (isFavorite === true)  where.isFavorite = true;
  if (showInStore === true)  where.showInStore = true;
  if (preferredSupplierId)  where.preferredSupplierId = preferredSupplierId;
  if (barcode)              where.barcode = barcode; // búsqueda exacta por barcode
  if (sku)                  where.sku = { contains: sku, mode: "insensitive" };

  if (q) {
    where.OR = [
      { name:        { contains: q, mode: "insensitive" } },
      { code:        { contains: q, mode: "insensitive" } },
      { description: { contains: q, mode: "insensitive" } },
      { sku:         { contains: q, mode: "insensitive" } },
      { brand:       { contains: q, mode: "insensitive" } },
      { barcode:     { contains: q, mode: "insensitive" } },
    ];
  }

  const [rows, total] = await Promise.all([
    prisma.article.findMany({
      where,
      select: ARTICLE_LIST_SELECT,
      orderBy: { name: "asc" },
      skip,
      take,
    }),
    prisma.article.count({ where }),
  ]);

  const computedCosts = await batchComputeCosts(jewelryId, rows);

  // Enriquecer con costo calculado (necesario antes de resolver precio)
  const rowsWithCost = rows.map((r) => {
    const c = computedCosts.get(r.id);
    return {
      ...r,
      computedCostBase:    c?.computedCostBase    ?? null,
      computedCostWithTax: c?.computedCostWithTax ?? null,
    };
  });

  const resolvedPrices = await batchResolveSalePricesNoClient(jewelryId, rowsWithCost);

  // Stock sólo para artículos BY_ARTICLE (1 query total)
  const byArticleIds = rowsWithCost
    .filter((r) => r.stockMode === "BY_ARTICLE")
    .map((r) => r.id);
  const stockMap = await batchLoadStockSummary(jewelryId, byArticleIds);

  const enrichedRows = rowsWithCost.map((r) => {
    const p = resolvedPrices.get(r.id);
    const stockEntry = r.stockMode === "BY_ARTICLE"
      ? (stockMap.get(r.id) ?? { total: 0, byVariant: {} })
      : null;
    return {
      ...r,
      resolvedSalePrice:   p?.resolvedSalePrice   ?? null,
      resolvedPriceSource: p?.resolvedPriceSource  ?? "NONE",
      resolvedPriceName:   p?.resolvedPriceName    ?? null,
      stockData: stockEntry,
    };
  });

  const totalPages = Math.max(1, Math.ceil(total / take));
  return { rows: enrichedRows, total, skip, take, page, pageSize: take, totalPages };
}

// ===========================================================================
// Get one — incluye stock/disponibilidad integrada
// ===========================================================================
export async function getArticle(articleId: string, jewelryId: string) {
  const article = await prisma.article.findFirst({
    where: { id: articleId, jewelryId, deletedAt: null },
    select: ARTICLE_DETAIL_SELECT as any,
  });
  assert(article, "Artículo no encontrado.", 404);

  // Enriquecer con datos de stock según el modo
  let stockData: any = null;
  if ((article as any).stockMode === "BY_ARTICLE") {
    stockData = await getStockSummary(articleId, jewelryId);
  } else if ((article as any).stockMode === "BY_MATERIAL") {
    stockData = await _calcMaterialAvailabilityInternal(articleId, jewelryId, article as any);
  }

  // Calcular costo computado según el modo de cálculo
  const costResult = await computeCostPrice(jewelryId, article as any);

  // Aplicar impuestos para obtener computedCostWithTax.
  // Mismo criterio que batchComputeCosts() — los impuestos son capa de lectura, nunca se persisten.
  let computedCostWithTaxStr: string | null = null;
  if (costResult.value != null) {
    const costBase     = costResult.value as Prisma.Decimal;
    const taxIds: string[] = (article as any).manualTaxIds ?? [];
    if (taxIds.length > 0) {
      const taxObjects = await prisma.tax.findMany({
        where: { id: { in: taxIds }, deletedAt: null },
        select: { id: true, rate: true, fixedAmount: true, calculationType: true },
      });
      const taxMap = new Map(taxObjects.map((t) => [t.id, {
        rate:            new Prisma.Decimal((t.rate ?? 0).toString()),
        fixedAmount:     new Prisma.Decimal((t.fixedAmount ?? 0).toString()),
        calculationType: t.calculationType,
      }]));
      computedCostWithTaxStr = applyTaxes(costBase, taxIds, taxMap).toFixed(4);
    } else {
      computedCostWithTaxStr = costBase.toFixed(4);
    }
  }

  // Calcular precio de venta usando la lista de precios correspondiente
  const plResult = await resolvePriceList(jewelryId, { categoryId: (article as any).categoryId });
  let computedSalePrice: {
    value: string | null; mode: string; partial: boolean;
    priceListId: string | null; priceListName: string | null; priceSource: string;
  };

  if (plResult) {
    const { value, partial } = applyPriceList(plResult.priceList, costResult);
    computedSalePrice = {
      value:         value?.toString() ?? null,
      mode:          "PRICE_LIST",
      partial,
      priceListId:   plResult.priceList.id,
      priceListName: plResult.priceList.name,
      priceSource:   plResult.source,
    };
  } else {
    computedSalePrice = {
      value:         (article as any).salePrice?.toString() ?? null,
      mode:          "MANUAL",
      partial:       false,
      priceListId:   null,
      priceListName: null,
      priceSource:   "MANUAL",
    };
  }

  // Precio efectivo final: override manual → lista → fallback manual
  const useManualOverride = (article as any).useManualSalePrice === true;
  const manualSalePrice   = (article as any).salePrice;
  let effectiveSalePrice: string | null;
  let effectivePriceSource: "MANUAL_OVERRIDE" | "PRICE_LIST" | "MANUAL_FALLBACK";

  if (useManualOverride && manualSalePrice != null) {
    effectiveSalePrice  = manualSalePrice.toString();
    effectivePriceSource = "MANUAL_OVERRIDE";
  } else if (computedSalePrice.mode === "PRICE_LIST" && computedSalePrice.value != null) {
    effectiveSalePrice  = computedSalePrice.value;
    effectivePriceSource = "PRICE_LIST";
  } else {
    effectiveSalePrice  = manualSalePrice?.toString() ?? null;
    effectivePriceSource = "MANUAL_FALLBACK";
  }

  return {
    ...article,
    stockData,
    computedCostBase:    costResult.value != null ? (costResult.value as Prisma.Decimal).toFixed(4) : null,
    computedCostWithTax: computedCostWithTaxStr,
    computedCostPrice:   costResult,
    computedSalePrice,
    effectiveSalePrice,
    effectivePriceSource,
  };
}

// ===========================================================================
// Create
// ===========================================================================
export async function createArticle(jewelryId: string, data: any) {
  assert(s(data?.name), "El nombre del artículo es obligatorio.");

  const articleType = VALID_ARTICLE_TYPES.has(data?.articleType) ? data.articleType : "PRODUCT";
  const stockMode   = VALID_STOCK_MODE.has(data?.stockMode) ? data.stockMode : "NO_STOCK";

  validateTypeStockMode(articleType, stockMode);

  const costCalculationMode = VALID_COST_MODES.has(data?.costCalculationMode)
    ? data.costCalculationMode : "MANUAL";
  validateCostMode({
    costCalculationMode,
    costPrice:          data?.costPrice,
    multiplierBase:     data?.multiplierBase,
    multiplierValue:    data?.multiplierValue,
    multiplierQuantity: data?.multiplierQuantity,
  });

  const code = s(data?.code) || await generateArticleCode(jewelryId);
  const codeExists = await prisma.article.findFirst({
    where: { jewelryId, code }, select: { id: true },
  });
  assert(!codeExists, "Ya existe un artículo con ese código.");

  // SKU — unicidad en el tenant (si está informado)
  await assertSkuUnique(jewelryId, s(data?.sku));

  if (data?.categoryId) {
    const cat = await prisma.articleCategory.findFirst({
      where: { id: data.categoryId, jewelryId, deletedAt: null }, select: { id: true },
    });
    assert(cat, "Categoría no encontrada.");
  }

  // Barcode — se resuelve según barcodeSource
  const barcodeType = VALID_BARCODE_TYPES.has(data?.barcodeType) ? data.barcodeType : "CODE128";
  const { barcode, barcodeSource } = await resolveBarcode({
    jewelryId,
    source:         data?.barcodeSource ?? "CUSTOM",
    code,
    sku:            s(data?.sku),
    customBarcode:  data?.barcode,
    autoBarcode:    data?.autoBarcode === true,
    barcodeType,
  });

  // Proveedor preferido
  if (data?.preferredSupplierId) {
    await validatePreferredSupplier(jewelryId, data.preferredSupplierId);
  }

  assert(jewelryId, "jewelryId es requerido para crear un artículo.");

  const costCompositionLines: CostLineInput[] = Array.isArray(data?.costComposition) ? data.costComposition : [];

  const articleData = {
    jewelry:             { connect: { id: jewelryId } },
    ...(data?.categoryId          ? { category:          { connect: { id: data.categoryId } } }          : {}),
    ...(data?.preferredSupplierId ? { preferredSupplier: { connect: { id: data.preferredSupplierId } } } : {}),
    code,
    name:                s(data.name),
    description:         s(data?.description),
    articleType,
    status:              VALID_STATUS.has(data?.status) ? data.status : "DRAFT",
    stockMode,
    sku:                 s(data?.sku),
    barcode:             barcode ?? null,
    barcodeType,
    barcodeSource,
    brand:               s(data?.brand),
    manufacturer:        s(data?.manufacturer),
    supplierCode:        s(data?.supplierCode),
    costPrice:           data?.costPrice != null ? data.costPrice : null,
    salePrice:           data?.salePrice != null ? data.salePrice : null,
    useManualSalePrice:  !!data?.useManualSalePrice,
    hechuraPrice:        data?.hechuraPrice != null ? data.hechuraPrice : null,
    hechuraPriceMode:    VALID_HECHURA_MODE.has(data?.hechuraPriceMode) ? data.hechuraPriceMode : "FIXED",
    mermaPercent:        data?.mermaPercent != null ? data.mermaPercent : null,
    costCalculationMode,
    multiplierBase:        s(data?.multiplierBase),
    multiplierValue:       data?.multiplierValue != null ? data.multiplierValue : null,
    multiplierQuantity:    data?.multiplierQuantity != null ? data.multiplierQuantity : null,
    multiplierCurrencyId:  data?.multiplierCurrencyId ?? null,
    manualBaseCost:        data?.manualBaseCost != null ? data.manualBaseCost : null,
    manualCurrencyId:      data?.manualCurrencyId ?? null,
    manualAdjustmentKind:  s(data?.manualAdjustmentKind),
    manualAdjustmentType:  s(data?.manualAdjustmentType),
    manualAdjustmentValue: data?.manualAdjustmentValue != null ? data.manualAdjustmentValue : null,
    manualTaxIds:          Array.isArray(data?.manualTaxIds) ? data.manualTaxIds : [],
    sellWithoutVariants: data?.sellWithoutVariants !== false,
    isReturnable:        data?.isReturnable !== false,
    showInStore:         !!data?.showInStore,
    unitOfMeasure:       s(data?.unitOfMeasure),
    reorderPoint:        data?.reorderPoint != null ? data.reorderPoint : null,
    isFavorite:          !!data?.isFavorite,
    notes:               s(data?.notes),
  };

  const VALID_TYPES = new Set(["METAL", "HECHURA", "PRODUCT", "SERVICE", "MANUAL"]);
  const articleId = await prisma.$transaction(async (tx) => {
    const created = await tx.article.create({ data: articleData, select: { id: true } });
    if (costCompositionLines.length > 0) {
      await tx.articleCostLine.createMany({
        data: costCompositionLines.map((l, idx) => ({
          articleId:     created.id,
          jewelryId,
          type:          VALID_TYPES.has(l.type) ? (l.type as any) : "MANUAL",
          label:         l.label ?? "",
          quantity:      l.quantity,
          unitValue:     l.unitValue,
          currencyId:    l.type === "METAL" ? null : (l.currencyId ?? null),
          mermaPercent:  l.type === "METAL" ? (l.mermaPercent ?? null) : null,
          metalVariantId: l.type === "METAL" ? (l.metalVariantId ?? null) : null,
          catalogItemId: l.catalogItemId ?? null,
          sortOrder:     l.sortOrder ?? idx,
        })),
      });
    }
    return created.id;
  });

  return getArticle(articleId, jewelryId);
}

// ===========================================================================
// Update (base fields)
// ===========================================================================
export async function updateArticle(articleId: string, jewelryId: string, data: any) {
  await assertArticleOwnership(articleId, jewelryId);
  assert(s(data?.name), "El nombre del artículo es obligatorio.");

  const current = await prisma.article.findUnique({
    where: { id: articleId },
    select: { articleType: true, stockMode: true, barcode: true, barcodeSource: true, code: true, sku: true, costCalculationMode: true },
  });
  const newType      = VALID_ARTICLE_TYPES.has(data?.articleType) ? data.articleType : current!.articleType;
  const newStockMode = VALID_STOCK_MODE.has(data?.stockMode) ? data.stockMode : current!.stockMode;
  validateTypeStockMode(newType, newStockMode);

  // Si se envían campos de costo, validar coherencia
  const hasCostFields = data?.costCalculationMode != null || data?.multiplierBase != null
    || data?.multiplierValue != null || data?.multiplierQuantity != null;
  if (hasCostFields) {
    const effectiveCostMode = VALID_COST_MODES.has(data?.costCalculationMode)
      ? data.costCalculationMode
      : current!.costCalculationMode;
    validateCostMode({
      costCalculationMode: effectiveCostMode,
      costPrice:           data?.costPrice,
      multiplierBase:      data?.multiplierBase,
      multiplierValue:     data?.multiplierValue,
      multiplierQuantity:  data?.multiplierQuantity,
    });
  }

  if (data?.code) {
    const conflict = await prisma.article.findFirst({
      where: { jewelryId, code: s(data.code), id: { not: articleId } }, select: { id: true },
    });
    assert(!conflict, "Ya existe un artículo con ese código.");
  }
  // SKU — si se envía, validar unicidad excluyendo este artículo
  if (data?.sku !== undefined) {
    await assertSkuUnique(jewelryId, s(data.sku), articleId);
  }
  if (data?.categoryId) {
    const cat = await prisma.articleCategory.findFirst({
      where: { id: data.categoryId, jewelryId, deletedAt: null }, select: { id: true },
    });
    assert(cat, "Categoría no encontrada.");
  }

  // Barcode — re-resolve si cambia source, code, sku, o barcode (para CUSTOM)
  const effectiveSource = VALID_BARCODE_SOURCES.has(data?.barcodeSource)
    ? data.barcodeSource : current!.barcodeSource;
  const effectiveCode = data?.code ? s(data.code) : current!.code;
  const effectiveSku  = data?.sku !== undefined ? s(data.sku) : current!.sku;
  const barcodeType = VALID_BARCODE_TYPES.has(data?.barcodeType) ? data.barcodeType : "CODE128";

  const needsBarcodeResolve = data?.barcodeSource !== undefined
    || (data?.barcode !== undefined && effectiveSource === "CUSTOM")
    || (data?.code   !== undefined && effectiveSource === "CODE")
    || (data?.sku    !== undefined && effectiveSource === "SKU");

  let barcode: string | null | undefined = undefined;
  let barcodeSource: BarcodeSource | undefined = undefined;

  if (needsBarcodeResolve) {
    const resolved = await resolveBarcode({
      jewelryId,
      source:        effectiveSource,
      code:          effectiveCode,
      sku:           effectiveSku,
      customBarcode: effectiveSource === "CUSTOM" ? data?.barcode : undefined,
      barcodeType,
      excludeArticleId: articleId,
    });
    barcode = resolved.barcode;
    barcodeSource = resolved.barcodeSource;
  }

  if (data?.preferredSupplierId) {
    await validatePreferredSupplier(jewelryId, data.preferredSupplierId);
  }

  const updateData = {
    ...(data?.code ? { code: s(data.code) } : {}),
    ...(data?.categoryId !== undefined
      ? { category: data.categoryId ? { connect: { id: data.categoryId } } : { disconnect: true } }
      : {}),
    ...(data?.preferredSupplierId !== undefined
      ? { preferredSupplier: data.preferredSupplierId ? { connect: { id: data.preferredSupplierId } } : { disconnect: true } }
      : {}),
    name:               s(data.name),
    description:        s(data?.description),
    articleType:        VALID_ARTICLE_TYPES.has(data?.articleType) ? data.articleType : undefined,
    status:             VALID_STATUS.has(data?.status) ? data.status : undefined,
    stockMode:          VALID_STOCK_MODE.has(data?.stockMode) ? data.stockMode : undefined,
    sku:                data?.sku !== undefined ? s(data.sku) : undefined,
    barcode,
    barcodeType:        needsBarcodeResolve ? barcodeType : undefined,
    barcodeSource:      barcodeSource,
    brand:              data?.brand !== undefined ? s(data.brand) : undefined,
    manufacturer:       data?.manufacturer !== undefined ? s(data.manufacturer) : undefined,
    supplierCode:       data?.supplierCode !== undefined ? s(data.supplierCode) : undefined,
    costPrice:           data?.costPrice !== undefined ? (data.costPrice ?? null) : undefined,
    salePrice:           data?.salePrice !== undefined ? (data.salePrice ?? null) : undefined,
    useManualSalePrice:  data?.useManualSalePrice !== undefined ? !!data.useManualSalePrice : undefined,
    hechuraPrice:        data?.hechuraPrice !== undefined ? (data.hechuraPrice ?? null) : undefined,
    hechuraPriceMode:    VALID_HECHURA_MODE.has(data?.hechuraPriceMode) ? data.hechuraPriceMode : undefined,
    mermaPercent:        data?.mermaPercent !== undefined ? (data.mermaPercent ?? null) : undefined,
    costCalculationMode: VALID_COST_MODES.has(data?.costCalculationMode) ? data.costCalculationMode : undefined,
    multiplierBase:        data?.multiplierBase !== undefined ? s(data.multiplierBase) : undefined,
    multiplierValue:       data?.multiplierValue !== undefined ? (data.multiplierValue ?? null) : undefined,
    multiplierQuantity:    data?.multiplierQuantity !== undefined ? (data.multiplierQuantity ?? null) : undefined,
    multiplierCurrencyId:  data?.multiplierCurrencyId !== undefined ? (data.multiplierCurrencyId ?? null) : undefined,
    manualBaseCost:        data?.manualBaseCost !== undefined ? (data.manualBaseCost ?? null) : undefined,
    manualCurrencyId:      data?.manualCurrencyId !== undefined ? (data.manualCurrencyId ?? null) : undefined,
    manualAdjustmentKind:  data?.manualAdjustmentKind !== undefined ? s(data.manualAdjustmentKind) : undefined,
    manualAdjustmentType:  data?.manualAdjustmentType !== undefined ? s(data.manualAdjustmentType) : undefined,
    manualAdjustmentValue: data?.manualAdjustmentValue !== undefined ? (data.manualAdjustmentValue ?? null) : undefined,
    manualTaxIds:          data?.manualTaxIds !== undefined ? (Array.isArray(data.manualTaxIds) ? data.manualTaxIds : []) : undefined,
    sellWithoutVariants: data?.sellWithoutVariants !== undefined ? !!data.sellWithoutVariants : undefined,
    isReturnable:       data?.isReturnable !== undefined ? !!data.isReturnable : undefined,
    showInStore:        data?.showInStore !== undefined ? !!data.showInStore : undefined,
    unitOfMeasure:      data?.unitOfMeasure !== undefined ? s(data.unitOfMeasure) : undefined,
    reorderPoint:       data?.reorderPoint !== undefined ? (data.reorderPoint ?? null) : undefined,
    isFavorite:         data?.isFavorite !== undefined ? !!data.isFavorite : undefined,
    notes:              data?.notes !== undefined ? s(data.notes) : undefined,
  };

  const hasCostComposition = data?.costComposition !== undefined;
  const costCompositionLines: CostLineInput[] = hasCostComposition
    ? (Array.isArray(data.costComposition) ? data.costComposition : [])
    : [];

  const VALID_TYPES_SET = new Set(["METAL", "HECHURA", "PRODUCT", "SERVICE", "MANUAL"]);
  await prisma.$transaction(async (tx) => {
    await tx.article.update({ where: { id: articleId }, data: updateData });
    if (hasCostComposition) {
      await tx.articleCostLine.deleteMany({ where: { articleId, jewelryId } });
      if (costCompositionLines.length > 0) {
        await tx.articleCostLine.createMany({
          data: costCompositionLines.map((l, idx) => ({
            articleId,
            jewelryId,
            type:          VALID_TYPES_SET.has(l.type) ? (l.type as any) : "MANUAL",
            label:         l.label ?? "",
            quantity:      l.quantity,
            unitValue:     l.unitValue,
            currencyId:    l.type === "METAL" ? null : (l.currencyId ?? null),
            mermaPercent:  l.type === "METAL" ? (l.mermaPercent ?? null) : null,
            metalVariantId: l.type === "METAL" ? (l.metalVariantId ?? null) : null,
            catalogItemId: l.catalogItemId ?? null,
            sortOrder:     l.sortOrder ?? idx,
          })),
        });
      }
    }
  });

  return getArticle(articleId, jewelryId);
}

// ===========================================================================
// Toggle active
// ===========================================================================
export async function toggleArticle(articleId: string, jewelryId: string) {
  await assertArticleOwnership(articleId, jewelryId);
  const article = await prisma.article.findUnique({ where: { id: articleId }, select: { isActive: true } });
  return prisma.article.update({
    where: { id: articleId },
    data: { isActive: !article!.isActive },
    select: ARTICLE_LIST_SELECT,
  });
}

// ===========================================================================
// Toggle favorite
// ===========================================================================
export async function toggleFavorite(articleId: string, jewelryId: string) {
  await assertArticleOwnership(articleId, jewelryId);
  const article = await prisma.article.findUnique({ where: { id: articleId }, select: { isFavorite: true } });
  return prisma.article.update({
    where: { id: articleId },
    data: { isFavorite: !article!.isFavorite },
    select: { id: true, isFavorite: true },
  });
}

// ===========================================================================
// Soft delete
// ===========================================================================
export async function deleteArticle(articleId: string, jewelryId: string) {
  await assertArticleOwnership(articleId, jewelryId);
  await prisma.article.update({
    where: { id: articleId },
    data: { deletedAt: new Date(), isActive: false },
  });
  return { id: articleId };
}

// ===========================================================================
// Compositions
// ===========================================================================
const COMPOSITION_SELECT = {
  id: true,
  variantId: true,
  grams: true,
  isBase: true,
  sortOrder: true,
  createdAt: true,
  metalVariant: {
    select: {
      id: true, name: true, sku: true, purity: true,
      metal: { select: { id: true, name: true } },
    },
  },
} as const;

export async function listCompositions(articleId: string, jewelryId: string) {
  await assertArticleOwnership(articleId, jewelryId);
  return prisma.articleMetalComposition.findMany({
    where: { articleId },
    select: COMPOSITION_SELECT,
    orderBy: [{ sortOrder: "asc" as const }, { createdAt: "asc" as const }],
  });
}

export async function upsertComposition(articleId: string, jewelryId: string, data: any) {
  await assertArticleOwnership(articleId, jewelryId);

  const variantId = s(data?.variantId);
  assert(variantId, "variantId es obligatorio.");
  assert(data?.grams != null, "grams es obligatorio.");

  const variant = await prisma.metalVariant.findFirst({
    where: { id: variantId, deletedAt: null }, select: { id: true },
  });
  assert(variant, "Variante de metal no encontrada.");

  const isBase = !!data?.isBase;

  return prisma.$transaction(async (tx) => {
    if (isBase) {
      await tx.articleMetalComposition.updateMany({
        where: { articleId, id: { not: undefined } },
        data: { isBase: false },
      });
    }
    return tx.articleMetalComposition.upsert({
      where: { articleId_variantId: { articleId, variantId } },
      create: {
        articleId, jewelryId, variantId, grams: data.grams, isBase,
        sortOrder: typeof data?.sortOrder === "number" ? data.sortOrder : 0,
      },
      update: {
        grams: data.grams, isBase,
        sortOrder: typeof data?.sortOrder === "number" ? data.sortOrder : undefined,
      },
      select: COMPOSITION_SELECT,
    });
  });
}

export async function removeComposition(articleId: string, compositionId: string, jewelryId: string) {
  await assertArticleOwnership(articleId, jewelryId);
  const comp = await prisma.articleMetalComposition.findFirst({
    where: { id: compositionId, articleId }, select: { id: true },
  });
  assert(comp, "Composición no encontrada.");
  await prisma.articleMetalComposition.delete({ where: { id: compositionId } });
  return { id: compositionId };
}

// ===========================================================================
// Variants
// ===========================================================================
export async function listVariants(articleId: string, jewelryId: string) {
  await assertArticleOwnership(articleId, jewelryId);
  return prisma.articleVariant.findMany({
    where: { articleId, deletedAt: null },
    select: VARIANT_SELECT,
    orderBy: [{ sortOrder: "asc" as const }, { createdAt: "asc" as const }],
  });
}

/** Lista variantes con soft-delete para mostrar el badge "Regenerable" en el modal */
export async function listDeletedVariants(articleId: string, jewelryId: string) {
  await assertArticleOwnership(articleId, jewelryId);
  return prisma.articleVariant.findMany({
    where: { articleId, jewelryId, deletedAt: { not: null } },
    select: VARIANT_SELECT,
    orderBy: [{ createdAt: "asc" as const }],
  });
}

export async function createVariant(articleId: string, jewelryId: string, data: any) {
  await assertArticleOwnership(articleId, jewelryId);

  // Regla: los servicios no pueden tener variantes
  const article = await prisma.article.findUnique({
    where: { id: articleId },
    select: { articleType: true },
  });
  assert(article?.articleType !== "SERVICE",
    "Los servicios no pueden tener variantes. Creá artículos de tipo SERVICE separados si necesitás diferenciación.");

  const code = s(data?.code);
  assert(code, "El código de variante es obligatorio.");
  assert(s(data?.name), "El nombre de variante es obligatorio.");

  const conflict = await prisma.articleVariant.findFirst({
    where: { articleId, code, deletedAt: null }, select: { id: true },
  });
  assert(!conflict, "Ya existe una variante con ese código en este artículo.");

  // Si existe una variante borrada con el mismo código, restaurarla en vez de crear una nueva
  // (evita colisión en el @@unique([articleId, code]) de la DB que no ignora soft deletes)
  const softDeleted = await prisma.articleVariant.findFirst({
    where: { articleId, code, deletedAt: { not: null } },
    select: { id: true },
  });
  if (softDeleted) {
    return restoreVariant(articleId, softDeleted.id, jewelryId, {
      name: s(data.name),
      sku: s(data?.sku),
    });
  }

  // SKU — unicidad en el tenant (si está informado)
  await assertSkuUnique(jewelryId, s(data?.sku));

  // Barcode de variante — se resuelve según barcodeSource
  const barcodeType = VALID_BARCODE_TYPES.has(data?.barcodeType) ? data.barcodeType : "CODE128";
  const { barcode: varBarcode, barcodeSource: varBarcodeSource } = await resolveBarcode({
    jewelryId,
    source:        data?.barcodeSource ?? "CUSTOM",
    code,
    sku:           s(data?.sku),
    customBarcode: data?.barcode,
    autoBarcode:   data?.autoBarcode === true,
    barcodeType,
    excludeVariantId: undefined,
  });

  return prisma.articleVariant.create({
    data: {
      articleId,
      jewelryId,
      code,
      name:                s(data.name),
      sku:                 s(data?.sku),
      barcode:             varBarcode ?? null,
      barcodeType,
      barcodeSource:       varBarcodeSource,
      weightOverride:      data?.weightOverride != null ? data.weightOverride : null,
      hechuraPriceOverride: data?.hechuraPriceOverride != null ? data.hechuraPriceOverride : null,
      priceOverride:       data?.priceOverride != null ? data.priceOverride : null,
      costPrice:           data?.costPrice != null ? data.costPrice : null,
      reorderPoint:        data?.reorderPoint != null ? data.reorderPoint : null,
      imageUrl:            s(data?.imageUrl),
      notes:               s(data?.notes),
      sortOrder:           typeof data?.sortOrder === "number" ? data.sortOrder : 0,
    },
    select: VARIANT_SELECT,
  });
}

export async function updateVariant(articleId: string, variantId: string, jewelryId: string, data: any) {
  await assertArticleOwnership(articleId, jewelryId);
  const variant = await prisma.articleVariant.findFirst({
    where: { id: variantId, articleId, deletedAt: null },
    select: { id: true, barcodeSource: true, code: true, sku: true },
  });
  assert(variant, "Variante no encontrada.");

  if (data?.code) {
    const conflict = await prisma.articleVariant.findFirst({
      where: { articleId, code: s(data.code), deletedAt: null, id: { not: variantId } },
      select: { id: true },
    });
    assert(!conflict, "Ya existe una variante con ese código en este artículo.");
  }
  // SKU — si se envía, validar unicidad excluyendo esta variante
  if (data?.sku !== undefined) {
    await assertSkuUnique(jewelryId, s(data.sku), undefined, variantId);
  }

  // Barcode — re-resolve si cambia source, code, sku, o barcode (CUSTOM)
  const vEffectiveSource = VALID_BARCODE_SOURCES.has(data?.barcodeSource)
    ? data.barcodeSource : variant!.barcodeSource;
  const vEffectiveCode = data?.code ? s(data.code) : variant!.code;
  const vEffectiveSku  = data?.sku !== undefined ? s(data.sku) : variant!.sku;
  const vBarcodeType = VALID_BARCODE_TYPES.has(data?.barcodeType) ? data.barcodeType : "CODE128";

  const vNeedsBarcodeResolve = data?.barcodeSource !== undefined
    || (data?.barcode !== undefined && vEffectiveSource === "CUSTOM")
    || (data?.code   !== undefined && vEffectiveSource === "CODE")
    || (data?.sku    !== undefined && vEffectiveSource === "SKU");

  let barcode: string | null | undefined = undefined;
  let vBarcodeSource: BarcodeSource | undefined = undefined;

  if (vNeedsBarcodeResolve) {
    const resolved = await resolveBarcode({
      jewelryId,
      source:        vEffectiveSource,
      code:          vEffectiveCode,
      sku:           vEffectiveSku,
      customBarcode: vEffectiveSource === "CUSTOM" ? data?.barcode : undefined,
      barcodeType:   vBarcodeType,
      excludeVariantId: variantId,
    });
    barcode = resolved.barcode;
    vBarcodeSource = resolved.barcodeSource;
  }

  return prisma.articleVariant.update({
    where: { id: variantId },
    data: {
      ...(data?.code ? { code: s(data.code) } : {}),
      ...(data?.name ? { name: s(data.name) } : {}),
      sku:                 data?.sku !== undefined ? s(data.sku) : undefined,
      barcode,
      barcodeType:         vNeedsBarcodeResolve ? vBarcodeType : undefined,
      barcodeSource:       vBarcodeSource,
      weightOverride:      data?.weightOverride !== undefined ? (data.weightOverride ?? null) : undefined,
      hechuraPriceOverride: data?.hechuraPriceOverride !== undefined ? (data.hechuraPriceOverride ?? null) : undefined,
      priceOverride:       data?.priceOverride !== undefined ? (data.priceOverride ?? null) : undefined,
      costPrice:           data?.costPrice !== undefined ? (data.costPrice ?? null) : undefined,
      reorderPoint:        data?.reorderPoint !== undefined ? (data.reorderPoint ?? null) : undefined,
      imageUrl:            data?.imageUrl !== undefined ? s(data.imageUrl) : undefined,
      notes:               data?.notes !== undefined ? s(data.notes) : undefined,
      ...(typeof data?.sortOrder === "number" ? { sortOrder: data.sortOrder } : {}),
    },
    select: VARIANT_SELECT,
  });
}

export async function toggleVariant(articleId: string, variantId: string, jewelryId: string) {
  await assertArticleOwnership(articleId, jewelryId);
  const variant = await prisma.articleVariant.findFirst({
    where: { id: variantId, articleId, deletedAt: null },
    select: { id: true, isActive: true },
  });
  assert(variant, "Variante no encontrada.");
  return prisma.articleVariant.update({
    where: { id: variantId },
    data: { isActive: !variant!.isActive },
    select: VARIANT_SELECT,
  });
}

export async function removeVariant(articleId: string, variantId: string, jewelryId: string) {
  await assertArticleOwnership(articleId, jewelryId);
  const variant = await prisma.articleVariant.findFirst({
    where: { id: variantId, articleId, deletedAt: null }, select: { id: true },
  });
  assert(variant, "Variante no encontrada.");
  await prisma.articleVariant.update({
    where: { id: variantId },
    data: { deletedAt: new Date(), isActive: false },
  });
  return { id: variantId };
}

export async function restoreVariant(
  articleId: string,
  variantId: string,
  jewelryId: string,
  overrides?: { name?: string; sku?: string },
) {
  await assertArticleOwnership(articleId, jewelryId);
  const variant = await prisma.articleVariant.findFirst({
    where: { id: variantId, articleId, jewelryId, deletedAt: { not: null } },
    select: { id: true, sku: true },
  });
  assert(variant, "Variante borrada no encontrada.");
  const newSku = overrides?.sku || variant!.sku || undefined;
  await assertSkuUnique(jewelryId, newSku || "", undefined, variantId);
  return prisma.articleVariant.update({
    where: { id: variantId },
    data: {
      deletedAt: null,
      isActive: true,
      ...(overrides?.name ? { name: overrides.name } : {}),
      ...(newSku !== undefined ? { sku: newSku } : {}),
    },
    select: VARIANT_SELECT,
  });
}

// ===========================================================================
// Reorder variants
// ===========================================================================
export async function reorderVariants(articleId: string, jewelryId: string, ids: string[]) {
  await assertArticleOwnership(articleId, jewelryId);
  assert(Array.isArray(ids) && ids.length > 0, "ids debe ser un array no vacío.");
  // Verify all provided IDs belong to this article+tenant
  const existing = await prisma.articleVariant.findMany({
    where: { articleId, jewelryId, deletedAt: null },
    select: { id: true },
  });
  const validSet = new Set(existing.map(v => v.id));
  const filtered = ids.filter(id => validSet.has(id));
  if (filtered.length === 0) return { ok: true };
  await prisma.$transaction(
    filtered.map((id, i) =>
      prisma.articleVariant.update({ where: { id }, data: { sortOrder: i } })
    )
  );
  return { ok: true };
}

// ===========================================================================
// Attribute values (bulk set)
// ===========================================================================
export async function setAttributeValues(
  articleId: string,
  jewelryId: string,
  values: { assignmentId: string; value: string }[]
) {
  await assertArticleOwnership(articleId, jewelryId);
  assert(Array.isArray(values), "values debe ser un array.");

  await prisma.$transaction(
    values.map(({ assignmentId, value }) =>
      prisma.articleAttributeValue.upsert({
        where: { articleId_assignmentId: { articleId, assignmentId } },
        create: { articleId, jewelryId, assignmentId, value: s(value) },
        update: { value: s(value) },
      })
    )
  );

  return prisma.articleAttributeValue.findMany({
    where: { articleId },
    select: {
      id: true, assignmentId: true, value: true,
      assignment: {
        select: {
          id: true, isRequired: true, sortOrder: true,
          definition: {
            select: {
              id: true, name: true, code: true, inputType: true,
              options: { select: { id: true, label: true, value: true } },
            },
          },
        },
      },
    },
    orderBy: { assignment: { sortOrder: "asc" as const } },
  });
}

// ===========================================================================
// Images
// ===========================================================================
const IMAGE_SELECT = { id: true, url: true, label: true, isMain: true, sortOrder: true } as const;

export async function addImage(
  articleId: string,
  jewelryId: string,
  data: { url: string; label?: string; isMain?: boolean }
) {
  await assertArticleOwnership(articleId, jewelryId);
  assert(s(data?.url), "URL de imagen requerida.");
  const isMain = !!data?.isMain;

  return prisma.$transaction(async (tx) => {
    if (isMain) {
      await tx.articleImage.updateMany({ where: { articleId }, data: { isMain: false } });
      await tx.article.update({ where: { id: articleId }, data: { mainImageUrl: data.url } });
    }
    const existingCount = await tx.articleImage.count({ where: { articleId } });
    const autoMain = existingCount === 0;
    if (autoMain && !isMain) {
      await tx.article.update({ where: { id: articleId }, data: { mainImageUrl: data.url } });
    }
    return tx.articleImage.create({
      data: {
        articleId, jewelryId, url: data.url, label: s(data?.label),
        isMain: isMain || autoMain, sortOrder: 0,
      },
      select: IMAGE_SELECT,
    });
  });
}

export async function setMainImage(articleId: string, imageId: string, jewelryId: string) {
  await assertArticleOwnership(articleId, jewelryId);
  const image = await prisma.articleImage.findFirst({
    where: { id: imageId, articleId }, select: { id: true, url: true },
  });
  assert(image, "Imagen no encontrada.");
  return prisma.$transaction(async (tx) => {
    await tx.articleImage.updateMany({ where: { articleId }, data: { isMain: false } });
    await tx.article.update({ where: { id: articleId }, data: { mainImageUrl: image!.url } });
    return tx.articleImage.update({ where: { id: imageId }, data: { isMain: true }, select: IMAGE_SELECT });
  });
}

export async function updateImageLabel(
  articleId: string, imageId: string, jewelryId: string, label: string
) {
  await assertArticleOwnership(articleId, jewelryId);
  const image = await prisma.articleImage.findFirst({ where: { id: imageId, articleId }, select: { id: true } });
  assert(image, "Imagen no encontrada.");
  return prisma.articleImage.update({ where: { id: imageId }, data: { label: s(label) }, select: IMAGE_SELECT });
}

export async function removeImage(articleId: string, imageId: string, jewelryId: string) {
  await assertArticleOwnership(articleId, jewelryId);
  const image = await prisma.articleImage.findFirst({
    where: { id: imageId, articleId }, select: { id: true, isMain: true, url: true },
  });
  assert(image, "Imagen no encontrada.");
  return prisma.$transaction(async (tx) => {
    await tx.articleImage.delete({ where: { id: imageId } });
    if (image!.isMain) {
      const next = await tx.articleImage.findFirst({ where: { articleId }, orderBy: { sortOrder: "asc" } });
      if (next) {
        await tx.articleImage.update({ where: { id: next.id }, data: { isMain: true } });
        await tx.article.update({ where: { id: articleId }, data: { mainImageUrl: next.url } });
      } else {
        await tx.article.update({ where: { id: articleId }, data: { mainImageUrl: "" } });
      }
    }
    return { id: imageId };
  });
}

// ===========================================================================
// Variant Images
// ===========================================================================
async function assertVariantOwnership(articleId: string, variantId: string, jewelryId: string) {
  const v = await prisma.articleVariant.findFirst({
    where: { id: variantId, articleId, jewelryId, deletedAt: null },
    select: { id: true },
  });
  assert(v, "Variante no encontrada.", 404);
}

export async function addVariantImage(
  articleId: string,
  variantId: string,
  jewelryId: string,
  data: { url: string; label?: string; isMain?: boolean }
) {
  await assertArticleOwnership(articleId, jewelryId);
  await assertVariantOwnership(articleId, variantId, jewelryId);
  assert(s(data?.url), "URL de imagen requerida.");

  return prisma.$transaction(async (tx) => {
    const existingCount = await tx.articleVariantImage.count({ where: { variantId } });
    assert(existingCount < 5, "Máximo 5 imágenes por variante.", 400);

    const isMain = !!data?.isMain || existingCount === 0; // primera imagen → principal automáticamente
    if (isMain) {
      await tx.articleVariantImage.updateMany({ where: { variantId }, data: { isMain: false } });
      await tx.articleVariant.update({ where: { id: variantId }, data: { imageUrl: data.url } });
    }
    return tx.articleVariantImage.create({
      data: {
        variantId, articleId, jewelryId,
        url: data.url,
        label: s(data?.label),
        isMain,
        sortOrder: existingCount,
      },
      select: VARIANT_IMAGE_SELECT,
    });
  });
}

export async function setVariantMainImage(
  articleId: string, variantId: string, imageId: string, jewelryId: string
) {
  await assertArticleOwnership(articleId, jewelryId);
  await assertVariantOwnership(articleId, variantId, jewelryId);
  const image = await prisma.articleVariantImage.findFirst({
    where: { id: imageId, variantId }, select: { id: true, url: true },
  });
  assert(image, "Imagen no encontrada.");
  return prisma.$transaction(async (tx) => {
    await tx.articleVariantImage.updateMany({ where: { variantId }, data: { isMain: false } });
    await tx.articleVariant.update({ where: { id: variantId }, data: { imageUrl: image!.url } });
    return tx.articleVariantImage.update({ where: { id: imageId }, data: { isMain: true }, select: VARIANT_IMAGE_SELECT });
  });
}

export async function removeVariantImage(
  articleId: string, variantId: string, imageId: string, jewelryId: string
) {
  await assertArticleOwnership(articleId, jewelryId);
  await assertVariantOwnership(articleId, variantId, jewelryId);
  const image = await prisma.articleVariantImage.findFirst({
    where: { id: imageId, variantId }, select: { id: true, isMain: true, url: true },
  });
  assert(image, "Imagen no encontrada.");
  return prisma.$transaction(async (tx) => {
    await tx.articleVariantImage.delete({ where: { id: imageId } });
    if (image!.isMain) {
      const next = await tx.articleVariantImage.findFirst({
        where: { variantId }, orderBy: { sortOrder: "asc" },
      });
      if (next) {
        await tx.articleVariantImage.update({ where: { id: next.id }, data: { isMain: true } });
        await tx.articleVariant.update({ where: { id: variantId }, data: { imageUrl: next.url } });
      } else {
        await tx.articleVariant.update({ where: { id: variantId }, data: { imageUrl: "" } });
      }
    }
    return { id: imageId };
  });
}

export async function updateVariantImageLabel(
  articleId: string, variantId: string, imageId: string, jewelryId: string, label: string
) {
  await assertArticleOwnership(articleId, jewelryId);
  await assertVariantOwnership(articleId, variantId, jewelryId);
  const image = await prisma.articleVariantImage.findFirst({ where: { id: imageId, variantId }, select: { id: true } });
  assert(image, "Imagen no encontrada.");
  return prisma.articleVariantImage.update({ where: { id: imageId }, data: { label: s(label) }, select: VARIANT_IMAGE_SELECT });
}

// ===========================================================================
// Stock helpers internos
// ===========================================================================
async function findStock(
  tx: Prisma.TransactionClient,
  key: { jewelryId: string; warehouseId: string; articleId: string; variantId: string | null }
) {
  return tx.articleStock.findFirst({
    where: {
      jewelryId: key.jewelryId,
      warehouseId: key.warehouseId,
      articleId: key.articleId,
      variantId: key.variantId ?? null,
    },
    select: { id: true, quantity: true, reservedQty: true },
  });
}

export async function applyStockDelta(
  tx: Prisma.TransactionClient,
  params: {
    jewelryId: string;
    warehouseId: string;
    articleId: string;
    variantId: string | null;
    delta: number | Prisma.Decimal;
    preventNegative?: boolean;
  }
): Promise<void> {
  const { jewelryId, warehouseId, articleId, variantId, preventNegative = false } = params;
  const delta = new Prisma.Decimal(params.delta.toString());
  const existing = await findStock(tx, { jewelryId, warehouseId, articleId, variantId });

  if (existing) {
    const newQty = existing.quantity.add(delta);
    if (preventNegative) {
      assert(newQty.gte(0),
        `Stock insuficiente. Disponible: ${existing.quantity.toFixed(4)}, solicitado: ${delta.abs().toFixed(4)}.`
      );
    }
    await tx.articleStock.update({ where: { id: existing.id }, data: { quantity: newQty } });
  } else {
    if (preventNegative) {
      assert(delta.gte(0),
        `Stock insuficiente. No hay stock registrado y se quiere descontar ${delta.abs().toFixed(4)}.`
      );
    }
    await tx.articleStock.create({
      data: { jewelryId, warehouseId, articleId, variantId: variantId ?? null, quantity: delta },
    });
  }
}

// ===========================================================================
// Stock (BY_ARTICLE) — read
// ===========================================================================
const STOCK_SELECT = {
  id: true,
  variantId: true,
  warehouseId: true,
  quantity: true,
  reservedQty: true,
  updatedAt: true,
  variant:   { select: { id: true, code: true, name: true } },
  warehouse: { select: { id: true, name: true, code: true } },
} as const;

export async function getStock(articleId: string, jewelryId: string) {
  await assertArticleOwnership(articleId, jewelryId);
  return prisma.articleStock.findMany({
    where: { articleId, jewelryId },
    select: STOCK_SELECT,
    orderBy: { warehouse: { name: "asc" as const } },
  });
}

// ===========================================================================
// adjustStock — ajuste con trazabilidad en ArticleMovement
// ===========================================================================
export async function adjustStock(
  articleId: string,
  jewelryId: string,
  userId: string,
  data: { warehouseId: string; variantId?: string | null; quantity: number; note?: string }
) {
  await assertArticleOwnership(articleId, jewelryId);

  const article = await prisma.article.findUnique({
    where: { id: articleId },
    select: { stockMode: true, articleType: true },
  });
  assert(article?.articleType !== "SERVICE",
    "Los servicios no tienen stock.");
  assert(article?.stockMode === "BY_ARTICLE",
    "Este artículo no tiene modo de stock BY_ARTICLE.");
  assert(data?.warehouseId, "warehouseId es obligatorio.");
  assert(data?.quantity != null, "quantity es obligatoria.");

  const warehouse = await prisma.warehouse.findFirst({
    where: { id: data.warehouseId, jewelryId, deletedAt: null }, select: { id: true },
  });
  assert(warehouse, "Almacén no encontrado.");

  const variantId = data?.variantId ?? null;
  const newQty = new Prisma.Decimal(data.quantity.toString());

  return prisma.$transaction(async (tx) => {
    const existing = await findStock(tx, { jewelryId, warehouseId: data.warehouseId, articleId, variantId });
    const currentQty = existing?.quantity ?? new Prisma.Decimal(0);
    const delta = newQty.sub(currentQty);

    if (!delta.equals(0)) {
      const count = await tx.articleMovement.count({ where: { jewelryId, kind: "ADJUST" } });
      const code = `AA-${String(count + 1).padStart(4, "0")}`;
      await tx.articleMovement.create({
        data: {
          jewelryId, kind: "ADJUST", code,
          note: s(data?.note || "Ajuste manual de stock"),
          effectiveAt: new Date(),
          warehouseId: data.warehouseId,
          createdById: userId || null,
          lines: {
            create: { jewelryId, articleId, variantId: variantId ?? null, quantity: delta },
          },
        },
      });
    }

    if (existing) {
      return tx.articleStock.update({
        where: { id: existing.id },
        data: { quantity: newQty },
        select: STOCK_SELECT,
      });
    } else {
      return tx.articleStock.create({
        data: { articleId, variantId: variantId ?? null, warehouseId: data.warehouseId, jewelryId, quantity: newQty },
        select: STOCK_SELECT,
      });
    }
  });
}

// ===========================================================================
// calcMaterialAvailability — disponibilidad teórica por material
// ===========================================================================

/** Implementación interna sin volver a buscar el artículo (para reusar en getArticle). */
async function _calcMaterialAvailabilityInternal(
  articleId: string,
  jewelryId: string,
  art: {
    stockMode: string;
    mermaPercent: any;
    compositions: Array<{ variantId: string; grams: any; metalVariant: { id: string; name: string } }>;
    category: { mermaPercent: any } | null;
  }
) {
  if (art.stockMode !== "BY_MATERIAL" || art.compositions.length === 0) {
    return { articleId, stockMode: art.stockMode, byWarehouse: [], totalFabricable: 0 };
  }

  const jewelry = await prisma.jewelry.findUnique({
    where: { id: jewelryId }, select: { defaultMermaPercent: true },
  });
  const mermaPercent = art.mermaPercent
    ?? art.category?.mermaPercent
    ?? jewelry?.defaultMermaPercent
    ?? new Prisma.Decimal(0);
  const mermaFactor = new Prisma.Decimal(1).add(
    new Prisma.Decimal(mermaPercent.toString()).div(100)
  );

  const warehouses = await prisma.warehouse.findMany({
    where: { jewelryId, deletedAt: null, isActive: true }, select: { id: true, name: true },
  });

  const variantIds = art.compositions.map((c) => c.variantId);
  const stocks = await prisma.warehouseStock.findMany({
    where: { jewelryId, variantId: { in: variantIds } },
    select: { warehouseId: true, variantId: true, grams: true },
  });

  const stockMap: Record<string, Record<string, Prisma.Decimal>> = {};
  for (const st of stocks) {
    if (!stockMap[st.warehouseId]) stockMap[st.warehouseId] = {};
    stockMap[st.warehouseId][st.variantId] = st.grams;
  }

  const byWarehouse = warehouses.map((wh) => {
    let minUnits = Infinity;
    let bottleneckVariantId: string | null = null;
    let bottleneckVariantName: string | null = null;
    for (const comp of art.compositions) {
      const available = stockMap[wh.id]?.[comp.variantId] ?? new Prisma.Decimal(0);
      const gramsNeeded = new Prisma.Decimal(comp.grams.toString()).mul(mermaFactor);
      if (gramsNeeded.equals(0)) continue;
      const units = Math.floor(available.div(gramsNeeded).toNumber());
      if (units < minUnits) {
        minUnits = units;
        bottleneckVariantId = comp.variantId;
        bottleneckVariantName = comp.metalVariant.name;
      }
    }
    const fabricable = minUnits === Infinity ? 0 : minUnits;
    return {
      warehouseId: wh.id,
      warehouseName: wh.name,
      fabricableUnits: fabricable,
      bottleneckVariantId:   fabricable === 0 ? bottleneckVariantId : null,
      bottleneckVariantName: fabricable === 0 ? bottleneckVariantName : null,
    };
  });

  const totalFabricable = byWarehouse.reduce((sum, w) => sum + w.fabricableUnits, 0);
  return { articleId, stockMode: art.stockMode, byWarehouse, totalFabricable };
}

/** Endpoint público — puede usarse standalone. */
export async function calcMaterialAvailability(
  articleId: string,
  jewelryId: string,
  warehouseId?: string
) {
  const article = await prisma.article.findFirst({
    where: { id: articleId, jewelryId, deletedAt: null },
    select: {
      id: true, stockMode: true, mermaPercent: true,
      compositions: {
        select: {
          variantId: true, grams: true,
          metalVariant: { select: { id: true, name: true } },
        },
      },
      category: { select: { mermaPercent: true } },
    },
  });
  assert(article, "Artículo no encontrado.", 404);
  const art = article!;

  if (art.stockMode !== "BY_MATERIAL") {
    return { articleId, stockMode: art.stockMode, byWarehouse: [], totalFabricable: 0 };
  }
  assert(art.compositions.length > 0, "El artículo no tiene composición metálica definida.");

  const result = await _calcMaterialAvailabilityInternal(articleId, jewelryId, art as any);

  // Filtrar por almacén si se especificó
  if (warehouseId) {
    result.byWarehouse = result.byWarehouse.filter((w) => w.warehouseId === warehouseId);
  }
  return result;
}

// ===========================================================================
// listBrands — marcas distintas del tenant (campo brand de Article)
// ===========================================================================
export async function listBrands(jewelryId: string): Promise<string[]> {
  const rows = await prisma.article.findMany({
    where: {
      jewelryId,
      deletedAt: null,
      brand: { not: "" },
    },
    select: { brand: true },
    distinct: ["brand"],
    orderBy: { brand: "asc" },
  });
  return rows.map((r) => r.brand).filter(Boolean) as string[];
}

// ===========================================================================
// lookupByBarcode — búsqueda exacta por barcode en artículos y variantes
// ===========================================================================
export async function lookupByBarcode(jewelryId: string, barcode: string) {
  assert(s(barcode), "barcode es obligatorio.");

  const [article, variant] = await Promise.all([
    prisma.article.findFirst({
      where: { jewelryId, barcode, deletedAt: null },
      select: { id: true, code: true, name: true, articleType: true, stockMode: true, mainImageUrl: true },
    }),
    prisma.articleVariant.findFirst({
      where: { jewelryId, barcode, deletedAt: null },
      select: {
        id: true, code: true, name: true,
        article: { select: { id: true, code: true, name: true, articleType: true } },
      },
    }),
  ]);

  if (article) return { type: "article" as const, article };
  if (variant) return { type: "variant" as const, variant, article: variant.article };
  return null;
}

// ===========================================================================
// Cost Lines (nueva composición de costo por líneas)
// ===========================================================================
export type CostLineInput = {
  id?: string;
  type: string;
  label: string;
  quantity: number;
  unitValue: number;
  currencyId?: string | null;
  mermaPercent?: number | null;
  metalVariantId?: string | null;
  catalogItemId?: string | null;
  sortOrder?: number;
};

/** Reemplaza todas las líneas de costo del artículo (operación atómica). */
export async function setCostLines(
  articleId: string,
  jewelryId: string,
  lines: CostLineInput[]
) {
  await assertArticleOwnership(articleId, jewelryId);

  const VALID_TYPES = new Set(["METAL", "HECHURA", "PRODUCT", "SERVICE", "MANUAL"]);

  for (const l of lines) {
    assert(VALID_TYPES.has(l.type), `Tipo de línea inválido: ${l.type}`);
    assert(l.quantity >= 0, "La cantidad no puede ser negativa.");
    assert(l.unitValue >= 0, "El valor unitario no puede ser negativo.");
    if (l.type === "METAL") {
      assert(l.metalVariantId, "Las líneas de tipo METAL requieren metalVariantId.");
    }
  }

  await prisma.$transaction(async (tx) => {
    // Borrar líneas anteriores
    await tx.articleCostLine.deleteMany({ where: { articleId, jewelryId } });

    // Crear nuevas líneas
    if (lines.length > 0) {
      await tx.articleCostLine.createMany({
        data: lines.map((l, idx) => ({
          articleId,
          jewelryId,
          type:           l.type as any,
          label:          l.label ?? "",
          quantity:       l.quantity,
          unitValue:      l.unitValue,
          currencyId:     l.type === "METAL" ? null : (l.currencyId ?? null),
          mermaPercent:   l.type === "METAL" ? (l.mermaPercent ?? null) : null,
          metalVariantId: l.type === "METAL" ? (l.metalVariantId ?? null) : null,
          catalogItemId:  l.catalogItemId ?? null,
          sortOrder:      l.sortOrder ?? idx,
        })),
      });
    }
  });

  // Devolver artículo actualizado con costo computado
  return getArticle(articleId, jewelryId);
}
