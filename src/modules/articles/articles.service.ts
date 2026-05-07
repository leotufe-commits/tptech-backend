import { Prisma, BarcodeSource } from "@prisma/client";
import { prisma } from "../../lib/prisma.js";
import {
  findStock as engineFindStock,
  applyStockDelta as engineApplyStockDelta,
  recalcArticleStock,
} from "../../lib/stock-engine.js";
import {
  resolvePriceList,
  applyPriceList,
  PL_COMPUTE_SELECT,
  buildBatchCostContext,
  calculateCostFromLines,
  isPriceListValidNow,
  isPromotionValid,
  applyTaxesFromMap,
  computePurchaseTaxes as enginePurchaseTaxes,
  type CostBreakdown,
  type ArticleCostInput,
  type PurchaseTaxResult,
  type PurchaseTaxBreakdownItem,
} from "../../lib/pricing-engine/pricing-engine.js";
import type { CostLineInput as EngineCostLineInput } from "../../lib/pricing-engine/pricing-engine.js";
import {
  normalizeComboFields,
  validateComboComponentsShape,
  validateComboComponentsAgainstDb,
  computeComboAvailability,
} from "../../lib/combo.utils.js";
import { assignGroupToArticle } from "../article-groups/article-groups.service.js";

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
const VALID_BARCODE_TYPES   = new Set(["CODE128", "EAN13", "QR"]);
const VALID_BARCODE_SOURCES = new Set(["CODE", "SKU", "CUSTOM"]);

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
// Validaciones defensivas de contratos con el pricing-engine
//
// El motor de precios (src/lib/pricing-engine) asume ciertas invariantes:
//   1. Las variantes heredan precio y costo del artículo padre. El único
//      override soportado es `weightOverride`.
//   2. Los servicios (articleType=SERVICE) no tienen composición metálica,
//      merma ni hechura; su costo se modela como línea SERVICE o MANUAL.
//
// Estas funciones rechazan payloads que violan el contrato para que el motor
// nunca tenga que lidiar con datos inconsistentes.
// ===========================================================================

/**
 * Campos de precio/costo que NO pueden guardarse en una variante.
 * El motor siempre lee estos valores del artículo padre.
 */
const FORBIDDEN_VARIANT_PRICING_FIELDS = [
  "salePrice",
  "costPrice",
  "priceWithTax",
  "costWithTax",
  "costPerGram",
  "useManualSalePrice",
  "manualSalePrice",
  "mermaPercent",
  "manualAdjustmentKind",
  "manualAdjustmentType",
  "manualAdjustmentValue",
  "manualTaxIds",
  "marginPercent",
  "commercialMode",
  "comboAdjustmentKind",
  "comboAdjustmentValue",
] as const;

function assertNoVariantPricingOverrides(data: any): void {
  if (!data || typeof data !== "object") return;
  const offending = FORBIDDEN_VARIANT_PRICING_FIELDS.filter((k) => data[k] !== undefined);
  assert(
    offending.length === 0,
    `Las variantes heredan precio y costo del artículo padre. Campos no permitidos en variante: ${offending.join(", ")}. Solo weightOverride está permitido como override.`,
  );
}

/**
 * Servicios no manejan stock físico ni composición metálica.
 *
 * Reglas vigentes (TPTech):
 *  - HECHURA, SERVICE, MANUAL → permitidos (un servicio puede tener costo de
 *    mano de obra, sub-servicios y ajustes manuales).
 *  - PRODUCT → permitido SOLO con `affectsStock=false` (no se puede descontar
 *    stock físico desde un servicio).
 *  - METAL → bloqueado (los servicios no se valúan por gramaje).
 *  - `metalVariantId` en cualquier línea → bloqueado.
 *  - `mermaPercent` distinto de 0/null → bloqueado.
 *
 * Se invoca desde createArticle, updateArticle y setCostLines.
 */
function assertServiceArticleComposition(
  articleType: string,
  data: { mermaPercent?: any } | null,
  costLines?: Array<{ type?: string; metalVariantId?: string | null; affectsStock?: boolean }> | null,
): void {
  if (articleType !== "SERVICE") return;

  if (data && data.mermaPercent !== undefined && data.mermaPercent !== null) {
    const m = Number(data.mermaPercent);
    assert(
      Number.isFinite(m) && m === 0,
      "Los servicios no pueden tener merma. Dejá mermaPercent vacío o en 0.",
    );
  }

  if (costLines && costLines.length > 0) {
    for (const l of costLines) {
      assert(
        l.type !== "METAL",
        "Los servicios no pueden tener líneas de tipo METAL en su composición de costo.",
      );
      assert(
        !l.metalVariantId,
        "Los servicios no pueden referenciar un metalVariantId en sus líneas de costo.",
      );
      assert(
        !(l.type === "PRODUCT" && l.affectsStock === true),
        "Los servicios no pueden descontar stock de componentes. Desmarcá \"Descuenta stock\" en las líneas PRODUCT.",
      );
    }
  }
}

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
  const barcodeSource = (VALID_BARCODE_SOURCES.has(opts.source) ? opts.source : "SKU") as BarcodeSource;
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

  // Normalizar: string vacío no es barcode válido → null
  // (cubre el caso donde s(customBarcode) devuelve "" tras trim de espacios)
  if (barcode === "") barcode = null;

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
  commercialMode: true,
  comboAdjustmentKind: true,
  comboAdjustmentValue: true,
  sku: true,
  barcode: true,
  barcodeType: true,
  barcodeSource: true,
  brand: true,
  manufacturer: true,
  salePrice: true,
  mermaPercent: true,
  manualAdjustmentKind: true,
  manualAdjustmentType: true,
  manualAdjustmentValue: true,
  manualTaxIds: true,
  sellWithoutVariants: true,
  showInStore: true,
  isReturnable: true,
  notes: true,
  unitOfMeasure: true,
  reorderPoint: true,
  dimensionLength: true,
  dimensionWidth: true,
  dimensionHeight: true,
  dimensionUnit: true,
  weight: true,
  weightUnit: true,
  minSaleQuantity: true,
  maxSaleQuantity: true,
  defaultQuantity: true,
  inventoryAccount: true,
  mainImageUrl: true,
  isFavorite: true,
  isActive: true,
  useManualSalePrice: true,
  createdAt: true,
  updatedAt: true,
  category:          { select: { id: true, name: true, mermaPercent: true } },
  preferredSupplier: { select: { id: true, code: true, displayName: true } },
  groupItems:        { where: { itemType: "ARTICLE" }, take: 1, select: { groupId: true, groupOrder: true, group: { select: { id: true, name: true, slug: true } } } },
  costComposition: {
    select: {
      type:             true,
      label:            true,
      quantity:         true,
      unitValue:        true,
      currencyId:       true,
      mermaPercent:     true,
      metalVariantId:   true,
      catalogItemId:    true,
      catalogVariantId: true,
      sortOrder:        true,
      lineAdjKind:      true,
      lineAdjType:      true,
      lineAdjValue:     true,
      currency: {
        select: { id: true, code: true, symbol: true },
      },
      metalVariant: {
        select: {
          id: true, name: true, sku: true, purity: true,
          metal: { select: { id: true, name: true } },
        },
      },
      // catalogItem: relación a Article (producto/servicio referenciado en la composición).
      catalogItem: { select: { id: true, code: true, name: true, sku: true } },
      // FASE 2: variante específica del componente (cuando aplica).
      catalogVariant: {
        select: { id: true, code: true, name: true, sku: true, weightOverride: true },
      },
    },
    orderBy: { sortOrder: "asc" as const },
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
      reorderPoint: true,
      openingStock: true,
      minSaleQuantity: true,
      maxSaleQuantity: true,
      defaultQuantity: true,
      weightOverride: true,
      notes: true,
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
  commercialMode: true,
  comboAdjustmentKind: true,
  comboAdjustmentValue: true,
  sku: true,
  barcode: true,
  barcodeType: true,
  barcodeSource: true,
  brand: true,
  manufacturer: true,
  supplierCode: true,
  preferredSupplierId: true,
  salePrice: true,
  useManualSalePrice: true,
  mermaPercent: true,
  manualAdjustmentKind: true,
  manualAdjustmentType: true,
  manualAdjustmentValue: true,
  manualTaxIds: true,
  sellWithoutVariants: true,
  isReturnable: true,
  showInStore: true,
  unitOfMeasure: true,
  reorderPoint: true,
  dimensionLength: true,
  dimensionWidth: true,
  dimensionHeight: true,
  dimensionUnit: true,
  weight: true,
  weightUnit: true,
  minSaleQuantity: true,
  maxSaleQuantity: true,
  defaultQuantity: true,
  inventoryAccount: true,
  mainImageUrl: true,
  isFavorite: true,
  isActive: true,
  notes: true,
  createdAt: true,
  updatedAt: true,
  category:          { select: { id: true, name: true, mermaPercent: true } },
  preferredSupplier: { select: { id: true, code: true, displayName: true } },
  groupItems:        { where: { itemType: "ARTICLE" }, take: 1, select: { groupId: true, groupOrder: true, group: { select: { id: true, name: true, slug: true } } } },
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
      reorderPoint: true,
      openingStock: true,
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
      catalogVariantId: true,
      sortOrder: true,
      lineAdjKind:  true,
      lineAdjType:  true,
      lineAdjValue: true,
      currency: { select: { id: true, code: true, symbol: true } },
      metalVariant: {
        select: {
          id: true, name: true, sku: true, purity: true,
          metal: { select: { id: true, name: true } },
        },
      },
      catalogItem: { select: { id: true, code: true, name: true, sku: true } },
      catalogVariant: {
        select: { id: true, code: true, name: true, sku: true, weightOverride: true },
      },
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
  reorderPoint: true,
  openingStock: true,
  minSaleQuantity: true,
  maxSaleQuantity: true,
  defaultQuantity: true,
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
// enrichArticles — resolución de precio y stock para otros módulos
// Reúsa batchComputeCosts + batchResolveSalePricesNoClient + batchLoadStockSummary
// sin duplicar lógica. Usado por article-groups.service.
// ===========================================================================
export async function enrichArticles(
  ids: string[],
  jewelryId: string,
): Promise<Map<string, { resolvedSalePrice: string | null; resolvedSalePriceWithTax: string | null; stockTotal: number }>> {
  const out = new Map<string, { resolvedSalePrice: string | null; resolvedSalePriceWithTax: string | null; stockTotal: number }>();
  if (ids.length === 0) return out;

  const rows = await prisma.article.findMany({
    where: { id: { in: ids }, jewelryId, deletedAt: null },
    select: ARTICLE_LIST_SELECT,
  });

  const computedCosts = await batchComputeCosts(jewelryId, rows as any[]);
  const rowsWithCost  = rows.map((r) => ({
    ...r,
    computedCostBase:    computedCosts.get(r.id)?.computedCostBase    ?? null,
    computedCostWithTax: computedCosts.get(r.id)?.computedCostWithTax ?? null,
  }));

  const resolvedPrices = await batchResolveSalePricesNoClient(jewelryId, rowsWithCost);

  const byArticleIds = rows.filter((r) => r.stockMode === "BY_ARTICLE").map((r) => r.id);
  const stockMap     = await batchLoadStockSummary(jewelryId, byArticleIds);

  for (const row of rows) {
    const stockEntry = row.stockMode === "BY_ARTICLE" ? stockMap.get(row.id) : null;
    const p = resolvedPrices.get(row.id);
    out.set(row.id, {
      resolvedSalePrice:        p?.resolvedSalePrice        ?? null,
      resolvedSalePriceWithTax: p?.resolvedSalePriceWithTax ?? null,
      stockTotal:               stockEntry?.total ?? 0,
    });
  }
  return out;
}

// ===========================================================================
// enrichVariants — precio (del padre) y stock (de la variante) para grupos
// ===========================================================================
export async function enrichVariants(
  variantIds: string[],
  jewelryId: string,
): Promise<Map<string, { resolvedSalePrice: string | null; resolvedSalePriceWithTax: string | null; stockTotal: number }>> {
  const out = new Map<string, { resolvedSalePrice: string | null; resolvedSalePriceWithTax: string | null; stockTotal: number }>();
  if (variantIds.length === 0) return out;

  // Obtener artículo padre de cada variante
  const variants = await prisma.articleVariant.findMany({
    where: { id: { in: variantIds }, jewelryId },
    select: { id: true, articleId: true },
  });
  const articleIds = [...new Set(variants.map((v) => v.articleId))];

  // Precio: resuelto a nivel de artículo padre
  const articles = await prisma.article.findMany({
    where: { id: { in: articleIds }, jewelryId, deletedAt: null },
    select: ARTICLE_LIST_SELECT,
  });
  const computedCosts = await batchComputeCosts(jewelryId, articles as any[]);
  const rowsWithCost  = articles.map((r) => ({
    ...r,
    computedCostBase:    computedCosts.get(r.id)?.computedCostBase    ?? null,
    computedCostWithTax: computedCosts.get(r.id)?.computedCostWithTax ?? null,
  }));
  const resolvedPrices = await batchResolveSalePricesNoClient(jewelryId, rowsWithCost);

  // Stock: por variante (suma de todos los depósitos)
  const stocks = await prisma.articleStock.findMany({
    where: { jewelryId, variantId: { in: variantIds } },
    select: { variantId: true, quantity: true },
  });
  const stockByVariant = new Map<string, number>();
  for (const s of stocks) {
    if (s.variantId) {
      const qty = parseFloat(s.quantity.toString());
      stockByVariant.set(s.variantId, (stockByVariant.get(s.variantId) ?? 0) + qty);
    }
  }

  // Combinar por variantId
  const articlePriceMap = new Map(articles.map((a) => [a.id, resolvedPrices.get(a.id)]));
  for (const v of variants) {
    const priceInfo = articlePriceMap.get(v.articleId);
    out.set(v.id, {
      resolvedSalePrice:        priceInfo?.resolvedSalePrice        ?? null,
      resolvedSalePriceWithTax: priceInfo?.resolvedSalePriceWithTax ?? null,
      stockTotal:               stockByVariant.get(v.id) ?? 0,
    });
  }
  return out;
}

// ===========================================================================
// Batch resolve sale price — sin contexto de cliente
// 3 queries paralelas al inicio, resto en memoria.
// ===========================================================================
type NoClientPriceResult = {
  resolvedSalePrice:        string | null;
  resolvedSalePriceWithTax: string | null;
  resolvedPriceSource: "PROMOTION" | "PRICE_LIST_CATEGORY" | "PRICE_LIST_GENERAL" | "MANUAL_OVERRIDE" | "MANUAL_FALLBACK" | "NONE";
  resolvedPriceName:   string | null;
};

// Select canónico de listas de precio — importado del motor de pricing
const PL_LIST_SELECT = PL_COMPUTE_SELECT;


async function batchResolveSalePricesNoClient(
  jewelryId: string,
  rows: any[],
): Promise<Map<string, NoClientPriceResult>> {
  const result = new Map<string, NoClientPriceResult>();
  if (rows.length === 0) return result;

  const D = Prisma.Decimal;
  const articleIds      = rows.map((r) => r.id);
  const uniqueCatIds    = [...new Set(rows.map((r: any) => r.categoryId).filter(Boolean) as string[])];

  // Collect unique tax IDs for sale price tax calculation
  const saleTaxIds = new Set<string>();
  for (const row of rows) {
    for (const tid of row.manualTaxIds ?? []) saleTaxIds.add(tid);
  }

  // ── queries paralelas ────────────────────────────────────────────────────
  const [promotions, categories, generalPL, taxes] = await Promise.all([
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
    saleTaxIds.size > 0
      ? prisma.tax.findMany({
          where: { jewelryId, id: { in: Array.from(saleTaxIds) }, deletedAt: null, appliesOnSale: true },
          select: { id: true, rate: true, fixedAmount: true, calculationType: true },
        })
      : Promise.resolve([]),
  ]);

  // Indexar listas por categoría
  const catPLMap = new Map<string, any>();
  for (const cat of categories) {
    const pl = (cat as any).defaultPriceList;
    if (pl && isPriceListValidNow(pl)) catPLMap.set(cat.id, pl);
  }

  const validGeneralPL = generalPL && isPriceListValidNow(generalPL as any) ? generalPL : null;

  // Indexar impuestos
  const taxMap = new Map<string, { rate: Prisma.Decimal; fixedAmount: Prisma.Decimal; calculationType: string }>();
  for (const t of taxes) {
    taxMap.set(t.id, {
      rate:            new Prisma.Decimal((t.rate ?? 0).toString()),
      fixedAmount:     new Prisma.Decimal((t.fixedAmount ?? 0).toString()),
      calculationType: t.calculationType,
    });
  }

  // ── Resolver por artículo (en memoria) ───────────────────────────────────
  for (const row of rows) {
    const none: NoClientPriceResult = { resolvedSalePrice: null, resolvedSalePriceWithTax: null, resolvedPriceSource: "NONE", resolvedPriceName: null };

    // CostBreakdown mínimo: value + totalGrams (para COST_PER_GRAM)
    const costValue = row.computedCostBase != null ? new D(row.computedCostBase) : null;
    let totalGrams: Prisma.Decimal | null = null;
    const metalLines = (row.costComposition ?? []).filter((l: any) => l.type === "METAL");
    if (metalLines.length > 0) {
      totalGrams = metalLines.reduce(
        (acc: Prisma.Decimal, l: any) => acc.add(new D(l.quantity?.toString() ?? "0")),
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
      isPromotionValid(p) && (
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

    const rowTaxIds = row.manualTaxIds ?? [];
    const priceWithTax = rowTaxIds.length > 0
      ? applyTaxesFromMap(finalPrice, rowTaxIds, taxMap)
      : null;

    result.set(row.id, {
      resolvedSalePrice:        finalPrice.toFixed(4),
      resolvedSalePriceWithTax: priceWithTax != null ? priceWithTax.toFixed(4) : null,
      resolvedPriceSource:      finalSource,
      resolvedPriceName:        finalName,
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

  // Pre-cargar contexto batch: evita N+1 queries en el loop
  const ctx = await buildBatchCostContext(jewelryId, rows as ArticleCostInput[]);

  // Batch fetch de impuestos (no está en el pricing engine)
  const taxIds = new Set<string>();
  for (const row of rows) {
    for (const tid of row.manualTaxIds ?? []) taxIds.add(tid);
  }
  const taxMap = new Map<string, { rate: Prisma.Decimal; fixedAmount: Prisma.Decimal; calculationType: string }>();
  if (taxIds.size > 0) {
    const taxes = await prisma.tax.findMany({
      where: { jewelryId, id: { in: Array.from(taxIds) }, deletedAt: null, appliesOnPurchase: true, isRecoverable: false },
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

  // Calcular costo por artículo (in-memory con ctx, sin queries adicionales por artículo)
  for (const row of rows) {
    const costLines = (row as any).costComposition as EngineCostLineInput[] | undefined;
    const costResult = await calculateCostFromLines(
      jewelryId,
      costLines ?? [],
      {
        kind:  (row as any).manualAdjustmentKind,
        type:  (row as any).manualAdjustmentType,
        value: (row as any).manualAdjustmentValue,
      },
      ctx,
    );
    const costBase = costResult.value;
    const costWithTax = costBase != null
      ? applyTaxesFromMap(costBase, row.manualTaxIds ?? [], taxMap)
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
const ARTICLE_SORT_MAP: Record<string, (dir: "asc" | "desc") => object> = {
  name:                (d) => ({ name: d }),
  code:                (d) => ({ code: d }),
  sku:                 (d) => ({ sku: d }),
  brand:               (d) => ({ brand: d }),
  manufacturer:        (d) => ({ manufacturer: d }),
  category:            (d) => ({ category: { name: d } }),
  supplier:            (d) => ({ preferredSupplier: { displayName: d } }),
  group:               (d) => ({ group: { name: d } }),
  updatedAt:           (d) => ({ updatedAt: d }),
  isReturnable:        (d) => ({ isReturnable: d }),
  showInStore:         (d) => ({ showInStore: d }),
  isFavorite:          (d) => ({ isFavorite: d }),
  salePrice:           (d) => ({ salePrice: d }),
  stock:               (d) => ({ stock: { _sum: { quantity: d } } }),
  articleType:         (d) => ({ articleType: d }),
  isActive:            (d) => ({ isActive: d }),
  sellWithoutVariants: (d) => ({ sellWithoutVariants: d }),
  variantCount:        (d) => ({ variants: { _count: d } }),
};

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
    ids?: string[];
    preferredSupplierId?: string;
    groupId?: string;
    brand?: string;
    hasVariants?: boolean;
    metalId?: string;
    metalVariantId?: string;
    skip?: number;
    take?: number;
    page?: number;
    pageSize?: number;
    sortKey?: string;
    sortDir?: "asc" | "desc";
  }
) {
  const {
    q, categoryId, articleType, status, stockMode, isFavorite,
    showInActive, showInStore, barcode, sku, ids, preferredSupplierId,
    groupId, brand, hasVariants, metalId, metalVariantId,
  } = opts;

  // Soporte page/pageSize (prioridad) ó skip/take (legacy).
  // Blindaje contra entradas inválidas (NaN, strings, null): si Number() no
  // produce un finite, caemos a defaults seguros (25 take, 0 skip). Esto cubre
  // cualquier caller — hoy el controller saneaba con `|| 50`, pero otros
  // entrypoints (imports, tests, jobs) podrían pasar valores crudos.
  const safeNum = (v: any, fallback: number): number => {
    const n = Number(v);
    return Number.isFinite(n) ? n : fallback;
  };
  const pageSizeRaw = safeNum(opts.pageSize ?? opts.take, 25);
  const skipRaw     = safeNum(opts.skip, 0);
  const pageRaw     = opts.page != null
    ? safeNum(opts.page, 1)
    : (opts.skip != null ? Math.floor(skipRaw / Math.max(1, pageSizeRaw)) + 1 : 1);
  const take = Math.min(200, Math.max(1, pageSizeRaw));
  const page = Math.max(1, pageRaw);
  const skip = Math.max(0, (page - 1) * take);

  const where: any = { jewelryId, deletedAt: null };
  if (!showInActive) where.isActive = true;
  if (categoryId)           where.categoryId = categoryId;
  if (articleType && VALID_ARTICLE_TYPES.has(articleType)) where.articleType = articleType;
  if (status && VALID_STATUS.has(status)) where.status = status;
  if (stockMode && VALID_STOCK_MODE.has(stockMode)) where.stockMode = stockMode;
  if (isFavorite === true)   where.isFavorite = true;
  if (showInStore === true)  where.showInStore = true;
  if (showInStore === false) where.showInStore = false;
  if (preferredSupplierId)   where.preferredSupplierId = preferredSupplierId;
  if (barcode)               where.barcode = barcode; // búsqueda exacta por barcode
  if (sku) {
    where.AND = [
      ...(where.AND ?? []),
      { OR: [
        { sku: { contains: sku, mode: "insensitive" } },
        { variants: { some: { sku: { contains: sku, mode: "insensitive" }, deletedAt: null } } },
      ]},
    ];
  }
  if (ids && ids.length > 0) where.id = { in: ids };
  if (groupId)               (where as any).groupItems = { some: { groupId, itemType: "ARTICLE" } };
  if (brand)                 where.brand = { contains: brand, mode: "insensitive" };
  if (hasVariants === true)  where.variants = { some: { deletedAt: null } };
  if (hasVariants === false) where.variants = { none: { deletedAt: null } };

  // Filtro por variante de metal
  if (metalVariantId) {
    where.AND = [
      ...(where.AND ?? []),
      { costComposition: { some: { metalVariantId } } },
    ];
  } else if (metalId) {
    where.AND = [
      ...(where.AND ?? []),
      { costComposition: { some: { metalVariant: { metalId } } } },
    ];
  }

  if (q) {
    // Pre-query 1: variantes que coincidan por sus campos directos (sku, code, name, barcode)
    // (evita depender de `variants.some` dentro de OR en Prisma 7 con adapter-pg)
    const variantsByFields = (await prisma.articleVariant.findMany({
      where: {
        jewelryId,
        deletedAt: null,
        OR: [
          { sku:     { contains: q, mode: "insensitive" } },
          { code:    { contains: q, mode: "insensitive" } },
          { name:    { contains: q, mode: "insensitive" } },
          { barcode: { contains: q, mode: "insensitive" } },
        ],
      },
      select: { articleId: true },
      take: 200,
    })).map((v) => v.articleId);

    // Pre-query 2: variantes cuyo atributo de eje (variantLabel) coincida con el término
    // Esto cubre búsquedas como "Oro 18K" o "Talle 12" que se muestran en la tabla
    const attrValueVariantIds = (await prisma.articleVariantAttributeValue.findMany({
      where: {
        jewelryId,
        value: { contains: q, mode: "insensitive" },
      },
      select: { variantId: true },
      take: 200,
    })).map((av) => av.variantId);

    const variantsByAttr = attrValueVariantIds.length > 0
      ? (await prisma.articleVariant.findMany({
          where: {
            id:        { in: attrValueVariantIds },
            jewelryId,
            deletedAt: null,
          },
          select: { articleId: true },
          take: 200,
        })).map((v) => v.articleId)
      : [];

    // Unir todos los articleIds encontrados vía variante (sin duplicados)
    const variantArticleIds = [...new Set([...variantsByFields, ...variantsByAttr])];

    const orConditions: any[] = [
      { name:        { contains: q, mode: "insensitive" } },
      { code:        { contains: q, mode: "insensitive" } },
      { description: { contains: q, mode: "insensitive" } },
      { sku:         { contains: q, mode: "insensitive" } },
      { brand:       { contains: q, mode: "insensitive" } },
      { barcode:     { contains: q, mode: "insensitive" } },
    ];

    if (variantArticleIds.length > 0) {
      orConditions.push({ id: { in: variantArticleIds } });
    }

    where.OR = orConditions;
  }

  const sortDir = opts.sortDir === "desc" ? "desc" : "asc";
  const orderBy = (opts.sortKey && ARTICLE_SORT_MAP[opts.sortKey])
    ? ARTICLE_SORT_MAP[opts.sortKey](sortDir)
    : { name: "asc" };

  const [rows, total] = await Promise.all([
    prisma.article.findMany({
      where,
      select: ARTICLE_LIST_SELECT,
      orderBy,
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
    const gi = (r as any).groupItems?.[0];

    // FASE 1.1 G4 — marginPercent y taxAmount per-row.
    // Inputs ya disponibles en este scope. NO se hace cálculo nuevo: se
    // expone la derivación que el frontend hacía en InventarioArticulos.tsx
    // (POLICY.md R4.3 prohíbe inferir margen/tax desde resta en cliente).
    // Ambos quedan null cuando los inputs no están disponibles.
    const sale     = p?.resolvedSalePrice;
    const saleTax  = p?.resolvedSalePriceWithTax;
    const cost     = r.computedCostBase;
    const marginPercent =
      sale != null && cost != null && Number(sale) > 0
        ? ((Number(sale) - Number(cost)) / Number(sale)) * 100
        : null;
    const taxAmount =
      sale != null && saleTax != null
        ? Number(saleTax) - Number(sale)
        : null;

    return {
      ...r,
      resolvedSalePrice:        p?.resolvedSalePrice        ?? null,
      resolvedSalePriceWithTax: p?.resolvedSalePriceWithTax ?? null,
      resolvedPriceSource:      p?.resolvedPriceSource      ?? "NONE",
      resolvedPriceName:        p?.resolvedPriceName        ?? null,
      // G4 — campos derivados expuestos. Permite al frontend renderear sin
      // recalcular (POLICY.md R4.3). Decimales preservados por number simple.
      marginPercent,
      taxAmount,
      stockData: stockEntry,
      groupId:    gi?.groupId    ?? null,
      groupOrder: gi?.groupOrder ?? 0,
      group:      gi?.group      ?? null,
    };
  });

  // Enriquecer variantes con precios/costos con impuestos + adjuntar taxDetails a cada row
  const allTaxIds = new Set<string>();
  for (const r of enrichedRows) {
    for (const tid of ((r as any).manualTaxIds ?? []) as string[]) allTaxIds.add(tid);
  }
  if (allTaxIds.size > 0) {
    const taxRecords = await prisma.tax.findMany({
      where: { jewelryId, id: { in: [...allTaxIds] }, deletedAt: null },
      select: {
        id: true, name: true, rate: true, fixedAmount: true,
        calculationType: true, appliesOnSale: true,
        appliesOnPurchase: true, isRecoverable: true,
      },
    });

    // Mapa nombre+tasa para mostrar en tabla
    const taxNameMap = new Map<string, { name: string; rate: string | null }>();
    for (const t of taxRecords) {
      taxNameMap.set(t.id, { name: (t as any).name as string, rate: t.rate?.toString() ?? null });
    }
    for (const row of enrichedRows as any[]) {
      const taxIds: string[] = row.manualTaxIds ?? [];
      row.taxDetails = taxIds.map((id) => taxNameMap.get(id)).filter(Boolean);
    }

    const saleTaxMap = new Map<string, { rate: Prisma.Decimal; fixedAmount: Prisma.Decimal; calculationType: string }>();
    const costTaxMap = new Map<string, { rate: Prisma.Decimal; fixedAmount: Prisma.Decimal; calculationType: string }>();
    for (const t of taxRecords) {
      const entry = {
        rate:        new Prisma.Decimal(t.rate?.toString()        ?? "0"),
        fixedAmount: new Prisma.Decimal(t.fixedAmount?.toString() ?? "0"),
        calculationType: t.calculationType,
      };
      if (t.appliesOnSale) saleTaxMap.set(t.id, entry);
      if (t.appliesOnPurchase && !t.isRecoverable) costTaxMap.set(t.id, entry);
    }
    for (const row of enrichedRows as any[]) {
      if (!row.variants?.length) continue;
      const taxIds: string[] = row.manualTaxIds ?? [];
      if (taxIds.length === 0) continue;
      // Las variantes no tienen precio propio — no hay priceOverride que enriquecer con impuestos.
      // El precio y los impuestos son siempre del artículo padre.
    }
  }

  // ── Indicadores de beneficios: promociones activas y descuentos por cantidad ──
  {
    const now = new Date();
    const articleIds  = enrichedRows.map((r) => r.id);
    const catIds      = [...new Set(enrichedRows.map((r) => (r as any).categoryId).filter(Boolean) as string[])];
    const brands      = [...new Set(enrichedRows.map((r) => (r as any).brand).filter((b) => typeof b === "string" && b.length > 0) as string[])];
    const variantIds  = enrichedRows.flatMap((r) => ((r as any).variants ?? []).map((v: any) => v.id as string));

    const [activePromos, activeQDs] = await Promise.all([
      prisma.promotion.findMany({
        where: {
          jewelryId,
          isActive: true,
          deletedAt: null,
          AND: [
            { OR: [{ validFrom: null }, { validFrom: { lte: now } }] },
            { OR: [{ validTo:   null }, { validTo:   { gte: now } }] },
          ],
        },
        select: {
          id: true, name: true, type: true, value: true, scope: true,
          articles:   { select: { articleId: true } },
          variants:   { select: { variantId: true } },
          categories: { select: { categoryId: true } },
          brands:     { select: { brand: true } },
        },
      }),
      prisma.quantityDiscount.findMany({
        where: { jewelryId, isActive: true, deletedAt: null },
        select: {
          id: true, articleId: true, variantId: true, categoryId: true, brand: true,
          tiers: { select: { minQty: true, type: true, value: true }, orderBy: { minQty: "asc" } },
        },
      }),
    ]);

    // Mapas auxiliares para resolución en memoria
    const catToArticleIds = new Map<string, string[]>();
    for (const r of enrichedRows) {
      const cid = (r as any).categoryId as string | null;
      if (cid) {
        if (!catToArticleIds.has(cid)) catToArticleIds.set(cid, []);
        catToArticleIds.get(cid)!.push(r.id);
      }
    }
    const variantToArticleId = new Map<string, string>();
    for (const r of enrichedRows) {
      for (const v of ((r as any).variants ?? []) as any[]) {
        variantToArticleId.set(v.id as string, r.id);
      }
    }

    const promoSet    = new Set<string>();
    const promoSumMap = new Map<string, string>();
    const qdSet       = new Set<string>();
    const qdSumMap    = new Map<string, string>();
    const qdTiersMap  = new Map<string, Array<{ minQty: string; type: string; value: string }>>();

    function fmtPromo(p: { name: string; type: string; value: { toString(): string } }): string {
      const val = p.type === "PERCENTAGE" ? `-${p.value}%` : `-$${p.value}`;
      return `${p.name} · ${val}`;
    }
    function fmtQD(tiers: Array<{ minQty: { toString(): string }; type: string; value: { toString(): string } }>): string {
      const t = tiers[0];
      if (!t) return "Descuento por cantidad";
      const val = t.type === "PERCENTAGE" ? `-${t.value}%` : `-$${t.value}`;
      return `Desde ${t.minQty} u. → ${val}`;
    }
    function addPromo(aid: string, promo: { name: string; type: string; value: { toString(): string } }): void {
      promoSet.add(aid);
      if (!promoSumMap.has(aid)) promoSumMap.set(aid, fmtPromo(promo));
    }
    function addQD(aid: string, qd: { tiers: Array<{ minQty: { toString(): string }; type: string; value: { toString(): string } }> }): void {
      qdSet.add(aid);
      if (!qdSumMap.has(aid)) qdSumMap.set(aid, fmtQD(qd.tiers));
      if (!qdTiersMap.has(aid)) {
        qdTiersMap.set(aid, qd.tiers.map((t) => ({
          minQty: t.minQty.toString(),
          type:   t.type,
          value:  t.value.toString(),
        })));
      }
    }

    for (const promo of activePromos) {
      if (promo.scope === "ALL") {
        for (const r of enrichedRows) addPromo(r.id, promo);
      } else if (promo.scope === "ARTICLE") {
        for (const pa of promo.articles) {
          if (articleIds.includes(pa.articleId)) addPromo(pa.articleId, promo);
        }
      } else if (promo.scope === "CATEGORY") {
        const scopeCats = new Set(promo.categories.map((pc) => pc.categoryId));
        for (const cid of scopeCats) {
          for (const aid of catToArticleIds.get(cid) ?? []) addPromo(aid, promo);
        }
      } else if (promo.scope === "BRAND") {
        const scopeBrands = new Set(promo.brands.map((pb) => pb.brand));
        for (const r of enrichedRows) {
          const b = (r as any).brand as string;
          if (b && scopeBrands.has(b)) addPromo(r.id, promo);
        }
      } else if (promo.scope === "VARIANT") {
        const scopeVars = new Set(promo.variants.map((pv) => pv.variantId));
        for (const vid of scopeVars) {
          const aid = variantToArticleId.get(vid);
          if (aid) addPromo(aid, promo);
        }
      }
    }

    for (const qd of activeQDs) {
      if (qd.articleId) {
        if (articleIds.includes(qd.articleId)) addQD(qd.articleId, qd);
      } else if (qd.variantId) {
        const aid = variantToArticleId.get(qd.variantId);
        if (aid) addQD(aid, qd);
      } else if (qd.categoryId) {
        for (const aid of catToArticleIds.get(qd.categoryId) ?? []) addQD(aid, qd);
      } else if (qd.brand) {
        for (const r of enrichedRows) {
          if ((r as any).brand === qd.brand) addQD(r.id, qd);
        }
      } else {
        // Sin alcance específico → aplica a todos
        for (const r of enrichedRows) addQD(r.id, qd);
      }
    }

    for (const row of enrichedRows as any[]) {
      row.hasActivePromotion       = promoSet.has(row.id);
      row.hasQuantityDiscount      = qdSet.has(row.id);
      row.promotionSummary         = promoSumMap.get(row.id)  ?? null;
      row.quantityDiscountSummary  = qdSumMap.get(row.id)     ?? null;
      row.quantityDiscountTiers    = qdTiersMap.get(row.id)   ?? null;
    }
  }

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

  // Verificar si el artículo tiene movimientos registrados (vía líneas, que son el vínculo real)
  const variantIds: string[] = (article as any).variants?.map((v: any) => v.id as string) ?? [];
  const movementCount = await prisma.articleMovement.count({
    where: {
      jewelryId,
      lines: {
        some: {
          OR: [
            { articleId },
            ...(variantIds.length ? [{ variantId: { in: variantIds } }] : []),
          ],
        },
      },
    },
  });
  const hasMovements = movementCount > 0;

  // Enriquecer con datos de stock según el modo
  let stockData: any = null;
  if ((article as any).stockMode === "BY_ARTICLE") {
    stockData = await getStockSummary(articleId, jewelryId);
  } else if ((article as any).stockMode === "BY_MATERIAL") {
    stockData = await _calcMaterialAvailabilityInternal(articleId, jewelryId, article as any);
  }

  // Calcular costo computado desde líneas de composición
  const _costLines = (article as any).costComposition as EngineCostLineInput[] | undefined;
  const costResult = await calculateCostFromLines(
    jewelryId,
    _costLines ?? [],
    {
      kind:  (article as any).manualAdjustmentKind,
      type:  (article as any).manualAdjustmentType,
      value: (article as any).manualAdjustmentValue,
    },
  );

  // ── Impuestos: fetch enriquecido con nombre (para display en tab Costos) ─
  const taxIdsForDetail: string[] = (article as any).manualTaxIds ?? [];
  const taxDetails = taxIdsForDetail.length > 0
    ? await prisma.tax.findMany({
        where: { jewelryId, id: { in: taxIdsForDetail }, deletedAt: null, appliesOnPurchase: true, isRecoverable: false },
        select: { id: true, name: true, rate: true, fixedAmount: true, calculationType: true },
      })
    : [];

  // Aplicar impuestos para obtener computedCostWithTax.
  // Mismo criterio que batchComputeCosts() — los impuestos son capa de lectura, nunca se persisten.
  let computedCostWithTaxStr: string | null = null;
  if (costResult.value != null) {
    const costBase = costResult.value as Prisma.Decimal;
    if (taxDetails.length > 0) {
      const taxMap = new Map(taxDetails.map((t) => [t.id, {
        rate:            new Prisma.Decimal((t.rate ?? 0).toString()),
        fixedAmount:     new Prisma.Decimal((t.fixedAmount ?? 0).toString()),
        calculationType: t.calculationType,
      }]));
      computedCostWithTaxStr = applyTaxesFromMap(costBase, taxIdsForDetail, taxMap).toFixed(4);
    } else {
      computedCostWithTaxStr = costBase.toFixed(4);
    }
  }

  // ── Enriquecer líneas de costo con valores actuales (para tab Costos) ────
  const costLinesForDetail: any[] = (article as any).costComposition ?? [];

  const baseCurrencyForDetail = await prisma.currency.findFirst({
    where: { jewelryId, isBase: true, deletedAt: null },
    select: { id: true, code: true, symbol: true },
  });

  const metalVarIdsForDetail = [...new Set(
    costLinesForDetail
      .filter((l: any) => l.type === "METAL" && l.metalVariantId)
      .map((l: any) => l.metalVariantId as string),
  )];

  const metalQuoteCurrentMap = new Map<string, { price: string; effectiveAt: string }>();
  if (metalVarIdsForDetail.length > 0 && baseCurrencyForDetail) {
    const quotes = await prisma.metalQuote.findMany({
      where: { variantId: { in: metalVarIdsForDetail }, currencyId: baseCurrencyForDetail.id },
      orderBy: { effectiveAt: "desc" },
      select: { variantId: true, price: true, effectiveAt: true },
    });
    for (const q of quotes) {
      if (!metalQuoteCurrentMap.has(q.variantId))
        metalQuoteCurrentMap.set(q.variantId, { price: q.price.toFixed(6), effectiveAt: q.effectiveAt.toISOString() });
    }
  }

  const costLineCurrentValues = costLinesForDetail.map((line: any) => {
    if (line.type === "METAL" && line.metalVariantId) {
      const q = metalQuoteCurrentMap.get(line.metalVariantId) ?? null;
      return { currentUnitValue: q?.price ?? null, source: q ? "METAL_QUOTE" : "NO_REFERENCE", quotedAt: q?.effectiveAt ?? null };
    }
    return { currentUnitValue: line.unitValue?.toString() ?? null, source: "REGISTERED", quotedAt: null };
  });

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

  const _gi = (article as any).groupItems?.[0];
  return {
    ...article,
    hasMovements,
    stockData,
    computedCostBase:    costResult.value != null ? (costResult.value as Prisma.Decimal).toFixed(4) : null,
    computedCostWithTax: computedCostWithTaxStr,
    computedCostPrice:   costResult,
    computedSalePrice,
    effectiveSalePrice,
    effectivePriceSource,
    // Enriquecimiento para tab Costos
    baseCurrency:          baseCurrencyForDetail,
    taxDetails,
    costLineCurrentValues,
    groupId:    _gi?.groupId    ?? null,
    groupOrder: _gi?.groupOrder ?? 0,
    group:      _gi?.group      ?? null,
  };
}

// ===========================================================================
// FASE 2 — Validación de variantes de componente en composición de costo.
//
// Una línea PRODUCT/SERVICE con `catalogItemId` puede opcionalmente apuntar a
// una variante específica via `catalogVariantId`. Cuando el caller manda esta
// referencia, validamos en una sola query batch que:
//   - cada variante existe en el tenant y no está soft-deleted,
//   - el `articleId` de la variante coincide con el `catalogItemId` de la línea
//     (no se puede asociar una variante de otro padre al componente).
// Si solo viene `catalogItemId` (sin variantId), el flujo legacy se mantiene.
// ===========================================================================
async function validateCostLineVariants(
  jewelryId: string,
  lines: Array<{ catalogItemId?: string | null; catalogVariantId?: string | null }>,
): Promise<void> {
  const variantIds = [
    ...new Set(
      lines
        .map((l) => l.catalogVariantId)
        .filter((v): v is string => typeof v === "string" && v.length > 0),
    ),
  ];
  if (variantIds.length === 0) return;
  const variants = await prisma.articleVariant.findMany({
    where: { id: { in: variantIds }, jewelryId, deletedAt: null },
    select: { id: true, articleId: true, isActive: true },
  });
  const variantMap = new Map(variants.map((v) => [v.id, v]));
  for (const l of lines) {
    if (!l.catalogVariantId) continue;
    const v = variantMap.get(l.catalogVariantId);
    assert(v, `La variante "${l.catalogVariantId}" del componente no existe o fue eliminada.`);
    assert(
      l.catalogItemId && v!.articleId === l.catalogItemId,
      "La variante seleccionada no pertenece al artículo del componente.",
    );
  }
}

// ===========================================================================
// Create
// ===========================================================================
export async function createArticle(jewelryId: string, data: any) {
  assert(s(data?.name), "El nombre del artículo es obligatorio.");

  const articleType = VALID_ARTICLE_TYPES.has(data?.articleType) ? data.articleType : "PRODUCT";
  let   stockMode   = VALID_STOCK_MODE.has(data?.stockMode) ? data.stockMode : "NO_STOCK";

  // ── Combo comercial: normaliza/valida campos y fuerza flags si corresponde ──
  const combo = normalizeComboFields({
    articleType,
    commercialMode:       data?.commercialMode,
    comboAdjustmentKind:  data?.comboAdjustmentKind,
    comboAdjustmentValue: data?.comboAdjustmentValue,
  });
  const isCombo = combo.commercialMode === "COMBO_COMMERCIAL";
  if (isCombo && combo.stockMode) stockMode = combo.stockMode;

  validateTypeStockMode(articleType, stockMode);

  // Validación defensiva temprana (sin DB): fail-fast para payloads mal formados.
  // El shape del combo depende de costComposition, por eso lo resolvemos antes.
  const costCompositionLinesEarly: CostLineInput[] = Array.isArray(data?.costComposition) ? data.costComposition : [];
  assertServiceArticleComposition(articleType, data, costCompositionLinesEarly);

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

  const costCompositionLines = costCompositionLinesEarly;

  // Combo: validar shape de componentes (sin DB) antes de tocar nada.
  if (isCombo) {
    validateComboComponentsShape({ ownArticleId: null, componentLines: costCompositionLines });
  }

  // FASE 2: validar que las variantes referenciadas en las líneas existan y
  // pertenezcan al artículo del componente.
  await validateCostLineVariants(jewelryId, costCompositionLines);

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
    // Precio de venta. Combos también pueden tener precio manual (lista o override).
    salePrice:           data?.salePrice != null ? data.salePrice : null,
    useManualSalePrice:  !!data?.useManualSalePrice,
    mermaPercent:        data?.mermaPercent != null ? data.mermaPercent : null,
    // Ajuste global sobre composición de costo (se aplica sobre la suma de ArticleCostLine)
    manualAdjustmentKind:  s(data?.manualAdjustmentKind),
    manualAdjustmentType:  s(data?.manualAdjustmentType),
    manualAdjustmentValue: data?.manualAdjustmentValue != null ? data.manualAdjustmentValue : null,
    manualTaxIds:          Array.isArray(data?.manualTaxIds) ? data.manualTaxIds : [],
    // Combo: campos comerciales del combo + flags forzados
    commercialMode:        combo.commercialMode,
    comboAdjustmentKind:   combo.comboAdjustmentKind,
    comboAdjustmentValue:  combo.comboAdjustmentValue,
    sellWithoutVariants: isCombo ? true : (data?.sellWithoutVariants !== false),
    isReturnable:        data?.isReturnable !== false,
    showInStore:         !!data?.showInStore,
    unitOfMeasure:       s(data?.unitOfMeasure),
    reorderPoint:        data?.reorderPoint != null ? data.reorderPoint : null,
    dimensionLength:     data?.dimensionLength != null ? data.dimensionLength : null,
    dimensionWidth:      data?.dimensionWidth  != null ? data.dimensionWidth  : null,
    dimensionHeight:     data?.dimensionHeight != null ? data.dimensionHeight : null,
    dimensionUnit:       s(data?.dimensionUnit) || "cm",
    weight:              data?.weight     != null ? data.weight     : null,
    weightUnit:          s(data?.weightUnit),
    minSaleQuantity:     data?.minSaleQuantity  != null ? data.minSaleQuantity  : null,
    maxSaleQuantity:     data?.maxSaleQuantity  != null ? data.maxSaleQuantity  : null,
    defaultQuantity:     data?.defaultQuantity  != null ? data.defaultQuantity  : null,
    inventoryAccount:    s(data?.inventoryAccount),
    isFavorite:          !!data?.isFavorite,
    notes:               s(data?.notes),
  };

  const VALID_TYPES = new Set(["METAL", "HECHURA", "PRODUCT", "SERVICE", "MANUAL"]);
  const articleId = await prisma.$transaction(async (tx) => {
    // Validación contra DB de los componentes del combo (servicio? eliminado? ciclo?).
    // En createArticle no hay ownArticleId previo → no chequea ciclos del propio artículo,
    // pero sí valida que cada componente exista, sea PRODUCT activo, etc.
    if (isCombo) {
      const componentIds = costCompositionLines
        .filter(l => (l.type === "PRODUCT" || l.type === "SERVICE") && l.catalogItemId)
        .map(l => l.catalogItemId as string);
      await validateComboComponentsAgainstDb(tx, {
        jewelryId,
        ownArticleId: null,
        componentArticleIds: componentIds,
      });
    }

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
          // FASE 2: variante específica del componente. Solo se persiste para
          // líneas PRODUCT/SERVICE que apunten a un artículo. Validado arriba.
          catalogVariantId:
            (l.type === "PRODUCT" || l.type === "SERVICE") && l.catalogItemId
              ? (l.catalogVariantId ?? null)
              : null,
          // Combo: forzar affectsStock=true en líneas componente (PRODUCT/SERVICE con ref)
          // para que confirmSale dispare el descuento de stock de los componentes.
          affectsStock:  isCombo && (l.type === "PRODUCT" || l.type === "SERVICE") && l.catalogItemId
                            ? true
                            : (l.affectsStock ?? false),
          sortOrder:     l.sortOrder ?? idx,
          lineAdjKind:   l.lineAdjKind  ?? "",
          lineAdjType:   l.lineAdjType  ?? "",
          lineAdjValue:  l.lineAdjValue ?? null,
        })),
      });
    }
    return created.id;
  });

  // Grupo comercial: la relación vive en ArticleGroupItem (no es campo escalar
  // en Article). Solo se asigna si el caller envió `groupId` con un valor truthy
  // — en create no tiene sentido "desasignar" porque el artículo nace sin grupo.
  if (typeof data?.groupId === "string" && data.groupId) {
    await assignGroupToArticle(articleId, data.groupId, jewelryId);
  }

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
    select: { articleType: true, stockMode: true, barcode: true, barcodeSource: true, code: true, sku: true, categoryId: true, commercialMode: true },
  });
  const newType      = VALID_ARTICLE_TYPES.has(data?.articleType) ? data.articleType : current!.articleType;
  let   newStockMode = VALID_STOCK_MODE.has(data?.stockMode) ? data.stockMode : current!.stockMode;

  // ── Combo comercial: normaliza/valida campos y fuerza flags si corresponde ──
  // Si commercialMode no viene en data, se preserva el actual (current.commercialMode).
  const incomingCommercialMode =
    data?.commercialMode !== undefined ? data.commercialMode : current!.commercialMode;
  const combo = normalizeComboFields({
    articleType:          newType,
    commercialMode:       incomingCommercialMode,
    comboAdjustmentKind:  data?.comboAdjustmentKind,
    comboAdjustmentValue: data?.comboAdjustmentValue,
  });
  const isCombo = combo.commercialMode === "COMBO_COMMERCIAL";
  if (isCombo && combo.stockMode) newStockMode = combo.stockMode;

  validateTypeStockMode(newType, newStockMode);

  // Validación defensiva temprana (sin DB): fail-fast para payloads mal formados.
  // Resolvemos costComposition acá para poder validar servicios, reutilizamos
  // luego en combo validation + transacción.
  const hasCostComposition = data?.costComposition !== undefined;
  const costCompositionLines: CostLineInput[] = hasCostComposition
    ? (Array.isArray(data.costComposition) ? data.costComposition : [])
    : [];
  assertServiceArticleComposition(
    newType,
    data,
    hasCostComposition ? costCompositionLines : null,
  );

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

  // Validar cambio de categoría: compatibilidad de ejes (si tiene variantes) o conversión (si es simple)
  if (data?.categoryId && data.categoryId !== current!.categoryId) {
    const existingVariantCount = await prisma.articleVariant.count({
      where: { articleId, jewelryId, deletedAt: null },
    });

    if (existingVariantCount > 0) {
      // Artículo ya varianteado → solo permitir si los ejes de variante son exactamente los mismos
      const getEffectiveAxisDefIds = async (catId: string): Promise<Set<string>> => {
        const result = new Set<string>();
        let curId: string | null = catId;
        const seen = new Set<string>();
        let isOwn = true;
        while (curId && !seen.has(curId)) {
          seen.add(curId);
          const cat: { parentId: string | null; attributes: { definitionId: string }[] } | null =
            await prisma.articleCategory.findFirst({
              where: { id: curId, deletedAt: null },
              select: {
                parentId: true,
                attributes: {
                  where: { isVariantAxis: true, deletedAt: null, ...(isOwn ? {} : { inheritToChild: true }) },
                  select: { definitionId: true },
                },
              },
            });
          if (!cat) break;
          cat.attributes.forEach((a: { definitionId: string }) => result.add(a.definitionId));
          curId = cat.parentId ?? null;
          isOwn = false;
        }
        return result;
      };
      const [currentDefs, newDefs] = await Promise.all([
        getEffectiveAxisDefIds(current!.categoryId ?? ""),
        getEffectiveAxisDefIds(data.categoryId),
      ]);
      const axesCompatible =
        currentDefs.size === newDefs.size &&
        [...currentDefs].every(id => newDefs.has(id));
      assert(
        axesCompatible,
        "Este artículo ya tiene variantes creadas con la estructura de atributos de su categoría actual y no puede cambiarse a una categoría con ejes distintos."
      );
    } else {
      // Artículo simple → bloquear conversión a categoría con ejes si tiene movimientos
      const axisCount = await prisma.articleCategoryAttribute.count({
        where: { categoryId: data.categoryId, isVariantAxis: true, deletedAt: null },
      });
      if (axisCount > 0) {
        const movCount = await prisma.articleMovement.count({
          where: { jewelryId, lines: { some: { articleId } } },
        });
        assert(
          movCount === 0,
          "Este artículo tiene movimientos registrados y no puede convertirse en un artículo con variantes."
        );
      }
    }
  }

  // Validar variantes obligatorias si la categoría efectiva tiene ejes de variante
  {
    const effectiveCategoryId = data?.categoryId ?? current!.categoryId;
    if (effectiveCategoryId && newType !== "SERVICE") {
      const axisCount = await prisma.articleCategoryAttribute.count({
        where: { categoryId: effectiveCategoryId, isVariantAxis: true, deletedAt: null },
      });
      if (axisCount > 0) {
        const variantCount = await prisma.articleVariant.count({
          where: { articleId, jewelryId, deletedAt: null },
        });
        assert(
          variantCount > 0,
          "Esta categoría requiere al menos una variante. Creá las variantes antes de guardar el artículo."
        );
      }
    }
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
    // Precio de venta. Combos también pueden tener precio manual (lista o override).
    salePrice:           data?.salePrice !== undefined ? (data.salePrice ?? null) : undefined,
    useManualSalePrice:  data?.useManualSalePrice !== undefined ? !!data.useManualSalePrice : undefined,
    mermaPercent:        data?.mermaPercent !== undefined ? (data.mermaPercent ?? null) : undefined,
    // Ajuste global sobre composición de costo (se aplica sobre la suma de ArticleCostLine)
    manualAdjustmentKind:  data?.manualAdjustmentKind !== undefined ? s(data.manualAdjustmentKind) : undefined,
    manualAdjustmentType:  data?.manualAdjustmentType !== undefined ? s(data.manualAdjustmentType) : undefined,
    manualAdjustmentValue: data?.manualAdjustmentValue !== undefined ? (data.manualAdjustmentValue ?? null) : undefined,
    manualTaxIds:          data?.manualTaxIds !== undefined ? (Array.isArray(data.manualTaxIds) ? data.manualTaxIds : []) : undefined,
    // Combo: persistir siempre los 3 campos resueltos por normalizeComboFields
    commercialMode:        combo.commercialMode,
    comboAdjustmentKind:   combo.comboAdjustmentKind,
    comboAdjustmentValue:  combo.comboAdjustmentValue,
    sellWithoutVariants: isCombo
                            ? true
                            : (data?.sellWithoutVariants !== undefined ? !!data.sellWithoutVariants : undefined),
    isReturnable:       data?.isReturnable !== undefined ? !!data.isReturnable : undefined,
    showInStore:        data?.showInStore !== undefined ? !!data.showInStore : undefined,
    unitOfMeasure:      data?.unitOfMeasure !== undefined ? s(data.unitOfMeasure) : undefined,
    reorderPoint:       data?.reorderPoint !== undefined ? (data.reorderPoint ?? null) : undefined,
    dimensionLength:    data?.dimensionLength !== undefined ? (data.dimensionLength ?? null) : undefined,
    dimensionWidth:     data?.dimensionWidth  !== undefined ? (data.dimensionWidth  ?? null) : undefined,
    dimensionHeight:    data?.dimensionHeight !== undefined ? (data.dimensionHeight ?? null) : undefined,
    dimensionUnit:      data?.dimensionUnit   !== undefined ? (s(data.dimensionUnit) || "cm") : undefined,
    weight:             data?.weight      !== undefined ? (data.weight      ?? null) : undefined,
    weightUnit:         data?.weightUnit  !== undefined ? s(data.weightUnit)          : undefined,
    minSaleQuantity:    data?.minSaleQuantity  !== undefined ? (data.minSaleQuantity  ?? null) : undefined,
    maxSaleQuantity:    data?.maxSaleQuantity  !== undefined ? (data.maxSaleQuantity  ?? null) : undefined,
    defaultQuantity:    data?.defaultQuantity  !== undefined ? (data.defaultQuantity  ?? null) : undefined,
    inventoryAccount:   data?.inventoryAccount !== undefined ? s(data.inventoryAccount) : undefined,
    isFavorite:         data?.isFavorite !== undefined ? !!data.isFavorite : undefined,
    notes:              data?.notes !== undefined ? s(data.notes) : undefined,
  };

  // Combo: si vienen componentes O si pasamos a/seguimos siendo combo, validar shape.
  // Si NO vienen componentes pero sí seguimos siendo combo, hay que validar contra los
  // existentes (cargados desde DB) para garantizar que el combo no quede sin componentes.
  if (isCombo) {
    if (hasCostComposition) {
      validateComboComponentsShape({ ownArticleId: articleId, componentLines: costCompositionLines });
    } else {
      const existingCount = await prisma.articleCostLine.count({
        where: {
          articleId, jewelryId,
          type: { in: ["PRODUCT", "SERVICE"] },
          catalogItemId: { not: null },
        },
      });
      assert(existingCount > 0, "El combo comercial debe tener al menos un componente.");
    }
  }

  // FASE 2: validar variantes referenciadas en las líneas (cuando vienen).
  if (hasCostComposition) {
    await validateCostLineVariants(jewelryId, costCompositionLines);
  }

  const VALID_TYPES_SET = new Set(["METAL", "HECHURA", "PRODUCT", "SERVICE", "MANUAL"]);
  await prisma.$transaction(async (tx) => {
    // Validación contra DB de los componentes del combo (existencia, tipo, ciclos).
    // Solo se ejecuta cuando el caller envía costComposition Y el artículo es combo.
    if (isCombo && hasCostComposition) {
      const componentIds = costCompositionLines
        .filter(l => (l.type === "PRODUCT" || l.type === "SERVICE") && l.catalogItemId)
        .map(l => l.catalogItemId as string);
      await validateComboComponentsAgainstDb(tx, {
        jewelryId,
        ownArticleId: articleId,
        componentArticleIds: componentIds,
      });
    }

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
            // FASE 2: variante específica del componente, solo PRODUCT/SERVICE con ref.
            catalogVariantId:
              (l.type === "PRODUCT" || l.type === "SERVICE") && l.catalogItemId
                ? (l.catalogVariantId ?? null)
                : null,
            // Combo: forzar affectsStock=true en componentes (PRODUCT/SERVICE con ref).
            affectsStock:  isCombo && (l.type === "PRODUCT" || l.type === "SERVICE") && l.catalogItemId
                              ? true
                              : (l.affectsStock ?? false),
            sortOrder:     l.sortOrder ?? idx,
            lineAdjKind:   l.lineAdjKind  ?? "",
            lineAdjType:   l.lineAdjType  ?? "",
            lineAdjValue:  l.lineAdjValue ?? null,
          })),
        });
      }
    }
  });

  // Grupo comercial: la relación vive en ArticleGroupItem (no es campo escalar
  // en Article). Solo procesamos si el caller envía `groupId` definido. Si llega
  // string vacío o null, se interpreta como "quitar del grupo" (el frontend
  // envía `d.groupId || null`, así que `null` representa "Sin grupo").
  if (data?.groupId !== undefined) {
    const target = typeof data.groupId === "string" && data.groupId ? data.groupId : null;
    await assignGroupToArticle(articleId, target, jewelryId);
  }

  return getArticle(articleId, jewelryId);
}

// ===========================================================================
// Clone — copia profunda del artículo: composición, atributos, imágenes,
// variantes (con sus atributos e imágenes) y grupo comercial.
//
// NO copia: stock, movimientos, ventas/compras, historial, openingStock,
// createdAt/updatedAt, isFavorite. El clon nace en estado DRAFT con `code`
// nuevo autogenerado, `sku=""`, `barcode=null` y nombre con sufijo " (Copia)".
// Las imágenes reusan las URLs del original (no se duplican blobs en R2).
// ===========================================================================
export async function cloneArticle(sourceId: string, jewelryId: string) {
  assert(sourceId, "Id de artículo inválido.");

  const src = await prisma.article.findFirst({
    where: { id: sourceId, jewelryId, deletedAt: null },
    select: {
      id: true,
      name: true,
      description: true,
      categoryId: true,
      articleType: true,
      stockMode: true,
      barcodeType: true,
      brand: true,
      manufacturer: true,
      supplierCode: true,
      preferredSupplierId: true,
      salePrice: true,
      useManualSalePrice: true,
      mermaPercent: true,
      manualAdjustmentKind: true,
      manualAdjustmentType: true,
      manualAdjustmentValue: true,
      manualTaxIds: true,
      commercialMode: true,
      comboAdjustmentKind: true,
      comboAdjustmentValue: true,
      sellWithoutVariants: true,
      isReturnable: true,
      showInStore: true,
      unitOfMeasure: true,
      reorderPoint: true,
      dimensionLength: true,
      dimensionWidth: true,
      dimensionHeight: true,
      dimensionUnit: true,
      weight: true,
      weightUnit: true,
      minSaleQuantity: true,
      maxSaleQuantity: true,
      defaultQuantity: true,
      inventoryAccount: true,
      mainImageUrl: true,
      notes: true,
      costComposition: {
        select: {
          type: true, label: true, quantity: true, unitValue: true,
          currencyId: true, mermaPercent: true, metalVariantId: true,
          catalogItemId: true, catalogVariantId: true,
          lineAdjKind: true, lineAdjType: true,
          lineAdjValue: true, sortOrder: true, affectsStock: true,
        },
        orderBy: { sortOrder: "asc" },
      },
      attributeValues: {
        select: { assignmentId: true, value: true },
      },
      images: {
        select: { url: true, label: true, isMain: true, sortOrder: true },
        orderBy: { sortOrder: "asc" },
      },
      variants: {
        where: { deletedAt: null },
        orderBy: { sortOrder: "asc" },
        select: {
          code: true, name: true, barcodeType: true,
          weightOverride: true, reorderPoint: true,
          minSaleQuantity: true, maxSaleQuantity: true, defaultQuantity: true,
          imageUrl: true, notes: true, isActive: true, isFavorite: true,
          sortOrder: true,
          attributeValues: { select: { assignmentId: true, value: true } },
          images: {
            select: { url: true, label: true, isMain: true, sortOrder: true },
            orderBy: { sortOrder: "asc" },
          },
        },
      },
      groupItems: {
        where: { itemType: "ARTICLE" },
        take: 1,
        select: { groupId: true },
      },
    },
  });
  assert(src, "Artículo no encontrado.", 404);

  const newCode = await generateArticleCode(jewelryId);

  const newArticleId = await prisma.$transaction(async (tx) => {
    const created = await tx.article.create({
      data: {
        jewelry: { connect: { id: jewelryId } },
        ...(src!.categoryId          ? { category:          { connect: { id: src!.categoryId } } } : {}),
        ...(src!.preferredSupplierId ? { preferredSupplier: { connect: { id: src!.preferredSupplierId } } } : {}),
        code:           newCode,
        name:           `${src!.name} (Copia)`,
        description:    src!.description,
        articleType:    src!.articleType,
        status:         "DRAFT",
        stockMode:      src!.stockMode,
        sku:            "",
        barcode:        null,
        barcodeType:    src!.barcodeType,
        barcodeSource:  "CUSTOM",
        brand:          src!.brand,
        manufacturer:   src!.manufacturer,
        supplierCode:   src!.supplierCode,
        salePrice:           src!.salePrice,
        useManualSalePrice:  src!.useManualSalePrice,
        mermaPercent:        src!.mermaPercent,
        manualAdjustmentKind:  src!.manualAdjustmentKind,
        manualAdjustmentType:  src!.manualAdjustmentType,
        manualAdjustmentValue: src!.manualAdjustmentValue,
        manualTaxIds:          src!.manualTaxIds,
        commercialMode:        src!.commercialMode,
        comboAdjustmentKind:   src!.comboAdjustmentKind,
        comboAdjustmentValue:  src!.comboAdjustmentValue,
        sellWithoutVariants:   src!.sellWithoutVariants,
        isReturnable:  src!.isReturnable,
        showInStore:   src!.showInStore,
        unitOfMeasure: src!.unitOfMeasure,
        reorderPoint:  src!.reorderPoint,
        dimensionLength: src!.dimensionLength,
        dimensionWidth:  src!.dimensionWidth,
        dimensionHeight: src!.dimensionHeight,
        dimensionUnit:   src!.dimensionUnit,
        weight:          src!.weight,
        weightUnit:      src!.weightUnit,
        minSaleQuantity: src!.minSaleQuantity,
        maxSaleQuantity: src!.maxSaleQuantity,
        defaultQuantity: src!.defaultQuantity,
        inventoryAccount: src!.inventoryAccount,
        mainImageUrl:     src!.mainImageUrl,
        isFavorite:       false,
        notes:            src!.notes,
      },
      select: { id: true },
    });

    if (src!.costComposition.length > 0) {
      await tx.articleCostLine.createMany({
        data: src!.costComposition.map((l, idx) => ({
          articleId:        created.id,
          jewelryId,
          type:             l.type,
          label:            l.label,
          quantity:         l.quantity,
          unitValue:        l.unitValue,
          currencyId:       l.currencyId,
          mermaPercent:     l.mermaPercent,
          metalVariantId:   l.metalVariantId,
          catalogItemId:    l.catalogItemId,
          catalogVariantId: l.catalogVariantId,
          lineAdjKind:      l.lineAdjKind,
          lineAdjType:      l.lineAdjType,
          lineAdjValue:     l.lineAdjValue,
          sortOrder:        l.sortOrder ?? idx,
          affectsStock:     l.affectsStock,
        })),
      });
    }

    if (src!.attributeValues.length > 0) {
      await tx.articleAttributeValue.createMany({
        data: src!.attributeValues.map((av) => ({
          articleId:    created.id,
          jewelryId,
          assignmentId: av.assignmentId,
          value:        av.value,
        })),
      });
    }

    if (src!.images.length > 0) {
      await tx.articleImage.createMany({
        data: src!.images.map((im) => ({
          articleId: created.id,
          jewelryId,
          url:       im.url,
          label:     im.label,
          isMain:    im.isMain,
          sortOrder: im.sortOrder,
        })),
      });
    }

    // Variantes — el unique de variant es (articleId, code), y el articleId es
    // nuevo, así que reusar el `code` del original NO colisiona. `sku` y
    // `barcode` se resetean (barcode es único por tenant).
    for (const v of src!.variants) {
      const newVariant = await tx.articleVariant.create({
        data: {
          articleId:       created.id,
          jewelryId,
          code:            v.code,
          name:            v.name,
          sku:             "",
          barcode:         null,
          barcodeType:     v.barcodeType,
          barcodeSource:   "CUSTOM",
          weightOverride:  v.weightOverride,
          reorderPoint:    v.reorderPoint,
          openingStock:    null,
          minSaleQuantity: v.minSaleQuantity,
          maxSaleQuantity: v.maxSaleQuantity,
          defaultQuantity: v.defaultQuantity,
          imageUrl:        v.imageUrl,
          notes:           v.notes,
          isActive:        v.isActive,
          isFavorite:      v.isFavorite,
          sortOrder:       v.sortOrder,
        },
        select: { id: true },
      });

      if (v.attributeValues.length > 0) {
        await tx.articleVariantAttributeValue.createMany({
          data: v.attributeValues.map((av) => ({
            variantId:    newVariant.id,
            jewelryId,
            assignmentId: av.assignmentId,
            value:        av.value,
          })),
        });
      }

      if (v.images.length > 0) {
        await tx.articleVariantImage.createMany({
          data: v.images.map((im) => ({
            variantId: newVariant.id,
            articleId: created.id,
            jewelryId,
            url:       im.url,
            label:     im.label,
            isMain:    im.isMain,
            sortOrder: im.sortOrder,
          })),
        });
      }
    }

    return created.id;
  });

  // Grupo comercial — fuera de la transacción porque assignGroupToArticle
  // usa el cliente prisma global, no `tx`. Se replica el grupo del original
  // si existía.
  const sourceGroupId = src!.groupItems[0]?.groupId ?? null;
  if (sourceGroupId) {
    await assignGroupToArticle(newArticleId, sourceGroupId, jewelryId);
  }

  return getArticle(newArticleId, jewelryId);
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
// Bulk update (activar / desactivar / favorito / categoría / grupo / tienda / devoluciones / variantes)
// ===========================================================================
export async function bulkUpdateArticles(
  jewelryId: string,
  ids: string[],
  data: {
    isActive?: boolean;
    isFavorite?: boolean;
    categoryId?: string;
    showInStore?: boolean;
    isReturnable?: boolean;
    sellWithoutVariants?: boolean;
  },
) {
  if (!ids.length || Object.keys(data).length === 0) return { updated: 0 };

  // Validar que categoryId pertenece al mismo tenant
  if (data.categoryId) {
    const cat = await prisma.articleCategory.findFirst({
      where: { id: data.categoryId, jewelryId, deletedAt: null },
      select: { id: true },
    });
    if (!cat) {
      const e: any = new Error("Categoría no encontrada o no pertenece a este tenant.");
      e.status = 400; throw e;
    }
  }

  const result = await prisma.article.updateMany({
    where: { id: { in: ids }, jewelryId, deletedAt: null },
    data,
  });
  return { updated: result.count };
}

// ===========================================================================
// Bulk hechura update
// ===========================================================================
export type BulkHechuraAdjType = "PERCENTAGE" | "FIXED";
export type BulkHechuraDirection = "ADD" | "SUBTRACT";
export type BulkHechuraScope = "ARTICLE" | "VARIANTS" | "BOTH";

export interface BulkHechuraParams {
  adjustType: BulkHechuraAdjType;
  direction: BulkHechuraDirection;
  value: number;         // porcentaje (0-100) o monto fijo positivo
  scope: BulkHechuraScope;
  preview?: boolean;
  // Para ajuste FIXED: solo aplica a líneas de costo cuya moneda coincida (null = moneda base).
  currencyId?: string;
  // Filtros de selección
  ids?: string[];         // IDs de artículos explícitos
  categoryId?: string;
  brand?: string;         // filtro por marca (valor único)
  manufacturer?: string;
  groupId?: string;
  metalIds?: string[];    // filtro por metal padre (multi)
  metalVariantIds?: string[]; // filtro por variante de metal (multi)
  preferredSupplierId?: string; // filtro por proveedor preferido (valor único)
  onlyActive?: boolean;
  onlyFavorite?: boolean;
  // Exclusiones manuales desde el preview del frontend
  excludedArticleIds?:  string[];
  excludedVariantIds?:  string[];
  excludedCostLineIds?: string[];
}

export interface BulkHechuraPreviewItem {
  articleId: string;
  articleName: string;
  articleSku?: string;
  kind: "cost_line";
  variantId?: string;
  variantName?: string;
  variantSku?: string;
  costLineId?: string;
  costLineLabel?: string;
  costLineCurrencyCode?: string;   // código de moneda de la línea (null = moneda base)
  oldValue: number | null;
  newValue: number | null;
  /** true cuando el ajuste es FIXED y la moneda de la línea no coincide con currencyId */
  currencyMismatch?: boolean;
}

export interface BulkHechuraResult {
  preview: boolean;
  articlesUpdated: number;
  variantsUpdated: number;
  items?: BulkHechuraPreviewItem[];
}

export async function bulkUpdateHechura(
  jewelryId: string,
  params: BulkHechuraParams,
): Promise<BulkHechuraResult> {
  const {
    adjustType, direction, value, scope, preview = false,
    currencyId,
    ids, categoryId, brand, manufacturer, groupId,
    metalIds, metalVariantIds, preferredSupplierId,
    onlyActive, onlyFavorite,
    excludedArticleIds, excludedVariantIds, excludedCostLineIds,
  } = params;

  const exArticles  = new Set(excludedArticleIds  ?? []);
  const exVariants  = new Set(excludedVariantIds   ?? []);
  const exCostLines = new Set(excludedCostLineIds  ?? []);

  assert(["PERCENTAGE", "FIXED"].includes(adjustType), "adjustType inválido.");
  assert(["ADD", "SUBTRACT"].includes(direction), "direction inválido.");
  assert(["ARTICLE", "VARIANTS", "BOTH"].includes(scope), "scope inválido.");
  assert(value != null && isFinite(value) && value >= 0, "value debe ser un número no negativo.");

  // ---------- construir WHERE de artículo ----------
  const articleWhere: Prisma.ArticleWhereInput = {
    jewelryId,
    deletedAt: null,
    ...(ids?.length          && { id:                 { in: ids } }),
    ...(categoryId           && { categoryId }),
    ...(brand                && { brand }),
    ...(manufacturer         && { manufacturer }),
    ...(groupId              && { groupId }),
    ...(preferredSupplierId  && { preferredSupplierId }),
    ...(onlyActive           && { isActive: true }),
    ...(onlyFavorite         && { isFavorite: true }),
  };

  // Filtro por metal / variante de metal
  if (metalIds?.length || metalVariantIds?.length) {
    const costLineWhere: Prisma.ArticleCostLineWhereInput = {};
    if (metalVariantIds?.length)   costLineWhere.metalVariantId = { in: metalVariantIds };
    else if (metalIds?.length)     costLineWhere.metalVariant   = { metalId: { in: metalIds } };
    articleWhere.costComposition = { some: costLineWhere };
  }

  // ---------- cargar artículos afectados ----------
  const articles = await prisma.article.findMany({
    where: articleWhere,
    select: {
      id: true,
      name: true,
      sku: true,
      costComposition: {
        where: { type: "HECHURA" },
        select: {
          id: true,
          label: true,
          unitValue: true,
          currencyId: true,
          currency: { select: { code: true } },
        },
      },
    },
  });

  // ---------- calcular nuevos valores ----------
  const sign = direction === "ADD" ? 1 : -1;

  function applyAdjust(current: number | null): number | null {
    if (current == null) return null;  // no tocar nulos
    let next: number;
    if (adjustType === "PERCENTAGE") {
      next = current + sign * current * (value / 100);
    } else {
      next = current + sign * value;
    }
    return Math.max(0, Math.round(next * 10000) / 10000); // 4 decimales, nunca negativo
  }

  const previewItems: BulkHechuraPreviewItem[] = [];
  let articlesUpdated = 0;
  let variantsUpdated = 0;

  for (const art of articles) {
    const hechuraLines: Array<{ id: string; label: string; unitValue: any; currencyId: string | null; currency: { code: string } | null }> =
      (art as any).costComposition ?? [];

    if (scope === "ARTICLE" || scope === "BOTH") {
      // — 1. Líneas de costo tipo HECHURA (sistema nuevo, tiene prioridad)
      if (hechuraLines.length > 0) {
        for (const line of hechuraLines) {
          const oldVal = parseFloat(line.unitValue.toString());
          const lineCurrencyId = line.currencyId ?? null;
          const lineCurrencyCode = line.currency?.code ?? null;

          // Para FIXED: solo tocar líneas cuya moneda coincida con currencyId solicitado.
          // null en ambos = moneda base → coinciden.
          const isCurrencyMismatch =
            adjustType === "FIXED" &&
            lineCurrencyId !== (currencyId ?? null);

          if (preview) {
            previewItems.push({
              articleId: art.id, articleName: art.name,
              articleSku: (art as any).sku ?? undefined,
              kind: "cost_line",
              costLineId: line.id,
              costLineLabel: line.label || "Hechura",
              costLineCurrencyCode: lineCurrencyCode ?? undefined,
              oldValue: isCurrencyMismatch ? null : oldVal,
              newValue: isCurrencyMismatch ? null : applyAdjust(oldVal),
              currencyMismatch: isCurrencyMismatch || undefined,
            });
          } else if (!isCurrencyMismatch && !exCostLines.has(line.id)) {
            const newVal = applyAdjust(oldVal);
            if (newVal !== null) {
              await prisma.articleCostLine.update({
                where: { id: line.id },
                data: { unitValue: newVal },
              });
              articlesUpdated++;
            }
          }
        }
      }
    }
  }

  if (preview) {
    return { preview: true, articlesUpdated: 0, variantsUpdated: 0, items: previewItems };
  }
  return { preview: false, articlesUpdated, variantsUpdated };
}

// ===========================================================================
// Soft delete
// ===========================================================================
export async function deleteArticle(articleId: string, jewelryId: string) {
  await assertArticleOwnership(articleId, jewelryId);
  const now = new Date();
  await prisma.$transaction(async (tx) => {
    // Pre-consultar variantes para limpiar ArticleGroupItem de tipo VARIANT
    const variants = await tx.articleVariant.findMany({
      where: { articleId, deletedAt: null },
      select: { id: true },
    });
    const variantIds = variants.map((v) => v.id);

    // Limpiar grupos: items de tipo ARTICLE y de tipo VARIANT
    await tx.articleGroupItem.deleteMany({ where: { articleId } });
    if (variantIds.length > 0) {
      await tx.articleGroupItem.deleteMany({ where: { variantId: { in: variantIds } } });
    }

    // Cascade soft-delete variantes
    await tx.articleVariant.updateMany({
      where: { articleId, deletedAt: null },
      data: { deletedAt: now, isActive: false },
    });
    // Soft-delete artículo
    await tx.article.update({
      where: { id: articleId },
      data: { deletedAt: now, isActive: false },
    });
  });
  return { id: articleId };
}

export async function bulkDeleteArticles(jewelryId: string, ids: string[]) {
  if (!ids.length) return { deleted: 0, variantsDeleted: 0 };
  // Verificar pertenencia al tenant antes de borrar
  const owned = await prisma.article.findMany({
    where: { id: { in: ids }, jewelryId, deletedAt: null },
    select: { id: true },
  });
  const ownedIds = owned.map((a) => a.id);
  if (!ownedIds.length) return { deleted: 0, variantsDeleted: 0 };

  const now = new Date();
  let variantsDeletedCount = 0;
  await prisma.$transaction(async (tx) => {
    const variants = await tx.articleVariant.findMany({
      where: { articleId: { in: ownedIds }, deletedAt: null },
      select: { id: true },
    });
    const variantIds = variants.map((v) => v.id);

    await tx.articleGroupItem.deleteMany({ where: { articleId: { in: ownedIds } } });
    if (variantIds.length > 0) {
      await tx.articleGroupItem.deleteMany({ where: { variantId: { in: variantIds } } });
    }

    const varResult = await tx.articleVariant.updateMany({
      where: { articleId: { in: ownedIds }, deletedAt: null },
      data: { deletedAt: now, isActive: false },
    });
    variantsDeletedCount = varResult.count;
    await tx.article.updateMany({
      where: { id: { in: ownedIds } },
      data: { deletedAt: now, isActive: false },
    });
  });
  return { deleted: ownedIds.length, variantsDeleted: variantsDeletedCount };
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

  // Regla defensiva: las variantes heredan precio/costo del padre (solo weightOverride permitido)
  assertNoVariantPricingOverrides(data);

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
      reorderPoint:        data?.reorderPoint != null ? data.reorderPoint : null,
      openingStock:        data?.openingStock != null ? data.openingStock : null,
      minSaleQuantity:     data?.minSaleQuantity != null ? data.minSaleQuantity : null,
      maxSaleQuantity:     data?.maxSaleQuantity != null ? data.maxSaleQuantity : null,
      defaultQuantity:     data?.defaultQuantity != null ? data.defaultQuantity : null,
      imageUrl:            s(data?.imageUrl),
      notes:               s(data?.notes),
      sortOrder:           typeof data?.sortOrder === "number" ? data.sortOrder : 0,
    },
    select: VARIANT_SELECT,
  });
}

export async function updateVariant(articleId: string, variantId: string, jewelryId: string, data: any) {
  await assertArticleOwnership(articleId, jewelryId);

  // Regla defensiva: las variantes heredan precio/costo del padre (solo weightOverride permitido)
  assertNoVariantPricingOverrides(data);

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
      reorderPoint:        data?.reorderPoint !== undefined ? (data.reorderPoint ?? null) : undefined,
      minSaleQuantity:     data?.minSaleQuantity !== undefined ? (data.minSaleQuantity ?? null) : undefined,
      maxSaleQuantity:     data?.maxSaleQuantity !== undefined ? (data.maxSaleQuantity ?? null) : undefined,
      defaultQuantity:     data?.defaultQuantity !== undefined ? (data.defaultQuantity ?? null) : undefined,
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
  await prisma.$transaction([
    prisma.articleGroupItem.deleteMany({ where: { variantId } }),
    prisma.articleVariant.update({
      where: { id: variantId },
      data: { deletedAt: new Date(), isActive: false },
    }),
  ]);
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
// Stock helpers — delegados al motor central (src/lib/stock-engine.ts)
// ===========================================================================
// El motor central es la ÚNICA fuente autorizada para modificar ArticleStock.
// Estos alias mantienen compatibilidad con el código existente en este archivo.

const findStock    = engineFindStock;
export const applyStockDelta = engineApplyStockDelta;

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
  const article = await prisma.article.findUnique({
    where:  { id: articleId },
    select: { stockMode: true, articleType: true },
  });
  assert(article?.articleType !== "SERVICE",
    "Los servicios no tienen stock.");
  assert(article?.stockMode === "BY_ARTICLE",
    "Este artículo no tiene modo de stock BY_ARTICLE.");
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
    where: { id: data.warehouseId, jewelryId, deletedAt: null, isActive: true }, select: { id: true },
  });
  assert(warehouse, "Almacén no encontrado o inactivo.");

  // Validar coherencia variantId ↔ variantes activas del artículo
  const variantCount = await prisma.articleVariant.count({
    where: { articleId, deletedAt: null, isActive: true },
  });
  if (variantCount > 0) {
    assert(data?.variantId, "El artículo tiene variantes activas. Especificá la variante (variantId).");
    const variant = await prisma.articleVariant.findFirst({
      where: { id: data.variantId!, articleId, jewelryId, deletedAt: null, isActive: true },
      select: { id: true },
    });
    assert(variant, "Variante no encontrada, inactiva o no pertenece al artículo.");
  } else {
    assert(!data?.variantId, "El artículo no tiene variantes activas. No se debe especificar variantId.");
  }

  const variantId  = data?.variantId ?? null;
  const targetQty  = new Prisma.Decimal(data.quantity.toString());

  return prisma.$transaction(async (tx) => {
    const existing   = await findStock(tx, { jewelryId, warehouseId: data.warehouseId, articleId, variantId });
    const currentQty = existing?.quantity ?? new Prisma.Decimal(0);
    const delta      = targetQty.sub(currentQty);

    if (!delta.equals(0)) {
      const count = await tx.articleMovement.count({ where: { jewelryId, kind: "ADJUST" } });
      const code  = `AA-${String(count + 1).padStart(4, "0")}`;
      await tx.articleMovement.create({
        data: {
          jewelryId, kind: "ADJUST", code, status: "CONFIRMED", sourceType: "MANUAL",
          note:        s(data?.note || "Ajuste manual de stock"),
          effectiveAt: new Date(),
          warehouseId: data.warehouseId,
          createdById: userId || null,
          lines: {
            create: { jewelryId, articleId, variantId: variantId ?? null, quantity: delta },
          },
        },
      });
      await applyStockDelta(tx, { jewelryId, warehouseId: data.warehouseId, articleId, variantId, delta });
    }

    return tx.articleStock.findFirst({
      where:  { articleId, jewelryId, warehouseId: data.warehouseId, variantId },
      select: STOCK_SELECT,
    });
  });
}

// ===========================================================================
// recalcStock — reconstruye ArticleStock desde los movimientos CONFIRMED
// ===========================================================================
export async function recalcStock(articleId: string, jewelryId: string): Promise<{ rebuilt: number }> {
  await assertArticleOwnership(articleId, jewelryId);
  const article = await prisma.article.findUnique({
    where:  { id: articleId },
    select: { stockMode: true, articleType: true },
  });
  assert(article?.articleType !== "SERVICE", "Los servicios no tienen stock.");
  assert(article?.stockMode === "BY_ARTICLE", "Este artículo no tiene modo de stock BY_ARTICLE.");

  await prisma.$transaction(async (tx) => {
    await recalcArticleStock(tx, articleId, jewelryId);
  });

  const rebuilt = await prisma.articleStock.count({ where: { articleId, jewelryId } });
  return { rebuilt };
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
    costComposition: Array<{ metalVariantId: string | null; quantity: any; metalVariant: { id: string; name: string } | null }>;
    category: { mermaPercent: any } | null;
  }
) {
  const metalLines = art.costComposition.filter((l) => l.metalVariantId != null);
  if (art.stockMode !== "BY_MATERIAL" || metalLines.length === 0) {
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

  const variantIds = metalLines.map((l) => l.metalVariantId as string);
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
    for (const line of metalLines) {
      const variantId = line.metalVariantId as string;
      const available = stockMap[wh.id]?.[variantId] ?? new Prisma.Decimal(0);
      const gramsNeeded = new Prisma.Decimal(line.quantity?.toString() ?? "0").mul(mermaFactor);
      if (gramsNeeded.equals(0)) continue;
      const units = Math.floor(available.div(gramsNeeded).toNumber());
      if (units < minUnits) {
        minUnits = units;
        bottleneckVariantId = variantId;
        bottleneckVariantName = line.metalVariant?.name ?? null;
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
      costComposition: {
        where: { type: "METAL" },
        select: {
          metalVariantId: true, quantity: true,
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
  const metalLines = art.costComposition.filter((l) => l.metalVariantId != null);
  assert(metalLines.length > 0, "El artículo no tiene líneas de metal definidas en su costo.");

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
// listSkus — SKUs distintos del tenant (artículos + variantes)
// ===========================================================================
export async function listSkus(jewelryId: string): Promise<string[]> {
  const [articleSkus, variantSkus] = await Promise.all([
    prisma.article.findMany({
      where: { jewelryId, deletedAt: null, sku: { not: "" } },
      select: { sku: true },
      distinct: ["sku"],
      orderBy: { sku: "asc" },
    }),
    prisma.articleVariant.findMany({
      where: {
        article: { jewelryId, deletedAt: null },
        sku: { not: "" },
      },
      select: { sku: true },
      distinct: ["sku"],
      orderBy: { sku: "asc" },
    }),
  ]);
  const all = [
    ...articleSkus.map((r) => r.sku),
    ...variantSkus.map((r) => r.sku),
  ].filter(Boolean) as string[];
  return [...new Set(all)].sort();
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
  /** FASE 2: variante específica del componente (PRODUCT/SERVICE). */
  catalogVariantId?: string | null;
  affectsStock?: boolean;
  sortOrder?: number;
  lineAdjKind?: string | null;
  lineAdjType?: string | null;
  lineAdjValue?: number | null;
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

  // Regla defensiva: servicios no aceptan METAL, metalVariantId, ni PRODUCT
  // con affectsStock=true en su composición. HECHURA / SERVICE / MANUAL OK.
  const currentType = await prisma.article.findUnique({
    where: { id: articleId },
    select: { articleType: true },
  });
  assertServiceArticleComposition(currentType?.articleType ?? "", null, lines);

  // FASE 2: validar variantes referenciadas (existen, pertenecen al padre).
  await validateCostLineVariants(jewelryId, lines);

  await prisma.$transaction(async (tx) => {
    // Borrar líneas anteriores del artículo
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
          catalogVariantId:
            (l.type === "PRODUCT" || l.type === "SERVICE") && l.catalogItemId
              ? (l.catalogVariantId ?? null)
              : null,
          affectsStock:   l.affectsStock ?? false,
          sortOrder:      l.sortOrder ?? idx,
          lineAdjKind:    l.lineAdjKind  ?? "",
          lineAdjType:    l.lineAdjType  ?? "",
          lineAdjValue:   l.lineAdjValue ?? null,
        })),
      });
    }
  });

  // Devolver artículo actualizado con costo computado
  return getArticle(articleId, jewelryId);
}

// ===========================================================================
// previewCostLines — preview sin persistir, delega en el pricing-engine
//
// Recibe un conjunto de líneas (no necesariamente las persistidas), un ajuste
// manual global opcional, y devuelve el costo calculado + el breakdown de
// impuestos de compra sobre ese costo. Toda la aritmética vive en el motor:
//   · calculateCostFromLines (cost.ts)  — costo
//   · computePurchaseTaxes   (sale.ts)  — impuestos de compra
//
// Usos previstos: composición de costo en edición, CostosTab para valuar
// líneas registradas vs. actuales con tasas vigentes.
// ===========================================================================
export async function previewCostLines(
  articleId: string,
  jewelryId: string,
  input: {
    lines: CostLineInput[];
    manualAdjustment?: {
      kind?: string | null;
      type?: string | null;
      value?: number | null;
    };
  },
) {
  await assertArticleOwnership(articleId, jewelryId);

  const lines = Array.isArray(input?.lines) ? input.lines : [];
  const VALID_TYPES = new Set(["METAL", "HECHURA", "PRODUCT", "SERVICE", "MANUAL"]);
  for (const l of lines) {
    assert(VALID_TYPES.has(l.type), `Tipo de línea inválido: ${l.type}`);
    assert(l.quantity >= 0, "La cantidad no puede ser negativa.");
    assert(l.unitValue >= 0, "El valor unitario no puede ser negativo.");
  }

  const costResult = await calculateCostFromLines(
    jewelryId,
    lines as EngineCostLineInput[],
    {
      kind:  input?.manualAdjustment?.kind  ?? null,
      type:  input?.manualAdjustment?.type  ?? null,
      value: input?.manualAdjustment?.value ?? null,
    },
  );

  const purchaseTaxes = await enginePurchaseTaxes(
    jewelryId,
    articleId,
    costResult.value ?? null,
  );

  return {
    cost: {
      value:       costResult.value != null ? costResult.value.toFixed(4) : null,
      metalCost:   costResult.metalCost   != null ? costResult.metalCost.toFixed(4)   : null,
      hechuraCost: costResult.hechuraCost != null ? costResult.hechuraCost.toFixed(4) : null,
      totalGrams:  costResult.totalGrams  != null ? costResult.totalGrams.toFixed(4)  : null,
      partial:     costResult.partial,
      mode:        costResult.mode,
    },
    purchaseTaxes,
  };
}

// ===========================================================================
// computePurchaseTaxes — re-export desde el pricing-engine
//
// La lógica vive en src/lib/pricing-engine/pricing-engine.sale.ts.
// Mantenemos este re-export bajo el mismo nombre para compatibilidad con
// articles.controller.ts. Todos los tipos también provienen del motor.
// ===========================================================================
export const computePurchaseTaxes = enginePurchaseTaxes;
export type { PurchaseTaxBreakdownItem, PurchaseTaxResult };

// ===========================================================================
// Generic article tree search (for TPArticleScopeSelect)
// ===========================================================================
export async function searchArticlesTree(
  q: string,
  jewelryId: string,
  opts: { articleTypes?: string[]; includeVariants?: boolean }
) {
  const includeVariants = opts.includeVariants !== false;
  const typeFilter = opts.articleTypes && opts.articleTypes.length > 0
    ? { articleType: { in: opts.articleTypes as any[] } }
    : {};

  const trimmed = q.trim();
  const where: any = {
    jewelryId,
    deletedAt: null,
    isActive: true,
    ...typeFilter,
    ...(trimmed ? {
      OR: [
        { name: { contains: trimmed, mode: "insensitive" } },
        { code: { contains: trimmed, mode: "insensitive" } },
        ...(includeVariants ? [
          { variants: { some: { isActive: true, deletedAt: null, name: { contains: trimmed, mode: "insensitive" } } } },
          { variants: { some: { isActive: true, deletedAt: null, code: { contains: trimmed, mode: "insensitive" } } } },
          { variants: { some: { isActive: true, deletedAt: null, sku:  { contains: trimmed, mode: "insensitive" } } } },
        ] : []),
      ],
    } : {}),
  };

  const articles = await prisma.article.findMany({
    where,
    select: {
      id:           true,
      name:         true,
      code:         true,
      mainImageUrl: true,
      isActive:     true,
      articleType:  true,
      ...(includeVariants ? {
        variants: {
          where: { isActive: true, deletedAt: null },
          select: { id: true, name: true, code: true, sku: true, imageUrl: true, isActive: true },
          orderBy: { sortOrder: "asc" as const },
        },
      } : {}),
    },
    orderBy: { name: "asc" },
    take: 40,
  });

  return articles.map((a: any) => ({
    articleId:    a.id,
    name:         a.name,
    code:         a.code,
    mainImageUrl: a.mainImageUrl || null,
    isActive:     a.isActive,
    articleType:  a.articleType,
    hasVariants:  includeVariants ? (a.variants?.length > 0) : false,
    variants:     includeVariants
      ? (a.variants ?? []).map((v: any) => ({
          variantId: v.id,
          name:      v.name,
          code:      v.code,
          sku:       v.sku,
          imageUrl:  v.imageUrl || null,
          isActive:  v.isActive,
        }))
      : [],
  }));
}

// ===========================================================================
// Combo comercial — disponibilidad calculada según stock de componentes
// ===========================================================================
//
// Devuelve cuántos combos pueden venderse según el stock de los componentes
// (con `affectsStock=true`). Si se pasa `warehouseId`, calcula solo en ese
// almacén; sin almacén suma el stock de todos los almacenes.
//
// Uso típico desde frontend:
//   GET /api/articles/:id/combo-availability?warehouseId=...
export async function getComboAvailability(
  articleId: string,
  jewelryId: string,
  warehouseId?: string,
) {
  return computeComboAvailability(prisma, {
    jewelryId,
    articleId,
    warehouseId: warehouseId || null,
  });
}
