import type { Response } from "express";
import * as service from "./articles.service.js";
import * as importService from "./articles.import.service.js";
import * as variantAttrService from "./article-variant-attributes.service.js";
import * as groupsService from "../article-groups/article-groups.service.js";
import { toPublicUploadUrl } from "../../lib/uploads/localUploads.js";
import type { Request } from "express";
import {
  resolveFinalSalePrice,
  applySalesChannelAdjustment,
  applyCouponAdjustment,
  computeSaleDocumentTotals,
  type ChannelAdjustmentInput,
  type CouponInput,
  type SaleDocumentTotalsLineInput,
  type SaleDocumentTotals,
  // Sprint 3 — capa 10 del orden inmutable: resolución oficial del envío.
  resolveShippingAmount,
} from "../../lib/pricing-engine/pricing-engine.js";
import { validateCoupon } from "../coupons/coupons.service.js";
import { getCheckoutPreview } from "../payments/payments.service.js";
import { auditLog } from "../../lib/auditLogger.js";
import { prisma } from "../../lib/prisma.js";
import {
  buildComposition,
  fetchMetalVariantInfo,
  resolveMetalVariantIdFromResult,
} from "../../lib/pricing-composition.js";
// Multimoneda en preview (Fase MM). El motor sigue calculando en moneda BASE;
// el controller convierte la respuesta cuando el operador eligió otra moneda.
// Confirmación NO usa este helper — los snapshots persisten en moneda base.
import {
  getCurrencyDisplayContext,
  buildResponseCurrencyMetadata,
  convertArticlePreviewResponseInPlace,
  // FASE 1.1 G6 — converter de cost-lines/preview a la moneda solicitada.
  convertCostPreviewResponseInPlace,
} from "../../lib/pricing-currency-display.js";
// Política de redondeo a nivel comprobante (modo UNIFIED). El simulador NO
// aplica el redondeo doc (no hay comprobante), pero SÍ debe pasar
// `suppressListDeferredRounding` al motor cuando la política está activa
// para evitar divergencias con la Factura Ventas: si una lista tiene
// `roundingApplyOn = NET | TOTAL` y el tenant tiene política doc activa, la
// factura suprime ese redondeo y delega al motor doc-totals; el simulador
// debe espejar esa supresión para mostrar el mismo `unitPrice`.
import { loadDocumentRoundingConfig } from "../../lib/document-rounding.js";

function s(v: any) { return String(v ?? "").trim(); }
function assert(cond: any, msg: string) { if (!cond) { const e: any = new Error(msg); e.status = 400; throw e; } }

// ===========================================================================
// Article CRUD
// ===========================================================================
export async function list(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  // Soporte page/pageSize (prioridad) ó skip/take (legacy)
  const pageSize = parseInt(String(req.query.pageSize ?? req.query.take ?? "50"), 10) || 50;
  const page     = parseInt(String(req.query.page ?? "0"), 10) || 0;
  const skip     = parseInt(String(req.query.skip ?? "0"), 10) || 0;
  return res.json(await service.listArticles(req.user.jewelryId, {
    q: s(req.query.q),
    categoryId: s(req.query.categoryId) || undefined,
    articleType: s(req.query.articleType) || undefined,
    status: s(req.query.status) || undefined,
    stockMode: s(req.query.stockMode) || undefined,
    barcode: s(req.query.barcode) || undefined,
    sku: s(req.query.sku) || undefined,
    showInStore: req.query.showInStore === "true" ? true : req.query.showInStore === "false" ? false : undefined,
    preferredSupplierId: s(req.query.preferredSupplierId) || undefined,
    isFavorite: req.query.isFavorite === "true" ? true : undefined,
    showInActive: req.query.showInActive === "true" || req.query.showInactive === "true",
    groupId:  s(req.query.groupId)  || undefined,
    brand:    s(req.query.brand)    || undefined,
    hasVariants: req.query.hasVariants === "true" ? true : req.query.hasVariants === "false" ? false : undefined,
    metalId:        s(req.query.metalId)        || undefined,
    metalVariantId: s(req.query.metalVariantId) || undefined,
    ids: req.query.ids ? String(req.query.ids).split(",").filter(Boolean) : undefined,
    sortKey: s(req.query.sortKey) || undefined,
    sortDir: s(req.query.sortDir) === "desc" ? "desc" : undefined,
    ...(page > 0 ? { page, pageSize } : { skip, take: pageSize }),
  }));
}

export async function getOne(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");
  return res.json(await service.getArticle(id, req.user.jewelryId));
}

export async function create(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  console.log("BODY CREATE ARTICLE:", JSON.stringify(req.body, null, 2));
  return res.status(201).json(await service.createArticle(req.user.jewelryId, req.body));
}

export async function update(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");
  return res.json(await service.updateArticle(id, req.user.jewelryId, req.body));
}

export async function clone(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");
  return res.status(201).json(await service.cloneArticle(id, req.user.jewelryId));
}

export async function toggle(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");
  return res.json(await service.toggleArticle(id, req.user.jewelryId));
}

export async function favorite(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");
  return res.json(await service.toggleFavorite(id, req.user.jewelryId));
}

export async function bulkUpdate(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  const { ids, isActive, isFavorite, categoryId, groupId, showInStore, isReturnable, sellWithoutVariants } = req.body ?? {};
  if (!Array.isArray(ids) || ids.length === 0) {
    return res.status(400).json({ ok: false, message: "ids requerido y no vacío." });
  }
  const data: Record<string, unknown> = {};
  if (typeof isActive            === "boolean") data.isActive            = isActive;
  if (typeof isFavorite          === "boolean") data.isFavorite          = isFavorite;
  if (typeof showInStore         === "boolean") data.showInStore         = showInStore;
  if (typeof isReturnable        === "boolean") data.isReturnable        = isReturnable;
  if (typeof sellWithoutVariants === "boolean") data.sellWithoutVariants = sellWithoutVariants;
  if (typeof categoryId === "string" && categoryId) data.categoryId = categoryId;
  if (typeof groupId    === "string" && groupId)    data.groupId    = groupId;
  if (!Object.keys(data).length) {
    return res.status(400).json({ ok: false, message: "Nada que actualizar." });
  }
  return res.json(await service.bulkUpdateArticles(req.user.jewelryId, ids, data));
}

export async function bulkHechura(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  const {
    adjustType, direction, value, scope, preview,
    currencyId,
    ids, categoryId, brand, manufacturer, groupId,
    metalIds, metalVariantIds, preferredSupplierId,
    onlyActive, onlyFavorite,
    excludedArticleIds, excludedVariantIds, excludedCostLineIds,
  } = req.body ?? {};

  assert(adjustType, "adjustType requerido.");
  assert(direction,  "direction requerido.");
  assert(value != null, "value requerido.");
  assert(scope,      "scope requerido.");

  const result = await service.bulkUpdateHechura(req.user.jewelryId, {
    adjustType,
    direction,
    value: Number(value),
    scope,
    preview: preview === true || preview === "true",
    currencyId:          typeof currencyId        === "string" && currencyId  ? currencyId  : undefined,
    ids:                 Array.isArray(ids)                   ? ids                  : undefined,
    categoryId:          typeof categoryId        === "string" ? categoryId           : undefined,
    brand:               typeof brand             === "string" ? brand                : undefined,
    manufacturer:        typeof manufacturer      === "string" ? manufacturer         : undefined,
    groupId:             typeof groupId           === "string" ? groupId              : undefined,
    metalIds:            Array.isArray(metalIds)              ? metalIds             : undefined,
    metalVariantIds:     Array.isArray(metalVariantIds)       ? metalVariantIds      : undefined,
    preferredSupplierId: typeof preferredSupplierId === "string" ? preferredSupplierId : undefined,
    onlyActive:   onlyActive  === true || onlyActive  === "true",
    onlyFavorite: onlyFavorite === true || onlyFavorite === "true",
    excludedArticleIds:  Array.isArray(excludedArticleIds)  ? excludedArticleIds  : undefined,
    excludedVariantIds:  Array.isArray(excludedVariantIds)  ? excludedVariantIds  : undefined,
    excludedCostLineIds: Array.isArray(excludedCostLineIds) ? excludedCostLineIds : undefined,
  });

  if (!preview) {
    auditLog(req, {
      action: "BULK_HECHURA_UPDATE",
      success: true,
      meta: {
        adjustType, direction, value, scope,
        articlesUpdated: result.articlesUpdated,
        variantsUpdated: result.variantsUpdated,
      },
    });
  }

  return res.json(result);
}

export async function remove(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");
  return res.json(await service.deleteArticle(id, req.user.jewelryId));
}

export async function bulkRemove(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  const { ids } = req.body ?? {};
  if (!Array.isArray(ids) || ids.length === 0) {
    return res.status(400).json({ ok: false, message: "ids requerido y no vacío." });
  }
  return res.json(await service.bulkDeleteArticles(req.user.jewelryId, ids));
}

// ===========================================================================
// Cost Lines (nueva composición de costo por líneas)
// ===========================================================================
export async function setCostLines(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");
  const lines = req.body?.lines;
  assert(Array.isArray(lines), "Se esperaba { lines: [...] }.");
  return res.json(await service.setCostLines(id, req.user.jewelryId, lines));
}

// Preview de costo + impuestos de compra para un set de líneas (sin persistir).
// Usa el pricing-engine como única fuente de verdad.
export async function previewCostLines(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");
  const lines = req.body?.lines;
  assert(Array.isArray(lines), "Se esperaba { lines: [...] }.");
  const manualAdjustment = req.body?.manualAdjustment ?? undefined;
  // FASE 1.1 G6 — moneda de display. Si viene currencyId distinto a la base,
  // el response se convierte in-place. Mismo patrón que pricing-preview.
  const responseCurrencyId =
    typeof req.body?.currencyId === "string" && req.body.currencyId
      ? req.body.currencyId
      : null;

  const responseData = await service.previewCostLines(id, req.user.jewelryId, {
    lines,
    manualAdjustment,
  });

  const currencyCtx = await getCurrencyDisplayContext(req.user.jewelryId, responseCurrencyId);
  if (currencyCtx?.applied) {
    convertCostPreviewResponseInPlace(responseData, currencyCtx.rate);
  }
  if (currencyCtx) {
    Object.assign(responseData as any, buildResponseCurrencyMetadata(currencyCtx));
  }

  return res.json(responseData);
}

// ===========================================================================
// Variants
// ===========================================================================
export async function listVariants(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");
  return res.json(await service.listVariants(id, req.user.jewelryId));
}

export async function listDeletedVariants(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");
  return res.json(await service.listDeletedVariants(id, req.user.jewelryId));
}

export async function createVariant(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");
  return res.status(201).json(await service.createVariant(id, req.user.jewelryId, req.body));
}

export async function updateVariant(req: any, res: Response) {
  const id = s(req.params?.id);
  const variantId = s(req.params?.variantId);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id && variantId, "Ids inválidos.");
  return res.json(await service.updateVariant(id, variantId, req.user.jewelryId, req.body));
}

export async function toggleVariant(req: any, res: Response) {
  const id = s(req.params?.id);
  const variantId = s(req.params?.variantId);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id && variantId, "Ids inválidos.");
  return res.json(await service.toggleVariant(id, variantId, req.user.jewelryId));
}

export async function removeVariant(req: any, res: Response) {
  const id = s(req.params?.id);
  const variantId = s(req.params?.variantId);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id && variantId, "Ids inválidos.");
  return res.json(await service.removeVariant(id, variantId, req.user.jewelryId));
}

export async function restoreVariant(req: any, res: Response) {
  const id = s(req.params?.id);
  const variantId = s(req.params?.variantId);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id && variantId, "Ids inválidos.");
  return res.json(await service.restoreVariant(id, variantId, req.user.jewelryId));
}

// ===========================================================================
// Reorder variants
// ===========================================================================
export async function reorderVariants(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");
  const { ids } = req.body ?? {};
  assert(Array.isArray(ids), "ids requerido.");
  return res.json(await service.reorderVariants(id, req.user.jewelryId, ids));
}

// ===========================================================================
// Attribute values
// ===========================================================================
export async function setAttributeValues(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");
  const values = req.body?.values ?? req.body;
  return res.json(await service.setAttributeValues(id, req.user.jewelryId, values));
}

// ===========================================================================
// Variant attribute values
// ===========================================================================
export async function getVariantAttributeValues(req: any, res: Response) {
  const id = s(req.params?.id);
  const variantId = s(req.params?.variantId);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id && variantId, "Ids inválidos.");
  return res.json(await variantAttrService.getVariantAttributeValues(id, variantId, req.user.jewelryId));
}

export async function setVariantAttributeValues(req: any, res: Response) {
  const id = s(req.params?.id);
  const variantId = s(req.params?.variantId);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id && variantId, "Ids inválidos.");
  const values = Array.isArray(req.body) ? req.body : (req.body?.values ?? []);
  assert(Array.isArray(values), "Se esperaba { values: [...] } o un array.");
  return res.json(await variantAttrService.setVariantAttributeValues(id, variantId, req.user.jewelryId, values));
}

// ===========================================================================
// Images
// ===========================================================================
export async function addImage(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");
  const file = req.file as (Express.Multer.File & { _tpFolder?: string }) | undefined;
  if (!file) return res.status(400).json({ message: "No se recibió ningún archivo." });
  const folder = s((file as any)._tpFolder || "articles/images");
  const url = toPublicUploadUrl(req as Request, folder, file.filename);
  if (!url) return res.status(500).json({ message: "No se pudo generar la URL." });
  const isMain = req.body?.isMain === "true" || req.body?.isMain === true;
  return res.status(201).json(await service.addImage(id, req.user.jewelryId, { url, label: s(req.body?.label), isMain }));
}

export async function setMainImage(req: any, res: Response) {
  const id = s(req.params?.id);
  const imageId = s(req.params?.imageId);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id && imageId, "Ids inválidos.");
  return res.json(await service.setMainImage(id, imageId, req.user.jewelryId));
}

export async function updateImageLabel(req: any, res: Response) {
  const id = s(req.params?.id);
  const imageId = s(req.params?.imageId);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id && imageId, "Ids inválidos.");
  return res.json(await service.updateImageLabel(id, imageId, req.user.jewelryId, s(req.body?.label)));
}

export async function removeImage(req: any, res: Response) {
  const id = s(req.params?.id);
  const imageId = s(req.params?.imageId);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id && imageId, "Ids inválidos.");
  return res.json(await service.removeImage(id, imageId, req.user.jewelryId));
}

// ===========================================================================
// Stock
// ===========================================================================
export async function getStock(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");
  return res.json(await service.getStock(id, req.user.jewelryId));
}

export async function adjustStock(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");
  const userId = s(req.userId || req.user?.id || "");
  return res.json(await service.adjustStock(id, req.user.jewelryId, userId, req.body));
}

export async function recalcStock(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");
  return res.json(await service.recalcStock(id, req.user.jewelryId));
}

export async function getMaterialAvailability(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");
  const warehouseId = s(req.query.warehouseId) || undefined;
  return res.json(await service.calcMaterialAvailability(id, req.user.jewelryId, warehouseId));
}

// ===========================================================================
// Combo availability — cuántos combos pueden venderse según stock componentes
// ===========================================================================
export async function getComboAvailability(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");
  const warehouseId = s(req.query.warehouseId) || undefined;
  return res.json(await service.getComboAvailability(id, req.user.jewelryId, warehouseId));
}

// ===========================================================================
// Brands list
// ===========================================================================
export async function listBrands(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  const brands = await service.listBrands(req.user.jewelryId);
  return res.json({ brands });
}

// ===========================================================================
// SKUs list
// ===========================================================================
export async function listSkus(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  const skus = await service.listSkus(req.user.jewelryId);
  return res.json({ skus });
}

// ===========================================================================
// Barcode lookup
// ===========================================================================
export async function lookupByBarcode(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  const barcode = s(req.query.barcode || req.params?.barcode);
  assert(barcode, "Falta el código de barras.");
  return res.json(await service.lookupByBarcode(barcode, req.user.jewelryId));
}

// ===========================================================================
// Import
// ===========================================================================
export async function getImportTemplate(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  const jewelryId = req.user.jewelryId as string;

  // Cargar catálogos del tenant para los dropdowns del template
  const [categories, groups, suppliers] = await Promise.all([
    prisma.articleCategory.findMany({
      where: { jewelryId, deletedAt: null },
      select: { name: true },
      orderBy: { name: "asc" },
    }),
    prisma.articleGroup.findMany({
      where: { jewelryId, deletedAt: null },
      select: { name: true },
      orderBy: { name: "asc" },
    }),
    prisma.commercialEntity.findMany({
      where: { jewelryId, deletedAt: null, isSupplier: true, isActive: true },
      select: { code: true, displayName: true },
      orderBy: { displayName: "asc" },
    }),
  ]);

  const buffer = await importService.generateImportTemplate({
    categories: categories.map((c: any) => c.name),
    groups: groups.map((g: any) => g.name),
    suppliers: suppliers.map((sp: any) => sp.displayName),
  });

  res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
  res.setHeader("Content-Disposition", 'attachment; filename="tptech_articulos_template.xlsx"');
  return res.send(buffer);
}

export async function exportArticlesXlsx(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  const jewelryId = req.user.jewelryId as string;

  const [categories, groups, suppliers] = await Promise.all([
    prisma.articleCategory.findMany({
      where: { jewelryId, deletedAt: null },
      select: { name: true },
      orderBy: { name: "asc" },
    }),
    prisma.articleGroup.findMany({
      where: { jewelryId, deletedAt: null },
      select: { name: true },
      orderBy: { name: "asc" },
    }),
    prisma.commercialEntity.findMany({
      where: { jewelryId, deletedAt: null, isSupplier: true, isActive: true },
      select: { code: true, displayName: true },
      orderBy: { displayName: "asc" },
    }),
  ]);

  const buffer = await importService.exportArticles(jewelryId, {
    categories: categories.map((c: any) => c.name),
    groups: groups.map((g: any) => g.name),
    suppliers: suppliers.map((sp: any) => sp.displayName),
  });

  res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
  res.setHeader("Content-Disposition", `attachment; filename="tptech_articulos_export_${new Date().toISOString().slice(0, 10)}.xlsx"`);
  return res.send(buffer);
}

// ── V2 helpers ────────────────────────────────────────────────────────────────
async function loadCatalogV2(jewelryId: string) {
  const [categories, groups, suppliers, metalsRaw, warehouses] = await Promise.all([
    prisma.articleCategory.findMany({
      where: { jewelryId, deletedAt: null },
      select: { name: true },
      orderBy: { name: "asc" },
    }),
    prisma.articleGroup.findMany({
      where: { jewelryId, deletedAt: null },
      select: { name: true },
      orderBy: { name: "asc" },
    }),
    prisma.commercialEntity.findMany({
      where: { jewelryId, deletedAt: null, isSupplier: true, isActive: true },
      select: { code: true, displayName: true },
      orderBy: { displayName: "asc" },
    }),
    prisma.metal.findMany({
      where: { jewelryId, deletedAt: null, isActive: true },
      select: {
        name: true,
        variants: {
          where: { deletedAt: null, isActive: true },
          select: { name: true },
          orderBy: { name: "asc" },
        },
      },
      orderBy: { sortOrder: "asc" },
    }),
    prisma.warehouse.findMany({
      where: { jewelryId, deletedAt: null, isActive: true },
      select: { name: true, code: true },
      orderBy: { name: "asc" },
    }),
  ]);

  const metalVariants: string[] = [];
  for (const m of metalsRaw as any[]) {
    for (const v of m.variants) {
      metalVariants.push(`${m.name} · ${v.name}`);
    }
  }

  return {
    categories:   categories.map((c: any) => c.name),
    groups:       groups.map((g: any) => g.name),
    suppliers:    suppliers.map((sp: any) => sp.displayName),
    metals:       metalsRaw.map((m: any) => m.name),
    metalVariants,
    warehouses:   warehouses.map((w: any) => w.code ? `${w.code} · ${w.name}` : w.name),
  };
}

export async function getImportTemplateV2(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  const catalog = await loadCatalogV2(req.user.jewelryId as string);
  const buffer = await importService.generateImportTemplateV2(catalog);
  res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
  res.setHeader("Content-Disposition", 'attachment; filename="tptech_articulos_template_v2.xlsx"');
  return res.send(buffer);
}

/** Convierte un nombre de atributo en un identificador válido para Excel named range.
 *  Reglas: quitar acentos, reemplazar espacios/guiones con _, eliminar chars no-alnum. */
function toExcelRangeName(name: string): string {
  const clean = name
    .normalize("NFD").replace(/[\u0300-\u036f]/g, "")  // quitar acentos
    .replace(/[\s\-]+/g, "_")
    .replace(/[^A-Za-z0-9_]/g, "");
  return /^[A-Za-z]/.test(clean) ? clean : `Attr_${clean}`;
}

async function loadGuidedCatalog(jewelryId: string): Promise<importService.GuidedTemplateCatalog> {
  const [categories, groups, suppliers, taxes, metalsRaw, warehouses, currencies, attrDefs, brandsRaw, manufacturersRaw] = await Promise.all([
    prisma.articleCategory.findMany({
      where: { jewelryId, deletedAt: null },
      select: { name: true },
      orderBy: { name: "asc" },
    }),
    prisma.articleGroup.findMany({
      where: { jewelryId, deletedAt: null },
      select: { name: true },
      orderBy: { name: "asc" },
    }),
    prisma.commercialEntity.findMany({
      where: { jewelryId, deletedAt: null, isSupplier: true, isActive: true },
      select: { code: true, displayName: true },
      orderBy: { displayName: "asc" },
    }),
    prisma.tax.findMany({
      where: { jewelryId, deletedAt: null, isActive: true },
      select: { name: true },
      orderBy: { name: "asc" },
    }),
    prisma.metal.findMany({
      where: { jewelryId, deletedAt: null, isActive: true },
      select: {
        name: true,
        variants: {
          where: { deletedAt: null, isActive: true },
          select: { name: true },
          orderBy: { name: "asc" },
        },
      },
      orderBy: { sortOrder: "asc" },
    }),
    prisma.warehouse.findMany({
      where: { jewelryId, deletedAt: null, isActive: true },
      select: { name: true, code: true },
      orderBy: { name: "asc" },
    }),
    prisma.currency.findMany({
      // OR: incluir siempre la moneda base aunque isActive sea false
      where: { jewelryId, deletedAt: null, OR: [{ isActive: true }, { isBase: true }] },
      select: { name: true, code: true, isBase: true },
      orderBy: [{ isBase: "desc" }, { name: "asc" }],
    }),
    prisma.articleAttributeDef.findMany({
      where: { jewelryId, deletedAt: null, isActive: true },
      select: {
        name: true,
        inputType: true,
        options: {
          where: { isActive: true },
          select: { label: true },
          orderBy: [{ sortOrder: "asc" }, { label: "asc" }],
        },
      },
      orderBy: { name: "asc" },
    }),
    // Marcas y fabricantes distintos de artículos existentes del tenant
    prisma.article.findMany({
      where: { jewelryId, deletedAt: null, brand: { not: "" } },
      select: { brand: true },
      distinct: ["brand"],
      orderBy: { brand: "asc" },
    }),
    prisma.article.findMany({
      where: { jewelryId, deletedAt: null, manufacturer: { not: "" } },
      select: { manufacturer: true },
      distinct: ["manufacturer"],
      orderBy: { manufacturer: "asc" },
    }),
  ]);

  const metalVariants: string[] = [];
  for (const m of metalsRaw as any[]) {
    for (const v of m.variants) {
      metalVariants.push(`${m.name} · ${v.name}`);
    }
  }

  // Atributos con opciones predefinidas (SELECT / MULTISELECT / COLOR)
  const OPTION_TYPES = ["SELECT", "MULTISELECT", "COLOR"];
  const attributeOptions = (attrDefs as any[])
    .filter(d => OPTION_TYPES.includes(d.inputType) && d.options.length > 0)
    .map(d => ({
      name:      d.name as string,
      rangeName: toExcelRangeName(d.name),
      options:   d.options.map((o: any) => o.label as string),
    }));

  return {
    categories:    categories.map((c: any) => c.name),
    groups:        groups.map((g: any) => g.name),
    suppliers:     suppliers.map((sp: any) => sp.displayName),
    taxes:         taxes.map((t: any) => t.name),
    metals:        metalsRaw.map((m: any) => m.name),
    metalVariants,
    warehouses:    warehouses.map((w: any) => w.code ? `${w.code} · ${w.name}` : w.name),
    currencies:    currencies.map((c: any) => {
      const label = c.code ? `${c.code} · ${c.name}` : c.name;
      return c.isBase ? `${label} (Base)` : label;
    }),
    attributeDefs: attrDefs.map((d: any) => d.name),
    attributeOptions,
    brands:        brandsRaw.map((r: any) => r.brand as string),
    manufacturers: manufacturersRaw.map((r: any) => r.manufacturer as string),
  };
}

export async function getGuidedTemplate(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  const catalog = await loadGuidedCatalog(req.user.jewelryId as string);
  const buffer = await importService.generateGuidedTemplate(catalog);
  res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
  res.setHeader("Content-Disposition", 'attachment; filename="tptech_articulos_plantilla_guiada.xlsx"');
  return res.send(buffer);
}

export async function exportGuidedXlsx(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  const jewelryId = req.user.jewelryId as string;
  const catalog = await loadGuidedCatalog(jewelryId);
  const buffer = await importService.exportArticlesGuided(jewelryId, catalog);
  const date = new Date().toISOString().slice(0, 10);
  res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
  res.setHeader("Content-Disposition", `attachment; filename="tptech_articulos_${date}.xlsx"`);
  return res.send(buffer);
}

export async function exportArticlesV2Xlsx(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  const jewelryId = req.user.jewelryId as string;
  const catalog = await loadCatalogV2(jewelryId);
  const buffer = await importService.exportArticlesV2(jewelryId, catalog);
  const date = new Date().toISOString().slice(0, 10);
  res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
  res.setHeader("Content-Disposition", `attachment; filename="tptech_articulos_export_v2_${date}.xlsx"`);
  return res.send(buffer);
}

export async function previewImport(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  const file = (req as any).file;
  assert(file?.buffer, "No se recibió ningún archivo.");
  const parsed = importService.parseImportFileAuto(file.buffer, file.mimetype);
  if (parsed.format === "guided") {
    const result = await importService.previewImportGuided(parsed.buffer, req.user.jewelryId);
    return res.json(result);
  }
  if (parsed.format === "v2") {
    const result = await importService.previewImportV2(parsed.data, req.user.jewelryId);
    return res.json(result);
  }
  // v1
  const rows = parsed.rows;
  assert(rows.length > 0, "El archivo no contiene datos.");
  assert(rows.length <= 2000, "El archivo supera el límite de 2000 filas.");
  const result = await importService.previewImport(rows, req.user.jewelryId);
  return res.json(result);
}

export async function executeImport(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  const file = (req as any).file;
  assert(file?.buffer, "No se recibió ningún archivo.");
  const parsed = importService.parseImportFileAuto(file.buffer, file.mimetype);
  const onConflict: "skip" | "update" = req.body?.onConflict === "update" ? "update" : "skip";
  const importOpts = {
    onConflict,
    userId:   req.user?.id as string | undefined,
    fileName: String(file?.originalname ?? ""),
  };
  if (parsed.format === "guided") {
    const result = await importService.executeImportGuided(parsed.buffer, req.user.jewelryId, importOpts);
    return res.json(result);
  }
  if (parsed.format === "v2") {
    const result = await importService.executeImportV2(parsed.data, req.user.jewelryId, importOpts);
    return res.json(result);
  }
  // v1
  const rows = parsed.rows;
  assert(rows.length > 0, "El archivo no contiene datos.");
  assert(rows.length <= 2000, "El archivo supera el límite de 2000 filas.");
  const result = await importService.executeImport(rows, req.user.jewelryId, importOpts);
  return res.json(result);
}

// ===========================================================================
// Import — JSON endpoints (para mapeo de columnas en frontend)
// ===========================================================================
export async function previewImportJson(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  const rows = req.body?.rows;
  assert(Array.isArray(rows) && rows.length > 0, "Se esperaba { rows: [...] }.");
  assert(rows.length <= 2000, "El archivo supera el límite de 2000 filas.");
  const result = await importService.previewImport(rows, req.user.jewelryId);
  return res.json(result);
}

export async function executeImportJson(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  const rows = req.body?.rows;
  assert(Array.isArray(rows) && rows.length > 0, "Se esperaba { rows: [...] }.");
  assert(rows.length <= 2000, "El archivo supera el límite de 2000 filas.");
  const onConflict: "skip" | "update" = req.body?.onConflict === "update" ? "update" : "skip";
  const fileName = s(req.body?.fileName ?? "Importación manual");
  const result = await importService.executeImport(rows, req.user.jewelryId, {
    onConflict,
    userId: req.user?.id as string | undefined,
    fileName,
  });
  return res.json(result);
}

// ===========================================================================
// Variant image upload (legacy — sube y actualiza imageUrl directo)
// ===========================================================================
export async function uploadVariantImage(req: any, res: Response) {
  const id = s(req.params?.id);
  const variantId = s(req.params?.variantId);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id && variantId, "Ids inválidos.");
  const file = req.file as (Express.Multer.File & { _tpFolder?: string }) | undefined;
  if (!file) return res.status(400).json({ message: "No se recibió ningún archivo." });
  const folder = s((file as any)._tpFolder || "articles/images");
  const url = toPublicUploadUrl(req as Request, folder, file.filename);
  if (!url) return res.status(500).json({ message: "No se pudo generar la URL." });
  // Agrega a la galería y actualiza imageUrl (campo denormalizado)
  await service.addVariantImage(id, variantId, req.user.jewelryId, { url, isMain: true });
  return res.json(await service.updateVariant(id, variantId, req.user.jewelryId, { imageUrl: url }));
}

// ===========================================================================
// Variant images gallery (CRUD completo)
// ===========================================================================
export async function addVariantImage(req: any, res: Response) {
  const id = s(req.params?.id);
  const variantId = s(req.params?.variantId);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id && variantId, "Ids inválidos.");
  const file = req.file as (Express.Multer.File & { _tpFolder?: string }) | undefined;
  if (!file) return res.status(400).json({ message: "No se recibió ningún archivo." });
  const folder = s((file as any)._tpFolder || "articles/images");
  const url = toPublicUploadUrl(req as Request, folder, file.filename);
  if (!url) return res.status(500).json({ message: "No se pudo generar la URL." });
  const isMain = req.body?.isMain === "true" || req.body?.isMain === true;
  return res.status(201).json(await service.addVariantImage(id, variantId, req.user.jewelryId, { url, label: s(req.body?.label), isMain }));
}

export async function setVariantMainImage(req: any, res: Response) {
  const id = s(req.params?.id);
  const variantId = s(req.params?.variantId);
  const imageId = s(req.params?.imageId);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id && variantId && imageId, "Ids inválidos.");
  return res.json(await service.setVariantMainImage(id, variantId, imageId, req.user.jewelryId));
}

export async function removeVariantImage(req: any, res: Response) {
  const id = s(req.params?.id);
  const variantId = s(req.params?.variantId);
  const imageId = s(req.params?.imageId);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id && variantId && imageId, "Ids inválidos.");
  return res.json(await service.removeVariantImage(id, variantId, imageId, req.user.jewelryId));
}

// ===========================================================================
// Sale price resolution
// ===========================================================================
export async function getSalePrice(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  const articleId = s(req.params?.id);
  assert(articleId, "Id de artículo inválido.");

  const clientId   = s(req.query.clientId)   || undefined;
  const variantId  = s(req.query.variantId)  || null;
  const categoryId = s(req.query.categoryId) || undefined;
  const quantity   = parseFloat(String(req.query.quantity ?? "1")) || 1;

  // Anti doble redondeo: si el tenant tiene política doc activa, suprimimos el
  // redondeo diferido (`applyOn = NET | TOTAL`) de la lista. Mismo flag que
  // usan `getPricingPreview` y `previewSale` — sin él, este endpoint puede
  // devolver un `unitPrice` distinto al que ve la factura cuando la lista
  // usa redondeo NET/TOTAL y la política doc está activa.
  //
  // Nota: este endpoint NO aplica el redondeo doc (es per-artículo, no hay
  // comprobante). Solo elimina la divergencia con la factura.
  const { suppressListDeferredRounding } = await loadDocumentRoundingConfig(
    req.user.jewelryId,
  );

  // Motor único de pricing — mismo que /pricing-preview, serializado a strings para compat frontend
  const r = await resolveFinalSalePrice(req.user.jewelryId, {
    articleId, variantId, clientId, categoryId, quantity,
    suppressListDeferredRounding,
  });

  const fmt = (v: any) => v != null ? v.toFixed(4) : null;
  return res.json({
    unitPrice:               fmt(r.unitPrice),
    basePrice:               fmt(r.basePrice),
    quantityDiscountAmount:  fmt(r.quantityDiscountAmount),
    promotionDiscountAmount: fmt(r.promotionDiscountAmount),
    discountAmount:          r.discountAmount.greaterThan(0) ? r.discountAmount.toFixed(4) : null,
    priceSource:             r.priceSource,
    baseSource:              r.baseSource,
    appliedPriceListId:      r.appliedPriceListId,
    appliedPriceListName:    r.appliedPriceListName,
    appliedPromotionId:      r.appliedPromotionId,
    appliedPromotionName:    r.appliedPromotionName,
    appliedDiscountId:       r.appliedDiscountId,
    partial:                 r.partial,
    unitCost:                fmt(r.unitCost),
    unitMargin:              fmt(r.unitMargin),
    marginPercent:           fmt(r.marginPercent),
    costPartial:             r.costPartial,
    costMode:                r.costMode,
  });
}


// ===========================================================================
// Pricing preview — devuelve pasos detallados del motor de precios
// ===========================================================================

/** Convierte cualquier Prisma.Decimal en string dentro de un objeto meta. */
function serializeMeta(meta?: Record<string, unknown>): Record<string, unknown> | undefined {
  if (!meta) return undefined;
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(meta)) {
    if (v == null)                                    out[k] = v;
    else if (typeof v === "object" && "toFixed" in v) out[k] = (v as any).toString();
    else                                              out[k] = v;
  }
  return out;
}

export async function getPricingPreview(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  const articleId = s(req.params?.id);
  assert(articleId, "Id de artículo inválido.");

  const clientId              = s(req.query.clientId)              || undefined;
  const variantId             = s(req.query.variantId)             || null;
  const quantity              = parseFloat(String(req.query.quantity ?? "1")) || 1;
  const paymentMethodId       = s(req.query.paymentMethodId)       || undefined;
  const installmentsQty       = parseInt(String(req.query.installmentsQty ?? "0"), 10) || 0;
  const priceListIdOverride   = s(req.query.priceListId)           || null;
  const channelId             = s(req.query.channelId)             || null;
  const couponCode            = s(req.query.couponCode)            || null;
  const quantityDiscountIds   = s(req.query.quantityDiscountIds)
    ? s(req.query.quantityDiscountIds).split(",").map((id: string) => id.trim()).filter(Boolean)
    : undefined;
  // Fase MM — moneda en la que se quiere ver el response. Si no viene o coincide
  // con la base, el response queda en moneda base (sin conversión).
  const responseCurrencyId    = s(req.query.currencyId)            || null;

  // Override manual del impuesto a nivel línea (solo simulación / edición
  // controlada). El frontend lo manda cuando el operador edita el campo
  // Impuestos en el editor de líneas. El motor reemplaza el cálculo normal
  // por un único item sintético.
  const taxOverrideModeRaw  = s(req.query.taxOverrideMode);
  const taxOverrideValueRaw = req.query.taxOverrideValue;
  const taxOverrideMode: "PERCENT" | "AMOUNT" | null =
    taxOverrideModeRaw === "PERCENT" || taxOverrideModeRaw === "AMOUNT"
      ? taxOverrideModeRaw
      : null;
  const taxOverrideValue = taxOverrideValueRaw != null
    ? parseFloat(String(taxOverrideValueRaw))
    : NaN;
  const taxOverrideAppliesToRaw = s(req.query.taxOverrideAppliesTo);
  const taxOverrideAppliesTo: "METAL" | "HECHURA" | "PRODUCT" | "SERVICE" | "TOTAL" | undefined =
    taxOverrideAppliesToRaw === "METAL"   ||
    taxOverrideAppliesToRaw === "HECHURA" ||
    taxOverrideAppliesToRaw === "PRODUCT" ||
    taxOverrideAppliesToRaw === "SERVICE" ||
    taxOverrideAppliesToRaw === "TOTAL"
      ? taxOverrideAppliesToRaw
      : undefined;
  const taxOverride =
    taxOverrideMode && Number.isFinite(taxOverrideValue) && taxOverrideValue >= 0
      ? { mode: taxOverrideMode, value: taxOverrideValue, appliesTo: taxOverrideAppliesTo }
      : null;

  // Override manual del precio neto unitario. Pisa el resultado del paso
  // PRICE_LIST y desactiva descuentos por cantidad y promociones.
  const manualPriceOverrideRaw = req.query.manualPriceOverride;
  const manualPriceOverride = manualPriceOverrideRaw != null
    ? parseFloat(String(manualPriceOverrideRaw))
    : NaN;
  const manualPrice = Number.isFinite(manualPriceOverride) && manualPriceOverride >= 0
    ? manualPriceOverride
    : null;

  // Override manual del descuento aplicado al precio de lista.
  const manualDiscountModeRaw  = s(req.query.manualDiscountMode);
  const manualDiscountValueRaw = req.query.manualDiscountValue;
  const manualDiscountMode: "PERCENT" | "AMOUNT" | null =
    manualDiscountModeRaw === "PERCENT" || manualDiscountModeRaw === "AMOUNT"
      ? manualDiscountModeRaw
      : null;
  const manualDiscountValue = manualDiscountValueRaw != null
    ? parseFloat(String(manualDiscountValueRaw))
    : NaN;
  const manualDiscountAppliesToRaw = s(req.query.manualDiscountAppliesTo);
  const manualDiscountAppliesTo: "METAL" | "HECHURA" | "PRODUCT" | "SERVICE" | "TOTAL" | undefined =
    manualDiscountAppliesToRaw === "METAL"   ||
    manualDiscountAppliesToRaw === "HECHURA" ||
    manualDiscountAppliesToRaw === "PRODUCT" ||
    manualDiscountAppliesToRaw === "SERVICE" ||
    manualDiscountAppliesToRaw === "TOTAL"
      ? manualDiscountAppliesToRaw
      : undefined;
  const manualDiscount =
    manualDiscountMode && Number.isFinite(manualDiscountValue) && manualDiscountValue >= 0
      ? { mode: manualDiscountMode, value: manualDiscountValue, appliesTo: manualDiscountAppliesTo }
      : null;

  // Overrides de COMPOSICIÓN DE COSTO a nivel línea (Fase 2). Estos
  // overrides NO modifican la ficha del artículo en DB — el motor opera
  // sobre una copia en memoria.
  const gramsOverrideRaw = req.query.gramsOverride;
  const gramsOverride = gramsOverrideRaw != null
    ? parseFloat(String(gramsOverrideRaw))
    : NaN;
  const grams = Number.isFinite(gramsOverride) && gramsOverride >= 0
    ? gramsOverride
    : null;

  const mermaPercentOverrideRaw = req.query.mermaPercentOverride;
  const mermaPercentOverride = mermaPercentOverrideRaw != null
    ? parseFloat(String(mermaPercentOverrideRaw))
    : NaN;
  const mermaPercent = Number.isFinite(mermaPercentOverride) && mermaPercentOverride >= 0
    ? mermaPercentOverride
    : null;

  const metalVariantIdOverrideRaw = s(req.query.metalVariantIdOverride);
  const metalVariantIdOverride = metalVariantIdOverrideRaw && metalVariantIdOverrideRaw.length >= 8
    ? metalVariantIdOverrideRaw
    : null;

  const hechuraOverrideAmountRaw = req.query.hechuraOverrideAmount;
  const hechuraOverrideAmount = hechuraOverrideAmountRaw != null
    ? parseFloat(String(hechuraOverrideAmountRaw))
    : NaN;
  const hechuraAmount = Number.isFinite(hechuraOverrideAmount) && hechuraOverrideAmount >= 0
    ? hechuraOverrideAmount
    : null;

  // ── Envío / logística (solo simulación) ─────────────────────────────────────
  // Sprint 3 — Capa 10 del orden inmutable. Antes el cálculo era inline acá.
  // Ahora pasa por el helper compartido `resolveShippingAmount` (POLICY.md §5)
  // para que articles/pricing-preview y sales/preview produzcan el mismo monto
  // a partir del mismo input.
  const shippingMode   = s(req.query.shippingMode); // FIXED | BY_WEIGHT | FREE | ""
  const shippingValueRaw  = req.query.shippingValue;
  const shippingWeightRaw = req.query.shippingWeight;
  const shippingValueParsed  = shippingValueRaw  != null ? parseFloat(String(shippingValueRaw))  : null;
  const shippingWeightParsed = shippingWeightRaw != null ? parseFloat(String(shippingWeightRaw)) : null;
  const shippingResult = (shippingMode === "FIXED" || shippingMode === "BY_WEIGHT" || shippingMode === "FREE")
    ? resolveShippingAmount({
        mode:   shippingMode as "FIXED" | "BY_WEIGHT" | "FREE",
        value:  Number.isFinite(shippingValueParsed)  ? shippingValueParsed  : null,
        weight: Number.isFinite(shippingWeightParsed) ? shippingWeightParsed : null,
      })
    : null;

  // Anti doble redondeo (paridad simulador↔factura): cuando el tenant tiene
  // política de redondeo a nivel comprobante activa, la lista NO debe aplicar
  // su redondeo diferido (`applyOn = NET | TOTAL`). El simulador no aplica el
  // redondeo doc en sí (no hay comprobante), pero igual suprime el redondeo
  // de lista para que el `unitPrice` que muestra el simulador coincida con el
  // que produce la factura.
  const { suppressListDeferredRounding } = await loadDocumentRoundingConfig(
    req.user.jewelryId,
  );

  const result = await resolveFinalSalePrice(req.user.jewelryId, {
    articleId,
    variantId,
    clientId,
    quantity,
    priceListIdOverride,
    quantityDiscountIds,
    taxOverride,
    manualPriceOverride:    manualPrice,
    manualDiscountOverride: manualDiscount,
    gramsOverride:          grams,
    mermaPercentOverride:   mermaPercent,
    metalVariantIdOverride: metalVariantIdOverride,
    hechuraOverrideAmount:  hechuraAmount,
    suppressListDeferredRounding,
  });

  const fmt = (v: any) => v != null ? v.toFixed(4) : null;

  // ── Metadata del redondeo configurado en la lista aplicada ─────────────────
  // Necesaria para que la UI distinga entre:
  //   · Lista sin redondeo activo                  → no mostrar nada.
  //   · Lista con redondeo y motor lo aplicó       → `appliedRounding` populado.
  //   · Lista con redondeo NET/TOTAL pero la política doc lo suprimió →
  //     `appliedRounding = null` pero `appliedRoundingSuppressedByDocPolicy = true`.
  //     La UI muestra una nota "Omitido por redondeo de comprobante activo".
  // Es una query chica (la lista está cacheada en el controller; igual hacemos
  // una lectura puntual de los 4 campos de redondeo).
  let listRoundingMeta: {
    target:    string;
    mode:      string;
    direction: string;
    applyOn:   string;
  } | null = null;
  let appliedRoundingSuppressedByDocPolicy = false;
  if (result.appliedPriceListId) {
    const plMeta = await prisma.priceList.findUnique({
      where: { id: result.appliedPriceListId },
      select: {
        roundingTarget:    true,
        roundingMode:      true,
        roundingDirection: true,
        roundingApplyOn:   true,
      },
    });
    const listHasFinalPriceRounding =
      plMeta?.roundingTarget === "FINAL_PRICE" &&
      plMeta?.roundingMode   !== "NONE";
    if (plMeta && listHasFinalPriceRounding) {
      listRoundingMeta = {
        target:    plMeta.roundingTarget    as string,
        mode:      plMeta.roundingMode      as string,
        direction: plMeta.roundingDirection as string,
        applyOn:   plMeta.roundingApplyOn   as string,
      };
      // Caso "suprimido": la lista tiene redondeo NET/TOTAL configurado, la
      // política doc está activa y por eso `result.appliedRounding` es null.
      const isDeferredApplyOn =
        plMeta.roundingApplyOn === "NET" || plMeta.roundingApplyOn === "TOTAL";
      if (
        result.appliedRounding == null &&
        suppressListDeferredRounding &&
        isDeferredApplyOn
      ) {
        appliedRoundingSuppressedByDocPolicy = true;
      }
    }
  }

  // ── Capa de canal de venta (aplica DESPUÉS del motor, ANTES del pago) ──────
  // Base del canal: alineada con la factura (`pricing-engine.document.ts`),
  // que aplica el canal sobre `subtotalAfterLineDiscounts` — i.e. `lineTotal`
  // POST redondeo absorbido. En el simulador el equivalente per-unit es
  // `totalWithTax − tax` (= lineTotalWithTax − tax = lineTotal). Para
  // `applyOn=PRICE` o sin redondeo, `lineUnitNet ≈ unitPrice` y no hay
  // diferencia. Para `applyOn=NET/TOTAL`, esto absorbe el redondeo en la
  // base del canal y evita la divergencia `canalPct × redondeo` entre
  // simulador y factura. Mismo patrón aplicado al cupón.
  // Guardamos `channelInputForTotals` para reusarlo abajo en
  // `computeSaleDocumentTotals` y evitar otra query.
  let channelInputForTotals: ChannelAdjustmentInput | null = null;
  let channelResult = null;
  if (channelId && result.unitPrice != null) {
    const ch = await prisma.salesChannel.findFirst({
      where: { id: channelId, jewelryId: req.user.jewelryId, deletedAt: null, isActive: true },
      select: { id: true, name: true, adjustmentType: true, adjustmentValue: true },
    });
    if (ch) {
      channelInputForTotals = {
        id:              ch.id,
        name:            ch.name,
        adjustmentType:  ch.adjustmentType as "PERCENTAGE" | "FIXED",
        adjustmentValue: parseFloat(ch.adjustmentValue.toString()),
      };
      const taxNum    = result.taxAmount?.toNumber() ?? 0;
      const totalUnit = result.totalWithTax?.toNumber() ?? result.unitPrice.toNumber();
      const lineUnitNet = totalUnit - taxNum;
      channelResult = applySalesChannelAdjustment(lineUnitNet, channelInputForTotals);
    }
  }

  // ── Capa de cupón (aplica DESPUÉS del canal, ANTES del pago) ────────────────
  // Base del cupón: alineada con la factura (`pricing-engine.document.ts`),
  // que aplica el cupón sobre `subtotalAfterLineDiscounts` — i.e. `lineTotal`
  // POST redondeo absorbido. En el simulador el equivalente per-unit es
  // `totalWithTax − tax` (= lineTotalWithTax − tax = lineTotal). Para `applyOn=PRICE`
  // o sin redondeo, `lineUnitNet ≈ unitPrice` y no hay diferencia. Para
  // `applyOn=NET/TOTAL`, esto absorbe el redondeo en la base del cupón y
  // evita la divergencia de `cuponPct × redondeo` entre simulador y factura.
  // Guardamos `couponInputForTotals` para reusarlo en computeSaleDocumentTotals.
  let couponInputForTotals: CouponInput | null = null;
  let couponResult = null;
  if (couponCode) {
    const taxNum = result.taxAmount?.toNumber() ?? 0;
    const totalUnit = result.totalWithTax?.toNumber() ?? result.unitPrice?.toNumber() ?? 0;
    const lineUnitNet = totalUnit - taxNum;
    const priceAfterChannel = channelResult ? channelResult.finalAmount : lineUnitNet;
    if (priceAfterChannel != null) {
      const artData = await prisma.article.findFirst({
        where: { id: articleId, jewelryId: req.user.jewelryId },
        select: { categoryId: true },
      });
      // groupId vive en ArticleGroupItem.
      // Resolución: variante (itemType=VARIANT) → fallback artículo (itemType=ARTICLE).
      // Sin el fallback, los cupones con scope GROUP no validaban cuando el artículo
      // estaba asignado a nivel de ARTICLE en vez de VARIANT.
      const [variantGroupItem, articleGroupItem] = await Promise.all([
        variantId
          ? prisma.articleGroupItem.findFirst({
              where: { variantId, jewelryId: req.user.jewelryId },
              select: { groupId: true },
            })
          : Promise.resolve(null),
        prisma.articleGroupItem.findFirst({
          where: { articleId, jewelryId: req.user.jewelryId, itemType: "ARTICLE" },
          select: { groupId: true },
        }),
      ]);
      const resolvedGroupId = variantGroupItem?.groupId ?? articleGroupItem?.groupId ?? null;
      const validation = await validateCoupon(req.user.jewelryId, couponCode, {
        clientId:   clientId ?? null,
        articleId:  articleId,
        categoryId: artData?.categoryId ?? null,
        groupId:    resolvedGroupId,
      });
      if (validation.valid) {
        couponInputForTotals = {
          id:            validation.id,
          code:          validation.code,
          name:          validation.name,
          discountType:  validation.discountType,
          discountValue: validation.discountValue,
        };
        const couponAdjResult = applyCouponAdjustment(priceAfterChannel, couponInputForTotals);
        couponResult = { ...couponAdjResult, valid: true };
      } else {
        couponResult = { valid: false, reason: validation.reason, couponCode };
      }
    }
  }

  // Impuestos de compra sobre el costo
  const costTaxResult = await service.computePurchaseTaxes(
    req.user.jewelryId,
    articleId,
    result.unitCost ?? null,
  );

  // ── Capa de checkout: aplica ajuste de pago sobre precio con canal+cupón × cantidad ─
  // Orden: lista → canal → cupón → pago → impuestos ya calculados en motor
  let checkoutResult = null;
  if (result.unitPrice != null && (paymentMethodId || installmentsQty >= 1)) {
    const priceAfterChannel = channelResult ? channelResult.finalAmount : result.unitPrice.toNumber();
    const priceAfterCoupon  = (couponResult?.applied && couponResult?.finalAmount != null)
      ? couponResult.finalAmount
      : priceAfterChannel;
    const baseForPayment = result.totalWithTax != null
      ? result.totalWithTax.toNumber() + (channelResult?.channelAmount ?? 0) - (couponResult?.applied ? (couponResult.discountAmount ?? 0) : 0)
      : priceAfterCoupon;
    const commercialAmount = baseForPayment * quantity;
    checkoutResult = await getCheckoutPreview(
      req.user.jewelryId,
      commercialAmount,
      paymentMethodId,
      installmentsQty,
    );
  }

  // Fase 2A.7 — composition se arma con el helper compartido en
  // `src/lib/pricing-composition.ts`. La lógica original (purity/label,
  // bloque metal+hechura+taxes) vive ahí para que `sales/preview` exponga
  // exactamente el mismo shape sin duplicación.
  const metalVariantIdToFetch = resolveMetalVariantIdFromResult(result);
  const metalVariantInfo = await fetchMetalVariantInfo(metalVariantIdToFetch);
  const composition = buildComposition(result, metalVariantInfo);

  // ── Document totals (paridad simulador↔factura) ─────────────────────────
  // Antes el frontend derivaba `documentTotals` localmente desde unitPrice +
  // canal/cupón/pago/envío. Eso duplicaba la lógica de
  // `computeSaleDocumentTotals` y producía drift cuando el motor cambiaba.
  // Ahora el backend arma una línea sintética y delega al motor — mismo
  // cálculo que `sales/preview`.
  //
  // El simulador NO aplica redondeo a nivel comprobante (es per-artículo,
  // no hay comprobante). Solo refleja el redondeo de lista en
  // `roundingAdjustment` como display delta — mismo patrón que `previewSale`.
  const round2 = (n: number) => Math.round(n * 100) / 100;
  const unitPriceNum     = result.unitPrice?.toNumber()    ?? 0;
  const basePriceNum     = result.basePrice?.toNumber()    ?? unitPriceNum;
  const unitTaxNum       = result.taxAmount?.toNumber()    ?? 0;
  const unitTotalWithTax = result.totalWithTax?.toNumber() ?? unitPriceNum;
  const lineTotalWithTax = round2(unitTotalWithTax * quantity);
  const lineTaxAmountDoc = round2(unitTaxNum       * quantity);
  // `lineTotal` neto = totalWithTax − tax (preserva el redondeo absorbido
  // por la lista cuando applyOn=NET/TOTAL — mismo patrón que previewSale).
  const lineTotalNet     = round2(lineTotalWithTax - lineTaxAmountDoc);

  // FASE 2 — propagar el breakdown Metal/Hechura per-línea al motor de
  // documentTotals, escalado × quantity. `metalHechuraBreakdown` ya viene
  // poblado universalmente desde FASE 1 (METAL_HECHURA exacto, derivado por
  // proporción, SERVICE_AS_HECHURA, etc.). Si fuera null → todos los
  // agregados doc-level quedan en 0.
  const mhb = result.metalHechuraBreakdown ?? null;
  const docLine: SaleDocumentTotalsLineInput = {
    quantity,
    basePrice:     basePriceNum,
    unitPrice:     unitPriceNum,
    lineTotal:     lineTotalNet,
    lineTaxAmount: lineTaxAmountDoc,
    ...(mhb
      ? {
          metalCost:            round2(mhb.metalCost   * quantity),
          hechuraCost:          round2(mhb.hechuraCost * quantity),
          metalSale:            round2(mhb.metalSale   * quantity),
          hechuraSale:          round2(mhb.hechuraSale * quantity),
          metalSaleEstimated:   mhb.metalSaleEstimated   ?? false,
          hechuraSaleEstimated: mhb.hechuraSaleEstimated ?? false,
        }
      : {}),
  };

  const documentTotalsRaw = computeSaleDocumentTotals({
    lines:                   [docLine],
    channel:                 channelInputForTotals,
    coupon:                  couponInputForTotals,
    paymentAdjustmentAmount: checkoutResult?.paymentAdjustment ?? 0,
    shippingAmount:          shippingResult?.amount             ?? 0,
    globalDiscountAmount:    0,
    roundingAdjustment:      0,
    // Simulador no aplica política doc — la regla queda exclusiva del flujo
    // de venta. El `unitPrice` ya respeta `suppressListDeferredRounding`
    // para mantener paridad numérica con la factura.
    documentRounding:        null,
  });

  // Display delta del redondeo de lista: el motor lo absorbió en `lineTotal`
  // pero el frontend lo muestra como ajuste agregado en cabecera (mismo
  // patrón que `previewSale`).
  let docRoundingAdjustment = 0;
  let docRoundingInfo: SaleDocumentTotals["roundingInfo"] = null;
  if (result.appliedRounding) {
    const unitAdjustment = parseFloat(
      result.appliedRounding.postRounding.minus(result.appliedRounding.preRounding).toFixed(4),
    );
    docRoundingAdjustment = round2(unitAdjustment * quantity);
    docRoundingInfo = {
      source:        "PRICE_LIST",
      priceListId:   result.appliedRounding.priceListId,
      priceListName: result.appliedRounding.priceListName,
      applyOn:       result.appliedRounding.applyOn,
      mode:          result.appliedRounding.mode,
      direction:     result.appliedRounding.direction,
    };
  }
  const documentTotals: SaleDocumentTotals = {
    ...documentTotalsRaw,
    roundingAdjustment: docRoundingAdjustment,
    roundingInfo:       docRoundingInfo,
  };

  // Armado del response — sigue idéntico a antes; los importes están en
  // moneda BASE del tenant. Si el operador eligió una moneda distinta, el
  // helper de display abajo convierte in-place y agrega metadata.
  const responseData: Record<string, unknown> = {
    unitPrice:               fmt(result.unitPrice),
    basePrice:               fmt(result.basePrice),
    quantityDiscountAmount:  fmt(result.quantityDiscountAmount),
    promotionDiscountAmount: fmt(result.promotionDiscountAmount),
    discountAmount:          result.discountAmount.gt(0) ? result.discountAmount.toFixed(4) : null,
    priceSource:             result.priceSource,
    baseSource:              result.baseSource,
    appliedPriceListId:      result.appliedPriceListId,
    appliedPriceListName:    result.appliedPriceListName,
    appliedPriceListMode:    result.appliedPriceListMode,
    appliedPromotionId:      result.appliedPromotionId,
    appliedPromotionName:    result.appliedPromotionName,
    appliedDiscountId:       result.appliedDiscountId,
    marginPercent:           fmt(result.marginPercent),
    unitCost:                fmt(result.unitCost),
    unitMargin:              fmt(result.unitMargin),
    costPartial:             result.costPartial,
    costMode:                result.costMode,
    partial:                 result.partial,
    stackingMode:            result.stackingMode,
    steps: result.steps.map(step => ({
      key:     step.key,
      label:   step.label,
      status:  step.status,
      value:   step.value != null ? step.value.toFixed(4) : null,
      message: step.message,
      meta:    serializeMeta(step.meta),
    })),
    alerts:        result.alerts,
    policy:        result.policy,
    channelResult,
    couponResult,
    checkoutResult,
    shippingResult,        // envío como step final independiente (no entra al producto)
    metalHechuraBreakdown: result.metalHechuraBreakdown ?? null,
    componentSaleBreakdown: result.componentSaleBreakdown ?? null,
    taxAmount:             fmt(result.taxAmount),
    taxBreakdown:          result.taxBreakdown ?? [],
    totalWithTax:          fmt(result.totalWithTax),
    taxExemptByEntity:     result.taxExemptByEntity ?? false,
    // ── Redondeo aplicado por la lista de precios ─────────────────────────
    // El motor expone `appliedRounding` con preRounding / postRounding (per
    // unit). Lo dejo plano para que el frontend pueda compararlo contra
    // `salesApi.preview` sin tener que volver a leer `steps[]`.
    appliedRounding: result.appliedRounding
      ? {
          source:        "PRICE_LIST" as const,
          priceListId:   result.appliedRounding.priceListId,
          priceListName: result.appliedRounding.priceListName,
          applyOn:       result.appliedRounding.applyOn,
          mode:          result.appliedRounding.mode,
          direction:     result.appliedRounding.direction,
          preRounding:   result.appliedRounding.preRounding.toFixed(4),
          postRounding:  result.appliedRounding.postRounding.toFixed(4),
          // Delta unitario (puede ser positivo o negativo). Multiplicado por
          // quantity rinde el ajuste a nivel documento.
          unitAdjustment: parseFloat(
            result.appliedRounding.postRounding.minus(result.appliedRounding.preRounding).toFixed(4)
          ),
        }
      : null,
    // FASE 1.1 G3 — totales per-line escalados × quantity, expuestos top-level.
    // El backend ya los computa internamente para `documentTotals`; los
    // exponemos planos para que el normalizer del frontend pueda dejar de
    // multiplicar `unitPrice × qty` con `r2` (POLICY.md R4.5). El simulador
    // siempre tiene 1 línea — estos valores son agregados de esa única línea.
    lineTotal:        lineTotalNet,
    lineTaxAmount:    lineTaxAmountDoc,
    lineTotalWithTax: lineTotalWithTax,
    costBase:              costTaxResult.costBase,
    costTaxAmount:         costTaxResult.costTaxAmount,
    costWithTax:           costTaxResult.costWithTax,
    costTaxBreakdown:      costTaxResult.costTaxBreakdown,
    costOverrideContext:   result.costOverrideContext ?? null,
    // Bloque `composition` armado por el helper compartido (Fase 2A.7).
    composition,
    // Document totals — mismo motor que `sales/preview`. El frontend pasa a
    // consumirlos directamente sin recalcular nada.
    documentTotals,
    // Metadata del redondeo configurado en la lista (independiente de si se
    // aplicó). Permite que la UI muestre "Redondeo por artículo / lista"
    // incluso cuando el motor no popula `appliedRounding` por supresión doc.
    listRoundingMeta,
    appliedRoundingSuppressedByDocPolicy,
  };

  // ── Multimoneda (Fase MM) ────────────────────────────────────────────────
  // Si el operador eligió una moneda distinta a la base, convertir todos los
  // importes monetarios in-place y adosar metadata. Si no, no-op.
  const currencyCtx = await getCurrencyDisplayContext(req.user.jewelryId, responseCurrencyId);
  if (currencyCtx?.applied) {
    convertArticlePreviewResponseInPlace(responseData, currencyCtx.rate);
  }
  if (currencyCtx) {
    Object.assign(responseData, buildResponseCurrencyMetadata(currencyCtx));
  }

  return res.json(responseData);
}

export async function searchTree(req: any, res: Response) {
  const jewelryId   = req.user?.jewelryId;
  assert(jewelryId, "Tenant inválido.");
  const q           = s(req.query?.q);
  const typesRaw    = s(req.query?.articleTypes);
  const incVariants = req.query?.includeVariants !== "false";
  const articleTypes = typesRaw ? typesRaw.split(",").map((t: string) => t.trim()).filter(Boolean) : [];
  return res.json(await service.searchArticlesTree(q, jewelryId, { articleTypes, includeVariants: incVariants }));
}

// ===========================================================================
// Group assignment (PATCH /:id/group)
// ===========================================================================
export async function assignGroup(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  const id        = s(req.params?.id);
  const groupId   = req.body?.groupId ?? null;
  assert(jewelryId, "Tenant inválido.");
  assert(id,        "Id inválido.");
  return res.json(await groupsService.assignGroupToArticle(id, groupId, jewelryId));
}

// GET /:id/group-state — per-variant group membership
export async function getGroupState(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  const id        = s(req.params?.id);
  assert(jewelryId, "Tenant inválido.");
  assert(id,        "Id inválido.");
  return res.json(await groupsService.getArticleGroupState(id, jewelryId));
}

// PATCH /:id/group-batch — apply multiple group changes atomically
export async function applyGroupBatch(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  const id        = s(req.params?.id);
  assert(jewelryId, "Tenant inválido.");
  assert(id,        "Id inválido.");
  return res.json(await groupsService.applyArticleGroupBatch(id, jewelryId, req.body?.changes));
}
