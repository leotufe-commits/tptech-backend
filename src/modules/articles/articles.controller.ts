import type { Response } from "express";
import * as service from "./articles.service.js";
import * as importService from "./articles.import.service.js";
import * as variantAttrService from "./article-variant-attributes.service.js";
import { toPublicUploadUrl } from "../../lib/uploads/localUploads.js";
import type { Request } from "express";
import { resolveSalePrice } from "../../lib/sale-pricing.utils.js";

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
    showInStore: req.query.showInStore === "true" ? true : undefined,
    preferredSupplierId: s(req.query.preferredSupplierId) || undefined,
    isFavorite: req.query.isFavorite === "true" ? true : undefined,
    showInActive: req.query.showInActive === "true" || req.query.showInactive === "true",
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
  return res.status(201).json(await service.createArticle(req.user.jewelryId, req.body));
}

export async function update(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");
  return res.json(await service.updateArticle(id, req.user.jewelryId, req.body));
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

export async function remove(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");
  return res.json(await service.deleteArticle(id, req.user.jewelryId));
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

// ===========================================================================
// Compositions
// ===========================================================================
export async function listCompositions(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");
  return res.json(await service.listCompositions(id, req.user.jewelryId));
}

export async function upsertComposition(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");
  return res.json(await service.upsertComposition(id, req.user.jewelryId, req.body));
}

export async function removeComposition(req: any, res: Response) {
  const id = s(req.params?.id);
  const compositionId = s(req.params?.compositionId);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id && compositionId, "Ids inválidos.");
  return res.json(await service.removeComposition(id, compositionId, req.user.jewelryId));
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
  const values = req.body?.values ?? req.body;
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

export async function getMaterialAvailability(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");
  const warehouseId = s(req.query.warehouseId) || undefined;
  return res.json(await service.calcMaterialAvailability(id, req.user.jewelryId, warehouseId));
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
export async function getImportTemplate(_req: any, res: Response) {
  const buffer = importService.generateImportTemplate();
  res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
  res.setHeader("Content-Disposition", 'attachment; filename="tptech_articulos_template.xlsx"');
  return res.send(buffer);
}

export async function previewImport(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  const file = (req as any).file;
  assert(file?.buffer, "No se recibió ningún archivo.");
  const rows = importService.parseImportFile(file.buffer, file.mimetype);
  assert(rows.length > 0, "El archivo no contiene datos.");
  assert(rows.length <= 2000, "El archivo supera el límite de 2000 filas.");
  const result = await importService.previewImport(rows, req.user.jewelryId);
  // Guardar rows en memoria temporal para el execute (session-based via body en execute)
  return res.json(result);
}

export async function executeImport(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  const file = (req as any).file;
  assert(file?.buffer, "No se recibió ningún archivo.");
  const rows = importService.parseImportFile(file.buffer, file.mimetype);
  assert(rows.length > 0, "El archivo no contiene datos.");
  assert(rows.length <= 2000, "El archivo supera el límite de 2000 filas.");
  const onConflict = req.body?.onConflict === "update" ? "update" : "skip";
  const result = await importService.executeImport(rows, req.user.jewelryId, { onConflict });
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

  const result = await resolveSalePrice(req.user.jewelryId, {
    articleId,
    variantId,
    clientId,
    categoryId,
    quantity,
  });

  return res.json(result);
}

