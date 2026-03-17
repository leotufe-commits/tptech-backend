import type { Response } from "express";
import * as service from "./articles.service.js";
import { toPublicUploadUrl } from "../../lib/uploads/localUploads.js";
import type { Request } from "express";

function s(v: any) { return String(v ?? "").trim(); }
function assert(cond: any, msg: string) { if (!cond) { const e: any = new Error(msg); e.status = 400; throw e; } }

// ===========================================================================
// Article CRUD
// ===========================================================================
export async function list(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  const skip = Math.max(0, parseInt(String(req.query.skip ?? "0"), 10) || 0);
  const take = Math.min(200, Math.max(1, parseInt(String(req.query.take ?? "50"), 10) || 50));
  return res.json(await service.listArticles(req.user.jewelryId, {
    q: s(req.query.q),
    categoryId: s(req.query.categoryId) || undefined,
    status: s(req.query.status) || undefined,
    stockMode: s(req.query.stockMode) || undefined,
    isFavorite: req.query.isFavorite === "true" ? true : undefined,
    showInactive: req.query.showInactive === "true",
    skip,
    take,
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
  return res.json(await service.adjustStock(id, req.user.jewelryId, req.body));
}
