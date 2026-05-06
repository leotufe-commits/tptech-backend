import type { Request, Response } from "express";
import * as svc from "./article-groups.service.js";
import { toPublicUploadUrl } from "../../lib/uploads/localUploads.js";

function s(v: any) { return String(v ?? "").trim(); }
function assert(cond: any, msg: string) { if (!cond) { const err: any = new Error(msg); err.status = 400; throw err; } }

export async function list(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  assert(jewelryId, "Tenant inválido.");
  return res.json(await svc.listGroups(jewelryId));
}

export async function getOne(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId; const id = s(req.params?.id);
  assert(jewelryId, "Tenant inválido."); assert(id, "Id inválido.");
  return res.json(await svc.getGroup(id, jewelryId));
}

export async function create(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  assert(jewelryId, "Tenant inválido.");
  return res.status(201).json(await svc.createGroup(jewelryId, req.body));
}

export async function update(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId; const id = s(req.params?.id);
  assert(jewelryId, "Tenant inválido."); assert(id, "Id inválido.");
  return res.json(await svc.updateGroup(id, jewelryId, req.body));
}

export async function toggle(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId; const id = s(req.params?.id);
  assert(jewelryId, "Tenant inválido."); assert(id, "Id inválido.");
  return res.json(await svc.toggleGroup(id, jewelryId));
}

export async function remove(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId; const id = s(req.params?.id);
  assert(jewelryId, "Tenant inválido."); assert(id, "Id inválido.");
  return res.json(await svc.removeGroup(id, jewelryId));
}

// ── Gestión de items dentro del grupo ────────────────────────────────────────

export async function addItem(req: any, res: Response) {
  const jewelryId     = req.user?.jewelryId;
  const groupId       = s(req.params?.id);
  const itemType      = s(req.body?.itemType) as "ARTICLE" | "VARIANT";
  const refId         = s(req.body?.refId);
  const selectorValue = s(req.body?.selectorValue);
  assert(jewelryId,                         "Tenant inválido.");
  assert(groupId,                           "Id de grupo inválido.");
  assert(itemType === "ARTICLE" || itemType === "VARIANT", "Tipo de item inválido (ARTICLE|VARIANT).");
  assert(refId,                             "Id del item inválido.");
  return res.status(201).json(await svc.addItemToGroup(groupId, jewelryId, itemType, refId, selectorValue));
}

export async function updateSelectorValue(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  const groupId   = s(req.params?.id);
  const itemId    = s(req.params?.itemId);
  const value     = s(req.body?.value);
  assert(jewelryId, "Tenant inválido.");
  assert(groupId,   "Id de grupo inválido.");
  assert(itemId,    "Id de item inválido.");
  return res.json(await svc.updateItemSelectorValue(groupId, itemId, jewelryId, value));
}

export async function removeItem(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  const groupId   = s(req.params?.id);
  const itemId    = s(req.params?.itemId);
  assert(jewelryId, "Tenant inválido.");
  assert(groupId,   "Id de grupo inválido.");
  assert(itemId,    "Id de item inválido.");
  return res.json(await svc.removeItemFromGroup(groupId, itemId, jewelryId));
}

export async function reorderItems(req: any, res: Response) {
  const jewelryId  = req.user?.jewelryId;
  const groupId    = s(req.params?.id);
  const orderedIds = req.body?.orderedIds;
  assert(jewelryId, "Tenant inválido.");
  assert(groupId,   "Id de grupo inválido.");
  return res.json(await svc.reorderGroupItems(groupId, orderedIds, jewelryId));
}

export async function searchAvailable(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  const groupId   = s(req.params?.id);
  const q         = s(req.query?.q);
  assert(jewelryId, "Tenant inválido.");
  assert(groupId,   "Id de grupo inválido.");
  return res.json(await svc.searchAvailableItems(groupId, q, jewelryId));
}

export async function searchAvailableTree(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  const groupId   = s(req.params?.id);
  const q         = s(req.query?.q);
  assert(jewelryId, "Tenant inválido.");
  assert(groupId,   "Id de grupo inválido.");
  return res.json(await svc.searchAvailableArticlesTree(groupId, q, jewelryId));
}

export async function addItemsBatch(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  const groupId   = s(req.params?.id);
  assert(jewelryId, "Tenant inválido.");
  assert(groupId,   "Id de grupo inválido.");
  return res.status(201).json(await svc.addItemsBatch(groupId, jewelryId, req.body?.items));
}

// ── Gestión de imágenes del grupo ────────────────────────────────────────────

export async function listImages(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  const groupId   = s(req.params?.id);
  assert(jewelryId, "Tenant inválido.");
  assert(groupId,   "Id de grupo inválido.");
  return res.json(await svc.listGroupImages(groupId, jewelryId));
}

export async function addImage(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  const groupId   = s(req.params?.id);
  assert(jewelryId, "Tenant inválido.");
  assert(groupId,   "Id de grupo inválido.");
  const file = req.file as (Express.Multer.File & { _tpFolder?: string }) | undefined;
  if (!file) return res.status(400).json({ message: "No se recibió ningún archivo." });
  const folder = s((file as any)._tpFolder || "groups/images");
  const url = toPublicUploadUrl(req as Request, folder, file.filename);
  if (!url) return res.status(500).json({ message: "No se pudo generar la URL." });
  return res.status(201).json(await svc.addGroupImage(groupId, jewelryId, url));
}

export async function setMainImage(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  const groupId   = s(req.params?.id);
  const imageId   = s(req.params?.imageId);
  assert(jewelryId, "Tenant inválido.");
  assert(groupId && imageId, "Ids inválidos.");
  return res.json(await svc.setGroupMainImage(groupId, imageId, jewelryId));
}

export async function removeImage(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  const groupId   = s(req.params?.id);
  const imageId   = s(req.params?.imageId);
  assert(jewelryId, "Tenant inválido.");
  assert(groupId && imageId, "Ids inválidos.");
  return res.json(await svc.removeGroupImage(groupId, imageId, jewelryId));
}
