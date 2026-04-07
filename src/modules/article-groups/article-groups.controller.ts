import type { Response } from "express";
import * as svc from "./article-groups.service.js";

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

// ── Gestión de artículos dentro del grupo ────────────────────────────────────

export async function addArticle(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  const groupId   = s(req.params?.id);
  const articleId = s(req.body?.articleId);
  assert(jewelryId, "Tenant inválido.");
  assert(groupId,   "Id de grupo inválido.");
  assert(articleId, "Id de artículo inválido.");
  return res.json(await svc.addArticleToGroup(groupId, articleId, jewelryId));
}

export async function removeArticle(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  const groupId   = s(req.params?.id);
  const articleId = s(req.params?.articleId);
  assert(jewelryId, "Tenant inválido.");
  assert(groupId,   "Id de grupo inválido.");
  assert(articleId, "Id de artículo inválido.");
  return res.json(await svc.removeArticleFromGroup(groupId, articleId, jewelryId));
}

export async function reorderArticles(req: any, res: Response) {
  const jewelryId  = req.user?.jewelryId;
  const groupId    = s(req.params?.id);
  const orderedIds = req.body?.orderedIds;
  assert(jewelryId, "Tenant inválido.");
  assert(groupId,   "Id de grupo inválido.");
  return res.json(await svc.reorderGroupArticles(groupId, orderedIds, jewelryId));
}

export async function searchAvailable(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  const groupId   = s(req.params?.id);
  const q         = s(req.query?.q);
  assert(jewelryId, "Tenant inválido.");
  assert(groupId,   "Id de grupo inválido.");
  return res.json(await svc.searchAvailableArticles(groupId, q, jewelryId));
}
