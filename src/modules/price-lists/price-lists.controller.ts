import type { Response } from "express";
import * as service from "./price-lists.service.js";

function s(v: any) { return String(v ?? "").trim(); }
function assert(cond: any, msg: string) { if (!cond) { const err: any = new Error(msg); err.status = 400; throw err; } }

export async function list(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  return res.json(await service.listPriceLists(req.user.jewelryId));
}
export async function create(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  return res.status(201).json(await service.createPriceList(req.user.jewelryId, req.body));
}
export async function update(req: any, res: Response) {
  const id = s(req.params?.id); assert(req.user?.jewelryId, "Tenant inválido."); assert(id, "Id inválido.");
  return res.json(await service.updatePriceList(id, req.user.jewelryId, req.body));
}
export async function clone(req: any, res: Response) {
  const id = s(req.params?.id); assert(req.user?.jewelryId, "Tenant inválido."); assert(id, "Id inválido.");
  return res.status(201).json(await service.clonePriceList(id, req.user.jewelryId));
}
export async function toggle(req: any, res: Response) {
  const id = s(req.params?.id); assert(req.user?.jewelryId, "Tenant inválido."); assert(id, "Id inválido.");
  return res.json(await service.togglePriceList(id, req.user.jewelryId));
}
export async function setFavorite(req: any, res: Response) {
  const id = s(req.params?.id); assert(req.user?.jewelryId, "Tenant inválido."); assert(id, "Id inválido.");
  return res.json(await service.setFavoritePriceList(id, req.user.jewelryId));
}
export async function remove(req: any, res: Response) {
  const id = s(req.params?.id); assert(req.user?.jewelryId, "Tenant inválido."); assert(id, "Id inválido.");
  return res.json(await service.deletePriceList(id, req.user.jewelryId));
}
