import type { Response } from "express";
import * as service from "./sellers.service.js";

function s(v: any) { return String(v ?? "").trim(); }
function assert(cond: any, msg: string) { if (!cond) { const err: any = new Error(msg); err.status = 400; throw err; } }

export async function list(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  return res.json(await service.listSellers(req.user.jewelryId));
}
export async function create(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  return res.status(201).json(await service.createSeller(req.user.jewelryId, req.body));
}
export async function update(req: any, res: Response) {
  const id = s(req.params?.id); assert(req.user?.jewelryId, "Tenant inválido."); assert(id, "Id inválido.");
  return res.json(await service.updateSeller(id, req.user.jewelryId, req.body));
}
export async function toggle(req: any, res: Response) {
  const id = s(req.params?.id); assert(req.user?.jewelryId, "Tenant inválido."); assert(id, "Id inválido.");
  return res.json(await service.toggleSeller(id, req.user.jewelryId));
}
export async function setFavorite(req: any, res: Response) {
  const id = s(req.params?.id); assert(req.user?.jewelryId, "Tenant inválido."); assert(id, "Id inválido.");
  return res.json(await service.setFavoriteSeller(id, req.user.jewelryId));
}
export async function remove(req: any, res: Response) {
  const id = s(req.params?.id); assert(req.user?.jewelryId, "Tenant inválido."); assert(id, "Id inválido.");
  return res.json(await service.deleteSeller(id, req.user.jewelryId));
}
