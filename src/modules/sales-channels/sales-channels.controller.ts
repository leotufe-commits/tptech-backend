import type { Response } from "express";
import * as service from "./sales-channels.service.js";

function s(v: any) { return String(v ?? "").trim(); }
function assert(cond: any, msg: string) { if (!cond) { const err: any = new Error(msg); err.status = 400; throw err; } }

export async function list(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  return res.json(await service.listSalesChannels(req.user.jewelryId));
}

export async function create(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  return res.status(201).json(await service.createSalesChannel(req.user.jewelryId, req.body));
}

export async function update(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId && id, "Parámetros inválidos.");
  return res.json(await service.updateSalesChannel(id, req.user.jewelryId, req.body));
}

export async function toggle(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId && id, "Parámetros inválidos.");
  return res.json(await service.toggleSalesChannel(id, req.user.jewelryId));
}

export async function setFavorite(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId && id, "Parámetros inválidos.");
  return res.json(await service.setFavoriteSalesChannel(id, req.user.jewelryId));
}

export async function remove(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId && id, "Parámetros inválidos.");
  return res.json(await service.deleteSalesChannel(id, req.user.jewelryId));
}
