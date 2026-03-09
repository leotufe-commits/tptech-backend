import type { Response } from "express";
import * as service from "./payments.service.js";

function s(v: any) { return String(v ?? "").trim(); }
function assert(cond: any, msg: string) { if (!cond) { const err: any = new Error(msg); err.status = 400; throw err; } }

export async function list(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  assert(jewelryId, "Tenant inválido.");
  return res.json(await service.listPaymentMethods(jewelryId));
}
export async function create(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  assert(jewelryId, "Tenant inválido.");
  return res.status(201).json(await service.createPaymentMethod(jewelryId, req.body));
}
export async function update(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId; const id = s(req.params?.id);
  assert(jewelryId, "Tenant inválido."); assert(id, "Id inválido.");
  return res.json(await service.updatePaymentMethod(id, jewelryId, req.body));
}
export async function clone(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId; const id = s(req.params?.id);
  assert(jewelryId, "Tenant inválido."); assert(id, "Id inválido.");
  return res.status(201).json(await service.clonePaymentMethod(id, jewelryId));
}
export async function toggle(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId; const id = s(req.params?.id);
  assert(jewelryId, "Tenant inválido."); assert(id, "Id inválido.");
  return res.json(await service.togglePaymentMethod(id, jewelryId));
}
export async function setFavorite(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId; const id = s(req.params?.id);
  assert(jewelryId, "Tenant inválido."); assert(id, "Id inválido.");
  return res.json(await service.setFavoritePaymentMethod(id, jewelryId));
}
export async function remove(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId; const id = s(req.params?.id);
  assert(jewelryId, "Tenant inválido."); assert(id, "Id inválido.");
  return res.json(await service.deletePaymentMethod(id, jewelryId));
}
