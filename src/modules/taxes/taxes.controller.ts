import type { Response } from "express";
import * as service from "./taxes.service.js";

function s(v: any) { return String(v ?? "").trim(); }
function assert(cond: any, msg: string) {
  if (!cond) { const err: any = new Error(msg); err.status = 400; throw err; }
}

export async function list(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  assert(jewelryId, "Tenant inválido.");
  return res.json(await service.listTaxes(jewelryId));
}

export async function create(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  assert(jewelryId, "Tenant inválido.");
  return res.status(201).json(await service.createTax(jewelryId, req.body));
}

export async function update(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  const id = s(req.params?.id);
  assert(jewelryId, "Tenant inválido."); assert(id, "Id inválido.");
  return res.json(await service.updateTax(id, jewelryId, req.body));
}

export async function clone(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  const id = s(req.params?.id);
  assert(jewelryId, "Tenant inválido."); assert(id, "Id inválido.");
  return res.status(201).json(await service.cloneTax(id, jewelryId));
}

export async function toggle(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  const id = s(req.params?.id);
  assert(jewelryId, "Tenant inválido."); assert(id, "Id inválido.");
  return res.json(await service.toggleTax(id, jewelryId));
}

export async function remove(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  const id = s(req.params?.id);
  assert(jewelryId, "Tenant inválido."); assert(id, "Id inválido.");
  return res.json(await service.deleteTax(id, jewelryId));
}
