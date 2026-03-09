import type { Response } from "express";
import * as service from "./categories.service.js";

function s(v: any) {
  return String(v ?? "").trim();
}

function assert(cond: any, msg: string) {
  if (!cond) {
    const err: any = new Error(msg);
    err.status = 400;
    throw err;
  }
}

export async function list(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  assert(jewelryId, "Tenant inválido.");
  const rows = await service.listCategories(jewelryId);
  return res.json(rows);
}

export async function create(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  assert(jewelryId, "Tenant inválido.");
  const created = await service.createCategory(jewelryId, req.body);
  return res.status(201).json(created);
}

export async function update(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  const id = s(req.params?.id);
  assert(jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");
  const updated = await service.updateCategory(id, jewelryId, req.body);
  return res.json(updated);
}

export async function toggle(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  const id = s(req.params?.id);
  assert(jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");
  const updated = await service.toggleCategory(id, jewelryId);
  return res.json(updated);
}

export async function remove(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  const id = s(req.params?.id);
  assert(jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");
  const deleted = await service.deleteCategory(id, jewelryId);
  return res.json(deleted);
}
