import type { Response } from "express";
import * as service from "./attribute-defs.service.js";

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
  const rows = await service.listAttributeDefs(jewelryId);
  return res.json(rows);
}

export async function create(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  assert(jewelryId, "Tenant inválido.");
  const created = await service.createAttributeDef(jewelryId, req.body);
  return res.status(201).json(created);
}

export async function update(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  const id = s(req.params?.id);
  assert(jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");
  const updated = await service.updateAttributeDef(id, jewelryId, req.body);
  return res.json(updated);
}

export async function toggle(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  const id = s(req.params?.id);
  assert(jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");
  const updated = await service.toggleAttributeDef(id, jewelryId);
  return res.json(updated);
}

export async function remove(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  const id = s(req.params?.id);
  assert(jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");
  const deleted = await service.deleteAttributeDef(id, jewelryId);
  return res.json(deleted);
}

export async function createOption(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  const defId = s(req.params?.id);
  assert(jewelryId, "Tenant inválido.");
  assert(defId, "Id de atributo inválido.");
  const created = await service.createDefOption(defId, jewelryId, req.body);
  return res.status(201).json(created);
}

export async function updateOption(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  const optionId = s(req.params?.optionId);
  assert(jewelryId, "Tenant inválido.");
  assert(optionId, "Id de opción inválido.");
  const updated = await service.updateDefOption(optionId, jewelryId, req.body);
  return res.json(updated);
}

export async function toggleOption(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  const optionId = s(req.params?.optionId);
  assert(jewelryId, "Tenant inválido.");
  assert(optionId, "Id de opción inválido.");
  const updated = await service.toggleDefOption(optionId, jewelryId);
  return res.json(updated);
}

export async function reorderOptions(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  const defId = s(req.params?.id);
  assert(jewelryId, "Tenant inválido.");
  assert(defId, "Id de atributo inválido.");
  const { ids } = req.body;
  assert(Array.isArray(ids), "ids debe ser un array.");
  const result = await service.reorderDefOptions(defId, ids, jewelryId);
  return res.json(result);
}

export async function removeOption(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  const optionId = s(req.params?.optionId);
  assert(jewelryId, "Tenant inválido.");
  assert(optionId, "Id de opción inválido.");
  const deleted = await service.deleteDefOption(optionId, jewelryId);
  return res.json(deleted);
}
