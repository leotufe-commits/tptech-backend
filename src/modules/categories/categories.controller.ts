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

/* =========================
   CATEGORIES
========================= */

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

/* =========================
   REORDER
========================= */

export async function reorderCategories(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  assert(jewelryId, "Tenant inválido.");

  const parentId = req.body?.parentId ?? null;
  const orderedIds = req.body?.orderedIds;

  assert(Array.isArray(orderedIds) && orderedIds.length > 0, "orderedIds debe ser un array no vacío.");

  const result = await service.reorderCategories(jewelryId, parentId, orderedIds);
  return res.json(result);
}

/* =========================
   ATTRIBUTE ASSIGNMENTS
========================= */

export async function listAttributes(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  const categoryId = s(req.params?.id);
  assert(jewelryId, "Tenant inválido.");
  assert(categoryId, "Id de categoría inválido.");
  const rows = await service.listAttributes(categoryId, jewelryId);
  return res.json(rows);
}

export async function getEffectiveAttributes(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  const categoryId = s(req.params?.id);
  assert(jewelryId, "Tenant inválido.");
  assert(categoryId, "Id de categoría inválido.");
  const rows = await service.getEffectiveAttributes(categoryId, jewelryId);
  return res.json(rows);
}

export async function createAttribute(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  const categoryId = s(req.params?.id);
  assert(jewelryId, "Tenant inválido.");
  assert(categoryId, "Id de categoría inválido.");
  const created = await service.createAttribute(categoryId, jewelryId, req.body);
  return res.status(201).json(created);
}

export async function updateAttribute(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  const attributeId = s(req.params?.attributeId);
  assert(jewelryId, "Tenant inválido.");
  assert(attributeId, "Id de asignación inválido.");
  const updated = await service.updateAttribute(attributeId, jewelryId, req.body);
  return res.json(updated);
}

export async function toggleAttribute(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  const attributeId = s(req.params?.attributeId);
  assert(jewelryId, "Tenant inválido.");
  assert(attributeId, "Id de asignación inválido.");
  const updated = await service.toggleAttribute(attributeId, jewelryId);
  return res.json(updated);
}

export async function removeAttribute(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  const attributeId = s(req.params?.attributeId);
  assert(jewelryId, "Tenant inválido.");
  assert(attributeId, "Id de asignación inválido.");
  const deleted = await service.deleteAttribute(attributeId, jewelryId);
  return res.json(deleted);
}

/* =========================
   OPTIONS (on global def, via assignId for createOption)
========================= */

export async function createOption(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  const attributeId = s(req.params?.attributeId);
  assert(jewelryId, "Tenant inválido.");
  assert(attributeId, "Id de asignación inválido.");
  const created = await service.createOption(attributeId, jewelryId, req.body);
  return res.status(201).json(created);
}

export async function updateOption(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  const optionId = s(req.params?.optionId);
  assert(jewelryId, "Tenant inválido.");
  assert(optionId, "Id de opción inválido.");
  const updated = await service.updateOption(optionId, jewelryId, req.body);
  return res.json(updated);
}

export async function toggleOption(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  const optionId = s(req.params?.optionId);
  assert(jewelryId, "Tenant inválido.");
  assert(optionId, "Id de opción inválido.");
  const updated = await service.toggleOption(optionId, jewelryId);
  return res.json(updated);
}

export async function removeOption(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  const optionId = s(req.params?.optionId);
  assert(jewelryId, "Tenant inválido.");
  assert(optionId, "Id de opción inválido.");
  const deleted = await service.deleteOption(optionId, jewelryId);
  return res.json(deleted);
}
