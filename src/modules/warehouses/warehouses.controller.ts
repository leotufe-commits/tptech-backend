// tptech-backend/src/modules/warehouses/warehouses.controller.ts
import type { Response } from "express";
import * as service from "./warehouses.service.js";

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

function pickWarehousePayload(body: any) {
  const b = body ?? {};
  return {
    name: s(b.name),
    code: s(b.code),

    phoneCountry: s(b.phoneCountry),
    phoneNumber: s(b.phoneNumber),

    attn: s(b.attn),
    street: s(b.street),
    number: s(b.number),
    city: s(b.city),
    province: s(b.province),
    postalCode: s(b.postalCode),
    country: s(b.country),

    location: s(b.location),
    notes: s(b.notes),

    // solo update lo usa; create lo ignora en service y fuerza true
    isActive: b.isActive,
  };
}

/* =========================
   LIST
========================= */
export async function list(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  const userId = req.user?.id;

  assert(jewelryId, "Tenant inválido.");
  assert(userId, "Usuario inválido.");

  const rows = await service.listWarehousesForUser(jewelryId, userId);
  return res.json(rows);
}

/* =========================
   CREATE
========================= */
export async function create(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  const userId = req.user?.id;

  assert(jewelryId, "Tenant inválido.");
  assert(userId, "Usuario inválido.");

  const created = await service.createWarehouse(jewelryId, userId, pickWarehousePayload(req.body));
  return res.json(created);
}

/* =========================
   UPDATE
========================= */
export async function update(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  const id = s(req.params?.id);

  assert(jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");

  const updated = await service.updateWarehouse(id, jewelryId, pickWarehousePayload(req.body));
  return res.json(updated);
}

/* =========================
   TOGGLE ACTIVE
========================= */
export async function toggle(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  const id = s(req.params?.id);

  assert(jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");

  const updated = await service.toggleWarehouseActive(id, jewelryId);
  return res.json(updated);
}

/* =========================
   DELETE
========================= */
export async function remove(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  const id = s(req.params?.id);

  assert(jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");

  const deleted = await service.deleteWarehouse(id, jewelryId);
  return res.json(deleted);
}

/* =========================
   SET FAVORITE
========================= */
export async function setFavorite(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  const userId = req.user?.id;
  const warehouseId = s(req.params?.id);

  assert(jewelryId, "Tenant inválido.");
  assert(userId, "Usuario inválido.");
  assert(warehouseId, "Almacén inválido.");

  const out = await service.setFavoriteWarehouse({ userId, jewelryId, warehouseId });
  return res.json(out);
}