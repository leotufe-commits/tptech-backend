// src/modules/units/units.controller.ts
import type { Response } from "express";
import type { UnitType } from "@prisma/client";
import * as service from "./units.service.js";

function s(v: any) { return String(v ?? "").trim(); }
function assert(cond: any, msg: string, status = 400) {
  if (!cond) { const err: any = new Error(msg); err.status = status; throw err; }
}

const VALID_TYPES = new Set<UnitType>(["QUANTITY", "WEIGHT", "LENGTH", "VOLUME", "OTHER"]);
function parseType(raw: any): UnitType | undefined {
  if (raw === undefined || raw === null || raw === "") return undefined;
  const t = String(raw).trim().toUpperCase() as UnitType;
  return VALID_TYPES.has(t) ? t : undefined;
}
function parseBool(raw: any): boolean | undefined {
  if (raw === undefined || raw === null || raw === "") return undefined;
  if (typeof raw === "boolean") return raw;
  const v = String(raw).trim().toLowerCase();
  if (["1", "true", "yes", "y"].includes(v)) return true;
  if (["0", "false", "no", "n"].includes(v)) return false;
  return undefined;
}

export async function list(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  assert(jewelryId, "Tenant inválido.");

  const type = parseType(req.query?.type);
  if (req.query?.type && !type) {
    assert(false, "type inválido. Valores: QUANTITY, WEIGHT, LENGTH, VOLUME, OTHER.");
  }
  const isActive = parseBool(req.query?.isActive);
  const q = s(req.query?.q) || undefined;

  const result = await service.listUnits(jewelryId, { type, isActive, q });
  return res.json(result);
}

export async function create(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  assert(jewelryId, "Tenant inválido.");
  const result = await service.createUnit(jewelryId, req.body);
  return res.status(result.restored ? 200 : 201).json(result);
}

export async function update(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  const id = s(req.params?.id);
  assert(jewelryId, "Tenant inválido."); assert(id, "Id inválido.");
  const result = await service.updateUnit(id, jewelryId, req.body);
  return res.json(result);
}

export async function setFavorite(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  const id = s(req.params?.id);
  assert(jewelryId, "Tenant inválido."); assert(id, "Id inválido.");
  const isFavorite = req.body?.isFavorite;
  assert(typeof isFavorite === "boolean", "isFavorite es requerido (boolean).");
  const result = await service.setFavoriteUnit(id, jewelryId, isFavorite);
  return res.json(result);
}

export async function remove(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  const id = s(req.params?.id);
  assert(jewelryId, "Tenant inválido."); assert(id, "Id inválido.");
  const result = await service.deleteUnit(id, jewelryId);
  return res.json(result);
}
