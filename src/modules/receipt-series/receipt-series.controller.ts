// src/modules/receipt-series/receipt-series.controller.ts
// ============================================================================
// HTTP handlers — Etapa A admin de numeración (2026-05-29).
//
// Delgados por diseño: validan tenant + id + delegan al service. Sin lógica
// comercial. La validación de body Zod corre en el middleware `validateBody`
// configurado en `receipt-series.routes.ts`.
// ============================================================================

import type { Response } from "express";
import * as service from "./receipt-series.service.js";

function s(v: any): string {
  return String(v ?? "").trim();
}

function assert(cond: any, msg: string, status: number = 400): asserts cond {
  if (!cond) {
    const err: any = new Error(msg);
    err.status = status;
    throw err;
  }
}

export async function list(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  assert(jewelryId, "Tenant inválido.");
  return res.json(await service.listReceiptSeries(jewelryId));
}

export async function getOne(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  const id = s(req.params?.id);
  assert(jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");
  return res.json(await service.getReceiptSeries(id, jewelryId));
}

export async function create(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  assert(jewelryId, "Tenant inválido.");
  const row = await service.createReceiptSeries(jewelryId, req.body);
  return res.status(201).json(row);
}

export async function update(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  const id = s(req.params?.id);
  assert(jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");
  return res.json(await service.updateReceiptSeries(id, jewelryId, req.body));
}

export async function remove(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  const id = s(req.params?.id);
  assert(jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");
  return res.json(await service.softDeleteReceiptSeries(id, jewelryId));
}
