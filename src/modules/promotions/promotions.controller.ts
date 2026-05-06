// src/modules/promotions/promotions.controller.ts
import type { Response } from "express";
import * as service from "./promotions.service.js";

function s(v: any) { return String(v ?? "").trim(); }
function assert(cond: any, msg: string) { if (!cond) { const e: any = new Error(msg); e.status = 400; throw e; } }

export async function list(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  const skip  = Math.max(0, parseInt(String(req.query.skip  ?? "0"),  10) || 0);
  const take  = Math.min(200, Math.max(1, parseInt(String(req.query.take ?? "50"), 10) || 50));
  const active = req.query.active === "true" ? true : req.query.active === "false" ? false : undefined;
  return res.json(await service.listPromotions(req.user.jewelryId, {
    skip, take, q: s(req.query.q) || undefined, active,
  }));
}

export async function create(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  return res.status(201).json(await service.createPromotion(req.user.jewelryId, req.body));
}

export async function update(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  const id = s(req.params?.id);
  assert(id, "Id inválido.");
  return res.json(await service.updatePromotion(id, req.user.jewelryId, req.body));
}

export async function remove(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  const id = s(req.params?.id);
  assert(id, "Id inválido.");
  await service.deletePromotion(id, req.user.jewelryId);
  return res.json({ ok: true });
}

export async function toggle(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  const id = s(req.params?.id);
  assert(id, "Id inválido.");
  return res.json(await service.togglePromotionActive(id, req.user.jewelryId));
}
