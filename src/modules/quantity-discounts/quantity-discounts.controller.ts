// src/modules/quantity-discounts/quantity-discounts.controller.ts
import type { Response } from "express";
import * as service from "./quantity-discounts.service.js";

function s(v: any) { return String(v ?? "").trim(); }
function assert(cond: any, msg: string) { if (!cond) { const e: any = new Error(msg); e.status = 400; throw e; } }

export async function list(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  const skip      = Math.max(0, parseInt(String(req.query.skip  ?? "0"),  10) || 0);
  const take      = Math.min(500, Math.max(1, parseInt(String(req.query.take ?? "100"), 10) || 100));
  const articleId = s(req.query.articleId) || undefined;
  return res.json(await service.listQuantityDiscounts(req.user.jewelryId, { skip, take, articleId }));
}

export async function create(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  return res.status(201).json(await service.createQuantityDiscount(req.user.jewelryId, req.body));
}

export async function update(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  const id = s(req.params?.id);
  assert(id, "Id inválido.");
  return res.json(await service.updateQuantityDiscount(id, req.user.jewelryId, req.body));
}

export async function remove(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  const id = s(req.params?.id);
  assert(id, "Id inválido.");
  await service.deleteQuantityDiscount(id, req.user.jewelryId);
  return res.json({ ok: true });
}
