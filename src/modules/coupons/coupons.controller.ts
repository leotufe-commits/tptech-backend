import type { Response } from "express";
import * as service from "./coupons.service.js";

function s(v: any) { return String(v ?? "").trim(); }
function assert(cond: any, msg: string) { if (!cond) { const e: any = new Error(msg); e.status = 400; throw e; } }

export async function list(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  const skip = parseInt(String(req.query.skip ?? "0"), 10) || 0;
  const take = parseInt(String(req.query.take ?? "50"), 10) || 50;
  const q    = s(req.query.q) || undefined;
  const active = req.query.active === "true" ? true : req.query.active === "false" ? false : undefined;
  return res.json(await service.listCoupons(req.user.jewelryId, { skip, take, q, active }));
}

export async function getOne(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId && id, "Parámetros inválidos.");
  return res.json(await service.getCoupon(id, req.user.jewelryId));
}

export async function create(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  return res.status(201).json(await service.createCoupon(req.user.jewelryId, req.body));
}

export async function update(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId && id, "Parámetros inválidos.");
  return res.json(await service.updateCoupon(id, req.user.jewelryId, req.body));
}

export async function toggle(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId && id, "Parámetros inválidos.");
  return res.json(await service.toggleCoupon(id, req.user.jewelryId));
}

export async function remove(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId && id, "Parámetros inválidos.");
  return res.json(await service.deleteCoupon(id, req.user.jewelryId));
}

export async function validate(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  const code       = s(req.query.code || req.body?.code);
  const clientId   = s(req.query.clientId   || req.body?.clientId)   || null;
  const articleId  = s(req.query.articleId  || req.body?.articleId)  || null;
  const categoryId = s(req.query.categoryId || req.body?.categoryId) || null;
  const groupId    = s(req.query.groupId    || req.body?.groupId)    || null;
  assert(code, "El código es obligatorio.");
  return res.json(await service.validateCoupon(req.user.jewelryId, code, { clientId, articleId, categoryId, groupId }));
}
