import type { Response } from "express";
import * as service from "./sales.service.js";

function s(v: any) { return String(v ?? "").trim(); }
function assert(cond: any, msg: string) {
  if (!cond) { const e: any = new Error(msg); e.status = 400; throw e; }
}

export async function list(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  const skip = Math.max(0, parseInt(String(req.query.skip ?? "0"), 10) || 0);
  const take = Math.min(200, Math.max(1, parseInt(String(req.query.take ?? "50"), 10) || 50));
  return res.json(
    await service.listSales(req.user.jewelryId, {
      skip,
      take,
      status: s(req.query.status) || undefined,
      clientId: s(req.query.clientId) || undefined,
      sellerId: s(req.query.sellerId) || undefined,
      q: s(req.query.q) || undefined,
      dateFrom: s(req.query.dateFrom) || undefined,
      dateTo: s(req.query.dateTo) || undefined,
    })
  );
}

export async function getOne(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");
  return res.json(await service.getSale(id, req.user.jewelryId));
}

export async function create(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  const userId = s(req.userId || req.user?.id || "");
  return res.status(201).json(await service.createSale(req.user.jewelryId, userId, req.body));
}

export async function update(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");
  return res.json(await service.updateSale(id, req.user.jewelryId, req.body));
}

export async function confirm(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");
  const userId = s(req.userId || req.user?.id || "");
  return res.json(await service.confirmSale(id, req.user.jewelryId, userId));
}

export async function addPayment(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");
  return res.json(await service.addPayment(id, req.user.jewelryId, req.body));
}

export async function cajaSummary(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  const date = s(req.query.date) || new Date().toISOString().slice(0, 10);
  return res.json(await service.cajaDaySummary(req.user.jewelryId, date));
}

export async function cancel(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");
  const userId = s(req.userId || req.user?.id || "");
  const note = s(req.body?.note ?? req.body?.cancelNote ?? "");
  return res.json(await service.cancelSale(id, req.user.jewelryId, userId, note));
}
