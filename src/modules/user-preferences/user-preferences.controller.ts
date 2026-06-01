import type { Response } from "express";
import * as service from "./user-preferences.service.js";

function assert(cond: any, msg: string) {
  if (!cond) { const err: any = new Error(msg); err.status = 400; throw err; }
}

export async function getMe(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  const userId = req.user?.id ?? req.userId;
  assert(jewelryId, "Tenant inválido.");
  assert(userId, "Usuario inválido.");
  return res.json(await service.getMyPreference(jewelryId, userId));
}

export async function updateMe(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  const userId = req.user?.id ?? req.userId;
  assert(jewelryId, "Tenant inválido.");
  assert(userId, "Usuario inválido.");
  return res.json(await service.updateMyPreference(jewelryId, userId, req.body));
}
