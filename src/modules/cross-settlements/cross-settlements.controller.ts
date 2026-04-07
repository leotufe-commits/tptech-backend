// src/modules/cross-settlements/cross-settlements.controller.ts

import type { Request, Response } from "express";
import * as service from "./cross-settlements.service.js";

function s(v: any): string { return String(v ?? "").trim(); }
function assert(cond: any, msg: string): asserts cond {
  if (!cond) { const err: any = new Error(msg); err.status = 400; throw err; }
}

// ---------------------------------------------------------------------------
// GET /suppliers/:supplierId/cross-settlements
// ---------------------------------------------------------------------------
export async function list(req: Request, res: Response) {
  const user = (req as any).user;
  assert(user?.jewelryId, "Tenant inválido.");
  const supplierId    = s(req.params.supplierId);
  assert(supplierId, "supplierId inválido.");

  const skip          = Math.max(0, parseInt(s(req.query.skip ?? "0"), 10) || 0);
  const take          = Math.max(1, parseInt(s(req.query.take ?? "25"), 10) || 25);
  const includeVoided = req.query.includeVoided === "true";

  const result = await service.listCrossSettlements(supplierId, user.jewelryId, {
    skip,
    take,
    includeVoided,
  });
  return res.json(result);
}

// ---------------------------------------------------------------------------
// POST /suppliers/:supplierId/cross-settlements
// ---------------------------------------------------------------------------
export async function create(req: Request, res: Response) {
  const user = (req as any).user;
  assert(user?.jewelryId, "Tenant inválido.");
  const supplierId = s(req.params.supplierId);
  assert(supplierId, "supplierId inválido.");

  const body = req.body ?? {};
  assert(body.from, "El campo 'from' es obligatorio.");
  assert(body.to,   "El campo 'to' es obligatorio.");
  assert(body.conversion, "El campo 'conversion' es obligatorio.");
  assert(
    body.from.componentType === "MONEY" || body.from.componentType === "METAL",
    "from.componentType debe ser MONEY o METAL.",
  );
  assert(
    body.to.componentType === "MONEY" || body.to.componentType === "METAL",
    "to.componentType debe ser MONEY o METAL.",
  );

  const input: service.CrossSettlementInput = {
    supplierId,
    targetPurchaseId: body.targetPurchaseId ?? null,
    from:       body.from,
    to:         body.to,
    conversion: body.conversion,
    notes:      s(body.notes),
  };

  const settlement = await service.registerCrossSettlement(
    user.jewelryId,
    user.id,
    input,
  );
  return res.status(201).json(settlement);
}

// ---------------------------------------------------------------------------
// POST /cross-settlements/:id/void
// ---------------------------------------------------------------------------
export async function voidOne(req: Request, res: Response) {
  const user = (req as any).user;
  assert(user?.jewelryId, "Tenant inválido.");
  const id = s(req.params.id);
  assert(id, "id inválido.");

  const reason = s(req.body?.reason);
  assert(reason, "El campo 'reason' es obligatorio.");

  const settlement = await service.voidCrossSettlement(
    id,
    user.jewelryId,
    user.id,
    reason,
  );
  return res.json(settlement);
}

// ---------------------------------------------------------------------------
// GET /cross-settlements/:id
// ---------------------------------------------------------------------------
export async function getOne(req: Request, res: Response) {
  const user = (req as any).user;
  assert(user?.jewelryId, "Tenant inválido.");
  const id = s(req.params.id);
  assert(id, "id inválido.");

  const settlement = await service.getCrossSettlement(id, user.jewelryId);
  return res.json(settlement);
}
