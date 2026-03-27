import type { Response } from "express";
import * as service from "./article-movements.service.js";

function s(v: any): string { return String(v ?? "").trim(); }
function assert(cond: any, msg: string): void {
  if (!cond) { const e: any = new Error(msg); e.status = 400; throw e; }
}
function getUserId(req: any): string {
  return s(req.userId || req.user?.id || "");
}

// ===========================================================================
// List
// ===========================================================================
export async function list(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  const body = req.body ?? {};
  const query = req.query ?? {};

  const page     = Math.max(1, parseInt(String(body.page ?? query.page ?? "1"), 10) || 1);
  const pageSize = Math.min(200, Math.max(1, parseInt(String(body.pageSize ?? query.pageSize ?? "50"), 10) || 50));

  return res.json(await service.listArticleMovements({
    jewelryId:   req.user.jewelryId,
    page,
    pageSize,
    q:           s(body.q ?? query.q),
    warehouseId: s(body.warehouseId ?? query.warehouseId) || null,
    kind:        s(body.kind ?? query.kind) || null,
    articleId:   s(body.articleId ?? query.articleId) || null,
    from:        body.from ? new Date(body.from) : null,
    to:          body.to   ? new Date(body.to)   : null,
  }));
}

// ===========================================================================
// Create (IN / OUT / ADJUST / OPENING)
// ===========================================================================
export async function create(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  const body = req.body ?? {};
  const kind = s(body.kind).toUpperCase();
  assert(["IN", "OUT", "ADJUST", "OPENING"].includes(kind), "kind debe ser IN, OUT, ADJUST u OPENING.");
  assert(s(body.warehouseId), "warehouseId es obligatorio.");
  assert(Array.isArray(body.lines) && body.lines.length > 0, "lines es obligatorio y debe tener al menos un elemento.");

  return res.status(201).json(await service.createArticleMovement({
    jewelryId:   req.user.jewelryId,
    userId:      getUserId(req),
    kind:        kind as any,
    warehouseId: s(body.warehouseId),
    effectiveAt: body.effectiveAt ? new Date(body.effectiveAt) : new Date(),
    note:        s(body.note),
    lines:       body.lines,
  }));
}

// ===========================================================================
// Transfer
// ===========================================================================
export async function transfer(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  const body = req.body ?? {};
  assert(s(body.fromWarehouseId), "fromWarehouseId es obligatorio.");
  assert(s(body.toWarehouseId), "toWarehouseId es obligatorio.");
  assert(Array.isArray(body.lines) && body.lines.length > 0, "lines es obligatorio y debe tener al menos un elemento.");

  return res.status(201).json(await service.transferArticleMovement({
    jewelryId:       req.user.jewelryId,
    userId:          getUserId(req),
    fromWarehouseId: s(body.fromWarehouseId),
    toWarehouseId:   s(body.toWarehouseId),
    effectiveAt:     body.effectiveAt ? new Date(body.effectiveAt) : new Date(),
    note:            s(body.note),
    lines:           body.lines,
  }));
}

// ===========================================================================
// Void
// ===========================================================================
export async function voidMovement(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");

  return res.json(await service.voidArticleMovement({
    id,
    jewelryId: req.user.jewelryId,
    userId:    getUserId(req),
    note:      s(req.body?.note),
  }));
}
