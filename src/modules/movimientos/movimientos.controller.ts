// src/modules/movimientos/movimientos.controller.ts
import type { Response } from "express";
import * as service from "./movimientos.service.js";

function s(v: any) {
  return String(v ?? "").trim();
}

function toNum(v: any, fallback = NaN) {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

export async function list(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  const userId = req.user?.id;
  const body = req.body ?? {};

  const page = Math.max(1, Math.floor(toNum(body.page, 1) || 1));
  const pageSize = Math.max(
    1,
    Math.min(200, Math.floor(toNum(body.pageSize, 50) || 50))
  );

  const data = await service.listMovements({
    jewelryId,
    userId,
    page,
    pageSize,
    q: s(body.q || ""),
    warehouseId: s(body.warehouseId || "") || null,
    kind: s(body.kind || "") || null,
    from: body.from ? new Date(body.from) : null,
    to: body.to ? new Date(body.to) : null,
  });

  return res.json(data);
}

export async function create(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  const userId = req.user?.id;
  const body = req.body ?? {};

  const data = await service.createMovement({
    jewelryId,
    userId,
    warehouseId: s(body.warehouseId),
    kind: "IN",
    note: s(body.note || ""),
    effectiveAt: body.effectiveAt ? new Date(body.effectiveAt) : new Date(),
    lines: Array.isArray(body.lines) ? body.lines : [],
  });

  return res.json(data);
}

export async function transfer(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  const userId = req.user?.id;
  const body = req.body ?? {};

  const data = await service.transferMovement({
    jewelryId,
    userId,
    fromWarehouseId: s(body.fromWarehouseId),
    toWarehouseId: s(body.toWarehouseId),
    note: s(body.note || ""),
    effectiveAt: body.effectiveAt ? new Date(body.effectiveAt) : new Date(),
    lines: Array.isArray(body.lines) ? body.lines : [],
  });

  return res.json(data);
}

export async function adjustMovement(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  const userId = req.user?.id;
  const body = req.body ?? {};

  const data = await service.createMovement({
    jewelryId,
    userId,
    warehouseId: s(body.warehouseId),
    kind: "ADJUST",
    note: s(body.note || ""),
    effectiveAt: body.effectiveAt ? new Date(body.effectiveAt) : new Date(),
    lines: Array.isArray(body.lines) ? body.lines : [],
  });

  return res.json(data);
}

export async function voidMovement(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  const userId = req.user?.id;

  const id = s(req.params?.id);
  const note = s(req.body?.note || "");

  const data = await service.voidMovement({ id, jewelryId, userId, note });
  return res.json(data);
}

/* ========================================
   NUEVO: últimos movimientos de un almacén
======================================== */

export async function listForWarehouse(req: any, res: Response) {
  const jewelryId = req.user?.jewelryId;
  const warehouseId = s(req.params?.id);

  const rows = await service.listMovementsForWarehouse({
    jewelryId,
    warehouseId,
    take: 5,
  });

  return res.json(rows);
}