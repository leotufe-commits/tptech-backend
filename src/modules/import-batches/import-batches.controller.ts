// src/modules/import-batches/import-batches.controller.ts
import type { Response } from "express";
import * as service from "./import-batches.service.js";

function s(v: any): string { return String(v ?? "").trim(); }

function assert(cond: any, msg: string, status = 400): void {
  if (!cond) { const e: any = new Error(msg); e.status = status; throw e; }
}

// GET /api/import-batches
export async function listBatches(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  const { entityType, status, from, to, page, pageSize } = req.query as Record<string, string>;

  return res.json(
    await service.listBatches({
      jewelryId:  req.user.jewelryId,
      entityType: entityType || null,
      status:     status || null,
      from:       from  ? new Date(from)  : null,
      to:         to    ? new Date(to)    : null,
      page:       page     ? Number(page)     : 1,
      pageSize:   pageSize ? Number(pageSize) : 20,
    })
  );
}

// GET /api/import-batches/:id
export async function getBatch(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  const id = s(req.params?.id);
  assert(id, "Id inválido.");
  return res.json(await service.getBatch(id, req.user.jewelryId));
}

// GET /api/import-batches/:id/rows
export async function listBatchRows(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  const batchId = s(req.params?.id);
  assert(batchId, "Id inválido.");
  const { actionResult, page, pageSize } = req.query as Record<string, string>;

  return res.json(
    await service.listBatchRows({
      batchId,
      jewelryId:    req.user.jewelryId,
      actionResult: actionResult || null,
      page:         page     ? Number(page)     : 1,
      pageSize:     pageSize ? Number(pageSize) : 50,
    })
  );
}

// GET /api/import-batches/:id/errors.csv
export async function exportErrors(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  const batchId = s(req.params?.id);
  assert(batchId, "Id inválido.");

  const csv = await service.exportBatchErrorsCsv(batchId, req.user.jewelryId);
  res.setHeader("Content-Type", "text/csv; charset=utf-8");
  res.setHeader("Content-Disposition", `attachment; filename="errores-importacion-${batchId.slice(0, 8)}.csv"`);
  return res.send(csv);
}

// POST /api/import-batches/:id/retry-errors
export async function retryErrors(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  const batchId = s(req.params?.id);
  assert(batchId, "Id inválido.");

  const result = await service.retryErrors({
    batchId,
    jewelryId: req.user.jewelryId,
    userId:    req.userId,
  });

  return res.status(201).json(result);
}
