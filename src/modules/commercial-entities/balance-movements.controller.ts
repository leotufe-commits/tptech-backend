// src/modules/commercial-entities/balance-movements.controller.ts
// =============================================================================
// T57 (Fase 3B.7) — Controller para la lectura canónica de cuenta corriente
// con Balance Mode (BREAKDOWN/UNIFIED) y metalEntries.
// =============================================================================

import type { Request, Response } from "express";
import { listBalanceMovements } from "./balance-movements.service.js";

/** GET /api/commercial-entities/:id/balance-movements?from=&to=&skip=&take= */
export async function list(req: Request, res: Response): Promise<void> {
  const jewelryId = (req as any).tenantId as string;
  const entityId  = String(req.params.id);
  const fromDate  = typeof req.query.from === "string" ? req.query.from : undefined;
  const toDate    = typeof req.query.to   === "string" ? req.query.to   : undefined;
  const skip      = req.query.skip != null ? Number(req.query.skip) : undefined;
  const take      = req.query.take != null ? Number(req.query.take) : undefined;

  const out = await listBalanceMovements({
    entityId, jewelryId, fromDate, toDate, skip, take,
  });
  res.json(out);
}
