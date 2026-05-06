// src/modules/receipts/receipts.controller.ts
import type { Response } from "express";
import * as service from "./receipts.service.js";
import { createReceiptDraftSchema } from "./receipts.schemas.js";

function assert(cond: any, msg: string) {
  if (!cond) { const err: any = new Error(msg); err.status = 400; throw err; }
}

export async function createDraft(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  const parsed = createReceiptDraftSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({
      message: "Payload inválido.",
      issues:  parsed.error.flatten(),
    });
  }
  const userId = req.user?.id ?? null;
  const created = await service.createReceiptDraft(
    req.user.jewelryId,
    userId,
    parsed.data,
  );
  return res.status(201).json(created);
}
