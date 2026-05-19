// src/modules/receipts/receipts.controller.ts
import type { Request, Response } from "express";
import * as service from "./receipts.service.js";
import { createReceiptDraftSchema } from "./receipts.schemas.js";
import { toPublicUploadUrl } from "../../lib/uploads/localUploads.js";

function assert(cond: any, msg: string) {
  if (!cond) { const err: any = new Error(msg); err.status = 400; throw err; }
}

function s(v: any) { return String(v ?? "").trim(); }

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

// ===========================================================================
// Attachments
// ===========================================================================
export async function listAttachments(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");
  return res.json(await service.listAttachments(id, req.user.jewelryId));
}

export async function addAttachment(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");
  const file = req.file as (Express.Multer.File & { _tpFolder?: string }) | undefined;
  if (!file) return res.status(400).json({ message: "No se recibió ningún archivo." });
  const folder = s((file as any)._tpFolder || "receipts/attachments");
  const url = toPublicUploadUrl(req as Request, folder, file.filename);
  if (!url) return res.status(500).json({ message: "No se pudo generar la URL pública del adjunto." });
  return res.status(201).json(
    await service.addAttachment(id, req.user.jewelryId, {
      filename: file.originalname,
      url,
      mimeType: file.mimetype || "",
      size: file.size || 0,
      label: "",
      uploadedBy: req.user?.email || "",
    })
  );
}

export async function updateAttachmentLabel(req: any, res: Response) {
  const id = s(req.params?.id);
  const attachmentId = s(req.params?.attachmentId);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id && attachmentId, "Ids inválidos.");
  const label = s(req.body?.label);
  return res.json(await service.updateAttachmentLabel(id, attachmentId, req.user.jewelryId, label));
}

export async function removeAttachment(req: any, res: Response) {
  const id = s(req.params?.id);
  const attachmentId = s(req.params?.attachmentId);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id && attachmentId, "Ids inválidos.");
  return res.json(await service.removeAttachment(id, attachmentId, req.user.jewelryId));
}
