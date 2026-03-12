import type { Request, Response } from "express";
import * as service from "./sellers.service.js";
import { toPublicUploadUrl } from "../../lib/uploads/localUploads.js";

function s(v: any) { return String(v ?? "").trim(); }
function assert(cond: any, msg: string) { if (!cond) { const err: any = new Error(msg); err.status = 400; throw err; } }

export async function list(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  return res.json(await service.listSellers(req.user.jewelryId));
}

export async function create(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  return res.status(201).json(await service.createSeller(req.user.jewelryId, req.body));
}

export async function update(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");
  return res.json(await service.updateSeller(id, req.user.jewelryId, req.body));
}

export async function toggle(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");
  return res.json(await service.toggleSeller(id, req.user.jewelryId));
}

export async function setFavorite(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");
  return res.json(await service.setFavoriteSeller(id, req.user.jewelryId));
}

export async function remove(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");
  return res.json(await service.deleteSeller(id, req.user.jewelryId));
}

export async function uploadAvatar(req: any, res: Response) {
  const id = s(req.params?.id);
  const jewelryId = s(req.user?.jewelryId);
  assert(id, "Id inválido.");
  assert(jewelryId, "Tenant inválido.");

  const file = req.file as (Express.Multer.File & { _tpFolder?: string }) | undefined;
  if (!file) return res.status(400).json({ message: "No se recibió archivo." });

  const folder = s((file as any)._tpFolder || "sellers/avatars");
  const url = toPublicUploadUrl(req as Request, folder, file.filename);
  if (!url) return res.status(500).json({ message: "No se pudo generar la URL pública del avatar. Revisá la configuración de storage." });

  const updated = await service.updateSellerAvatar(id, jewelryId, url);
  return res.json(updated);
}

export async function addAttachment(req: any, res: Response) {
  const id = s(req.params?.id);
  const jewelryId = s(req.user?.jewelryId);
  assert(id, "Id inválido.");
  assert(jewelryId, "Tenant inválido.");

  const file = req.file as (Express.Multer.File & { _tpFolder?: string }) | undefined;
  if (!file) return res.status(400).json({ message: "No se recibió archivo." });

  const folder = s((file as any)._tpFolder || "sellers/attachments");
  const url = toPublicUploadUrl(req as Request, folder, file.filename);
  if (!url) return res.status(500).json({ message: "No se pudo generar la URL pública del adjunto. Revisá la configuración de storage." });

  const att = await service.addSellerAttachment(id, jewelryId, {
    filename: file.originalname,
    url,
    mimeType: file.mimetype,
    size: file.size,
  });
  return res.status(201).json(att);
}

export async function deleteAttachment(req: any, res: Response) {
  const id = s(req.params?.id);
  const attachmentId = s(req.params?.attachmentId);
  const jewelryId = s(req.user?.jewelryId);
  assert(id, "Id inválido.");
  assert(attachmentId, "Adjunto inválido.");
  assert(jewelryId, "Tenant inválido.");
  return res.json(await service.deleteSellerAttachment(id, attachmentId, jewelryId));
}
