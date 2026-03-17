import type { Request, Response } from "express";
import * as service from "./commercial-entities.service.js";
import { toPublicUploadUrl } from "../../lib/uploads/localUploads.js";

function s(v: any) { return String(v ?? "").trim(); }
function assert(cond: any, msg: string) { if (!cond) { const err: any = new Error(msg); err.status = 400; throw err; } }

// ===========================================================================
// Entity CRUD
// ===========================================================================
export async function list(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  const role = s(req.query.role) || "all";
  const q = s(req.query.q);
  const skip = Math.max(0, parseInt(String(req.query.skip ?? "0"), 10) || 0);
  const take = Math.min(200, Math.max(1, parseInt(String(req.query.take ?? "50"), 10) || 50));
  const showInactive = req.query.showInactive === "true";
  return res.json(
    await service.listEntities(req.user.jewelryId, {
      role: role as "client" | "supplier" | "all",
      q,
      skip,
      take,
      showInactive,
    })
  );
}

export async function getOne(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");
  return res.json(await service.getEntity(id, req.user.jewelryId));
}

export async function create(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  return res.status(201).json(await service.createEntity(req.user.jewelryId, req.body));
}

export async function update(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");
  return res.json(await service.updateEntity(id, req.user.jewelryId, req.body));
}

export async function toggle(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");
  return res.json(await service.toggleEntity(id, req.user.jewelryId));
}

export async function remove(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");
  return res.json(await service.deleteEntity(id, req.user.jewelryId));
}

// ===========================================================================
// Avatar
// ===========================================================================
export async function updateAvatar(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");
  const file = req.file as (Express.Multer.File & { _tpFolder?: string }) | undefined;
  if (!file) return res.status(400).json({ message: "No se recibió ningún archivo." });
  const folder = s((file as any)._tpFolder || "entities/avatars");
  const url = toPublicUploadUrl(req as Request, folder, file.filename);
  if (!url) return res.status(500).json({ message: "No se pudo generar la URL pública del avatar. Revisá la configuración de storage." });
  return res.json(await service.updateEntityAvatar(id, req.user.jewelryId, url));
}

// ===========================================================================
// Addresses
// ===========================================================================
export async function listAddresses(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");
  return res.json(await service.listAddresses(id, req.user.jewelryId));
}

export async function createAddress(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");
  return res.status(201).json(await service.createAddress(id, req.user.jewelryId, req.body));
}

export async function updateAddress(req: any, res: Response) {
  const id = s(req.params?.id);
  const addressId = s(req.params?.addressId);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id && addressId, "Ids inválidos.");
  return res.json(await service.updateAddress(id, addressId, req.user.jewelryId, req.body));
}

export async function removeAddress(req: any, res: Response) {
  const id = s(req.params?.id);
  const addressId = s(req.params?.addressId);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id && addressId, "Ids inválidos.");
  return res.json(await service.removeAddress(id, addressId, req.user.jewelryId));
}

export async function setDefaultAddress(req: any, res: Response) {
  const id = s(req.params?.id);
  const addressId = s(req.params?.addressId);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id && addressId, "Ids inválidos.");
  return res.json(await service.setDefaultAddress(id, addressId, req.user.jewelryId));
}

// ===========================================================================
// Contacts
// ===========================================================================
export async function listContacts(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");
  return res.json(await service.listContacts(id, req.user.jewelryId));
}

export async function createContact(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");
  return res.status(201).json(await service.createContact(id, req.user.jewelryId, req.body));
}

export async function updateContact(req: any, res: Response) {
  const id = s(req.params?.id);
  const contactId = s(req.params?.contactId);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id && contactId, "Ids inválidos.");
  return res.json(await service.updateContact(id, contactId, req.user.jewelryId, req.body));
}

export async function removeContact(req: any, res: Response) {
  const id = s(req.params?.id);
  const contactId = s(req.params?.contactId);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id && contactId, "Ids inválidos.");
  return res.json(await service.removeContact(id, contactId, req.user.jewelryId));
}

export async function setPrimaryContact(req: any, res: Response) {
  const id = s(req.params?.id);
  const contactId = s(req.params?.contactId);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id && contactId, "Ids inválidos.");
  return res.json(await service.setPrimaryContact(id, contactId, req.user.jewelryId));
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
  const folder = s((file as any)._tpFolder || "entities/attachments");
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

// ===========================================================================
// Commercial Rules
// ===========================================================================
export async function listRules(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");
  return res.json(await service.listRules(id, req.user.jewelryId));
}

export async function createRule(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");
  return res.status(201).json(await service.createRule(id, req.user.jewelryId, req.body));
}

export async function updateRule(req: any, res: Response) {
  const id = s(req.params?.id);
  const ruleId = s(req.params?.ruleId);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id && ruleId, "Ids inválidos.");
  return res.json(await service.updateRule(id, ruleId, req.user.jewelryId, req.body));
}

export async function toggleRule(req: any, res: Response) {
  const id = s(req.params?.id);
  const ruleId = s(req.params?.ruleId);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id && ruleId, "Ids inválidos.");
  return res.json(await service.toggleRule(id, ruleId, req.user.jewelryId));
}

export async function removeRule(req: any, res: Response) {
  const id = s(req.params?.id);
  const ruleId = s(req.params?.ruleId);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id && ruleId, "Ids inválidos.");
  return res.json(await service.removeRule(id, ruleId, req.user.jewelryId));
}

// ===========================================================================
// Tax Overrides
// ===========================================================================
export async function listTaxOverrides(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");
  return res.json(await service.listTaxOverrides(id, req.user.jewelryId));
}

export async function upsertTaxOverride(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");
  return res.json(await service.upsertTaxOverride(id, req.user.jewelryId, req.body));
}

export async function removeTaxOverride(req: any, res: Response) {
  const id = s(req.params?.id);
  const overrideId = s(req.params?.overrideId);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id && overrideId, "Ids inválidos.");
  return res.json(await service.removeTaxOverride(id, overrideId, req.user.jewelryId));
}
