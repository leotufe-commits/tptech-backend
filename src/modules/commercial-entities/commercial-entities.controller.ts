import type { Request, Response } from "express";
import * as service from "./commercial-entities.service.js";
import * as extService from "./commercial-entities-ext.service.js";
import * as importService from "./commercial-entities.import.service.js";
import * as exportService from "./commercial-entities.export.service.js";
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
  const take = Math.max(1, parseInt(String(req.query.take ?? "25"), 10) || 25);
  const showInactive = req.query.showInactive === "true";
  const sortKey = s(req.query.sortKey) || "displayName";
  const sortDir = s(req.query.sortDir) === "desc" ? "desc" : "asc";
  return res.json(
    await service.listEntities(req.user.jewelryId, {
      role: role as "client" | "supplier" | "all",
      q,
      skip,
      take,
      showInactive,
      sortKey,
      sortDir,
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

export async function bulkDelete(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  const ids = req.body?.ids;
  assert(Array.isArray(ids) && ids.length > 0, "Se requiere un array de IDs no vacío.");
  return res.json(await service.bulkDeleteEntities(ids as string[], req.user.jewelryId));
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

// ===========================================================================
// Merma Overrides
// ===========================================================================
export async function listMermaOverrides(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId, "Tenant inválido."); assert(id, "Id inválido.");
  return res.json(await extService.listMermaOverrides(id, req.user.jewelryId));
}

export async function upsertMermaOverride(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId, "Tenant inválido."); assert(id, "Id inválido.");
  return res.json(await extService.upsertMermaOverride(id, req.user.jewelryId, req.body));
}

export async function removeMermaOverride(req: any, res: Response) {
  const id = s(req.params?.id);
  const overrideId = s(req.params?.overrideId);
  assert(req.user?.jewelryId, "Tenant inválido."); assert(id && overrideId, "Ids inválidos.");
  return res.json(await extService.removeMermaOverride(id, overrideId, req.user.jewelryId));
}

// ===========================================================================
// Entity Relations
// ===========================================================================
export async function listRelations(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId, "Tenant inválido."); assert(id, "Id inválido.");
  return res.json(await extService.listRelations(id, req.user.jewelryId));
}

export async function addRelation(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId, "Tenant inválido."); assert(id, "Id inválido.");
  return res.status(201).json(await extService.addRelation(id, req.user.jewelryId, req.body));
}

export async function removeRelation(req: any, res: Response) {
  const id = s(req.params?.id);
  const relationId = s(req.params?.relationId);
  assert(req.user?.jewelryId, "Tenant inválido."); assert(id && relationId, "Ids inválidos.");
  return res.json(await extService.removeRelation(id, relationId, req.user.jewelryId));
}

// ===========================================================================
// Merge
// ===========================================================================
export async function getMergePreview(req: any, res: Response) {
  const id = s(req.params?.id);
  const targetId = s(req.params?.targetId);
  assert(req.user?.jewelryId, "Tenant inválido."); assert(id && targetId, "Ids inválidos.");
  return res.json(await extService.getMergePreview(id, targetId, req.user.jewelryId));
}

export async function mergeInto(req: any, res: Response) {
  const id = s(req.params?.id);
  const targetId = s(req.params?.targetId);
  assert(req.user?.jewelryId, "Tenant inválido."); assert(id && targetId, "Ids inválidos.");
  return res.json(await extService.mergeEntities(id, targetId, req.user.jewelryId, req.user?.id));
}

// ===========================================================================
// Bulk Import (legacy — mantiene compatibilidad)
// ===========================================================================
export async function bulkImport(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  const { rows, dryRun = true, mode = "create", role = "client", matchBy = "documentNumber" } = req.body ?? {};
  assert(Array.isArray(rows) && rows.length > 0, "rows debe ser un array no vacío.");
  assert(rows.length <= 500, "Máximo 500 filas por importación.");
  return res.json(
    await extService.bulkImportEntities(req.user.jewelryId, rows, { dryRun: Boolean(dryRun), mode, role, matchBy })
  );
}

// ===========================================================================
// Export
// ===========================================================================
export async function exportEntities(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  const { type, format } = req.query as Record<string, string>;
  assert(type === "clients" || type === "suppliers", "type debe ser 'clients' o 'suppliers'.");
  assert(format === "csv" || format === "xlsx",      "format debe ser 'csv' o 'xlsx'.");

  const result = await exportService.exportEntities(
    req.user.jewelryId,
    type as "clients" | "suppliers",
    format as "csv" | "xlsx",
  );

  res.setHeader("Content-Type", result.contentType);
  res.setHeader("Content-Disposition", `attachment; filename="${result.filename}"`);
  res.send(result.buffer);
}

// ===========================================================================
// Import v2
// ===========================================================================
export async function importPreview(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  const { rows, role = "supplier" } = req.body ?? {};
  assert(Array.isArray(rows) && rows.length > 0, "rows debe ser un array no vacío.");
  assert(rows.length <= 500, "Máximo 500 filas por importación.");
  return res.json(
    await importService.previewImport(req.user.jewelryId, rows, { role })
  );
}

export async function importCommit(req: any, res: Response) {
  assert(req.user?.jewelryId, "Tenant inválido.");
  const { rows, mode = "create", role = "supplier", matchBy = "documentNumber", fileName } = req.body ?? {};
  assert(Array.isArray(rows) && rows.length > 0, "rows debe ser un array no vacío.");
  assert(rows.length <= 500, "Máximo 500 filas por importación.");
  return res.json(
    await importService.commitImport(req.user.jewelryId, rows, {
      mode,
      role,
      matchBy,
      userId:   req.user?.id,
      fileName: fileName ? String(fileName) : "",
    })
  );
}
