// tptech-backend/src/controllers/company.controller.ts
import type { Request, Response } from "express";
import { prisma } from "../lib/prisma.js";
import { auditLog } from "../lib/auditLogger.js";
import fsSync from "node:fs";

import {
  toPublicUploadUrl,
  absLocalUploadFromUrl,
  safeDeleteLocalUploadByUrl,
} from "../lib/uploads/localUploads.js";

/* =========================
   HELPERS
========================= */
function requireTenantId(req: Request, res: Response): string | null {
  const tenantId = (req as any).tenantId as string | undefined;
  if (!tenantId) {
    res.status(400).json({ message: "Tenant no definido en el request." });
    return null;
  }
  return String(tenantId);
}

function clampInt(v: any, def: number, min: number, max: number) {
  const n = Number(v);
  if (!Number.isFinite(n)) return def;
  return Math.max(min, Math.min(max, Math.trunc(n)));
}

/* =========================
   GET /company/settings/security
========================= */
export async function getSecuritySettings(req: Request, res: Response) {
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  const jewelry = await prisma.jewelry.findUnique({
    where: { id: tenantId },
    select: {
      id: true,
      quickSwitchEnabled: true,
      pinLockEnabled: true,
      pinLockTimeoutSec: true,
      pinLockRequireOnUserSwitch: true,
    },
  });

  if (!jewelry) {
    return res.status(404).json({ message: "Joyería no encontrada." });
  }

  return res.json({
    security: {
      quickSwitchEnabled: Boolean(jewelry.quickSwitchEnabled),
      pinLockEnabled: Boolean(jewelry.pinLockEnabled),
      pinLockTimeoutSec: Number(jewelry.pinLockTimeoutSec ?? 300),
      pinLockRequireOnUserSwitch: Boolean(jewelry.pinLockRequireOnUserSwitch),
    },
  });
}

/* =========================
   PATCH /company/settings/security
========================= */
export async function updateSecuritySettings(req: Request, res: Response) {
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  const actorId = (req as any).userId as string | undefined;

  const body = (req.body ?? {}) as Partial<{
    quickSwitchEnabled: boolean;
    pinLockEnabled: boolean;
    pinLockTimeoutSec: number;
    pinLockRequireOnUserSwitch: boolean;
  }>;

  const data: {
    quickSwitchEnabled?: boolean;
    pinLockEnabled?: boolean;
    pinLockTimeoutSec?: number;
    pinLockRequireOnUserSwitch?: boolean;
  } = {};

  if ("quickSwitchEnabled" in body) {
    if (typeof body.quickSwitchEnabled !== "boolean") {
      return res.status(400).json({ message: "quickSwitchEnabled debe ser boolean." });
    }
    data.quickSwitchEnabled = body.quickSwitchEnabled;
  }

  if ("pinLockEnabled" in body) {
    if (typeof body.pinLockEnabled !== "boolean") {
      return res.status(400).json({ message: "pinLockEnabled debe ser boolean." });
    }
    data.pinLockEnabled = body.pinLockEnabled;
  }

  if ("pinLockTimeoutSec" in body) {
    data.pinLockTimeoutSec = clampInt(body.pinLockTimeoutSec, 300, 10, 60 * 60 * 12);
  }

  if ("pinLockRequireOnUserSwitch" in body) {
    if (typeof body.pinLockRequireOnUserSwitch !== "boolean") {
      return res.status(400).json({ message: "pinLockRequireOnUserSwitch debe ser boolean." });
    }
    data.pinLockRequireOnUserSwitch = body.pinLockRequireOnUserSwitch;
  }

  if (!Object.keys(data).length) {
    return res.status(400).json({ message: "No hay campos para actualizar." });
  }

  const updated = await prisma.jewelry.update({
    where: { id: tenantId },
    data,
    select: {
      id: true,
      quickSwitchEnabled: true,
      pinLockEnabled: true,
      pinLockTimeoutSec: true,
      pinLockRequireOnUserSwitch: true,
    },
  });

  auditLog(req, {
    action: "company.settings.security.update",
    success: true,
    userId: actorId,
    tenantId,
    meta: { fields: Object.keys(data) },
  });

  return res.json({
    ok: true,
    security: {
      quickSwitchEnabled: Boolean(updated.quickSwitchEnabled),
      pinLockEnabled: Boolean(updated.pinLockEnabled),
      pinLockTimeoutSec: Number(updated.pinLockTimeoutSec ?? 300),
      pinLockRequireOnUserSwitch: Boolean(updated.pinLockRequireOnUserSwitch),
    },
  });
}

/* =========================
   ✅ PUT /company/logo
   multipart field: logo (imagen)
   - usa uploadJewelryFiles middleware
========================= */
export async function uploadCompanyLogo(req: Request, res: Response) {
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  const actorId = (req as any).userId as string | undefined;

  const filesByField = (req as any).files as Record<string, Express.Multer.File[]> | undefined;
  const logoFile = filesByField?.logo?.[0];

  if (!logoFile) {
    return res.status(400).json({ message: "Falta archivo logo (multipart field: logo)." });
  }

  if (!logoFile.mimetype?.startsWith("image/")) {
    return res.status(400).json({ message: "El logo debe ser una imagen." });
  }

  const prev = await prisma.jewelry.findUnique({
    where: { id: tenantId },
    select: { id: true, logoUrl: true },
  });

  if (!prev) return res.status(404).json({ message: "Joyería no encontrada." });

  // ✅ NUEVO: logos van a /uploads/jewelry/logos/...
  const logoUrl = toPublicUploadUrl(req, "jewelry/logos", logoFile.filename);

  const updated = await prisma.jewelry.update({
    where: { id: tenantId },
    data: { logoUrl },
    select: { id: true, logoUrl: true },
  });

  // ✅ borrar anterior si era local y era logo
  await safeDeleteLocalUploadByUrl(prev.logoUrl, "jewelry/logos");

  auditLog(req, {
    action: "company.logo.upload",
    success: true,
    userId: actorId,
    tenantId,
    meta: { logoUrl },
  });

  return res.json({ ok: true, logoUrl: updated.logoUrl });
}

/* =========================
   ✅ DELETE /company/logo
========================= */
export async function deleteCompanyLogo(req: Request, res: Response) {
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  const actorId = (req as any).userId as string | undefined;

  const prev = await prisma.jewelry.findUnique({
    where: { id: tenantId },
    select: { id: true, logoUrl: true },
  });

  if (!prev) return res.status(404).json({ message: "Joyería no encontrada." });

  const updated = await prisma.jewelry.update({
    where: { id: tenantId },
    data: { logoUrl: "" },
    select: { id: true, logoUrl: true },
  });

  await safeDeleteLocalUploadByUrl(prev.logoUrl, "jewelry/logos");

  auditLog(req, {
    action: "company.logo.delete",
    success: true,
    userId: actorId,
    tenantId,
    meta: { prevLogoUrl: prev.logoUrl || "" },
  });

  return res.json({ ok: true, logoUrl: updated.logoUrl });
}

/* =========================
   ✅ PUT /company/attachments
   multipart fields: attachments | attachments[]
========================= */
export async function uploadCompanyAttachments(req: Request, res: Response) {
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  const actorId = (req as any).userId as string | undefined;

  const jewelry = await prisma.jewelry.findUnique({
    where: { id: tenantId },
    select: { id: true },
  });
  if (!jewelry) return res.status(404).json({ message: "Joyería no encontrada." });

  const filesByField = (req as any).files as Record<string, Express.Multer.File[]> | undefined;
  const a1 = filesByField?.attachments ?? [];
  const a2 = filesByField?.["attachments[]"] ?? [];
  const files = [...a1, ...a2];

  if (!files.length) {
    return res.status(400).json({ message: "No se recibieron archivos (field: attachments)." });
  }

  const created = await prisma.jewelryAttachment.createMany({
    data: files.map((f) => ({
      jewelryId: tenantId,
      // ✅ NUEVO: adjuntos van a /uploads/jewelry/attachments/...
      url: toPublicUploadUrl(req, "jewelry/attachments", f.filename),
      filename: f.originalname || f.filename,
      mimeType: f.mimetype || "application/octet-stream",
      size: typeof f.size === "number" ? f.size : 0,
    })),
    skipDuplicates: true,
  });

  auditLog(req, {
    action: "company.attachments.upload",
    success: true,
    userId: actorId,
    tenantId,
    meta: { count: files.length, createdCount: created.count },
  });

  const attachments = await prisma.jewelryAttachment.findMany({
    where: { jewelryId: tenantId },
    select: { id: true, url: true, filename: true, mimeType: true, size: true, createdAt: true },
    orderBy: { createdAt: "desc" },
  });

  return res.json({ ok: true, createdCount: created.count, attachments });
}

/* =========================
   ✅ GET /company/attachments/:attachmentId/download
   - sirve archivo si está en /uploads/...
========================= */
export async function downloadCompanyAttachment(req: Request, res: Response) {
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  const actorId = (req as any).userId as string | undefined;

  const attachmentId = String(req.params.attachmentId || "").trim();
  if (!attachmentId) return res.status(400).json({ message: "attachmentId inválido." });

  const att = await prisma.jewelryAttachment.findFirst({
    where: { id: attachmentId, jewelryId: tenantId },
    select: { id: true, url: true, filename: true, mimeType: true, size: true, createdAt: true },
  });

  if (!att) return res.status(404).json({ message: "Adjunto no encontrado." });

  const abs = absLocalUploadFromUrl(att.url);
  if (!abs) return res.status(400).json({ message: "URL de adjunto inválida." });
  if (!fsSync.existsSync(abs)) return res.status(404).json({ message: "Archivo no encontrado en disco." });

  res.setHeader("Content-Type", att.mimeType || "application/octet-stream");
  res.setHeader("Content-Length", String(att.size || fsSync.statSync(abs).size));
  res.setHeader("Content-Disposition", `attachment; filename="${encodeURIComponent(att.filename || "archivo")}"`);

  auditLog(req, {
    action: "company.attachments.download",
    success: true,
    userId: actorId,
    tenantId,
    meta: { attachmentId, mode: "local" },
  });

  return fsSync.createReadStream(abs).pipe(res);
}

/* =========================
   ✅ DELETE /company/attachments/:attachmentId
========================= */
export async function deleteCompanyAttachment(req: Request, res: Response) {
  const tenantId = requireTenantId(req, res);
  if (!tenantId) return;

  const actorId = (req as any).userId as string | undefined;

  const attachmentId = String(req.params.attachmentId || "").trim();
  if (!attachmentId) return res.status(400).json({ message: "attachmentId inválido." });

  const att = await prisma.jewelryAttachment.findFirst({
    where: { id: attachmentId, jewelryId: tenantId },
    select: { id: true, url: true },
  });

  if (!att) return res.status(404).json({ message: "Adjunto no encontrado." });

  await prisma.jewelryAttachment.delete({ where: { id: att.id } });

  await safeDeleteLocalUploadByUrl(att.url, "jewelry/attachments");

  auditLog(req, {
    action: "company.attachments.delete",
    success: true,
    userId: actorId,
    tenantId,
    meta: { attachmentId },
  });

  return res.json({ ok: true });
}