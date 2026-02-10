// tptech-backend/src/controllers/company.controller.ts
import type { Request, Response } from "express";
import { prisma } from "../lib/prisma.js";
import { auditLog } from "../lib/auditLogger.js";
import path from "node:path";
import fs from "node:fs/promises";
import fsSync from "node:fs";

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

function publicBaseUrl(req: Request) {
  const envBase = String(process.env.PUBLIC_BASE_URL || "").replace(/\/+$/, "");
  if (envBase) return envBase;
  return `${req.protocol}://${req.get("host")}`;
}

function toPublicUrlFromReq(req: Request, relativePath: string) {
  const base = publicBaseUrl(req);
  const p = relativePath.startsWith("/") ? relativePath : `/${relativePath}`;
  return `${base}${p}`;
}

function filenameFromAnyUrl(u: string) {
  try {
    if (u.startsWith("http://") || u.startsWith("https://")) {
      const url = new URL(u);
      return decodeURIComponent(url.pathname.split("/").pop() || "");
    }
  } catch {
    // ignore
  }
  const parts = String(u || "").split("/");
  return decodeURIComponent(parts[parts.length - 1] || "");
}

async function safeDeleteLocalJewelryFileByUrl(url: string | null) {
  if (!url) return;

  const s = String(url || "");
  // ✅ solo archivos subidos localmente por este backend
  if (!s.includes("/uploads/jewelry/")) return;

  const filename = filenameFromAnyUrl(s);
  if (!filename) return;

  const safeName = path.basename(filename);
  if (!safeName) return;

  const abs = path.join(process.cwd(), "uploads", "jewelry", safeName);

  try {
    await fs.unlink(abs);
  } catch {
    // ignore
  }
}

/**
 * Convierte una url pública local (…/uploads/jewelry/FILE) en path absoluto.
 * Devuelve null si no parece un archivo local del backend.
 */
function absLocalJewelryFileFromUrl(url: string) {
  const s = String(url || "");
  if (!s.includes("/uploads/jewelry/")) return null;

  const filename = filenameFromAnyUrl(s);
  if (!filename) return null;

  const safeName = path.basename(filename);
  if (!safeName) return null;

  return path.join(process.cwd(), "uploads", "jewelry", safeName);
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

  const rel = `/uploads/jewelry/${logoFile.filename}`;
  const logoUrl = toPublicUrlFromReq(req, rel);

  const updated = await prisma.jewelry.update({
    where: { id: tenantId },
    data: { logoUrl },
    select: { id: true, logoUrl: true },
  });

  // borrar el anterior si era local
  await safeDeleteLocalJewelryFileByUrl(prev.logoUrl);

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
   - setea logoUrl = ""
   - borra archivo anterior si era local
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

  // borrar el anterior si era local
  await safeDeleteLocalJewelryFileByUrl(prev.logoUrl);

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
   - usa uploadJewelryFiles middleware
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

  // persistir en DB
  const created = await prisma.jewelryAttachment.createMany({
    data: files.map((f) => {
      const rel = `/uploads/jewelry/${f.filename}`;
      return {
        jewelryId: tenantId,
        url: toPublicUrlFromReq(req, rel),
        filename: f.originalname || f.filename,
        mimeType: f.mimetype || "application/octet-stream",
        size: typeof f.size === "number" ? f.size : 0,
      };
    }),
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
   - fuerza descarga (Content-Disposition)
   - valida tenant
   - soporta: URL externa -> redirect, URL local -> stream
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

  // Si algún día guardás URLs externas reales: redirect.
  if (att.url.startsWith("http://") || att.url.startsWith("https://")) {
    const abs = absLocalJewelryFileFromUrl(att.url);

    // URL externa real (no local del backend)
    if (!abs) {
      auditLog(req, {
        action: "company.attachments.download",
        success: true,
        userId: actorId,
        tenantId,
        meta: { attachmentId, mode: "redirect" },
      });
      return res.redirect(att.url);
    }

    // URL pública local -> servir archivo local
    if (!fsSync.existsSync(abs)) {
      return res.status(404).json({ message: "Archivo no encontrado en disco." });
    }

    res.setHeader("Content-Type", att.mimeType || "application/octet-stream");
    res.setHeader("Content-Length", String(att.size || fsSync.statSync(abs).size));
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${encodeURIComponent(att.filename || "archivo")}"`
    );

    auditLog(req, {
      action: "company.attachments.download",
      success: true,
      userId: actorId,
      tenantId,
      meta: { attachmentId, mode: "local" },
    });

    return fsSync.createReadStream(abs).pipe(res);
  }

  // Robustez por si algún día guardás path relativo en vez de URL
  const abs = absLocalJewelryFileFromUrl(att.url);
  if (!abs) {
    return res.status(400).json({ message: "URL de adjunto inválida." });
  }
  if (!fsSync.existsSync(abs)) {
    return res.status(404).json({ message: "Archivo no encontrado en disco." });
  }

  res.setHeader("Content-Type", att.mimeType || "application/octet-stream");
  res.setHeader("Content-Length", String(att.size || fsSync.statSync(abs).size));
  res.setHeader(
    "Content-Disposition",
    `attachment; filename="${encodeURIComponent(att.filename || "archivo")}"`
  );

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

  await safeDeleteLocalJewelryFileByUrl(att.url);

  auditLog(req, {
    action: "company.attachments.delete",
    success: true,
    userId: actorId,
    tenantId,
    meta: { attachmentId },
  });

  return res.json({ ok: true });
}
