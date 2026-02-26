// src/modules/company/company.controller.ts
import type { Request, Response } from "express";
import { prisma } from "../../lib/prisma.js";
import { auditLog } from "../../lib/auditLogger.js";

import { DeleteObjectCommand } from "@aws-sdk/client-s3";
import { r2, R2_BUCKET, R2_ENABLED, R2_PUBLIC_BASE_URL, R2_ENDPOINT } from "../../lib/storage/r2.js";
import { toPublicUploadUrl, safeDeleteLocalUploadByUrl } from "../../lib/uploads/localUploads.js";

type MulterFile = {
  filename: string;
  originalname: string;
  mimetype: string;
  size: number;
  _tpFolder?: string;
};

function s(v: any) {
  return String(v ?? "").trim();
}

function normalizeBaseUrl(v: string) {
  return String(v || "").trim().replace(/\/+$/g, "");
}

function r2PublicBase() {
  const b1 = normalizeBaseUrl(R2_PUBLIC_BASE_URL || "");
  if (b1) return b1;

  const b2 = normalizeBaseUrl(R2_ENDPOINT || "");
  if (b2) return b2;

  return "";
}

/**
 * Dada una publicUrl armada por toPublicUploadUrl, intenta obtener el key de R2.
 * (asume que la URL es base + "/" + folder + "/" + filename)
 */
function extractR2KeyFromUrl(url: string) {
  const u = s(url);
  if (!u) return null;

  const base = r2PublicBase();
  if (!base) return null;

  if (!u.startsWith(base)) return null;

  const rest = u.slice(base.length);
  const rest2 = rest.startsWith("/") ? rest.slice(1) : rest;
  const key = decodeURIComponent(rest2.split("?")[0].split("#")[0]);
  return key || null;
}

async function safeDeleteUploadByUrl(url: string | null | undefined, expectedPrefixFolder: string) {
  const u = s(url);
  if (!u) return;

  // Si R2 está habilitado => intentamos borrar en R2
  if (R2_ENABLED && r2 && R2_BUCKET) {
    const key = extractR2KeyFromUrl(u);
    if (key) {
      try {
        await r2.send(new DeleteObjectCommand({ Bucket: R2_BUCKET, Key: key }));
      } catch {
        // ignore
      }
      return;
    }
    // Si no pudimos extraer key, NO hacemos nada (evita borrar cosas incorrectas)
    return;
  }

  // Si no hay R2 => borrar local con safety-check
  await safeDeleteLocalUploadByUrl(u, expectedPrefixFolder);
}

async function getMyJewelry(req: Request) {
  const userId = (req as any).userId as string;

  const meUser = await prisma.user.findUnique({
    where: { id: userId },
    select: { jewelryId: true },
  });

  if (!meUser?.jewelryId) return null;

  const jewelry = await prisma.jewelry.findUnique({
    where: { id: meUser.jewelryId },
  });

  const attachments = await prisma.jewelryAttachment.findMany({
    where: { jewelryId: meUser.jewelryId },
    orderBy: { createdAt: "desc" },
  });

  return { jewelry, attachments };
}

/* =========================================================
   PATCH /company/me
========================================================= */
export async function updateMyJewelry(req: Request, res: Response) {
  const userId = (req as any).userId as string;

  const me = await prisma.user.findUnique({
    where: { id: userId },
    select: { jewelryId: true },
  });

  if (!me?.jewelryId) {
    return res.status(400).json({ message: "Jewelry no configurada." });
  }

  const data = req.body ?? {};

  await prisma.jewelry.update({
    where: { id: me.jewelryId },
    data: {
      name: data.name ?? undefined,
      legalName: data.legalName ?? undefined,
      ivaCondition: data.ivaCondition ?? undefined,
      cuit: data.cuit ?? undefined,
      email: data.email ?? undefined,
      website: data.website ?? undefined,
      notes: data.notes ?? undefined,

      phoneCountry: data.phoneCountry ?? undefined,
      phoneNumber: data.phoneNumber ?? undefined,
      street: data.street ?? undefined,
      number: data.number ?? undefined,
      city: data.city ?? undefined,
      province: data.province ?? undefined,
      postalCode: data.postalCode ?? undefined,
      country: data.country ?? undefined,
    },
  });

  const fresh = await getMyJewelry(req);

  auditLog(req, {
    action: "company.update",
    success: true,
    userId,
    tenantId: me.jewelryId,
  });

  return res.json({ jewelry: { ...fresh?.jewelry, attachments: fresh?.attachments } });
}

/* =========================================================
   POST /company/me/logo
========================================================= */
export async function uploadMyJewelryLogo(req: Request, res: Response) {
  const userId = (req as any).userId as string;

  const me = await prisma.user.findUnique({
    where: { id: userId },
    select: { jewelryId: true },
  });

  if (!me?.jewelryId) {
    return res.status(400).json({ message: "Jewelry no configurada." });
  }

  const files = (req as any).files as { logo?: MulterFile[] };
  const file = files?.logo?.[0];

  if (!file) {
    return res.status(400).json({ message: "Falta archivo logo." });
  }

  if (!file.mimetype.startsWith("image/")) {
    return res.status(400).json({ message: "El logo debe ser una imagen." });
  }

  const folder = file._tpFolder || "jewelry/logos";
  const newUrl = toPublicUploadUrl(req, folder, file.filename);

  const prev = await prisma.jewelry.findUnique({
    where: { id: me.jewelryId },
    select: { logoUrl: true },
  });

  await prisma.jewelry.update({
    where: { id: me.jewelryId },
    data: { logoUrl: newUrl },
  });

  // ✅ borrar anterior (R2 o local)
  if (prev?.logoUrl) {
    await safeDeleteUploadByUrl(prev.logoUrl, "jewelry/logos");
  }

  const fresh = await getMyJewelry(req);

  auditLog(req, {
    action: "company.upload_logo",
    success: true,
    userId,
    tenantId: me.jewelryId,
    meta: { storage: R2_ENABLED ? "r2" : "local" },
  });

  return res.json({ jewelry: { ...fresh?.jewelry, attachments: fresh?.attachments } });
}

/* =========================================================
   DELETE /company/me/logo
========================================================= */
export async function deleteMyJewelryLogo(req: Request, res: Response) {
  const userId = (req as any).userId as string;

  const me = await prisma.user.findUnique({
    where: { id: userId },
    select: { jewelryId: true },
  });

  if (!me?.jewelryId) {
    return res.status(400).json({ message: "Jewelry no configurada." });
  }

  const prev = await prisma.jewelry.findUnique({
    where: { id: me.jewelryId },
    select: { logoUrl: true },
  });

  await prisma.jewelry.update({
    where: { id: me.jewelryId },
    data: { logoUrl: "" },
  });

  if (prev?.logoUrl) {
    await safeDeleteUploadByUrl(prev.logoUrl, "jewelry/logos");
  }

  const fresh = await getMyJewelry(req);

  auditLog(req, {
    action: "company.delete_logo",
    success: true,
    userId,
    tenantId: me.jewelryId,
    meta: { storage: R2_ENABLED ? "r2" : "local" },
  });

  return res.json({ jewelry: { ...fresh?.jewelry, attachments: fresh?.attachments } });
}

/* =========================================================
   POST /company/me/attachments
========================================================= */
export async function uploadMyJewelryAttachments(req: Request, res: Response) {
  const userId = (req as any).userId as string;

  const me = await prisma.user.findUnique({
    where: { id: userId },
    select: { jewelryId: true },
  });

  if (!me?.jewelryId) {
    return res.status(400).json({ message: "Jewelry no configurada." });
  }

  const files = (req as any).files as { attachments?: MulterFile[]; "attachments[]"?: MulterFile[] };

  const list = [...(files?.attachments ?? []), ...(files?.["attachments[]"] ?? [])];

  if (!list.length) {
    return res.status(400).json({ message: "No se recibieron archivos." });
  }

  await prisma.jewelryAttachment.createMany({
    data: list.map((f) => {
      const folder = f._tpFolder || "jewelry/attachments";
      return {
        jewelryId: me.jewelryId!,
        url: toPublicUploadUrl(req, folder, f.filename),
        filename: f.originalname,
        mimeType: f.mimetype,
        size: f.size,
      };
    }),
  });

  const fresh = await getMyJewelry(req);

  auditLog(req, {
    action: "company.upload_attachments",
    success: true,
    userId,
    tenantId: me.jewelryId,
    meta: { count: list.length, storage: R2_ENABLED ? "r2" : "local" },
  });

  return res.json({ jewelry: { ...fresh?.jewelry, attachments: fresh?.attachments } });
}

/* =========================================================
   DELETE /company/me/attachments/:id
========================================================= */
export async function deleteMyJewelryAttachment(req: Request, res: Response) {
  const userId = (req as any).userId as string;
  const id = String(req.params.id || "").trim();

  if (!id) {
    return res.status(400).json({ message: "ID inválido." });
  }

  const me = await prisma.user.findUnique({
    where: { id: userId },
    select: { jewelryId: true },
  });

  if (!me?.jewelryId) {
    return res.status(400).json({ message: "Jewelry no configurada." });
  }

  const att = await prisma.jewelryAttachment.findUnique({
    where: { id },
  });

  if (!att || att.jewelryId !== me.jewelryId) {
    return res.status(404).json({ message: "Adjunto no encontrado." });
  }

  await prisma.jewelryAttachment.delete({ where: { id } });

  await safeDeleteUploadByUrl(att.url, "jewelry/attachments");

  const fresh = await getMyJewelry(req);

  auditLog(req, {
    action: "company.delete_attachment",
    success: true,
    userId,
    tenantId: me.jewelryId,
    meta: { storage: R2_ENABLED ? "r2" : "local" },
  });

  return res.json({ jewelry: { ...fresh?.jewelry, attachments: fresh?.attachments } });
}