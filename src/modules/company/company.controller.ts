// tptech-backend/src/modules/company/company.controller.ts
import type { Request, Response } from "express";
import { DeleteObjectCommand } from "@aws-sdk/client-s3";

import { prisma } from "../../lib/prisma.js";
import { auditLog } from "../../lib/auditLogger.js";
import { toPublicUploadUrl, safeDeleteLocalUploadByUrl } from "../../lib/uploads/localUploads.js";
import { r2, R2_BUCKET, R2_PUBLIC_BASE_URL, R2_ENABLED } from "../../lib/storage/r2.js";

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

function extractR2KeyFromUrl(url: string) {
  const u = s(url);
  if (!u) return "";

  const base = normalizeBaseUrl(R2_PUBLIC_BASE_URL || "");
  if (base && u.startsWith(base)) {
    const rest = u.slice(base.length).replace(/^\/+/, "");
    return rest;
  }
  return "";
}

async function deleteStoredFileByUrl(url: string | null | undefined, prefixFolder: string) {
  const u = s(url);
  if (!u) return;

  if (R2_ENABLED && r2 && R2_BUCKET) {
    const key = extractR2KeyFromUrl(u);
    if (key) {
      try {
        await r2.send(new DeleteObjectCommand({ Bucket: R2_BUCKET, Key: key }));
        return;
      } catch {
        // ignore and try local delete if applicable
      }
    }
  }

  await safeDeleteLocalUploadByUrl(u, prefixFolder);
}

function requirePublicStoredUrl(req: Request, folder: string, filename: string) {
  const url = toPublicUploadUrl(req, folder, filename);
  if (!url) {
    throw new Error(
      "No se pudo generar una URL pública para el archivo. Revisá la configuración de storage (R2_PUBLIC_BASE_URL)."
    );
  }
  return url;
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

  if (!file) return res.status(400).json({ message: "Falta archivo logo." });
  if (!file.mimetype.startsWith("image/")) {
    return res.status(400).json({ message: "El logo debe ser una imagen." });
  }

  const folder = s((file as any)._tpFolder);
  if (!folder) {
    return res.status(400).json({ message: "Upload inválido (folder faltante)." });
  }

  let newUrl = "";
  try {
    newUrl = requirePublicStoredUrl(req, folder, file.filename);
  } catch (e: any) {
    return res.status(500).json({
      message: e?.message || "No se pudo generar la URL pública del logo.",
    });
  }

  const prev = await prisma.jewelry.findUnique({
    where: { id: me.jewelryId },
    select: { logoUrl: true },
  });

  await prisma.jewelry.update({
    where: { id: me.jewelryId },
    data: { logoUrl: newUrl },
  });

  if (prev?.logoUrl) {
    await deleteStoredFileByUrl(prev.logoUrl, folder);
  }

  const fresh = await getMyJewelry(req);

  auditLog(req, {
    action: "company.upload_logo",
    success: true,
    userId,
    tenantId: me.jewelryId,
    meta: { url: newUrl },
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

  const tenantPrefix = `tptech/tenants/${me.jewelryId}/jewelry`;
  await deleteStoredFileByUrl(prev?.logoUrl, tenantPrefix);

  const fresh = await getMyJewelry(req);

  auditLog(req, {
    action: "company.delete_logo",
    success: true,
    userId,
    tenantId: me.jewelryId,
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

  const files = (req as any).files as {
    attachments?: MulterFile[];
    "attachments[]"?: MulterFile[];
  };

  const list = [...(files?.attachments ?? []), ...(files?.["attachments[]"] ?? [])];

  if (!list.length) {
    return res.status(400).json({ message: "No se recibieron archivos." });
  }

  const rows: Array<{
    jewelryId: string;
    url: string;
    filename: string;
    mimeType: string;
    size: number;
  }> = [];

  for (const f of list) {
    const folder = s((f as any)._tpFolder);
    if (!folder) {
      return res.status(400).json({
        message: `Upload inválido para "${f.originalname}" (folder faltante).`,
      });
    }

    let url = "";
    try {
      url = requirePublicStoredUrl(req, folder, f.filename);
    } catch (e: any) {
      return res.status(500).json({
        message:
          e?.message ||
          `No se pudo generar la URL pública del archivo "${f.originalname}".`,
      });
    }

    rows.push({
      jewelryId: me.jewelryId,
      url,
      filename: f.originalname,
      mimeType: f.mimetype,
      size: f.size,
    });
  }

  await prisma.jewelryAttachment.createMany({
    data: rows,
  });

  const fresh = await getMyJewelry(req);

  auditLog(req, {
    action: "company.upload_attachments",
    success: true,
    userId,
    tenantId: me.jewelryId,
    meta: { count: rows.length },
  });

  return res.json({ jewelry: { ...fresh?.jewelry, attachments: fresh?.attachments } });
}

/* =========================================================
   DELETE /company/me/attachments/:id
========================================================= */
export async function deleteMyJewelryAttachment(req: Request, res: Response) {
  const userId = (req as any).userId as string;
  const id = s(req.params.id);

  if (!id) return res.status(400).json({ message: "ID inválido." });

  const me = await prisma.user.findUnique({
    where: { id: userId },
    select: { jewelryId: true },
  });

  if (!me?.jewelryId) {
    return res.status(400).json({ message: "Jewelry no configurada." });
  }

  const att = await prisma.jewelryAttachment.findUnique({ where: { id } });

  if (!att || att.jewelryId !== me.jewelryId) {
    return res.status(404).json({ message: "Adjunto no encontrado." });
  }

  await prisma.jewelryAttachment.delete({ where: { id } });

  const tenantPrefix = `tptech/tenants/${me.jewelryId}/attachments`;
  await deleteStoredFileByUrl(att.url, tenantPrefix);

  const fresh = await getMyJewelry(req);

  auditLog(req, {
    action: "company.delete_attachment",
    success: true,
    userId,
    tenantId: me.jewelryId,
  });

  return res.json({ jewelry: { ...fresh?.jewelry, attachments: fresh?.attachments } });
}