// src/modules/company/company.controller.ts
import type { Request, Response } from "express";
import fs from "node:fs";
import path from "node:path";
import { prisma } from "../../lib/prisma.js";
import { auditLog } from "../../lib/auditLogger.js";

type MulterFile = {
  filename: string;
  originalname: string;
  mimetype: string;
  size: number;
};

function publicBaseUrl(req: Request) {
  const envBase = process.env.PUBLIC_BASE_URL?.replace(/\/+$/, "");
  return envBase || `${req.protocol}://${req.get("host")}`;
}

function fileUrl(req: Request, folder: string, filename: string) {
  return `${publicBaseUrl(req)}/uploads/${folder}/${encodeURIComponent(filename)}`;
}

function safeFilename(name: string) {
  return path.basename(String(name || ""));
}

async function deleteLocalFile(folder: string, filename: string) {
  if (!folder || !filename) return;

  const p = path.join(process.cwd(), "uploads", folder, safeFilename(filename));
  try {
    await fs.promises.unlink(p);
  } catch {}
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

  const newUrl = fileUrl(req, "jewelry/logos", file.filename);

  const prev = await prisma.jewelry.findUnique({
    where: { id: me.jewelryId },
    select: { logoUrl: true },
  });

  await prisma.jewelry.update({
    where: { id: me.jewelryId },
    data: { logoUrl: newUrl },
  });

  if (prev?.logoUrl) {
    const parts = prev.logoUrl.split("/");
    const filename = parts.pop();
    if (filename) {
      await deleteLocalFile("jewelry/logos", filename);
    }
  }

  const fresh = await getMyJewelry(req);

  auditLog(req, {
    action: "company.upload_logo",
    success: true,
    userId,
    tenantId: me.jewelryId,
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
    const parts = prev.logoUrl.split("/");
    const filename = parts.pop();
    if (filename) {
      await deleteLocalFile("jewelry/logos", filename);
    }
  }

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

  const files = (req as any).files as { attachments?: MulterFile[] };

  const list = files?.attachments ?? [];

  if (!list.length) {
    return res.status(400).json({ message: "No se recibieron archivos." });
  }

  await prisma.jewelryAttachment.createMany({
    data: list.map((f) => ({
      jewelryId: me.jewelryId,
      url: fileUrl(req, "jewelry/attachments", f.filename),
      filename: f.originalname,
      mimeType: f.mimetype,
      size: f.size,
    })),
  });

  const fresh = await getMyJewelry(req);

  auditLog(req, {
    action: "company.upload_attachments",
    success: true,
    userId,
    tenantId: me.jewelryId,
    meta: { count: list.length },
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

  const parts = att.url.split("/");
  const filename = parts.pop();
  if (filename) {
    await deleteLocalFile("jewelry/attachments", filename);
  }

  const fresh = await getMyJewelry(req);

  auditLog(req, {
    action: "company.delete_attachment",
    success: true,
    userId,
    tenantId: me.jewelryId,
  });

  return res.json({ jewelry: { ...fresh?.jewelry, attachments: fresh?.attachments } });
}