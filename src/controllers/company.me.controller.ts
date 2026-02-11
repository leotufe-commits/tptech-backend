// tptech-backend/src/controllers/company.me.controller.ts
import type { Request, Response } from "express";
import fs from "node:fs";
import path from "node:path";
import { prisma } from "../lib/prisma.js";
import { auditLog } from "../lib/auditLogger.js";

const s = (v: unknown) => String(v ?? "").trim();

function parseBodyData(req: Request): Record<string, unknown> {
  const b = ((req as any).body ?? {}) as any;
  if (b && typeof b === "object" && typeof b.data === "string" && b.data.trim()) {
    try {
      const parsed = JSON.parse(b.data);
      return parsed && typeof parsed === "object" ? parsed : {};
    } catch {
      return {};
    }
  }
  return b && typeof b === "object" ? b : {};
}

function publicBaseUrl(req: Request) {
  const envBase = process.env.PUBLIC_BASE_URL?.replace(/\/+$/, "");
  return envBase || `${req.protocol}://${req.get("host")}`;
}
function fileUrl(req: Request, filename: string) {
  return `${publicBaseUrl(req)}/uploads/jewelry/${encodeURIComponent(filename)}`;
}
function filenameFromPublicUrl(url: string) {
  try {
    const u = new URL(url);
    return decodeURIComponent(u.pathname.split("/").pop() || "");
  } catch {
    const parts = String(url || "").split("/");
    return decodeURIComponent(parts[parts.length - 1] || "");
  }
}
async function tryDeleteUploadFile(storageFilename: string) {
  if (!storageFilename) return;
  const safe = path.basename(storageFilename);
  if (!safe) return;
  const p = path.join(process.cwd(), "uploads", "jewelry", safe);
  try {
    await fs.promises.unlink(p);
  } catch {}
}

type MulterFile = { filename: string; originalname: string; mimetype: string; size: number };

export async function updateMyJewelry(req: Request, res: Response) {
  const userId = (req as any).userId as string;
  const data = parseBodyData(req);

  const meUser = await prisma.user.findUnique({
    where: { id: userId },
    select: { jewelryId: true },
  });

  if (!meUser) return res.status(404).json({ message: "User not found." });
  if (!meUser.jewelryId) return res.status(400).json({ message: "Jewelry not set for user." });

  const files = (req as any).files as
    | { logo?: MulterFile[]; attachments?: MulterFile[]; "attachments[]"?: MulterFile[] }
    | undefined;

  const logoFile = files?.logo?.[0] ?? null;
  const attachments: MulterFile[] = [...(files?.attachments ?? []), ...(files?.["attachments[]"] ?? [])];
  const newLogoUrl = logoFile ? fileUrl(req, logoFile.filename) : undefined;

  const baseUpdateData: any = {
    name: s((data as any).name),
    phoneCountry: s((data as any).phoneCountry),
    phoneNumber: s((data as any).phoneNumber),
    street: s((data as any).street),
    number: s((data as any).number),
    city: s((data as any).city),
    province: s((data as any).province),
    postalCode: s((data as any).postalCode),
    country: s((data as any).country),
  };

  const extendedUpdateData: any = {
    ...baseUpdateData,
    legalName: s((data as any).legalName),
    cuit: s((data as any).cuit),
    ivaCondition: s((data as any).ivaCondition),
    email: s((data as any).email),
    website: s((data as any).website),
    notes: String((data as any).notes ?? ""),
    ...(newLogoUrl ? { logoUrl: newLogoUrl } : { logoUrl: s((data as any).logoUrl) }),
  };

  let updated: any = null;
  try {
    updated = await prisma.jewelry.update({
      where: { id: meUser.jewelryId },
      data: extendedUpdateData,
    } as any);
  } catch {
    updated = await prisma.jewelry.update({
      where: { id: meUser.jewelryId },
      data: baseUpdateData,
    } as any);
  }

  if (attachments.length > 0) {
    try {
      await (prisma as any).jewelryAttachment.createMany({
        data: attachments.map((f: MulterFile) => ({
          jewelryId: meUser.jewelryId,
          url: fileUrl(req, f.filename),
          filename: f.originalname,
          mimeType: f.mimetype,
          size: f.size,
        })),
        skipDuplicates: true,
      });
    } catch {}
  }

  try {
    const jewelry = await prisma.jewelry.findUnique({ where: { id: meUser.jewelryId } });

    let atts: any[] = [];
    try {
      atts = await (prisma as any).jewelryAttachment.findMany({
        where: { jewelryId: meUser.jewelryId },
        orderBy: { createdAt: "desc" },
      });
    } catch {}

    auditLog(req, {
      action: "jewelry.update_profile",
      success: true,
      userId,
      tenantId: meUser.jewelryId,
      meta: { logoUploaded: !!logoFile, attachmentsUploaded: attachments.length },
    });

    return res.json({ jewelry: { ...(jewelry ?? updated), attachments: atts } });
  } catch {
    return res.json({ jewelry: updated });
  }
}

export async function uploadMyJewelryLogo(req: Request, res: Response) {
  const userId = (req as any).userId as string;

  const meUser = await prisma.user.findUnique({
    where: { id: userId },
    select: { jewelryId: true },
  });

  if (!meUser) return res.status(404).json({ message: "User not found." });
  if (!meUser.jewelryId) return res.status(400).json({ message: "Jewelry not set for user." });

  const files = (req as any).files as { logo?: MulterFile[] } | undefined;
  const logoFile = files?.logo?.[0] ?? null;

  if (!logoFile) return res.status(400).json({ message: "Falta archivo logo (field: logo)." });
  if (!String(logoFile.mimetype || "").startsWith("image/")) {
    return res.status(400).json({ message: "El logo debe ser una imagen." });
  }

  const prev = await prisma.jewelry.findUnique({
    where: { id: meUser.jewelryId },
    select: { logoUrl: true } as any,
  });

  const prevUrl = String((prev as any)?.logoUrl || "");
  const prevFilename = prevUrl ? filenameFromPublicUrl(prevUrl) : "";

  const newLogoUrl = fileUrl(req, logoFile.filename);

  await prisma.jewelry.update({
    where: { id: meUser.jewelryId },
    data: { logoUrl: newLogoUrl } as any,
  });

  if (prevFilename) await tryDeleteUploadFile(prevFilename);

  auditLog(req, {
    action: "jewelry.upload_logo",
    success: true,
    userId,
    tenantId: meUser.jewelryId,
    meta: { filename: logoFile.originalname, size: logoFile.size },
  });

  try {
    const jewelry = await prisma.jewelry.findUnique({ where: { id: meUser.jewelryId } });

    let atts: any[] = [];
    try {
      atts = await (prisma as any).jewelryAttachment.findMany({
        where: { jewelryId: meUser.jewelryId },
        orderBy: { createdAt: "desc" },
      });
    } catch {}

    return res.json({ jewelry: { ...(jewelry as any), attachments: atts } });
  } catch {
    return res.json({ ok: true, logoUrl: newLogoUrl });
  }
}

export async function deleteMyJewelryLogo(req: Request, res: Response) {
  const userId = (req as any).userId as string;

  const meUser = await prisma.user.findUnique({
    where: { id: userId },
    select: { jewelryId: true },
  });

  if (!meUser) return res.status(404).json({ message: "User not found." });
  if (!meUser.jewelryId) return res.status(400).json({ message: "Jewelry not set for user." });

  const jewelry = await prisma.jewelry.findUnique({
    where: { id: meUser.jewelryId },
    select: { logoUrl: true } as any,
  });

  const prevUrl = (jewelry as any)?.logoUrl || "";
  const prevFilename = prevUrl ? filenameFromPublicUrl(prevUrl) : "";

  try {
    await prisma.jewelry.update({
      where: { id: meUser.jewelryId },
      data: { logoUrl: "" } as any,
    });
  } catch {}

  if (prevFilename) await tryDeleteUploadFile(prevFilename);

  auditLog(req, {
    action: "jewelry.delete_logo",
    success: true,
    userId,
    tenantId: meUser.jewelryId,
  });

  return res.json({ ok: true });
}

export async function deleteMyJewelryAttachment(req: Request, res: Response) {
  const userId = (req as any).userId as string;
  const attachmentId = String(req.params.id || "").trim();
  if (!attachmentId) return res.status(400).json({ message: "ID inválido." });

  const meUser = await prisma.user.findUnique({
    where: { id: userId },
    select: { jewelryId: true },
  });

  if (!meUser) return res.status(404).json({ message: "User not found." });
  if (!meUser.jewelryId) return res.status(400).json({ message: "Jewelry not set for user." });

  try {
    const att = await (prisma as any).jewelryAttachment.findUnique({
      where: { id: attachmentId },
      select: { id: true, jewelryId: true, url: true },
    });

    if (!att || att.jewelryId !== meUser.jewelryId) {
      return res.status(404).json({ message: "Adjunto no encontrado." });
    }

    const storageFilename = filenameFromPublicUrl(att.url);

    await (prisma as any).jewelryAttachment.delete({ where: { id: attachmentId } });

    if (storageFilename) await tryDeleteUploadFile(storageFilename);

    auditLog(req, {
      action: "jewelry.delete_attachment",
      success: true,
      userId,
      tenantId: meUser.jewelryId,
      meta: { attachmentId },
    });

    return res.json({ ok: true });
  } catch {
    return res.status(404).json({ message: "Adjunto no encontrado." });
  }
}
