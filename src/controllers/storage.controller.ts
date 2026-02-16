import type { Request, Response } from "express";
import { PutObjectCommand } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";

import { r2, R2_BUCKET, R2_PUBLIC_BASE_URL } from "../lib/storage/r2";
import { buildObjectKey } from "../lib/storage/keys.js";

function s(v: any) {
  return String(v ?? "").trim();
}

function guessExtFromMime(mime: string) {
  const m = s(mime).toLowerCase();
  if (m === "image/jpeg") return "jpg";
  if (m === "image/png") return "png";
  if (m === "image/webp") return "webp";
  if (m === "image/gif") return "gif";
  if (m === "image/avif") return "avif";
  if (m === "video/mp4") return "mp4";
  if (m === "video/webm") return "webm";
  if (m === "application/pdf") return "pdf";
  return "";
}

export async function signUpload(req: Request, res: Response) {
  const tenantId = s((req as any).tenantId || (req as any).jewelryId);
  if (!tenantId) return res.status(401).json({ message: "Unauthorized" });

  const body = (req.body || {}) as any;

  const kind = s(body.kind) as any;
  const mime = s(body.mime);
  const size = Number(body.size || 0);

  if (!kind) return res.status(400).json({ message: "kind requerido" });
  if (!mime) return res.status(400).json({ message: "mime requerido" });
  if (!Number.isFinite(size) || size <= 0) return res.status(400).json({ message: "size inválido" });

  const MAX_IMAGE = 8 * 1024 * 1024;
  const MAX_FILE = 30 * 1024 * 1024;
  const MAX_VIDEO = 200 * 1024 * 1024;

  const isVideo = mime.startsWith("video/");
  const isImage = mime.startsWith("image/");
  const isPdf = mime === "application/pdf";

  if (isImage && size > MAX_IMAGE) return res.status(400).json({ message: "Imagen demasiado grande (máx 8MB)" });
  if (isVideo && size > MAX_VIDEO) return res.status(400).json({ message: "Video demasiado grande (máx 200MB)" });
  if (!isVideo && !isImage && !isPdf && size > MAX_FILE) return res.status(400).json({ message: "Archivo demasiado grande (máx 30MB)" });

  const ext = guessExtFromMime(mime);

  const key = buildObjectKey({
    tenantId,
    kind,
    userId: s(body.userId),
    productId: s(body.productId),
    originalName: s(body.filename || "file"),
    ext,
  });

  const cmd = new PutObjectCommand({
    Bucket: R2_BUCKET,
    Key: key,
    ContentType: mime,
    CacheControl: isImage ? "public, max-age=31536000, immutable" : "public, max-age=3600",
  });

  const uploadUrl = await getSignedUrl(r2, cmd, { expiresIn: 60 * 15 });
  const publicUrl = R2_PUBLIC_BASE_URL ? `${R2_PUBLIC_BASE_URL}/${key}` : `/${key}`;

  return res.json({
    key,
    uploadUrl,
    publicUrl,
    expiresInSec: 900,
  });
}

// ✅ CLAVE: para que también exista "default"
export default signUpload;
