// src/modules/storage/storage.controller.ts
import type { Request, Response } from "express";
import { PutObjectCommand } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";

import { r2, R2_BUCKET, R2_PUBLIC_BASE_URL } from "../../lib/storage/r2.js";
import { buildObjectKey } from "../../lib/storage/keys.js";

function s(v: any) {
  return String(v ?? "").trim();
}

function normalizeBaseUrl(v: string) {
  return String(v || "").trim().replace(/\/+$/g, "");
}

// El key puede tener "/" (path). encodeURI lo mantiene, pero escapa espacios y cosas raras.
function publicUrlFromKey(base: string, key: string) {
  const b = normalizeBaseUrl(base);
  const k = String(key || "").replace(/^\/+/, "");
  return `${b}/${encodeURI(k)}`;
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

function normalizeKind(raw: string) {
  const k = s(raw);

  if (k === "avatar") return "user_avatar";
  if (k === "jewelry-logo" || k === "jewelry_logo") return "jewelry_logo";
  if (k === "product-image") return "product_image";
  if (k === "product-video") return "product_video";

  if (
    k === "user_avatar" ||
    k === "jewelry_logo" ||
    k === "product_image" ||
    k === "product_video" ||
    k === "attachment" ||
    k === "document"
  ) {
    return k;
  }

  return "";
}

export async function signUpload(req: Request, res: Response) {
  const tenantId = s((req as any).tenantId || (req as any).jewelryId);
  if (!tenantId) return res.status(401).json({ message: "Unauthorized" });

  // ✅ Si usás este endpoint, asumimos R2 sí o sí
  if (!r2 || !R2_BUCKET) {
    return res.status(500).json({ message: "Storage no configurado (R2)" });
  }

  // ✅ Profesional: sin R2_PUBLIC_BASE_URL no hay URL pública confiable
  const basePublic = normalizeBaseUrl(R2_PUBLIC_BASE_URL || "");
  if (!basePublic) {
    return res.status(500).json({
      message:
        "Storage configurado pero falta R2_PUBLIC_BASE_URL (necesario para generar links públicos).",
    });
  }

  const body = (req.body || {}) as any;

  const kindRaw = s(body.kind);
  const kind = normalizeKind(kindRaw);
  const mime = s(body.mime);
  const size = Number(body.size || 0);

  if (!kindRaw) return res.status(400).json({ message: "kind requerido" });
  if (!kind) return res.status(400).json({ message: "kind inválido" });

  if (!mime) return res.status(400).json({ message: "mime requerido" });
  if (!Number.isFinite(size) || size <= 0) {
    return res.status(400).json({ message: "size inválido" });
  }

  const MAX_IMAGE = 8 * 1024 * 1024;
  const MAX_FILE = 30 * 1024 * 1024;
  const MAX_VIDEO = 200 * 1024 * 1024;

  const isVideo = mime.startsWith("video/");
  const isImage = mime.startsWith("image/");
  const isPdf = mime === "application/pdf";

  if (kind === "user_avatar" || kind === "jewelry_logo" || kind === "product_image") {
    if (!isImage) return res.status(400).json({ message: "mime inválido para imagen" });
  }

  if (kind === "product_video") {
    if (!isVideo) return res.status(400).json({ message: "mime inválido para video" });
  }

  if (isImage && size > MAX_IMAGE) {
    return res.status(400).json({ message: "Imagen demasiado grande (máx 8MB)" });
  }
  if (isVideo && size > MAX_VIDEO) {
    return res.status(400).json({ message: "Video demasiado grande (máx 200MB)" });
  }
  if (!isVideo && !isImage && !isPdf && size > MAX_FILE) {
    return res.status(400).json({ message: "Archivo demasiado grande (máx 30MB)" });
  }

  const ext = guessExtFromMime(mime);

  const key = buildObjectKey({
    tenantId,
    kind: kind as any,
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

  const publicUrl = publicUrlFromKey(basePublic, key);

  return res.json({
    ok: true,
    kind: kindRaw,
    normalizedKind: kind,
    key,
    uploadUrl,
    publicUrl,
    expiresInSec: 900,
  });
}

export default signUpload;