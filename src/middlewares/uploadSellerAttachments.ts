// tptech-backend/src/middlewares/uploadSellerAttachments.ts
import type { Request, Response, NextFunction } from "express";
import multer from "multer";
import path from "node:path";
import crypto from "node:crypto";
import fs from "node:fs";
import { PutObjectCommand } from "@aws-sdk/client-s3";

import { r2, R2_BUCKET, R2_ENABLED } from "../lib/storage/r2.js";

const UPLOAD_DIR = path.join(process.cwd(), "uploads", "sellers", "attachments");

function ensureDir(dir: string) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

ensureDir(UPLOAD_DIR);

const BLOCKED_EXT = new Set([".exe", ".msi", ".bat", ".cmd", ".sh", ".js", ".mjs", ".cjs", ".ps1", ".jar", ".com", ".scr"]);
const ALLOWED_MIME = new Set([
  "image/jpeg", "image/png", "image/webp", "image/gif",
  "application/pdf", "text/plain", "text/csv",
  "application/msword",
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  "application/vnd.ms-excel",
  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  "application/zip", "application/x-zip-compressed",
]);
const ALLOWED_EXT = new Set([".jpg", ".jpeg", ".png", ".webp", ".gif", ".pdf", ".txt", ".doc", ".docx", ".xls", ".xlsx", ".csv", ".zip"]);

function fileFilter(_req: any, file: Express.Multer.File, cb: multer.FileFilterCallback) {
  const ext = path.extname(String(file.originalname || "")).toLowerCase();
  const mime = String(file.mimetype || "").toLowerCase();
  if (BLOCKED_EXT.has(ext)) return cb(new Error("Tipo de archivo no permitido."));
  if (ALLOWED_MIME.has(mime) || ALLOWED_EXT.has(ext)) return cb(null, true);
  return cb(new Error("Tipo de archivo no permitido."));
}

function buildName(req: any, file: Express.Multer.File) {
  const sellerId = String(req?.params?.id || "seller");
  const ext = path.extname(String(file.originalname || "")).toLowerCase();
  const safeExt = ext.length <= 12 ? ext : "";
  return `seller_att_${sellerId}_${Date.now()}_${crypto.randomBytes(6).toString("hex")}${safeExt}`;
}

const diskStorage = multer.diskStorage({
  destination: (_req, _file, cb) => {
    ensureDir(UPLOAD_DIR);
    cb(null, UPLOAD_DIR);
  },
  filename: (req, file, cb) => {
    cb(null, buildName(req, file));
  },
});

const memoryStorage = multer.memoryStorage();

const baseUpload = multer({
  storage: R2_ENABLED ? memoryStorage : diskStorage,
  fileFilter,
  limits: { fileSize: 20 * 1024 * 1024, files: 1 },
});

function withMulterErrorJson(fn: any) {
  return (req: Request, res: Response, next: NextFunction) => {
    fn(req, res, (err: any) => {
      if (!err) return next();
      if (err?.code === "LIMIT_FILE_SIZE") return res.status(413).json({ message: "El archivo supera el máximo permitido (20 MB)." });
      if (err?.code === "LIMIT_UNEXPECTED_FILE") return res.status(400).json({ message: "Archivo inesperado. Revisá el field multipart." });
      if (String(err?.message || "").includes("Tipo de archivo no permitido")) return res.status(400).json({ message: "Tipo de archivo no permitido." });
      return res.status(400).json({ message: err?.message || "Error subiendo archivo." });
    });
  };
}

async function uploadToR2(req: any, res: any, next: any) {
  try {
    if (!R2_ENABLED) return next();
    if (!req.file) return next();
    if (!r2 || !R2_BUCKET) return res.status(500).json({ message: "Storage R2 no configurado." });

    const f = req.file as Express.Multer.File & { buffer?: Buffer };
    const filename = buildName(req, f);
    const key = `sellers/attachments/${filename}`;

    await r2.send(new PutObjectCommand({
      Bucket: R2_BUCKET,
      Key: key,
      Body: (f as any).buffer,
      ContentType: f.mimetype || "application/octet-stream",
    }));

    f.filename = filename;
    (f as any)._tpFolder = "sellers/attachments";
    delete (f as any).buffer;

    return next();
  } catch (e: any) {
    return res.status(400).json({ message: e?.message || "Error subiendo adjunto." });
  }
}

export const uploadSellerAttachmentMiddleware = [
  withMulterErrorJson(baseUpload.single("file")),
  uploadToR2,
] as any;
