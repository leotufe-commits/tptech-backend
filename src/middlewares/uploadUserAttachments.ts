// tptech-backend/src/middlewares/uploadUserAttachments.ts
import type { Request, Response, NextFunction } from "express";
import multer from "multer";
import path from "node:path";
import crypto from "node:crypto";
import fs from "node:fs";
import { PutObjectCommand } from "@aws-sdk/client-s3";

import { r2, R2_BUCKET, R2_ENABLED } from "../lib/storage/r2.js";

function ensureDir(dir: string) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function extLower(name: string) {
  return path.extname(String(name || "")).toLowerCase();
}

const USER_ATT_DIR = path.join(process.cwd(), "uploads", "user-attachments");
ensureDir(USER_ATT_DIR);

const ALLOWED_EXT = new Set([
  // imágenes
  ".jpg",
  ".jpeg",
  ".png",
  ".webp",
  ".gif",

  // documentos
  ".pdf",
  ".txt",
  ".doc",
  ".docx",
  ".xls",
  ".xlsx",
  ".csv",

  // 3D / comprimidos
  ".stl",
  ".zip",
]);

const BLOCKED_EXT = new Set([
  ".exe",
  ".msi",
  ".bat",
  ".cmd",
  ".sh",
  ".js",
  ".mjs",
  ".cjs",
  ".ps1",
  ".jar",
  ".com",
  ".scr",
]);

const ALLOWED_MIME = new Set([
  // imágenes
  "image/jpeg",
  "image/png",
  "image/webp",
  "image/gif",

  // documentos
  "application/pdf",
  "text/plain",
  "text/csv",
  "application/msword",
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  "application/vnd.ms-excel",
  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",

  // comprimidos
  "application/zip",
  "application/x-zip-compressed",

  // 3D (varía según cliente)
  "model/stl",
  "application/sla",
  "application/vnd.ms-pki.stl",
]);

function attachmentsFileFilter(_req: any, file: Express.Multer.File, cb: multer.FileFilterCallback) {
  const ext = extLower(file.originalname);
  const mime = String(file.mimetype || "").toLowerCase();

  if (BLOCKED_EXT.has(ext)) return cb(new Error("Tipo de archivo no permitido."));
  if (ALLOWED_MIME.has(mime)) return cb(null, true);
  if (mime === "application/octet-stream" && ALLOWED_EXT.has(ext)) return cb(null, true);
  if (ALLOWED_EXT.has(ext)) return cb(null, true);

  return cb(new Error("Tipo de archivo no permitido."));
}

function buildName(req: any, file: Express.Multer.File) {
  const userId = String(req?.params?.id || req?.user?.id || "user");
  const ext = extLower(file.originalname);
  const safeExt = ext.length <= 12 ? ext : "";
  return `uatt_${userId}_${Date.now()}_${crypto.randomBytes(6).toString("hex")}${safeExt}`;
}

// LOCAL (disco)
const diskStorage = multer.diskStorage({
  destination: (_req, _file, cb) => {
    ensureDir(USER_ATT_DIR);
    cb(null, USER_ATT_DIR);
  },
  filename: (req, file, cb) => {
    cb(null, buildName(req, file));
  },
});

// R2 (memoria)
const memoryStorage = multer.memoryStorage();

const baseUpload = multer({
  storage: R2_ENABLED ? memoryStorage : diskStorage,
  fileFilter: attachmentsFileFilter,
  limits: { fileSize: 50 * 1024 * 1024, files: 10 },
});

function withMulterErrorJson(fn: any) {
  return (req: Request, res: Response, next: NextFunction) => {
    fn(req, res, (err: any) => {
      if (!err) return next();

      if (err?.code === "LIMIT_FILE_SIZE") return res.status(413).json({ message: "El archivo supera el máximo permitido." });
      if (err?.code === "LIMIT_FILE_COUNT") return res.status(400).json({ message: "Demasiados archivos." });
      if (err?.code === "LIMIT_UNEXPECTED_FILE") return res.status(400).json({ message: "Archivo inesperado. Revisá el field multipart." });

      if (String(err?.message || "").includes("Tipo de archivo no permitido")) {
        return res.status(400).json({ message: "Tipo de archivo no permitido." });
      }

      return res.status(400).json({ message: err?.message || "Error subiendo archivos." });
    });
  };
}

export const uploadUserAttachmentsFiles = [
  withMulterErrorJson(
    baseUpload.fields([
      { name: "attachments", maxCount: 10 },
      { name: "attachments[]", maxCount: 10 },
    ])
  ),
  async (req: any, res: any, next: any) => {
    try {
      if (!R2_ENABLED) return next();
      if (!r2 || !R2_BUCKET) return res.status(500).json({ message: "Storage R2 no configurado." });

      const filesByField = req.files as Record<string, Express.Multer.File[]> | undefined;
      if (!filesByField) return next();

      const allFiles = Object.values(filesByField).flat();
      if (!allFiles.length) return next();

      for (const f of allFiles) {
        const filename = buildName(req, f);
        const key = `user-attachments/${filename}`;

        await r2.send(
          new PutObjectCommand({
            Bucket: R2_BUCKET,
            Key: key,
            Body: (f as any).buffer,
            ContentType: f.mimetype || "application/octet-stream",
          })
        );

        (f as any).filename = filename;
        delete (f as any).buffer;
      }

      return next();
    } catch (err: any) {
      return res.status(400).json({ message: err?.message || "Error subiendo archivos." });
    }
  },
] as any;

// Se mantiene por compatibilidad (si lo usás en rutas viejas)
export function handleMulterErrors(err: any, _req: any, res: any, next: any) {
  if (!err) return next();

  if (err?.code === "LIMIT_FILE_SIZE") return res.status(413).json({ message: "El archivo supera el máximo permitido." });
  if (err?.code === "LIMIT_FILE_COUNT") return res.status(400).json({ message: "Demasiados archivos." });
  if (err?.code === "LIMIT_UNEXPECTED_FILE") return res.status(400).json({ message: "Archivo inesperado. Revisá el field multipart." });

  if (String(err?.message || "").includes("Tipo de archivo no permitido")) {
    return res.status(400).json({ message: "Tipo de archivo no permitido." });
  }

  return res.status(500).json({ message: err?.message || "Error subiendo archivo." });
}