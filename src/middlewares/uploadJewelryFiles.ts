// tptech-backend/src/middlewares/uploadJewelryFiles.ts
import type { Request, Response, NextFunction } from "express";
import multer from "multer";
import path from "node:path";
import fs from "node:fs";
import crypto from "node:crypto";
import { PutObjectCommand } from "@aws-sdk/client-s3";

import { r2, R2_BUCKET, R2_ENABLED } from "../lib/storage/r2.js";

type MulterFile = Express.Multer.File & { _tpFolder?: string };

function ensureDir(p: string) {
  if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true });
}

function extFromOriginal(name: string) {
  const ext = path.extname(String(name || "").trim()).toLowerCase();
  if (ext && ext.length <= 10) return ext;
  return "";
}

function randomName(originalname: string) {
  const ext = extFromOriginal(originalname);
  const rnd = crypto.randomBytes(8).toString("hex");
  return `${Date.now()}-${rnd}${ext}`;
}

/**
 * Field => folder
 * (tus controllers siguen usando toPublicUploadUrl(req, folder, file.filename))
 */
function folderForField(field: string) {
  if (field === "logo") return "jewelry/logos";
  if (field === "attachments" || field === "attachments[]") return "jewelry/attachments";
  return "jewelry/attachments";
}

/* =========================
   Multer base
========================= */

// LOCAL (disco)
const diskStorage = multer.diskStorage({
  destination: (_req, file, cb) => {
    const folder = folderForField(file.fieldname);
    const dest = path.join(process.cwd(), "uploads", folder);
    ensureDir(dest);
    (file as MulterFile)._tpFolder = folder;
    cb(null, dest);
  },
  filename: (_req, file, cb) => {
    cb(null, randomName(file.originalname));
  },
});

// R2 (memoria)
const memoryStorage = multer.memoryStorage();

const baseUpload = multer({
  storage: R2_ENABLED ? memoryStorage : diskStorage,
  limits: { fileSize: 15 * 1024 * 1024 }, // 15MB
});

function withMulterErrorJson(fn: any) {
  return (req: Request, res: Response, next: NextFunction) => {
    fn(req, res, (err: any) => {
      if (!err) return next();

      const msg =
        err?.code === "LIMIT_FILE_SIZE"
          ? "Archivo demasiado grande."
          : err?.code === "LIMIT_FILE_COUNT"
          ? "Demasiados archivos."
          : err?.code === "LIMIT_UNEXPECTED_FILE"
          ? "Archivo inesperado. Revisá el field multipart."
          : err?.message || "Error subiendo archivos.";

      return res.status(400).json({ message: msg });
    });
  };
}

export const uploadJewelryFiles = [
  withMulterErrorJson(
    baseUpload.fields([
      { name: "logo", maxCount: 1 },
      { name: "attachments", maxCount: 20 },
      { name: "attachments[]", maxCount: 20 },
    ])
  ),

  async (req: Request, res: Response, next: NextFunction) => {
    try {
      // Si no hay R2, ya quedó guardado en disco
      if (!R2_ENABLED) return next();

      // R2 habilitado, pero igual chequeamos por seguridad
      if (!r2 || !R2_BUCKET) {
        return res.status(500).json({ message: "Storage R2 no configurado." });
      }

      const filesByField = (req as any).files as Record<string, MulterFile[]> | undefined;
      if (!filesByField) return next();

      const allFiles: MulterFile[] = Object.values(filesByField).flat();

      for (const f of allFiles) {
        const folder = folderForField(f.fieldname);
        const filename = randomName(f.originalname);
        const key = `${folder}/${filename}`;

        await r2.send(
          new PutObjectCommand({
            Bucket: R2_BUCKET,
            Key: key,
            Body: (f as any).buffer,
            ContentType: f.mimetype || "application/octet-stream",
          })
        );

        // dejamos como si fuera disco: filename listo para toPublicUploadUrl(folder, filename)
        f.filename = filename;
        f._tpFolder = folder;

        // limpieza
        delete (f as any).buffer;
      }

      return next();
    } catch (e: any) {
      return res.status(400).json({ message: e?.message || "Error subiendo archivos." });
    }
  },
] as any;