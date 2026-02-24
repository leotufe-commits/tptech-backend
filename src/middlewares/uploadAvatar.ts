// tptech-backend/src/middlewares/uploadAvatar.ts
import type { Request, Response, NextFunction } from "express";
import multer from "multer";
import path from "node:path";
import fs from "node:fs";
import crypto from "node:crypto";
import { PutObjectCommand } from "@aws-sdk/client-s3";

import { r2, R2_BUCKET, R2_ENABLED } from "../lib/storage/r2.js";

const UPLOAD_ROOT = path.join(process.cwd(), "uploads");
const UPLOAD_DIR = path.join(UPLOAD_ROOT, "users", "avatars");

function ensureDir() {
  if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

function extFromOriginal(name: string) {
  const ext = path.extname(String(name || "")).slice(0, 10).toLowerCase();
  return ext || "";
}

function randomName(originalname: string) {
  const ext = extFromOriginal(originalname);
  return `avatar_${Date.now()}_${crypto.randomBytes(6).toString("hex")}${ext}`;
}

function fileFilter(_req: any, file: Express.Multer.File, cb: multer.FileFilterCallback) {
  const isImage = file.mimetype?.startsWith("image/");
  if (!isImage) return cb(new Error("El avatar debe ser una imagen."));
  return cb(null, true);
}

// LOCAL (disco)
const diskStorage = multer.diskStorage({
  destination: (_req, _file, cb) => {
    ensureDir();
    cb(null, UPLOAD_DIR);
  },
  filename: (_req, file, cb) => {
    cb(null, randomName(file.originalname));
  },
});

// R2 (memoria)
const memoryStorage = multer.memoryStorage();

const baseUpload = multer({
  storage: R2_ENABLED ? memoryStorage : diskStorage,
  fileFilter,
  limits: { fileSize: 5 * 1024 * 1024, files: 1 }, // 5MB
});

function withMulterErrorJson(fn: any) {
  return (req: Request, res: Response, next: NextFunction) => {
    fn(req, res, (err: any) => {
      if (!err) return next();

      const msg =
        err?.code === "LIMIT_FILE_SIZE"
          ? "Archivo demasiado grande."
          : err?.code === "LIMIT_UNEXPECTED_FILE"
          ? "Archivo inesperado. Revisá el field multipart."
          : err?.message || "Error subiendo avatar.";

      return res.status(400).json({ message: msg });
    });
  };
}

/**
 * ✅ IMPORTANTE:
 * Antes exportabas un ARRAY, y en routes hacés uploadAvatar.single(...)
 * Eso rompe porque un array no tiene .single.
 *
 * Solución: exportar un MULTER INSTANCE + un middleware extra para R2.
 */

export const uploadAvatar = baseUpload;

// middleware adicional que sube a R2 cuando R2_ENABLED
export async function uploadAvatarToR2(req: any, res: any, next: any) {
  try {
    if (!R2_ENABLED) return next();
    if (!req.file) return next();

    if (!r2 || !R2_BUCKET) return res.status(500).json({ message: "Storage R2 no configurado." });

    const f = req.file as Express.Multer.File & { buffer?: Buffer; filename: string };
    const filename = randomName(f.originalname);
    const key = `users/avatars/${filename}`;

    await r2.send(
      new PutObjectCommand({
        Bucket: R2_BUCKET,
        Key: key,
        Body: (f as any).buffer,
        ContentType: f.mimetype || "application/octet-stream",
      })
    );

    // dejamos filename final para el controller
    f.filename = filename;
    delete (f as any).buffer;

    return next();
  } catch (e: any) {
    return res.status(400).json({ message: e?.message || "Error subiendo avatar." });
  }
}

/**
 * ✅ Helper listo para usar si querés el “pack” completo
 * (opcional, por si preferís usarlo en routes)
 */
export const uploadAvatarMiddleware = [
  withMulterErrorJson(baseUpload.single("avatar")),
  uploadAvatarToR2,
] as any;