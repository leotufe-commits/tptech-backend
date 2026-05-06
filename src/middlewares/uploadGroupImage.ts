// tptech-backend/src/middlewares/uploadGroupImage.ts
import type { Request, Response, NextFunction } from "express";
import multer from "multer";
import path from "node:path";
import fs from "node:fs";
import crypto from "node:crypto";
import { PutObjectCommand } from "@aws-sdk/client-s3";

import { r2, R2_BUCKET, R2_ENABLED } from "../lib/storage/r2.js";

const UPLOAD_DIR = path.join(process.cwd(), "uploads", "groups", "images");

function ensureDir() {
  if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

function extFromOriginal(name: string) {
  return path.extname(String(name || "")).slice(0, 10).toLowerCase() || "";
}

function randomName(originalname: string, groupId: string) {
  const ext = extFromOriginal(originalname);
  return `group_img_${groupId}_${Date.now()}_${crypto.randomBytes(6).toString("hex")}${ext}`;
}

function fileFilter(_req: any, file: Express.Multer.File, cb: multer.FileFilterCallback) {
  if (!file.mimetype?.startsWith("image/")) return cb(new Error("Solo se permiten imágenes."));
  return cb(null, true);
}

const diskStorage = multer.diskStorage({
  destination: (_req, _file, cb) => {
    ensureDir();
    cb(null, UPLOAD_DIR);
  },
  filename: (req, file, cb) => {
    const groupId = String(req?.params?.id || "group");
    cb(null, randomName(file.originalname, groupId));
  },
});

const memoryStorage = multer.memoryStorage();

const baseUpload = multer({
  storage: R2_ENABLED ? memoryStorage : diskStorage,
  fileFilter,
  limits: { fileSize: 10 * 1024 * 1024, files: 1 },
});

function withMulterErrorJson(fn: any) {
  return (req: Request, res: Response, next: NextFunction) => {
    fn(req, res, (err: any) => {
      if (!err) return next();
      const msg =
        err?.code === "LIMIT_FILE_SIZE" ? "Archivo demasiado grande (máx 10 MB)." :
        err?.code === "LIMIT_UNEXPECTED_FILE" ? "Archivo inesperado. Revisá el field multipart." :
        err?.message || "Error subiendo imagen.";
      return res.status(400).json({ message: msg });
    });
  };
}

async function uploadToR2(req: any, res: any, next: any) {
  try {
    if (!R2_ENABLED) return next();
    if (!req.file) return next();
    if (!r2 || !R2_BUCKET) return res.status(500).json({ message: "Storage R2 no configurado." });

    const f = req.file as Express.Multer.File & { buffer?: Buffer };
    const groupId = String(req?.params?.id || "group");
    const filename = randomName(f.originalname, groupId);
    const key = `groups/images/${filename}`;

    await r2.send(new PutObjectCommand({
      Bucket: R2_BUCKET,
      Key: key,
      Body: (f as any).buffer,
      ContentType: f.mimetype || "application/octet-stream",
    }));

    f.filename = filename;
    (f as any)._tpFolder = "groups/images";
    delete (f as any).buffer;

    return next();
  } catch (e: any) {
    return res.status(400).json({ message: e?.message || "Error subiendo imagen." });
  }
}

export const uploadGroupImageMiddleware = [
  withMulterErrorJson(baseUpload.single("file")),
  uploadToR2,
] as any;
