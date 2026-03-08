// tptech-backend/src/middlewares/uploadJewelryFiles.ts
import type { Request, Response, NextFunction } from "express";
import multer from "multer";
import path from "node:path";
import fs from "node:fs";
import { PutObjectCommand } from "@aws-sdk/client-s3";

import { r2, R2_BUCKET, R2_ENABLED } from "../lib/storage/r2.js";
import { buildObjectKey } from "../lib/storage/keys.js";

type MulterFile = Express.Multer.File & { _tpFolder?: string };

function ensureDir(p: string) {
  if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true });
}

function extFromOriginal(name: string) {
  const ext = path.extname(String(name || "").trim()).toLowerCase();
  if (ext && ext.length <= 10) return ext;
  return "";
}

function s(v: any) {
  return String(v ?? "").trim();
}

function getTenantId(req: Request) {
  const anyReq = req as any;

  return s(
    anyReq.tenantId ||
      anyReq.jewelryId ||
      anyReq.user?.jewelryId ||
      anyReq.user?.tenantId ||
      anyReq.auth?.jewelryId ||
      anyReq.auth?.tenantId
  );
}

/**
 * Field => kind para buildObjectKey()
 */
function kindForField(field: string) {
  if (field === "logo") return "jewelry_logo" as const;
  if (field === "attachments" || field === "attachments[]") return "attachment" as const;
  return "attachment" as const;
}

/**
 * Genera un key PRO (por tenant) y devuelve:
 * - key completo
 * - folder
 * - filename
 */
function buildKeyFor(req: Request, file: Express.Multer.File) {
  const tenantId = getTenantId(req);
  if (!tenantId) {
    throw new Error("Tenant no definido");
  }

  const kind = kindForField(file.fieldname);
  const originalName = s(file.originalname || "file");
  const ext = extFromOriginal(originalName).replace(/^\./, "");

  const key = buildObjectKey({
    tenantId,
    kind,
    originalName,
    ext,
  });

  const folder = path.posix.dirname(key);
  const filename = path.posix.basename(key);

  return { key, folder, filename };
}

/* =========================
   Multer base
========================= */

// LOCAL (disco)
const diskStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    try {
      const { folder } = buildKeyFor(req, file);
      const dest = path.join(process.cwd(), "uploads", folder);

      ensureDir(dest);
      (file as MulterFile)._tpFolder = folder;

      cb(null, dest);
    } catch (e: any) {
      cb(e, "");
    }
  },
  filename: (req, file, cb) => {
    try {
      const { filename } = buildKeyFor(req, file);
      cb(null, filename);
    } catch (e: any) {
      cb(e, "");
    }
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
      if (!R2_ENABLED) return next();

      if (!r2 || !R2_BUCKET) {
        return res.status(500).json({ message: "Storage R2 no configurado." });
      }

      const tenantId = getTenantId(req);
      if (!tenantId) {
        return res.status(400).json({ message: "Tenant no definido." });
      }

      console.log("[UPLOAD] R2_ENABLED =", R2_ENABLED);
      console.log("[UPLOAD] tenantId =", tenantId);
      console.log("[UPLOAD] req ids =", {
        userId: (req as any).userId,
        tenantId: (req as any).tenantId,
        jewelryId: (req as any).jewelryId,
        user: (req as any).user,
      });

      const filesByField = (req as any).files as Record<string, MulterFile[]> | undefined;
      if (!filesByField) return next();

      const allFiles: MulterFile[] = Object.values(filesByField).flat();

      for (const f of allFiles) {
        const { key, folder, filename } = buildKeyFor(req, f);

        console.log("[UPLOAD] key =", key);
        console.log("[UPLOAD] folder =", folder);
        console.log("[UPLOAD] filename =", filename);

        await r2.send(
          new PutObjectCommand({
            Bucket: R2_BUCKET,
            Key: key,
            Body: (f as any).buffer,
            ContentType: f.mimetype || "application/octet-stream",
            CacheControl: (f.mimetype || "").startsWith("image/")
              ? "public, max-age=31536000, immutable"
              : "public, max-age=3600",
          })
        );

        f.filename = filename;
        f._tpFolder = folder;

        delete (f as any).buffer;
      }

      return next();
    } catch (e: any) {
      return res.status(400).json({
        message: e?.message || "Error subiendo archivos.",
      });
    }
  },
] as any;