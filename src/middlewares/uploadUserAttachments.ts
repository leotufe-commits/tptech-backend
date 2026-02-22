// tptech-backend/src/middlewares/uploadUserAttachments.ts
import multer from "multer";
import path from "node:path";
import crypto from "node:crypto";
import fs from "node:fs";

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

// ✅ MIME whitelist (más seguro que solo extensión)
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

  // Bloqueo explícito por extensión
  if (BLOCKED_EXT.has(ext)) {
    return cb(new Error("Tipo de archivo no permitido."));
  }

  // ✅ Si MIME está permitido, OK
  if (ALLOWED_MIME.has(mime)) return cb(null, true);

  // ✅ Caso común: algunos clientes mandan octet-stream (ej STL)
  if (mime === "application/octet-stream" && ALLOWED_EXT.has(ext)) return cb(null, true);

  // ✅ Fallback por extensión
  if (ALLOWED_EXT.has(ext)) return cb(null, true);

  return cb(new Error("Tipo de archivo no permitido."));
}

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => {
    ensureDir(USER_ATT_DIR);
    cb(null, USER_ATT_DIR);
  },
  filename: (req, file, cb) => {
    // ✅ /:id usa params, /me usa req.user.id (requireAuth)
    const userId = String((req as any)?.params?.id || (req as any)?.user?.id || "user");
    const ext = extLower(file.originalname);

    // ✅ seguridad: extensión acotada
    const safeExt = ext.length <= 12 ? ext : "";

    const name = `uatt_${userId}_${Date.now()}_${crypto.randomBytes(6).toString("hex")}${safeExt}`;
    cb(null, name);
  },
});

export const uploadUserAttachmentsFiles = multer({
  storage,
  fileFilter: attachmentsFileFilter,
  limits: {
    fileSize: 50 * 1024 * 1024, // 50MB por archivo
    files: 10,
  },
}).fields([
  { name: "attachments", maxCount: 10 },
  { name: "attachments[]", maxCount: 10 },
]);

export function handleMulterErrors(err: any, _req: any, res: any, next: any) {
  if (!err) return next();

  // errores típicos de multer
  if (err?.code === "LIMIT_FILE_SIZE")
    return res.status(413).json({ message: "El archivo supera el máximo permitido." });

  if (err?.code === "LIMIT_FILE_COUNT")
    return res.status(400).json({ message: "Demasiados archivos." });

  if (err?.code === "LIMIT_UNEXPECTED_FILE")
    return res.status(400).json({ message: "Archivo inesperado. Revisá el field multipart." });

  // errores del fileFilter
  if (String(err?.message || "").includes("Tipo de archivo no permitido")) {
    return res.status(400).json({ message: "Tipo de archivo no permitido." });
  }

  // cualquier otro error real
  return res.status(500).json({ message: err?.message || "Error subiendo archivo." });
}