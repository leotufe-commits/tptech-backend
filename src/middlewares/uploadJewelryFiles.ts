// tptech-backend/src/middlewares/uploadJewelryFiles.ts
import multer from "multer";
import path from "node:path";
import fs from "node:fs";

const UPLOAD_ROOT = path.join(process.cwd(), "uploads");

function ensureDir(dir: string) {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

function dirForField(fieldname: string) {
  // Logo: carpeta específica
  if (fieldname === "logo") {
    return path.join(UPLOAD_ROOT, "jewelry", "logos");
  }

  // Adjuntos: carpeta específica
  if (fieldname === "attachments" || fieldname === "attachments[]") {
    return path.join(UPLOAD_ROOT, "jewelry", "attachments");
  }

  // Por seguridad, no aceptar otros campos
  return null;
}

const storage = multer.diskStorage({
  destination: (_req, file, cb) => {
    const dir = dirForField(file.fieldname);
    if (!dir) return cb(new Error("Campo de archivo no permitido."), "");
    ensureDir(dir);
    cb(null, dir);
  },
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname || "").slice(0, 10).toLowerCase();
    const base = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
    cb(null, `${base}${ext}`);
  },
});

function fileFilter(_req: any, file: Express.Multer.File, cb: multer.FileFilterCallback) {
  const isImage = file.mimetype.startsWith("image/");
  const isDoc =
    file.mimetype === "application/pdf" ||
    file.mimetype === "text/plain" ||
    file.mimetype === "application/msword" ||
    file.mimetype === "application/vnd.openxmlformats-officedocument.wordprocessingml.document" ||
    file.mimetype === "application/vnd.ms-excel" ||
    file.mimetype === "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";

  // Logo: solo imagen
  if (file.fieldname === "logo") {
    if (!isImage) return cb(new Error("El logo debe ser una imagen."));
    return cb(null, true);
  }

  // Adjuntos: permitir docs o imágenes
  if (file.fieldname === "attachments" || file.fieldname === "attachments[]") {
    if (!(isDoc || isImage)) return cb(new Error("Tipo de adjunto no permitido."));
    return cb(null, true);
  }

  return cb(new Error("Campo de archivo no permitido."));
}

export const uploadJewelryFiles = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: 20 * 1024 * 1024, // 20MB por archivo
    files: 21, // 1 logo + hasta 20 por robustez
  },
}).fields([
  { name: "logo", maxCount: 1 },
  { name: "attachments", maxCount: 10 },
  { name: "attachments[]", maxCount: 10 },
]);