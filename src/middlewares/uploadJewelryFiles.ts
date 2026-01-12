// tptech-backend/src/middlewares/uploadJewelryFiles.ts
import multer from "multer";
import path from "node:path";
import fs from "node:fs";

const UPLOAD_DIR = path.join(process.cwd(), "uploads", "jewelry");

function ensureDir() {
  if (!fs.existsSync(UPLOAD_DIR)) {
    fs.mkdirSync(UPLOAD_DIR, { recursive: true });
  }
}

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => {
    ensureDir();
    cb(null, UPLOAD_DIR);
  },
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname || "").slice(0, 10).toLowerCase();
    const base = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
    cb(null, `${base}${ext}`);
  },
});

function fileFilter(
  _req: any,
  file: Express.Multer.File,
  cb: multer.FileFilterCallback
) {
  const isImage = file.mimetype.startsWith("image/");
  const isDoc =
    file.mimetype === "application/pdf" ||
    file.mimetype === "text/plain" ||
    file.mimetype === "application/msword" ||
    file.mimetype ===
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document" ||
    file.mimetype === "application/vnd.ms-excel" ||
    file.mimetype ===
      "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";

  // Logo: solo imagen
  if (file.fieldname === "logo") {
    if (!isImage) return cb(new Error("El logo debe ser una imagen."));
    return cb(null, true);
  }

  // Adjuntos: permitir docs o imágenes (attachments o attachments[])
  if (file.fieldname === "attachments" || file.fieldname === "attachments[]") {
    if (!(isDoc || isImage))
      return cb(new Error("Tipo de adjunto no permitido."));
    return cb(null, true);
  }

  return cb(new Error("Campo de archivo no permitido."));
}

export const uploadJewelryFiles = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: 20 * 1024 * 1024, // 20MB por archivo
    files: 21, // ✅ 1 logo + hasta 20 por robustez
  },
}).fields([
  { name: "logo", maxCount: 1 },
  { name: "attachments", maxCount: 10 },
  { name: "attachments[]", maxCount: 10 }, // ✅ robusto
]);
