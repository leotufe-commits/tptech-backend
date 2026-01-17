import multer from "multer";
import path from "node:path";
import fs from "node:fs";

const UPLOAD_DIR = path.join(process.cwd(), "uploads", "avatars");

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
    const base = `avatar_${Date.now()}-${Math.random().toString(16).slice(2)}`;
    cb(null, `${base}${ext}`);
  },
});

function fileFilter(_req: any, file: Express.Multer.File, cb: multer.FileFilterCallback) {
  const isImage = file.mimetype?.startsWith("image/");
  if (!isImage) return cb(new Error("El avatar debe ser una imagen."));
  return cb(null, true);
}

export const uploadAvatar = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB
    files: 1,
  },
});
