// tptech-backend/src/modules/users/users.routes.ts
import { Router } from "express";
import multer from "multer";
import path from "node:path";
import crypto from "node:crypto";
import fs from "node:fs";

import * as Users from "../../controllers/users.controller.js";

const router = Router();

/**
 * NOTA:
 * requireAuth ya se aplica en src/routes/index.ts (privateRouter.use(requireAuth)).
 * Así evitamos duplicaciones de auth y problemas de routing.
 */

/* =========================
   Helpers
========================= */
function ensureDir(dir: string) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

/* =========================
   Multer storage (avatars)
   - Guarda en: uploads/avatars
   - Field esperado: avatar
========================= */
const AVATARS_DIR = path.join(process.cwd(), "uploads", "avatars");
ensureDir(AVATARS_DIR);

const avatarStorage = multer.diskStorage({
  destination: (_req, _file, cb) => {
    ensureDir(AVATARS_DIR);
    cb(null, AVATARS_DIR);
  },
  filename: (req, file, cb) => {
    const userId = String((req as any).userId || "user");
    const ext = path.extname(file.originalname || "").slice(0, 10).toLowerCase();
    const safeExt = ext && ext.length <= 10 ? ext : "";
    const name = `avatar_${userId}_${Date.now()}_${crypto
      .randomBytes(4)
      .toString("hex")}${safeExt}`;
    cb(null, name);
  },
});

function avatarFileFilter(
  _req: any,
  file: Express.Multer.File,
  cb: multer.FileFilterCallback
) {
  if (!file.mimetype?.startsWith("image/")) {
    return cb(new Error("El archivo debe ser una imagen"));
  }
  cb(null, true);
}

const uploadAvatar = multer({
  storage: avatarStorage,
  fileFilter: avatarFileFilter,
  limits: { fileSize: 5 * 1024 * 1024, files: 1 }, // 5MB
});

/* =========================
   Multer storage (user attachments)
   - Guarda en: uploads/user-attachments
   - Field esperado: attachments (multiple)
========================= */
const USER_ATT_DIR = path.join(process.cwd(), "uploads", "user-attachments");
ensureDir(USER_ATT_DIR);

const attStorage = multer.diskStorage({
  destination: (_req, _file, cb) => {
    ensureDir(USER_ATT_DIR);
    cb(null, USER_ATT_DIR);
  },
  filename: (req, file, cb) => {
    const userId = String(req.params?.id || (req as any).userId || "user");
    const ext = path.extname(file.originalname || "").slice(0, 12).toLowerCase();
    const safeExt = ext && ext.length <= 12 ? ext : "";
    const name = `uatt_${userId}_${Date.now()}_${crypto
      .randomBytes(6)
      .toString("hex")}${safeExt}`;
    cb(null, name);
  },
});

// Adjuntos: permitimos pdf/imágenes/docs (no filtramos por mimetype)
const uploadUserAttachments = multer({
  storage: attStorage,
  limits: {
    fileSize: 20 * 1024 * 1024, // 20MB por archivo
    files: 10,
  },
});

/* =========================
   FAVORITE WAREHOUSE
========================= */
router.patch("/me/favorite-warehouse", Users.updateMyFavoriteWarehouse);
router.patch("/:id/favorite-warehouse", Users.updateUserFavoriteWarehouse);

/* =========================
   ✅ CLAVE RÁPIDA (PIN)
========================= */
router.put("/me/quick-pin", Users.updateMyQuickPin);
router.delete("/me/quick-pin", Users.removeMyQuickPin);

router.put("/:id/quick-pin", Users.updateUserQuickPin);
router.delete("/:id/quick-pin", Users.removeUserQuickPin);

/** ✅ habilitar/deshabilitar acceso por PIN (sin mostrar ni cambiar el PIN) */
router.patch("/:id/quick-pin/enabled", Users.updateUserQuickPinEnabled);

/* =========================
   AVATAR (ME)
========================= */
router.put("/me/avatar", uploadAvatar.single("avatar"), Users.updateMyAvatar);
router.delete("/me/avatar", Users.removeMyAvatar);

/* =========================
   AVATAR (ADMIN)
========================= */
router.put("/:id/avatar", uploadAvatar.single("avatar"), Users.updateUserAvatarForUser);
router.delete("/:id/avatar", Users.removeUserAvatarForUser);

/* =========================
   USER ATTACHMENTS (ADMIN)
========================= */
router.put(
  "/:id/attachments",
  uploadUserAttachments.array("attachments", 10),
  Users.uploadUserAttachments
);
router.delete("/:id/attachments/:attachmentId", Users.deleteUserAttachment);

/* =========================
   USERS CRUD / ADMIN
========================= */
router.post("/", Users.createUser);
router.get("/", Users.listUsers);
router.get("/:id", Users.getUser);

/** ✅ EDITAR PERFIL/DIRECCIÓN/NOTAS */
router.patch("/:id", Users.updateUserProfile);

// Estado / roles
router.patch("/:id/status", Users.updateUserStatus);
router.put("/:id/roles", Users.assignRolesToUser);

// Overrides (permisos especiales)
router.post("/:id/overrides", Users.setUserOverride);
router.delete("/:id/overrides/:permissionId", Users.removeUserOverride);

// ✅ SOFT DELETE
router.delete("/:id", Users.softDeleteUser);

/* =========================
   Multer error handler
========================= */
router.use((err: any, _req: any, res: any, next: any) => {
  if (!err) return next();

  // Multer límites
  if (err?.code === "LIMIT_FILE_SIZE") {
    return res.status(413).json({ message: "El archivo supera el máximo permitido." });
  }
  if (err?.code === "LIMIT_FILE_COUNT") {
    return res.status(400).json({ message: "Demasiados archivos." });
  }
  if (err?.code === "LIMIT_UNEXPECTED_FILE") {
    return res
      .status(400)
      .json({ message: "Archivo inesperado. Revisá el field multipart." });
  }

  // Errores propios (avatar filter, etc.)
  if (typeof err?.message === "string") {
    if (err.message.toLowerCase().includes("imagen")) {
      return res.status(400).json({ message: err.message });
    }
  }

  return res.status(500).json({ message: err?.message || "Error subiendo archivo." });
});

export default router;
