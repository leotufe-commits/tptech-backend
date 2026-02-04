// tptech-backend/src/modules/users/users.routes.ts
import { Router } from "express";
import multer from "multer";
import path from "node:path";
import crypto from "node:crypto";
import fs from "node:fs";

import { requirePermission } from "../../middlewares/requirePermission.js";
import * as Users from "../../controllers/users.controller.js";

const router = Router();

/**
 * NOTA:
 * requireAuth ya se aplica en src/routes/index.ts (router.use("/users", requireAuth, usersRoutes)).
 */

/* =========================
   Helpers
========================= */
function ensureDir(dir: string) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

// ✅ Gate único para este módulo (OWNER bypass desde requirePermission)
const requireUsersAdmin = requirePermission("USERS_ROLES", "ADMIN");

/* =========================
   Multer storage (avatars)
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
    const name = `avatar_${userId}_${Date.now()}_${crypto.randomBytes(4).toString("hex")}${safeExt}`;
    cb(null, name);
  },
});

function avatarFileFilter(_req: any, file: Express.Multer.File, cb: multer.FileFilterCallback) {
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
========================= */
const USER_ATT_DIR = path.join(process.cwd(), "uploads", "user-attachments");
ensureDir(USER_ATT_DIR);

const userAttStorage = multer.diskStorage({
  destination: (_req, _file, cb) => {
    ensureDir(USER_ATT_DIR);
    cb(null, USER_ATT_DIR);
  },
  filename: (req, file, cb) => {
    const userId = String(req.params?.id || (req as any).userId || "user");
    const ext = path.extname(file.originalname || "").slice(0, 12).toLowerCase();
    const safeExt = ext && ext.length <= 12 ? ext : "";
    const name = `uatt_${userId}_${Date.now()}_${crypto.randomBytes(6).toString("hex")}${safeExt}`;
    cb(null, name);
  },
});

// Adjuntos: permitimos pdf/imágenes/docs (no filtramos por mimetype)
const uploadUserAttachments = multer({
  storage: userAttStorage,
  limits: {
    fileSize: 20 * 1024 * 1024, // 20MB por archivo
    files: 10,
  },
});

/* =========================
   FAVORITE WAREHOUSE
========================= */
router.patch("/me/favorite-warehouse", requireUsersAdmin, Users.updateMyFavoriteWarehouse);
router.patch("/:id/favorite-warehouse", requireUsersAdmin, Users.updateUserFavoriteWarehouse);

/* =========================
   ✅ CLAVE RÁPIDA (PIN)
========================= */
router.put("/me/quick-pin", requireUsersAdmin, Users.updateMyQuickPin);
router.delete("/me/quick-pin", requireUsersAdmin, Users.removeMyQuickPin);

router.put("/:id/quick-pin", requireUsersAdmin, Users.updateUserQuickPin);
router.delete("/:id/quick-pin", requireUsersAdmin, Users.removeUserQuickPin);

router.patch("/:id/quick-pin/enabled", requireUsersAdmin, Users.updateUserQuickPinEnabled);

/* =========================
   AVATAR
========================= */
router.put("/me/avatar", requireUsersAdmin, uploadAvatar.single("avatar"), Users.updateMyAvatar);
router.delete("/me/avatar", requireUsersAdmin, Users.removeMyAvatar);

router.put("/:id/avatar", requireUsersAdmin, uploadAvatar.single("avatar"), Users.updateUserAvatarForUser);
router.delete("/:id/avatar", requireUsersAdmin, Users.removeUserAvatarForUser);

/* =========================
   ✅ USER ATTACHMENTS (ADMIN)
========================= */
router.put(
  "/:id/attachments",
  requireUsersAdmin,
  uploadUserAttachments.array("attachments", 10),
  Users.uploadUserAttachments
);

router.delete("/:id/attachments/:attachmentId", requireUsersAdmin, Users.deleteUserAttachment);

/* =========================
   USERS CRUD / ADMIN
========================= */
router.post("/", requireUsersAdmin, Users.createUser);
router.get("/", requireUsersAdmin, Users.listUsers);
router.get("/:id", requireUsersAdmin, Users.getUser);

router.patch("/:id", requireUsersAdmin, Users.updateUserProfile);
router.patch("/:id/status", requireUsersAdmin, Users.updateUserStatus);
router.put("/:id/roles", requireUsersAdmin, Users.assignRolesToUser);

router.post("/:id/overrides", requireUsersAdmin, Users.setUserOverride);
router.delete("/:id/overrides/:permissionId", requireUsersAdmin, Users.removeUserOverride);

router.delete("/:id", requireUsersAdmin, Users.softDeleteUser);

/* =========================
   Multer error handler
========================= */
router.use((err: any, _req: any, res: any, next: any) => {
  if (!err) return next();

  if (err?.code === "LIMIT_FILE_SIZE") {
    return res.status(413).json({ message: "El archivo supera el máximo permitido." });
  }
  if (err?.code === "LIMIT_FILE_COUNT") {
    return res.status(400).json({ message: "Demasiados archivos." });
  }
  if (err?.code === "LIMIT_UNEXPECTED_FILE") {
    return res.status(400).json({ message: "Archivo inesperado. Revisá el field multipart." });
  }

  if (typeof err?.message === "string") {
    if (err.message.toLowerCase().includes("imagen")) {
      return res.status(400).json({ message: err.message });
    }
  }

  return res.status(500).json({ message: err?.message || "Error subiendo archivo." });
});

export default router;
