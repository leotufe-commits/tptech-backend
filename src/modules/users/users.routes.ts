// tptech-backend/src/modules/users/users.routes.ts
import { Router } from "express";
import multer from "multer";
import path from "node:path";
import crypto from "node:crypto";
import fs from "node:fs";

import { requireAuth } from "../../middlewares/requireAuth.js";
import { requirePermission } from "../../middlewares/requirePermission.js";
import { uploadAvatar } from "../../middlewares/uploadAvatar.js";
import * as Users from "../../controllers/users.controller.js";

const router = Router();

/* =========================
   ✅ AUTH (cookie httpOnly)
   Esto asegura req.user en TODO el router
========================= */
router.use(requireAuth);

/* =========================
   Helpers
========================= */
function ensureDir(dir: string) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function extLower(name: string) {
  return path.extname(String(name || "")).toLowerCase();
}

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
    const authUser = (req as any).user as { id?: string } | undefined;

    // ✅ /:id usa params, /me usa req.user.id (por requireAuth)
    const userId = String(req.params?.id || authUser?.id || "user");

    const ext = extLower(file.originalname).slice(0, 12);
    const safeExt = ext && ext.length <= 12 ? ext : "";
    const name = `uatt_${userId}_${Date.now()}_${crypto.randomBytes(6).toString("hex")}${safeExt}`;
    cb(null, name);
  },
});

/* =========================
   FileFilter (attachments)
   - Permitimos: imágenes, pdf, doc/docx, xls/xlsx, txt, zip, stl
   - Bloqueamos ejecutables
========================= */
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

  // 3D
  ".stl",

  // comprimidos
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

  // Bloqueo explícito
  if (BLOCKED_EXT.has(ext)) {
    return cb(new Error("Tipo de archivo no permitido."));
  }

  const mime = String(file.mimetype || "").toLowerCase();

  // ✅ Permitimos si MIME está en whitelist
  if (ALLOWED_MIME.has(mime)) return cb(null, true);

  // ✅ Si el navegador manda octet-stream (común en STL), permitimos por extensión
  if (mime === "application/octet-stream" && ALLOWED_EXT.has(ext)) return cb(null, true);

  // ✅ Permitimos por extensión (fallback)
  if (ALLOWED_EXT.has(ext)) return cb(null, true);

  return cb(new Error("Tipo de archivo no permitido."));
}

const uploadUserAttachmentsFiles = multer({
  storage: userAttStorage,
  fileFilter: attachmentsFileFilter,
  limits: {
    fileSize: 50 * 1024 * 1024, // ✅ 50MB por archivo (mejor para STL/ZIP)
    files: 10,
  },
}).fields([
  { name: "attachments", maxCount: 10 },
  { name: "attachments[]", maxCount: 10 },
]);

/* =========================
   Gates
========================= */
const requireUsersView = requirePermission("USERS_ROLES", "VIEW");
const requireUsersAdmin = requirePermission("USERS_ROLES", "ADMIN");

/* =========================================================
   SAFE HANDLERS (evita crash si algún export falta)
========================================================= */
type H = any;
function h(fn: H, name: string) {
  if (typeof fn === "function") return fn;
  return (_req: any, res: any) =>
    res.status(501).json({ message: `${name} no está exportado en users.controller.ts` });
}

const updateMyFavoriteWarehouse = h((Users as any).updateMyFavoriteWarehouse, "updateMyFavoriteWarehouse");
const updateMyQuickPin = h((Users as any).updateMyQuickPin, "updateMyQuickPin");
const removeMyQuickPin = h((Users as any).removeMyQuickPin, "removeMyQuickPin");
const updateMyAvatar = h((Users as any).updateMyAvatar, "updateMyAvatar");
const removeMyAvatar = h((Users as any).removeMyAvatar, "removeMyAvatar");
const uploadMyAttachments = h((Users as any).uploadMyAttachments, "uploadMyAttachments");

const listUsers = h((Users as any).listUsers, "listUsers");
const getUser = h((Users as any).getUser, "getUser");
const downloadUserAttachment = h((Users as any).downloadUserAttachment, "downloadUserAttachment");

const updateUserFavoriteWarehouse = h((Users as any).updateUserFavoriteWarehouse, "updateUserFavoriteWarehouse");
const updateUserQuickPin = h((Users as any).updateUserQuickPin, "updateUserQuickPin");
const removeUserQuickPin = h((Users as any).removeUserQuickPin, "removeUserQuickPin");
const updateUserQuickPinEnabled = h((Users as any).updateUserQuickPinEnabled, "updateUserQuickPinEnabled");

const updateUserAvatarForUser = h((Users as any).updateUserAvatarForUser, "updateUserAvatarForUser");
const removeUserAvatarForUser = h((Users as any).removeUserAvatarForUser, "removeUserAvatarForUser");

const uploadUserAttachments = h((Users as any).uploadUserAttachments, "uploadUserAttachments");
const deleteUserAttachment = h((Users as any).deleteUserAttachment, "deleteUserAttachment");

const createUser = h((Users as any).createUser, "createUser");
const updateUserProfile = h((Users as any).updateUserProfile, "updateUserProfile");
const updateUserStatus = h((Users as any).updateUserStatus, "updateUserStatus");
const assignRolesToUser = h((Users as any).assignRolesToUser, "assignRolesToUser");
const setUserOverride = h((Users as any).setUserOverride, "setUserOverride");
const removeUserOverride = h((Users as any).removeUserOverride, "removeUserOverride");
const softDeleteUser = h((Users as any).softDeleteUser, "softDeleteUser");

// ✅ NEW: INVITE
const sendUserInvite = h((Users as any).sendUserInvite, "sendUserInvite");

/* =========================================================
   /ME (antes que /:id)
========================================================= */
router.patch("/me/favorite-warehouse", updateMyFavoriteWarehouse);

router.put("/me/quick-pin", updateMyQuickPin);
router.delete("/me/quick-pin", removeMyQuickPin);

router.put("/me/avatar", uploadAvatar.single("avatar"), updateMyAvatar);
router.delete("/me/avatar", removeMyAvatar);

router.put("/me/attachments", uploadUserAttachmentsFiles, uploadMyAttachments);

/* =========================================================
   VIEW
========================================================= */
router.get("/", requireUsersView, listUsers);
router.get("/:id", requireUsersView, getUser);
router.get("/:id/attachments/:attachmentId/download", requireUsersView, downloadUserAttachment);

/* =========================================================
   ADMIN
========================================================= */
router.patch("/:id/favorite-warehouse", requireUsersAdmin, updateUserFavoriteWarehouse);

router.put("/:id/quick-pin", requireUsersAdmin, updateUserQuickPin);
router.delete("/:id/quick-pin", requireUsersAdmin, removeUserQuickPin);
router.patch("/:id/quick-pin/enabled", requireUsersAdmin, updateUserQuickPinEnabled);

router.put("/:id/avatar", requireUsersAdmin, uploadAvatar.single("avatar"), updateUserAvatarForUser);
router.delete("/:id/avatar", requireUsersAdmin, removeUserAvatarForUser);

router.put("/:id/attachments", requireUsersAdmin, uploadUserAttachmentsFiles, uploadUserAttachments);
router.delete("/:id/attachments/:attachmentId", requireUsersAdmin, deleteUserAttachment);

// ✅ NEW: INVITE (ADMIN) - envía link de reset como invitación
router.post("/:id/invite", requireUsersAdmin, sendUserInvite);

router.post("/", requireUsersAdmin, createUser);
router.patch("/:id", requireUsersAdmin, updateUserProfile);
router.patch("/:id/status", requireUsersAdmin, updateUserStatus);
router.put("/:id/roles", requireUsersAdmin, assignRolesToUser);

router.post("/:id/overrides", requireUsersAdmin, setUserOverride);
router.delete("/:id/overrides/:permissionId", requireUsersAdmin, removeUserOverride);

router.delete("/:id", requireUsersAdmin, softDeleteUser);

/* =========================
   Multer error handler
========================= */
router.use((err: any, _req: any, res: any, next: any) => {
  if (!err) return next();

  if (err?.code === "LIMIT_FILE_SIZE")
    return res.status(413).json({ message: "El archivo supera el máximo permitido." });
  if (err?.code === "LIMIT_FILE_COUNT") return res.status(400).json({ message: "Demasiados archivos." });
  if (err?.code === "LIMIT_UNEXPECTED_FILE")
    return res.status(400).json({ message: "Archivo inesperado. Revisá el field multipart." });

  // Errores del fileFilter
  if (String(err?.message || "").includes("Tipo de archivo no permitido")) {
    return res.status(400).json({ message: "Tipo de archivo no permitido." });
  }

  return res.status(500).json({ message: err?.message || "Error subiendo archivo." });
});

export default router;
