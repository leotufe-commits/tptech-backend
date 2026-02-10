// tptech-backend/src/modules/users/users.routes.ts
import { Router } from "express";
import multer from "multer";
import path from "node:path";
import crypto from "node:crypto";
import fs from "node:fs";

import { requirePermission } from "../../middlewares/requirePermission.js";
import { uploadAvatar } from "../../middlewares/uploadAvatar.js"; // ✅ middleware central
import * as Users from "../../controllers/users.controller.js";

const router = Router();

/**
 * NOTA:
 * requireAuth ya se aplica en src/routes/index.ts
 * (router.use("/users", requireAuth, usersRoutes))
 */

/* =========================
   Helpers
========================= */
function ensureDir(dir: string) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

// ✅ Gates del módulo
// OWNER bypass desde requirePermission (según tu comentario)
const requireUsersView = requirePermission("USERS_ROLES", "VIEW");
const requireUsersAdmin = requirePermission("USERS_ROLES", "ADMIN");

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

// Adjuntos: permitimos cualquier tipo (controlás en frontend o controller)
const uploadUserAttachments = multer({
  storage: userAttStorage,
  limits: {
    fileSize: 20 * 1024 * 1024, // 20MB por archivo
    files: 10,
  },
}).fields([
  { name: "attachments", maxCount: 10 },
  { name: "attachments[]", maxCount: 10 }, // ✅ robusto
]);

/* =========================================================
   ✅ RUTAS /ME/* (NO requieren ADMIN)
   - requireAuth ya alcanza
   - /me debe ir ANTES que /:id
========================================================= */

/* =========================
   FAVORITE WAREHOUSE (ME)
========================= */
router.patch("/me/favorite-warehouse", Users.updateMyFavoriteWarehouse);

/* =========================
   CLAVE RÁPIDA (PIN) (ME)
========================= */
router.put("/me/quick-pin", Users.updateMyQuickPin);
router.delete("/me/quick-pin", Users.removeMyQuickPin);

/* =========================
   AVATAR (ME)
========================= */
router.put("/me/avatar", uploadAvatar.single("avatar"), Users.updateMyAvatar);
router.delete("/me/avatar", Users.removeMyAvatar);

/* =========================
   USER ATTACHMENTS (ME)
   ⚠️ FIX: si el controller no existe todavía, NO crashear el server.
========================= */
const uploadMyAttachmentsHandler =
  (Users as any).uploadMyAttachments ??
  ((req, res) => {
    return res.status(501).json({
      message:
        "uploadMyAttachments no está implementado/exportado en users.controller.ts. Implementalo o cambiá la ruta.",
    });
  });

router.put("/me/attachments", uploadUserAttachments, uploadMyAttachmentsHandler);

/* =========================================================
   ✅ RUTAS VIEW (USERS_ROLES:VIEW)
   - Lectura y descargas (como Empresa)
========================================================= */

// ✅ Listado (si tu UI permite USERS_ROLES:VIEW, el backend debe acompañar)
router.get("/", requireUsersView, Users.listUsers);

// ✅ Ver detalle
router.get("/:id", requireUsersView, Users.getUser);

// ✅ Descargar adjunto (VIEW, no ADMIN)
router.get("/:id/attachments/:attachmentId/download", requireUsersView, Users.downloadUserAttachment);

/* =========================================================
   ✅ RUTAS ADMIN (USERS_ROLES:ADMIN)
   - Todo lo que modifica
========================================================= */

/* =========================
   FAVORITE WAREHOUSE (ADMIN)
========================= */
router.patch("/:id/favorite-warehouse", requireUsersAdmin, Users.updateUserFavoriteWarehouse);

/* =========================
   CLAVE RÁPIDA (PIN) (ADMIN)
========================= */
router.put("/:id/quick-pin", requireUsersAdmin, Users.updateUserQuickPin);
router.delete("/:id/quick-pin", requireUsersAdmin, Users.removeUserQuickPin);
router.patch("/:id/quick-pin/enabled", requireUsersAdmin, Users.updateUserQuickPinEnabled);

/* =========================
   AVATAR (ADMIN)
========================= */
router.put("/:id/avatar", requireUsersAdmin, uploadAvatar.single("avatar"), Users.updateUserAvatarForUser);
router.delete("/:id/avatar", requireUsersAdmin, Users.removeUserAvatarForUser);

/* =========================
   USER ATTACHMENTS (ADMIN)
========================= */
router.put("/:id/attachments", requireUsersAdmin, uploadUserAttachments, Users.uploadUserAttachments);
router.delete("/:id/attachments/:attachmentId", requireUsersAdmin, Users.deleteUserAttachment);

/* =========================
   USERS CRUD / ADMIN
========================= */
router.post("/", requireUsersAdmin, Users.createUser);

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
