// tptech-backend/src/modules/users/users.routes.ts
import { Router } from "express";
import multer from "multer";
import path from "node:path";
import crypto from "node:crypto";

import { requireAuth } from "../../middlewares/requireAuth.js";
import * as Users from "../../controllers/users.controller.js";

const router = Router();

// ✅ protegemos todo el módulo
router.use(requireAuth);

/* =========================
   Multer storage
   - Guarda en: uploads/avatars
   - Nombre único para evitar cache y colisiones
========================= */
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => {
    cb(null, "uploads/avatars");
  },
  filename: (req, file, cb) => {
    const userId = req.userId || "user";
    const ext = path.extname(file.originalname || "") || "";
    const name = `avatar_${userId}_${Date.now()}_${crypto.randomBytes(4).toString("hex")}${ext}`;
    cb(null, name);
  },
});

function fileFilter(_req: any, file: Express.Multer.File, cb: multer.FileFilterCallback) {
  if (!file.mimetype?.startsWith("image/")) {
    return cb(new Error("El archivo debe ser una imagen"));
  }
  cb(null, true);
}

const upload = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB
  },
});

/* =========================
   USERS CRUD / ADMIN
========================= */
router.post("/", Users.createUser);
router.get("/", Users.listUsers);
router.get("/:id", Users.getUser);

router.patch("/:id/status", Users.updateUserStatus);
router.put("/:id/roles", Users.assignRolesToUser);

router.post("/:id/overrides", Users.setUserOverride);
router.delete("/:id/overrides/:permissionId", Users.removeUserOverride);

/* =========================
   AVATAR (ME)
========================= */
router.put("/me/avatar", upload.single("avatar"), Users.updateMyAvatar);
router.delete("/me/avatar", Users.removeMyAvatar);

export default router;
