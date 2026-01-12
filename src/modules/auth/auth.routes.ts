// tptech-backend/src/modules/auth/auth.routes.ts
import { Router } from "express";

import { requireAuth } from "../../middlewares/requireAuth.js";
import { validateBody } from "../../middlewares/validate.js";
import {
  authLoginLimiter,
  authForgotLimiter,
  authResetLimiter,
} from "../../config/rateLimit.js";

import * as Auth from "../../controllers/auth.controller.js";
import {
  registerSchema,
  loginSchema,
  forgotSchema,
  resetSchema,
  updateJewelrySchema,
} from "./auth.schemas.js";

import { uploadJewelryFiles } from "../../middlewares/uploadJewelryFiles.js";
import { parseJsonBodyField } from "../../middlewares/parseJsonBodyField.js";

const router = Router();

/**
 * Wrapper para capturar errores de multer y responder JSON
 */
function withMulter(mw: any) {
  return (req: any, res: any, next: any) => {
    mw(req, res, (err: any) => {
      if (!err) return next();

      // MulterError o Error normal
      const msg =
        err?.message ||
        (err?.code === "LIMIT_FILE_SIZE" ? "Archivo demasiado grande." : "Error subiendo archivos.");

      return res.status(400).json({ message: msg });
    });
  };
}

/* ===========================
   ROUTES
=========================== */

router.post("/logout", requireAuth, Auth.logout);

router.get("/me", requireAuth, Auth.me);

/**
 * ✅ Soporta:
 * - JSON
 * - multipart/form-data con:
 *    - data: JSON string
 *    - logo: File
 *    - attachments: File[]
 */
router.put(
  "/me/jewelry",
  requireAuth,
  withMulter(uploadJewelryFiles),
  parseJsonBodyField("data"),
  validateBody(updateJewelrySchema),
  Auth.updateMyJewelry
);

router.delete("/me/jewelry/logo", requireAuth, Auth.deleteMyJewelryLogo);

router.delete("/me/jewelry/attachments/:id", requireAuth, Auth.deleteMyJewelryAttachment);

router.post("/register", validateBody(registerSchema), Auth.register);
router.post("/login", authLoginLimiter, validateBody(loginSchema), Auth.login);

router.post("/forgot-password", authForgotLimiter, validateBody(forgotSchema), Auth.forgotPassword);
router.post("/reset-password", authResetLimiter, validateBody(resetSchema), Auth.resetPassword);

export default router;
