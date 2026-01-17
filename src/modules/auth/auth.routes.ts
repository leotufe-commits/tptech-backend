// tptech-backend/src/modules/auth/auth.routes.ts
import { Router, type Request, type Response, type NextFunction } from "express";

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

  // ✅ NUEVO (PIN)
  pinSetSchema,
  pinDisableSchema,
  pinUnlockSchema,
  pinSwitchSchema,
} from "./auth.schemas.js";

import { uploadJewelryFiles } from "../../middlewares/uploadJewelryFiles.js";
import { parseJsonBodyField } from "../../middlewares/parseJsonBodyField.js";

const router = Router();

/**
 * Wrapper para capturar errores de multer y responder JSON
 */
function withMulter(
  mw: (req: Request, res: Response, cb: (err?: any) => void) => void
) {
  return (req: Request, res: Response, next: NextFunction) => {
    mw(req, res, (err?: any) => {
      if (!err) return next();

      const msg =
        err?.message ||
        (err?.code === "LIMIT_FILE_SIZE"
          ? "Archivo demasiado grande."
          : "Error subiendo archivos.");

      return res.status(400).json({ message: msg });
    });
  };
}

/* ===========================
   ROUTES
=========================== */

// sesión
router.post("/logout", requireAuth, Auth.logout);
router.get("/me", requireAuth, Auth.me);

// jewelry profile (JSON + multipart)
router.put(
  "/me/jewelry",
  requireAuth,
  withMulter(uploadJewelryFiles as any),
  parseJsonBodyField("data"),
  validateBody(updateJewelrySchema),
  Auth.updateMyJewelry
);

router.delete("/me/jewelry/logo", requireAuth, Auth.deleteMyJewelryLogo);
router.delete("/me/jewelry/attachments/:id", requireAuth, Auth.deleteMyJewelryAttachment);

// auth público
router.post("/register", validateBody(registerSchema), Auth.register);
router.post("/login", authLoginLimiter, validateBody(loginSchema), Auth.login);
router.post("/forgot-password", authForgotLimiter, validateBody(forgotSchema), Auth.forgotPassword);
router.post("/reset-password", authResetLimiter, validateBody(resetSchema), Auth.resetPassword);

/* ===========================
   ✅ PIN (solo dentro del sistema)
=========================== */

// configurar/cambiar PIN (usuario actual)
router.post("/me/pin/set", requireAuth, validateBody(pinSetSchema), Auth.setMyPin);

// desactivar PIN (requiere PIN actual)
router.post("/me/pin/disable", requireAuth, validateBody(pinDisableSchema), Auth.disableMyPin);

// desbloquear pantalla (validación PIN del usuario actual)
router.post("/me/pin/unlock", requireAuth, validateBody(pinUnlockSchema), Auth.unlockWithPin);

// lista de usuarios para quick switch (si la joyería lo habilita)
router.get("/me/pin/quick-users", requireAuth, Auth.quickUsers);

// cambiar de usuario rápido (si la joyería lo habilita)
router.post("/me/pin/switch", requireAuth, validateBody(pinSwitchSchema), Auth.switchUserWithPin);

export default router;
