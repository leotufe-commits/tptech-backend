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
  loginOptionsSchema,
  forgotSchema,
  resetSchema,
  updateJewelrySchema,

  // PIN
  pinSetSchema,
  pinDisableSchema,
  pinUnlockSchema,
  pinSwitchSchema,

  // ✅ PIN LOCK SETTINGS (JOYERÍA)
  pinLockSettingsSchema,
} from "./auth.schemas.js";

import { uploadJewelryFiles } from "../../middlewares/uploadJewelryFiles.js";
import { parseJsonBodyField } from "../../middlewares/parseJsonBodyField.js";

const router = Router();

/**
 * Wrapper para capturar errores de Multer
 * y responder siempre JSON limpio
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

/* =========================
   SESIÓN / PERFIL
========================= */

// sesión
router.post("/logout", requireAuth, Auth.logout);
router.get("/me", requireAuth, Auth.me);

// joyería (perfil empresa)
router.put(
  "/me/jewelry",
  requireAuth,
  withMulter(uploadJewelryFiles as any),
  parseJsonBodyField("data"),
  validateBody(updateJewelrySchema),
  Auth.updateMyJewelry
);

router.delete("/me/jewelry/logo", requireAuth, Auth.deleteMyJewelryLogo);
router.delete(
  "/me/jewelry/attachments/:id",
  requireAuth,
  Auth.deleteMyJewelryAttachment
);

/* =========================
   AUTH PÚBLICO
========================= */

router.post("/register", validateBody(registerSchema), Auth.register);

/**
 * ✅ LOGIN OPTIONS
 * email -> lista de joyerías/tenants para ese email
 * (lo usa el Login.tsx nuevo)
 */
router.post("/login/options", validateBody(loginOptionsSchema), Auth.loginOptions);

router.post("/login", authLoginLimiter, validateBody(loginSchema), Auth.login);

router.post(
  "/forgot-password",
  authForgotLimiter,
  validateBody(forgotSchema),
  Auth.forgotPassword
);

router.post(
  "/reset-password",
  authResetLimiter,
  validateBody(resetSchema),
  Auth.resetPassword
);

/* =========================
   🔐 PIN / LOCK / QUICK SWITCH
   (solo dentro del sistema)
========================= */

// crear / cambiar PIN del usuario actual
router.post("/me/pin/set", requireAuth, validateBody(pinSetSchema), Auth.setMyPin);

// desactivar PIN (requiere PIN actual)
router.post(
  "/me/pin/disable",
  requireAuth,
  validateBody(pinDisableSchema),
  Auth.disableMyPin
);

// desbloquear pantalla (PIN del usuario actual)
router.post(
  "/me/pin/unlock",
  requireAuth,
  validateBody(pinUnlockSchema),
  Auth.unlockWithPin
);

// lista de usuarios para quick switch (si la empresa lo permite)
router.get("/me/pin/quick-users", requireAuth, Auth.quickUsers);

// cambiar de usuario rápido (requiere PIN del usuario destino, si la config lo pide)
router.post(
  "/me/pin/switch",
  requireAuth,
  validateBody(pinSwitchSchema),
  Auth.switchUserWithPin
);

/**
 * ✅ SETTINGS DE SEGURIDAD (JOYERÍA)
 * (lo usa AuthContext.tsx: /auth/company/security/pin-lock)
 */
router.patch(
  "/company/security/pin-lock",
  requireAuth,
  validateBody(pinLockSettingsSchema),
  Auth.setPinLockSettingsForJewelry
);

// admin: habilitar/deshabilitar quick switch por joyería (legacy/compat)
router.post("/me/jewelry/quick-switch", requireAuth, Auth.setQuickSwitchForJewelry);

export default router;
