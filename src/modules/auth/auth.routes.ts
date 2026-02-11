import { Router, type Request, type Response, type NextFunction } from "express";
import { requireAuth } from "../../middlewares/requireAuth.js";
import { validateBody } from "../../middlewares/validate.js";
import { authLoginLimiter, authForgotLimiter, authResetLimiter } from "../../config/rateLimit.js";

import * as Auth from "../../controllers/auth.base.controller.js";
import * as Pin from "../../controllers/auth.pin.controller.js";
import * as CompanyMe from "../../controllers/company.me.controller.js";

import {
  registerSchema,
  loginSchema,
  loginOptionsSchema,
  forgotSchema,
  resetSchema,
  updateJewelrySchema,
  pinSetSchema,
  pinDisableSchema,
  pinUnlockSchema,
  pinSwitchSchema,
  pinLockSettingsSchema,
} from "./auth.schemas.js";

import { uploadJewelryFiles } from "../../middlewares/uploadJewelryFiles.js";
import { parseJsonBodyField } from "../../middlewares/parseJsonBodyField.js";

const router = Router();

/**
 * ✅ Si un middleware/handler viene undefined (export roto),
 * Express crashea con "argument handler must be a function".
 * Esto lo evita y deja el server arrancar.
 */
function safeMw(mw: any) {
  if (typeof mw === "function") return mw;
  return (_req: Request, _res: Response, next: NextFunction) => next();
}

/**
 * Wrapper para capturar errores de Multer
 * y responder siempre JSON limpio
 */
function withMulter(mw: (req: Request, res: Response, cb: (err?: any) => void) => void) {
  return (req: Request, res: Response, next: NextFunction) => {
    mw(req, res, (err?: any) => {
      if (!err) return next();

      const msg =
        err?.message ||
        (err?.code === "LIMIT_FILE_SIZE" ? "Archivo demasiado grande." : "Error subiendo archivos.");

      return res.status(400).json({ message: msg });
    });
  };
}

/* =========================
   SESIÓN / PERFIL
========================= */

// sesión
router.post("/logout", safeMw((Auth as any).logout));

// me
router.get("/me", requireAuth, safeMw((Auth as any).me));

// joyería (perfil empresa)
router.put(
  "/me/jewelry",
  requireAuth,
  withMulter(uploadJewelryFiles as any),
  parseJsonBodyField("data"),
  validateBody(updateJewelrySchema),
  safeMw((CompanyMe as any).updateMyJewelry ?? (Auth as any).updateMyJewelry)
);

router.put(
  "/me/jewelry/logo",
  requireAuth,
  withMulter(uploadJewelryFiles as any),
  safeMw((CompanyMe as any).uploadMyJewelryLogo ?? (Auth as any).uploadMyJewelryLogo)
);

router.delete(
  "/me/jewelry/logo",
  requireAuth,
  safeMw((CompanyMe as any).deleteMyJewelryLogo ?? (Auth as any).deleteMyJewelryLogo)
);

router.delete(
  "/me/jewelry/attachments/:id",
  requireAuth,
  safeMw((CompanyMe as any).deleteMyJewelryAttachment ?? (Auth as any).deleteMyJewelryAttachment)
);

/* =========================
   AUTH PÚBLICO
========================= */

router.post("/register", validateBody(registerSchema), safeMw((Auth as any).register));
router.post("/login/options", validateBody(loginOptionsSchema), safeMw((Auth as any).loginOptions));

router.post(
  "/login",
  safeMw(authLoginLimiter),
  validateBody(loginSchema),
  safeMw((Auth as any).login)
);

router.post(
  "/forgot-password",
  safeMw(authForgotLimiter),
  validateBody(forgotSchema),
  safeMw((Auth as any).forgotPassword)
);

router.post(
  "/reset-password",
  safeMw(authResetLimiter),
  validateBody(resetSchema),
  safeMw((Auth as any).resetPassword)
);

/* =========================
   🔐 PIN / LOCK / QUICK SWITCH
========================= */

router.post("/me/pin/set", requireAuth, validateBody(pinSetSchema), safeMw((Pin as any).setMyPin));
router.post(
  "/me/pin/disable",
  requireAuth,
  validateBody(pinDisableSchema),
  safeMw((Pin as any).disableMyPin)
);
router.post(
  "/me/pin/unlock",
  requireAuth,
  validateBody(pinUnlockSchema),
  safeMw((Pin as any).unlockWithPin)
);

router.get("/me/pin/quick-users", requireAuth, safeMw((Pin as any).quickUsers));
router.post(
  "/me/pin/switch",
  requireAuth,
  validateBody(pinSwitchSchema),
  safeMw((Pin as any).switchUserWithPin)
);

router.patch(
  "/company/security/pin-lock",
  requireAuth,
  validateBody(pinLockSettingsSchema),
  safeMw((Pin as any).setPinLockSettingsForJewelry)
);

// legacy
router.post("/me/jewelry/quick-switch", requireAuth, safeMw((Pin as any).setQuickSwitchForJewelry));

export default router;
