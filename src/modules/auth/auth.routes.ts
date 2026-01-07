// src/modules/auth/auth.routes.ts
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

const router = Router();

/* ===========================
   ROUTES
=========================== */

// ✅ logout (evita 404 y queda protegido)
router.post("/logout", requireAuth, Auth.logout);

router.get("/me", requireAuth, Auth.me);

router.put(
  "/me/jewelry",
  requireAuth,
  validateBody(updateJewelrySchema),
  Auth.updateMyJewelry
);

router.post("/register", validateBody(registerSchema), Auth.register);

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

export default router;
