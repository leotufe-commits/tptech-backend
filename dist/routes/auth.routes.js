import { Router } from "express";
import { z } from "zod";
import { requireAuth } from "../middlewares/requireAuth.js";
import { validateBody } from "../middlewares/validate.js";
import { authLoginLimiter, authForgotLimiter, authResetLimiter, } from "../middlewares/rateLimit.js";
import * as Auth from "../controllers/auth.controller.js";
const router = Router();
/* ===========================
   SCHEMAS
=========================== */
const registerSchema = z.object({
    email: z.string().email(),
    password: z.string().min(6),
    jewelryName: z.string().min(1),
    firstName: z.string().min(1),
    lastName: z.string().min(1),
    phoneCountry: z.string().min(1),
    phoneNumber: z.string().min(1),
    street: z.string().min(1),
    number: z.string().min(1),
    city: z.string().min(1),
    province: z.string().min(1),
    postalCode: z.string().min(1),
    country: z.string().min(1),
});
const loginSchema = z.object({
    email: z.string().email(),
    password: z.string().min(1),
});
const forgotSchema = z.object({
    email: z.string().email(),
});
const resetSchema = z.object({
    token: z.string().min(10),
    newPassword: z.string().min(6),
});
const updateJewelrySchema = z.object({
    name: z.string().min(1),
    firstName: z.string().min(1),
    lastName: z.string().min(1),
    phoneCountry: z.string().min(1),
    phoneNumber: z.string().min(1),
    street: z.string().min(1),
    number: z.string().min(1),
    city: z.string().min(1),
    province: z.string().min(1),
    postalCode: z.string().min(1),
    country: z.string().min(1),
});
/* ===========================
   ROUTES
=========================== */
router.get("/me", requireAuth, Auth.me);
router.put("/me/jewelry", requireAuth, validateBody(updateJewelrySchema), Auth.updateMyJewelry);
router.post("/register", validateBody(registerSchema), Auth.register);
router.post("/login", authLoginLimiter, validateBody(loginSchema), Auth.login);
router.post("/forgot-password", authForgotLimiter, validateBody(forgotSchema), Auth.forgotPassword);
router.post("/reset-password", authResetLimiter, validateBody(resetSchema), Auth.resetPassword);
export default router;
//# sourceMappingURL=auth.routes.js.map