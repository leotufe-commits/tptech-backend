// tptech-backend/src/modules/storage/storage.routes.ts
import { Router } from "express";
import signUpload from "./storage.controller.js";

const router = Router();

/**
 * requireAuth ya se aplica en src/routes/index.ts
 */
router.post("/sign-upload", signUpload);

export default router;