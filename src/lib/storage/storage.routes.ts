// tptech-backend/src/lib/storage/storage.routes.ts
import { Router } from "express";
import { requireAuth } from "../../middlewares/requireAuth.js";
import signUpload from "../../controllers/storage.controller.js";

const router = Router();

router.post("/sign-upload", requireAuth, signUpload);

export default router;
