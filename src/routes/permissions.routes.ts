// tptech-backend/src/routes/permissions.routes.ts
import { Router } from "express";
import { requirePermission } from "../middlewares/requirePermission.js";
import { listPermissions } from "../controllers/permissions.controller.js";

const router = Router();

/**
 * NOTA:
 * requireAuth ya se aplica en src/routes/index.ts (privateRouter.use(requireAuth)).
 */

router.get("/", requirePermission("USERS_ROLES", "ADMIN"), listPermissions);

export default router;
