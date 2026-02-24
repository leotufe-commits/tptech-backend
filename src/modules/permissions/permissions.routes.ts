// tptech-backend/src/modules/permissions/permissions.routes.ts
import { Router } from "express";
import { requirePermission } from "../../middlewares/requirePermission.js";
import { listPermissions } from "./permissions.controller.js";

/**
 * requireAuth ya se aplica en routes/index.ts
 */
export const router = Router();

router.get("/", requirePermission("USERS_ROLES", "ADMIN"), listPermissions);

export default router;