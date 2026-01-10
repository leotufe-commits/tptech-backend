import { Router } from "express";
import { requireAuth } from "../middlewares/requireAuth.js";
import { requirePermission } from "../middlewares/requirePermission.js";
import { listPermissions } from "../controllers/permissions.controller.js";

const router = Router();

router.use(requireAuth);

router.get(
  "/",
  requirePermission("USERS_ROLES", "ADMIN"),
  listPermissions
);

export default router;
