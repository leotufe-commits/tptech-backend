// tptech-backend/src/routes/roles.routes.ts
import { Router } from "express";
import { validateBody } from "../middlewares/validate.js";
import { requirePermission } from "../middlewares/requirePermission.js";

import {
  listRoles,
  getRole,
  createRole,
  updateRole,
  updateRolePermissions,
  deleteRole,
} from "../controllers/roles.controller.js";

import {
  createRoleSchema,
  updateRoleSchema,
  updateRolePermissionsSchema,
} from "../modules/roles/roles.schemas.js";

const router = Router();

/**
 * ✅ requireAuth ya se aplica en src/routes/index.ts
 * ✅ Acá protegemos por permisos:
 * - OWNER bypass automático en requirePermission
 */

// Lista / detalle: normalmente solo ADMIN en sistemas con RBAC
// Si querés que sea visible para más gente, lo ajustamos luego.
router.get("/", requirePermission("USERS_ROLES", "ADMIN"), listRoles);
router.get("/:id", requirePermission("USERS_ROLES", "ADMIN"), getRole);

// CRUD: SIEMPRE ADMIN
router.post("/", requirePermission("USERS_ROLES", "ADMIN"), validateBody(createRoleSchema), createRole);
router.patch("/:id", requirePermission("USERS_ROLES", "ADMIN"), validateBody(updateRoleSchema), updateRole);

router.patch(
  "/:id/permissions",
  requirePermission("USERS_ROLES", "ADMIN"),
  validateBody(updateRolePermissionsSchema),
  updateRolePermissions
);

router.delete("/:id", requirePermission("USERS_ROLES", "ADMIN"), deleteRole);

export default router;
