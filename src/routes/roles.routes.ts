import { Router } from "express";
import { requireAuth } from "../middlewares/requireAuth.js";
import { validateBody } from "../middlewares/validate.js";

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

// todo roles es privado
router.use(requireAuth);

/**
 * GET /roles
 */
router.get("/", listRoles);

/**
 * GET /roles/:id   ✅ ESTA ES LA QUE TE FALTA (por eso te tira Cannot GET)
 */
router.get("/:id", getRole);

/**
 * POST /roles
 */
router.post("/", validateBody(createRoleSchema), createRole);

/**
 * PATCH /roles/:id
 */
router.patch("/:id", validateBody(updateRoleSchema), updateRole);

/**
 * PATCH /roles/:id/permissions
 */
router.patch(
  "/:id/permissions",
  validateBody(updateRolePermissionsSchema),
  updateRolePermissions
);

/**
 * DELETE /roles/:id
 */
router.delete("/:id", deleteRole);

export default router;
