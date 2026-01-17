// tptech-backend/src/routes/roles.routes.ts
import { Router } from "express";
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

/**
 * ✅ NOTA IMPORTANTE
 * En src/routes/index.ts ya estás aplicando:
 *   privateRouter.use(requireAuth)
 * Por eso acá NO se vuelve a aplicar requireAuth.
 */

/**
 * GET /roles
 */
router.get("/", listRoles);

/**
 * GET /roles/:id
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
router.patch("/:id/permissions", validateBody(updateRolePermissionsSchema), updateRolePermissions);

/**
 * DELETE /roles/:id
 */
router.delete("/:id", deleteRole);

export default router;
