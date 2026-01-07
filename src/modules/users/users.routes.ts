// tptech-backend/src/modules/users/users.routes.ts
import { Router } from "express";
import { requireAuth } from "../../middlewares/requireAuth.js";
import { requirePermission } from "../../middlewares/requirePermission.js";
import { validateBody } from "../../middlewares/validate.js";

import updateUserStatusSchema, {
  assignRolesSchema,
  userOverrideSchema,
} from "./users.schemas.js";

import * as Users from "../../controllers/users.controller.js";

const router = Router();

// ===============================
// base: /users
// ===============================

/**
 * GET /users
 * Lista usuarios del tenant
 */
router.get(
  "/",
  requireAuth,
  requirePermission("USERS_ROLES", "VIEW"),
  Users.listUsers
);

/**
 * PATCH /users/:id/status
 */
router.patch(
  "/:id/status",
  requireAuth,
  requirePermission("USERS_ROLES", "EDIT"),
  validateBody(updateUserStatusSchema),
  Users.updateUserStatus
);

/**
 * PUT /users/:id/roles
 */
router.put(
  "/:id/roles",
  requireAuth,
  requirePermission("USERS_ROLES", "ADMIN"),
  validateBody(assignRolesSchema),
  Users.assignRolesToUser
);

/**
 * POST /users/:id/overrides
 */
router.post(
  "/:id/overrides",
  requireAuth,
  requirePermission("USERS_ROLES", "ADMIN"),
  validateBody(userOverrideSchema),
  Users.setUserOverride
);

/**
 * DELETE /users/:id/overrides/:permissionId
 */
router.delete(
  "/:id/overrides/:permissionId",
  requireAuth,
  requirePermission("USERS_ROLES", "ADMIN"),
  Users.removeUserOverride
);

export default router;
