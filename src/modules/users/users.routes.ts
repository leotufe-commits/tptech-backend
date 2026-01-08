// tptech-backend/src/modules/users/users.routes.ts
import { Router } from "express";
import { requireAuth } from "../../middlewares/requireAuth.js";
import { requirePermission } from "../../middlewares/requirePermission.js";
import { validateBody } from "../../middlewares/validate.js";

import updateUserStatusSchema, {
  assignRolesSchema,
  userOverrideSchema,
  createUserSchema,
} from "./users.schemas.js";

import * as Users from "../../controllers/users.controller.js";

const router = Router();

// =========================
// Base: /users
// =========================
router.use(requireAuth);

/**
 * POST /users
 * Crear usuario (requiere ADMIN)
 */
router.post(
  "/",
  requirePermission("USERS_ROLES", "ADMIN"),
  validateBody(createUserSchema),
  Users.createUser
);

/**
 * GET /users
 * Listado liviano (sin overrides)
 */
router.get("/", requirePermission("USERS_ROLES", "VIEW"), Users.listUsers);

/**
 * GET /users/:id
 * Detalle del usuario (incluye overrides)
 */
router.get("/:id", requirePermission("USERS_ROLES", "ADMIN"), Users.getUser);

/**
 * PATCH /users/:id/status
 * Activar / Bloquear usuario
 */
router.patch(
  "/:id/status",
  requirePermission("USERS_ROLES", "EDIT"),
  validateBody(updateUserStatusSchema),
  Users.updateUserStatus
);

/**
 * PUT /users/:id/roles
 * Asignar roles al usuario
 */
router.put(
  "/:id/roles",
  requirePermission("USERS_ROLES", "ADMIN"),
  validateBody(assignRolesSchema),
  Users.assignRolesToUser
);

/**
 * POST /users/:id/overrides
 * Setear override (ALLOW / DENY)
 */
router.post(
  "/:id/overrides",
  requirePermission("USERS_ROLES", "ADMIN"),
  validateBody(userOverrideSchema),
  Users.setUserOverride
);

/**
 * DELETE /users/:id/overrides/:permissionId
 * Eliminar override
 */
router.delete(
  "/:id/overrides/:permissionId",
  requirePermission("USERS_ROLES", "ADMIN"),
  Users.removeUserOverride
);

export default router;
