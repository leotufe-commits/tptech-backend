// src/routes/roles.routes.ts
import { Router } from "express";
import { requireAuth } from "../middlewares/requireAuth.js";
import { validateBody } from "../middlewares/validate.js";
import * as Roles from "../controllers/roles.controller.js";
import {
  createRoleSchema,
  updateRoleSchema,
  updateRolePermissionsSchema,
} from "../modules/roles/roles.schemas.js";

const router = Router();

// secure-by-default
router.use(requireAuth);

/**
 * GET /roles
 * Lista roles del tenant
 */
router.get("/", Roles.listRoles);

/**
 * POST /roles
 * Crear rol custom
 */
router.post("/", validateBody(createRoleSchema), Roles.createRole);

/**
 * PATCH /roles/:id
 * Renombrar rol
 */
router.patch("/:id", validateBody(updateRoleSchema), Roles.updateRole);

/**
 * PATCH /roles/:id/permissions
 * Reemplaza permisos del rol
 */
router.patch(
  "/:id/permissions",
  validateBody(updateRolePermissionsSchema),
  Roles.updateRolePermissions
);

/**
 * DELETE /roles/:id
 * Elimina rol si no tiene usuarios asignados
 */
router.delete("/:id", Roles.deleteRole);

export default router;
