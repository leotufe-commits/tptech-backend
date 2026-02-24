import { Router } from "express";
import { requirePermission } from "../../middlewares/requirePermission.js";
import * as Roles from "./roles.controller.js";

const router = Router();

const requireRolesView = requirePermission("USERS_ROLES", "VIEW");
const requireRolesAdmin = requirePermission("USERS_ROLES", "ADMIN");

// LIST
router.get("/", requireRolesView, Roles.listRoles);

// GET BY ID
router.get("/:id", requireRolesView, Roles.getRoleById);

// CREATE
router.post("/", requireRolesAdmin, Roles.createRole);

// UPDATE NAME
router.patch("/:id", requireRolesAdmin, Roles.updateRole);

// UPDATE PERMISSIONS
router.patch("/:id/permissions", requireRolesAdmin, Roles.updateRolePermissions);

// DELETE
router.delete("/:id", requireRolesAdmin, Roles.deleteRole);

export default router;