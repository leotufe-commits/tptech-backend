import { Router } from "express";
import { requireAuth } from "../middlewares/requireAuth.js";
import * as Permissions from "../controllers/permissions.controller.js";

const router = Router();

// base: /permissions
router.get("/", requireAuth, Permissions.listPermissions);

export default router;
