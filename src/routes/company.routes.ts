// tptech-backend/src/routes/company.routes.ts
import { Router } from "express";
import { requireAnyPermission } from "../middlewares/requirePermission.js";
import { getSecuritySettings, updateSecuritySettings } from "../controllers/company.controller.js";

const router = Router();

router.get(
  "/settings/security",
  requireAnyPermission([
    "COMPANY_SETTINGS:VIEW",
    "COMPANY_SETTINGS:EDIT",
    "COMPANY_SETTINGS:ADMIN",
  ]),
  getSecuritySettings
);

router.patch(
  "/settings/security",
  requireAnyPermission(["COMPANY_SETTINGS:EDIT", "COMPANY_SETTINGS:ADMIN"]),
  updateSecuritySettings
);

export default router;
