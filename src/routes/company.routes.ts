// src/modules/company/company.routes.ts
import { Router } from "express";
import { requireAnyPermission } from "../../middlewares/requirePermission.js";
import {
  getSecuritySettings,
  updateSecuritySettings,
  listCatalog,
  createCatalogItem,
} from "./company.controller.js";

const router = Router();

router.get(
  "/settings/security",
  requireAnyPermission(["COMPANY_SETTINGS:VIEW"]),
  getSecuritySettings
);

router.patch(
  "/settings/security",
  requireAnyPermission(["COMPANY_SETTINGS:EDIT"]),
  updateSecuritySettings
);

router.get(
  "/catalogs/:type",
  requireAnyPermission(["COMPANY_SETTINGS:VIEW"]),
  listCatalog
);

router.post(
  "/catalogs/:type",
  requireAnyPermission(["COMPANY_SETTINGS:EDIT"]),
  createCatalogItem
);

export default router;