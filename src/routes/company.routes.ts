import { Router } from "express";
import { requireAnyPermission } from "../middlewares/requirePermission.js";
import { getSecuritySettings, updateSecuritySettings } from "../controllers/company.controller.js";
import {
  listCatalog,
  createCatalogItem,
  updateCatalogItem,
} from "../controllers/catalogs.controller.js";

const router = Router();

/* =====================
   Security settings
===================== */
router.get(
  "/settings/security",
  requireAnyPermission(["COMPANY_SETTINGS:VIEW", "COMPANY_SETTINGS:EDIT", "COMPANY_SETTINGS:ADMIN"]),
  getSecuritySettings
);

router.patch(
  "/settings/security",
  requireAnyPermission(["COMPANY_SETTINGS:EDIT", "COMPANY_SETTINGS:ADMIN"]),
  updateSecuritySettings
);

/* =====================
   Catalogs (combos)
===================== */
router.get(
  "/catalogs/:type",
  requireAnyPermission(["COMPANY_SETTINGS:VIEW", "COMPANY_SETTINGS:EDIT", "COMPANY_SETTINGS:ADMIN"]),
  listCatalog
);

router.post(
  "/catalogs/:type",
  requireAnyPermission(["COMPANY_SETTINGS:EDIT", "COMPANY_SETTINGS:ADMIN"]),
  createCatalogItem
);

router.patch(
  "/catalogs/item/:id",
  requireAnyPermission(["COMPANY_SETTINGS:EDIT", "COMPANY_SETTINGS:ADMIN"]),
  updateCatalogItem
);

export default router;
