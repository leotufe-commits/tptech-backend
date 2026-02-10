// tptech-backend/src/routes/company.routes.ts
import { Router } from "express";
import { requireAnyPermission } from "../middlewares/requirePermission.js";

import {
  getSecuritySettings,
  updateSecuritySettings,
  uploadCompanyAttachments,
  deleteCompanyAttachment,
  uploadCompanyLogo,
  deleteCompanyLogo,
  downloadCompanyAttachment, // ✅ NUEVO (DESCARGA)
} from "../controllers/company.controller.js";

import { uploadJewelryFiles } from "../middlewares/uploadJewelryFiles.js";

import {
  listCatalog,
  createCatalogItem,
  updateCatalogItem,
  bulkCreateCatalogItems,
  setCatalogItemFavorite,
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
   ✅ Company files (logo + attachments)
===================== */

/**
 * PUT /company/logo
 * multipart field: logo (imagen)
 */
router.put(
  "/logo",
  requireAnyPermission(["COMPANY_SETTINGS:EDIT", "COMPANY_SETTINGS:ADMIN"]),
  uploadJewelryFiles,
  uploadCompanyLogo
);

/**
 * DELETE /company/logo
 * borra el logo (setea logoUrl = "")
 */
router.delete(
  "/logo",
  requireAnyPermission(["COMPANY_SETTINGS:EDIT", "COMPANY_SETTINGS:ADMIN"]),
  deleteCompanyLogo
);

/**
 * PUT /company/attachments
 * multipart field: attachments o attachments[]
 */
router.put(
  "/attachments",
  requireAnyPermission(["COMPANY_SETTINGS:EDIT", "COMPANY_SETTINGS:ADMIN"]),
  uploadJewelryFiles,
  uploadCompanyAttachments
);

/**
 * ✅ GET /company/attachments/:attachmentId/download
 * descarga adjunto (con auth y filename real)
 */
router.get(
  "/attachments/:attachmentId/download",
  requireAnyPermission(["COMPANY_SETTINGS:VIEW", "COMPANY_SETTINGS:EDIT", "COMPANY_SETTINGS:ADMIN"]),
  downloadCompanyAttachment
);

/**
 * DELETE /company/attachments/:attachmentId
 */
router.delete(
  "/attachments/:attachmentId",
  requireAnyPermission(["COMPANY_SETTINGS:EDIT", "COMPANY_SETTINGS:ADMIN"]),
  deleteCompanyAttachment
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

router.post(
  "/catalogs/:type/bulk",
  requireAnyPermission(["COMPANY_SETTINGS:EDIT", "COMPANY_SETTINGS:ADMIN"]),
  bulkCreateCatalogItems
);

router.patch(
  "/catalogs/item/:id",
  requireAnyPermission(["COMPANY_SETTINGS:EDIT", "COMPANY_SETTINGS:ADMIN"]),
  updateCatalogItem
);

router.patch(
  "/catalogs/item/:id/favorite",
  requireAnyPermission(["COMPANY_SETTINGS:EDIT", "COMPANY_SETTINGS:ADMIN"]),
  setCatalogItemFavorite
);

export default router;
