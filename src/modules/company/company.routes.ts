// tptech-backend/src/modules/company/company.routes.ts
import { Router } from "express";
import { requirePermission } from "../../middlewares/requirePermission.js";
import { uploadJewelryFiles } from "../../middlewares/uploadJewelryFiles.js";

import {
  updateMyJewelry,
  uploadMyJewelryLogo,
  uploadMyJewelryAttachments,
  deleteMyJewelryLogo,
  deleteMyJewelryAttachment,
} from "./company.controller.js";

const router = Router();

/* =========================
   PERMISOS
========================= */
const requireCompanyView = requirePermission("COMPANY_SETTINGS", "VIEW");
const requireCompanyEdit = requirePermission("COMPANY_SETTINGS", "EDIT");

/* =========================
   PERFIL (DATOS)
========================= */
router.patch("/me", requireCompanyEdit, updateMyJewelry);

/* =========================
   LOGO
========================= */
router.post("/me/logo", requireCompanyEdit, ...uploadJewelryFiles, uploadMyJewelryLogo);
router.delete("/me/logo", requireCompanyEdit, deleteMyJewelryLogo);

/**
 * ✅ ALIAS para frontend viejo/otro hook:
 * (si tu hook usa /company/logo con PUT/DELETE)
 */
router.put("/logo", requireCompanyEdit, ...uploadJewelryFiles, uploadMyJewelryLogo);
router.delete("/logo", requireCompanyEdit, deleteMyJewelryLogo);

/* =========================
   ATTACHMENTS
========================= */

/**
 * ✅ RUTAS “OFICIALES” actuales del backend (me/attachments)
 */
router.post(
  "/me/attachments",
  requireCompanyEdit,
  ...uploadJewelryFiles,
  uploadMyJewelryAttachments
);

router.delete("/me/attachments/:id", requireCompanyEdit, deleteMyJewelryAttachment);

/**
 * ✅ ALIAS para tu FRONTEND actual (usePerfilJoyeria.ts):
 *   PUT /company/attachments
 *   DELETE /company/attachments/:id
 */
router.put(
  "/attachments",
  requireCompanyEdit,
  ...uploadJewelryFiles,
  uploadMyJewelryAttachments
);

router.post(
  "/attachments",
  requireCompanyEdit,
  ...uploadJewelryFiles,
  uploadMyJewelryAttachments
);

router.delete("/attachments/:id", requireCompanyEdit, deleteMyJewelryAttachment);

export default router;