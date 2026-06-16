// tptech-backend/src/modules/company/company.routes.ts
import { Router } from "express";
import { requirePermission } from "../../middlewares/requirePermission.js";
import { uploadJewelryFiles } from "../../middlewares/uploadJewelryFiles.js";

import {
  getMyJewelryProfile,
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
const requireCompanyEdit = requirePermission("COMPANY_SETTINGS", "EDIT");

/* =========================
   PERFIL (DATOS)
========================= */
// GET: accesible a cualquier usuario autenticado (requireAuth ya está en el router padre)
// PATCH: requiere permiso de edición
router.get("/me", getMyJewelryProfile);
router.patch("/me", requireCompanyEdit, updateMyJewelry);

/* =========================
   LOGO
========================= */
router.post("/me/logo", requireCompanyEdit, ...uploadJewelryFiles, uploadMyJewelryLogo);
router.delete("/me/logo", requireCompanyEdit, deleteMyJewelryLogo);

/* =========================
   ATTACHMENTS
========================= */

// Rutas canónicas (me/attachments). El frontend (usePerfilJoyeria.ts) usa
// SOLO estas variantes `/me/*`. Las antiguas alias sin `/me`
// (`PUT /logo`, `PUT|POST /attachments`, `DELETE /attachments/:id`) se
// eliminaron por estar sin consumidores — ver auditoría Configuración rápida.
router.post(
  "/me/attachments",
  requireCompanyEdit,
  ...uploadJewelryFiles,
  uploadMyJewelryAttachments
);

router.delete("/me/attachments/:id", requireCompanyEdit, deleteMyJewelryAttachment);

export default router;