import { Router } from "express";
import multer from "multer";
import { asyncHandler } from "../../middlewares/asyncHandlers.js";
import { validateBody } from "../../middlewares/validate.js";
import * as controller from "./articles.controller.js";
import { uploadArticleImageMiddleware } from "../../middlewares/uploadArticleImage.js";
import { createArticleSchema, updateArticleSchema } from "./articles.schemas.js";

const router = Router();
const uploadImport = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
  fileFilter: (_req, file, cb) => {
    const ok = file.mimetype.includes("spreadsheet")
      || file.mimetype.includes("excel")
      || file.mimetype === "text/csv"
      || file.originalname.endsWith(".xlsx")
      || file.originalname.endsWith(".xls")
      || file.originalname.endsWith(".csv");
    cb(null, ok ? true : (new Error("Solo se aceptan archivos Excel (.xlsx) o CSV.") as any));
  },
}).single("file");

// Tree search (debe ir antes de /:id para no colisionar)
router.get("/tree", asyncHandler(controller.searchTree));

// Barcode lookup (debe ir antes de /:id para no colisionar)
router.get("/lookup", asyncHandler(controller.lookupByBarcode));

// Brands list (antes de /:id para no colisionar)
router.get("/brands", asyncHandler(controller.listBrands));

// SKUs list (antes de /:id para no colisionar)
router.get("/skus", asyncHandler(controller.listSkus));

// Sale price resolution (antes de /:id para no colisionar)
router.get("/:id/sale-price",       asyncHandler(controller.getSalePrice));
router.get("/:id/pricing-preview",  asyncHandler(controller.getPricingPreview));

// Import / Export
router.get("/import/template",        asyncHandler(controller.getImportTemplate));
router.get("/import/template/v2",     asyncHandler(controller.getImportTemplateV2));
router.get("/import/template/guided", asyncHandler(controller.getGuidedTemplate));
router.post("/import/preview",        uploadImport, asyncHandler(controller.previewImport));
router.post("/import/execute",        uploadImport, asyncHandler(controller.executeImport));
router.post("/import/preview-json",   asyncHandler(controller.previewImportJson));
router.post("/import/execute-json",   asyncHandler(controller.executeImportJson));
router.get("/export",                 asyncHandler(controller.exportArticlesXlsx));
router.get("/export/v2",              asyncHandler(controller.exportArticlesV2Xlsx));
router.get("/export/guided",          asyncHandler(controller.exportGuidedXlsx));

// Article CRUD
router.get("/", asyncHandler(controller.list));
router.get("/:id", asyncHandler(controller.getOne));
router.post("/", validateBody(createArticleSchema), asyncHandler(controller.create));
router.put("/:id", validateBody(updateArticleSchema), asyncHandler(controller.update));
router.patch("/bulk", asyncHandler(controller.bulkUpdate));         // antes de /:id
router.delete("/bulk", asyncHandler(controller.bulkRemove));        // antes de /:id
router.post("/bulk-hechura", asyncHandler(controller.bulkHechura)); // antes de /:id
router.patch("/:id/group",       asyncHandler(controller.assignGroup));
router.get("/:id/group-state",   asyncHandler(controller.getGroupState));
router.patch("/:id/group-batch", asyncHandler(controller.applyGroupBatch));
router.patch("/:id/toggle", asyncHandler(controller.toggle));
router.patch("/:id/favorite", asyncHandler(controller.favorite));
router.post("/:id/clone", asyncHandler(controller.clone));
router.delete("/:id", asyncHandler(controller.remove));

// Cost lines (nueva composición de costo por líneas)
router.put("/:id/cost-lines", asyncHandler(controller.setCostLines));
// Preview de costo + impuestos de compra sin persistir (pricing-engine).
router.post("/:id/cost-lines/preview", asyncHandler(controller.previewCostLines));

// Variants
router.get("/:id/variants/deleted", asyncHandler(controller.listDeletedVariants));
router.get("/:id/variants", asyncHandler(controller.listVariants));
router.post("/:id/variants", asyncHandler(controller.createVariant));
router.patch("/:id/variants/reorder", asyncHandler(controller.reorderVariants));
router.put("/:id/variants/:variantId", asyncHandler(controller.updateVariant));
router.patch("/:id/variants/:variantId/toggle", asyncHandler(controller.toggleVariant));
router.delete("/:id/variants/:variantId", asyncHandler(controller.removeVariant));
router.post("/:id/variants/:variantId/restore", asyncHandler(controller.restoreVariant));

// Attribute values
router.put("/:id/attributes", asyncHandler(controller.setAttributeValues));

// Variant attribute values
router.get("/:id/variants/:variantId/attribute-values", asyncHandler(controller.getVariantAttributeValues));
router.put("/:id/variants/:variantId/attribute-values", asyncHandler(controller.setVariantAttributeValues));

// Variant image — upload single (legacy, mantiene imageUrl denormalizado)
router.post("/:id/variants/:variantId/image", ...uploadArticleImageMiddleware, asyncHandler(controller.uploadVariantImage));

// Variant images gallery (CRUD completo)
router.post("/:id/variants/:variantId/images", ...uploadArticleImageMiddleware, asyncHandler(controller.addVariantImage));
router.patch("/:id/variants/:variantId/images/:imageId/set-main", asyncHandler(controller.setVariantMainImage));
router.delete("/:id/variants/:variantId/images/:imageId", asyncHandler(controller.removeVariantImage));

// Images
router.post("/:id/images", ...uploadArticleImageMiddleware, asyncHandler(controller.addImage));
router.patch("/:id/images/:imageId/set-main", asyncHandler(controller.setMainImage));
router.patch("/:id/images/:imageId", asyncHandler(controller.updateImageLabel));
router.delete("/:id/images/:imageId", asyncHandler(controller.removeImage));

// Stock
router.get("/:id/stock", asyncHandler(controller.getStock));
router.put("/:id/stock", asyncHandler(controller.adjustStock));
router.post("/:id/stock/recalc", asyncHandler(controller.recalcStock));
router.get("/:id/stock/material-availability", asyncHandler(controller.getMaterialAvailability));

// Combo comercial
router.get("/:id/combo-availability", asyncHandler(controller.getComboAvailability));

export default router;
