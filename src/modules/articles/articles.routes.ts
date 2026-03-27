import { Router } from "express";
import multer from "multer";
import { asyncHandler } from "../../middlewares/asyncHandlers.js";
import * as controller from "./articles.controller.js";
import { uploadArticleImageMiddleware } from "../../middlewares/uploadArticleImage.js";

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

// Barcode lookup (debe ir antes de /:id para no colisionar)
router.get("/lookup", asyncHandler(controller.lookupByBarcode));

// Brands list (antes de /:id para no colisionar)
router.get("/brands", asyncHandler(controller.listBrands));

// Sale price resolution (antes de /:id para no colisionar)
router.get("/:id/sale-price", asyncHandler(controller.getSalePrice));

// Import
router.get("/import/template", asyncHandler(controller.getImportTemplate));
router.post("/import/preview",  uploadImport, asyncHandler(controller.previewImport));
router.post("/import/execute",  uploadImport, asyncHandler(controller.executeImport));

// Article CRUD
router.get("/", asyncHandler(controller.list));
router.get("/:id", asyncHandler(controller.getOne));
router.post("/", asyncHandler(controller.create));
router.put("/:id", asyncHandler(controller.update));
router.patch("/:id/toggle", asyncHandler(controller.toggle));
router.patch("/:id/favorite", asyncHandler(controller.favorite));
router.delete("/:id", asyncHandler(controller.remove));

// Cost lines (nueva composición de costo por líneas)
router.put("/:id/cost-lines", asyncHandler(controller.setCostLines));

// Compositions (metal)
router.get("/:id/compositions", asyncHandler(controller.listCompositions));
router.put("/:id/compositions", asyncHandler(controller.upsertComposition));
router.delete("/:id/compositions/:compositionId", asyncHandler(controller.removeComposition));

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
router.get("/:id/stock/material-availability", asyncHandler(controller.getMaterialAvailability));

export default router;
