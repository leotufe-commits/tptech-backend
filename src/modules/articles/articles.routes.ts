import { Router } from "express";
import { asyncHandler } from "../../middlewares/asyncHandlers.js";
import * as controller from "./articles.controller.js";
import { uploadArticleImageMiddleware } from "../../middlewares/uploadArticleImage.js";

const router = Router();

// Article CRUD
router.get("/", asyncHandler(controller.list));
router.get("/:id", asyncHandler(controller.getOne));
router.post("/", asyncHandler(controller.create));
router.put("/:id", asyncHandler(controller.update));
router.patch("/:id/toggle", asyncHandler(controller.toggle));
router.patch("/:id/favorite", asyncHandler(controller.favorite));
router.delete("/:id", asyncHandler(controller.remove));

// Compositions (metal)
router.get("/:id/compositions", asyncHandler(controller.listCompositions));
router.put("/:id/compositions", asyncHandler(controller.upsertComposition));
router.delete("/:id/compositions/:compositionId", asyncHandler(controller.removeComposition));

// Variants
router.get("/:id/variants", asyncHandler(controller.listVariants));
router.post("/:id/variants", asyncHandler(controller.createVariant));
router.put("/:id/variants/:variantId", asyncHandler(controller.updateVariant));
router.patch("/:id/variants/:variantId/toggle", asyncHandler(controller.toggleVariant));
router.delete("/:id/variants/:variantId", asyncHandler(controller.removeVariant));

// Attribute values
router.put("/:id/attributes", asyncHandler(controller.setAttributeValues));

// Images
router.post("/:id/images", ...uploadArticleImageMiddleware, asyncHandler(controller.addImage));
router.patch("/:id/images/:imageId/set-main", asyncHandler(controller.setMainImage));
router.patch("/:id/images/:imageId", asyncHandler(controller.updateImageLabel));
router.delete("/:id/images/:imageId", asyncHandler(controller.removeImage));

// Stock
router.get("/:id/stock", asyncHandler(controller.getStock));
router.put("/:id/stock", asyncHandler(controller.adjustStock));

export default router;
