import { Router } from "express";
import { asyncHandler } from "../../middlewares/asyncHandlers.js";
import * as controller from "./categories.controller.js";

const router = Router();

/* =========================
   CATEGORIES
========================= */
router.get("/", asyncHandler(controller.list));
router.post("/", asyncHandler(controller.create));
router.put("/:id", asyncHandler(controller.update));
router.patch("/:id/toggle", asyncHandler(controller.toggle));
router.delete("/:id", asyncHandler(controller.remove));

// Reorder siblings: PATCH /api/categories/reorder
router.patch("/reorder", asyncHandler(controller.reorderCategories));

/* =========================
   ATTRIBUTE ASSIGNMENTS
   Nota: rutas /attributes/* van antes de /:id/* para claridad
========================= */
router.get("/:id/attributes/effective", asyncHandler(controller.getEffectiveAttributes));
router.get("/:id/attributes", asyncHandler(controller.listAttributes));
router.post("/:id/attributes", asyncHandler(controller.createAttribute));

router.put("/attributes/:attributeId", asyncHandler(controller.updateAttribute));
router.patch("/attributes/:attributeId/toggle", asyncHandler(controller.toggleAttribute));
router.delete("/attributes/:attributeId", asyncHandler(controller.removeAttribute));

/* =========================
   OPTIONS (on global def, routed via assignment for createOption)
========================= */
router.post("/attributes/:attributeId/options", asyncHandler(controller.createOption));
router.put("/attributes/options/:optionId", asyncHandler(controller.updateOption));
router.patch("/attributes/options/:optionId/toggle", asyncHandler(controller.toggleOption));
router.delete("/attributes/options/:optionId", asyncHandler(controller.removeOption));

export default router;
