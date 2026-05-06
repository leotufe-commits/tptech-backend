// src/modules/promotions/promotions.routes.ts
import { Router } from "express";
import { asyncHandler } from "../../middlewares/asyncHandlers.js";
import { validateBody } from "../../middlewares/validate.js";
import * as controller from "./promotions.controller.js";
import { createPromotionSchema, updatePromotionSchema } from "./promotions.schemas.js";

const router = Router();

router.get("/",     asyncHandler(controller.list));
router.post("/",    validateBody(createPromotionSchema), asyncHandler(controller.create));
router.put("/:id",  validateBody(updatePromotionSchema), asyncHandler(controller.update));
router.patch("/:id/toggle", asyncHandler(controller.toggle));
router.delete("/:id", asyncHandler(controller.remove));

export default router;
