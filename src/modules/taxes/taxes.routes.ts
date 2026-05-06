import { Router } from "express";
import { asyncHandler } from "../../middlewares/asyncHandlers.js";
import { validateBody } from "../../middlewares/validate.js";
import * as controller from "./taxes.controller.js";
import { createTaxSchema, updateTaxSchema } from "./taxes.schemas.js";

const router = Router();

router.get("/", asyncHandler(controller.list));
router.post("/", validateBody(createTaxSchema), asyncHandler(controller.create));
router.post("/:id/clone", asyncHandler(controller.clone));
router.put("/:id", validateBody(updateTaxSchema), asyncHandler(controller.update));
router.patch("/:id/toggle", asyncHandler(controller.toggle));
router.patch("/:id/favorite", asyncHandler(controller.setFavorite));
router.delete("/:id", asyncHandler(controller.remove));

export default router;
