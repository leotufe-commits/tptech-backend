// src/modules/units/units.routes.ts
import { Router } from "express";
import { asyncHandler } from "../../middlewares/asyncHandlers.js";
import { validateBody } from "../../middlewares/validate.js";
import * as controller from "./units.controller.js";
import {
  createUnitSchema,
  updateUnitSchema,
  favoriteUnitSchema,
} from "./units.schemas.js";

const router = Router();

/**
 * Base (montado en routes/index.ts):
 * /company/units
 */
router.get("/", asyncHandler(controller.list));
router.post("/", validateBody(createUnitSchema), asyncHandler(controller.create));
router.patch("/:id", validateBody(updateUnitSchema), asyncHandler(controller.update));
router.patch("/:id/favorite", validateBody(favoriteUnitSchema), asyncHandler(controller.setFavorite));
router.delete("/:id", asyncHandler(controller.remove));

export default router;
