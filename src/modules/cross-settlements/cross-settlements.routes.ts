// src/modules/cross-settlements/cross-settlements.routes.ts

import { Router } from "express";
import { asyncHandler } from "../../middlewares/asyncHandlers.js";
import * as controller from "./cross-settlements.controller.js";

const router = Router();

// GET  /suppliers/:supplierId/cross-settlements
router.get(
  "/suppliers/:supplierId/cross-settlements",
  asyncHandler(controller.list),
);

// POST /suppliers/:supplierId/cross-settlements
router.post(
  "/suppliers/:supplierId/cross-settlements",
  asyncHandler(controller.create),
);

// POST /cross-settlements/:id/void
router.post(
  "/cross-settlements/:id/void",
  asyncHandler(controller.voidOne),
);

// GET  /cross-settlements/:id
router.get(
  "/cross-settlements/:id",
  asyncHandler(controller.getOne),
);

export default router;
