// src/modules/document-templates/document-templates.routes.ts

import { Router } from "express";
import { requireAuth } from "../../middlewares/requireAuth.js";
import { asyncHandler } from "../../middlewares/asyncHandlers.js";
import * as ctrl from "./document-templates.controller.js";

const router = Router();
router.use(requireAuth);

router.get  ("/:kind",       asyncHandler(ctrl.getTemplate));
router.put  ("/:kind",       asyncHandler(ctrl.putTemplate));
router.patch("/:kind",       asyncHandler(ctrl.patchTemplate));
router.post ("/:kind/reset", asyncHandler(ctrl.resetTemplateHandler));

export default router;
