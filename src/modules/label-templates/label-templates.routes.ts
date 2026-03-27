// src/modules/label-templates/label-templates.routes.ts
import { Router } from "express";
import { requireAuth } from "../../middlewares/requireAuth.js";
import { asyncHandler } from "../../middlewares/asyncHandlers.js";
import * as ctrl from "./label-templates.controller.js";

const router = Router();
router.use(requireAuth);

router.get   ("/",                             asyncHandler(ctrl.list));
router.post  ("/",                             asyncHandler(ctrl.create));
router.get   ("/:id",                          asyncHandler(ctrl.getOne));
router.put   ("/:id",                          asyncHandler(ctrl.update));
router.delete("/:id",                          asyncHandler(ctrl.remove));
router.post  ("/:id/elements",                 asyncHandler(ctrl.addEl));
router.put   ("/:id/elements",                 asyncHandler(ctrl.replaceEl));
router.put   ("/:id/elements/:elementId",      asyncHandler(ctrl.updateEl));
router.delete("/:id/elements/:elementId",      asyncHandler(ctrl.deleteEl));

export default router;
