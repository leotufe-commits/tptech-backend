// src/modules/printer-profiles/printer-profiles.routes.ts
import { Router } from "express";
import { requireAuth } from "../../middlewares/requireAuth.js";
import { asyncHandler } from "../../middlewares/asyncHandlers.js";
import * as ctrl from "./printer-profiles.controller.js";

const router = Router();
router.use(requireAuth);

router.get   ("/",    asyncHandler(ctrl.list));
router.post  ("/",    asyncHandler(ctrl.create));
router.put   ("/:id", asyncHandler(ctrl.update));
router.delete("/:id", asyncHandler(ctrl.remove));

export default router;
