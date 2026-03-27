// src/modules/promotions/promotions.routes.ts
import { Router } from "express";
import { asyncHandler } from "../../middlewares/asyncHandlers.js";
import * as controller from "./promotions.controller.js";

const router = Router();

router.get("/",     asyncHandler(controller.list));
router.post("/",    asyncHandler(controller.create));
router.put("/:id",  asyncHandler(controller.update));
router.delete("/:id", asyncHandler(controller.remove));

export default router;
