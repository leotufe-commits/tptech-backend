import { Router } from "express";
import { requireAuth } from "../../middlewares/requireAuth.js";
import * as controller from "./warehouses.controller.js";
import { asyncHandler } from "../../middlewares/asyncHandlers.js";

const router = Router();

router.use(requireAuth);

router.get("/", asyncHandler(controller.list));

router.post("/", asyncHandler(controller.create));
router.put("/:id", asyncHandler(controller.update));
router.patch("/:id/toggle", asyncHandler(controller.toggle));
router.delete("/:id", asyncHandler(controller.remove));

router.patch("/:id/favorite", asyncHandler(controller.setFavorite));

export default router;